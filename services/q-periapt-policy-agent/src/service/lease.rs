//! Instance lease lifecycle: acquire, renew, journal reconciliation, coverage
//! proofs, and fencing for the one exclusive lease this process holds.

use super::*;

/// In-memory fast path for the acknowledgements lease receipts are owed. The
/// durable lease-intent journal in the repository has the same bound
/// (`MAX_JOURNALED_LEASE_INTENTS`) and every queued receipt has a row there,
/// so the journal refuses a lease operation before this queue could overflow.
const MAX_UNACKNOWLEDGED_LEASE_RECEIPTS: usize = 64;
pub(super) const LEASE_VERSION_RESYNC_ATTEMPTS: usize = 2;
/// Longest pause between two acquire attempts while a predecessor's lease is
/// waited out; see `acquire_instance_lease_within`.
const LEASE_WAIT_STEP: Duration = Duration::from_secs(1);
/// Shortest such pause, so an authority whose lease is about to lapse, or that
/// reports none at all between two refused acquires, is not polled flat out.
const LEASE_WAIT_MIN_PAUSE: Duration = Duration::from_millis(10);

/// RAM-only client view of this process's exclusive instance lease.
///
/// The fence (lease generation plus fresh process identity) deliberately never
/// touches disk: a restored clone of this host must not be able to replay the
/// live fence, so a process restart always starts a new acquire cycle.
///
/// What does touch disk is the operation id of every lease mutation, journaled
/// in the repository before it is dispatched (`journal_lease_intent`). The
/// acknowledgement each receipt is owed is the only thing that prunes the
/// authority's bounded receipt table, and it used to be owed from this struct
/// alone. The two lists below are the bookkeeping between that journal and the
/// authority.
pub(super) struct InstanceLeaseState {
    instance_id: ProcessInstanceIdV2,
    pub(super) fence: Option<InstanceFenceV2>,
    authority_version: u64,
    fenced: bool,
    unacknowledged: VecDeque<DurablyRetainedAuthorityReceiptV2>,
    /// Journaled operation ids this process has settled with the authority --
    /// acknowledged, found already absent, or provably never executed. The
    /// next journal write deletes their rows in its own transaction, so the
    /// steady state costs one durable transaction per lease operation, not
    /// two. Bounded by the journal: every id here has a row.
    settled: Vec<OperationIdV2>,
    /// Journaled operation ids whose outcome this process has not yet learned:
    /// rows a previous process left that the start-up reconciliation could not
    /// resolve, and dispatches whose response was lost. Queried again before
    /// each guarded operation. Bounded by the journal for the same reason.
    unresolved: Vec<OperationIdV2>,
    /// Local instant until which this process has *proved* it holds the lease.
    ///
    /// The renew receipt carries no expiry, so the only way to learn one is a
    /// snapshot. This is anchored to an instant captured before that request is
    /// sent, so it can only understate the remaining life: the authority's clock
    /// floor is nondecreasing, so the elapsed time it implies is an upper bound.
    /// `None` means nothing has been proven and no secret may be retained.
    covered_until: Option<Instant>,
}

pub(super) enum LeaseCall {
    Acquire,
    Renew,
    Release,
}

// The receipt stays `Copy` so one short-lived stack value can be compared and
// recorded without heap allocation, matching the wire payload discipline.
#[allow(clippy::large_enum_variant)]
/// Outcome of one lease exchange after exact-operation reconciliation.
pub(super) enum LeaseExchange {
    /// The authority returned this operation's exact authenticated receipt.
    Receipt(AuthorityReceiptV2),
    /// The operation provably never dispatched; rebuild the intent and retry.
    Retry,
}

fn fresh_lease_random() -> Result<[u8; 32], AgentError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AgentError::LocalCryptoFailure)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(AgentError::LocalCryptoFailure);
    }
    Ok(bytes)
}

fn authority_snapshot<A: InstanceAuthorityPort>(
    authority: &A,
) -> Result<AuthoritySnapshotV2, AgentError> {
    match authority.snapshot() {
        Ok(AuthorityOutcomeV2::Known(snapshot)) => Ok(snapshot),
        Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_)) | Err(_) => {
            Err(AgentError::InstanceLeaseUnavailable)
        }
    }
}

pub(super) fn lease_intent(
    lease: &InstanceLeaseState,
    config: DeploymentConfigRevisionV2,
    mutation: AuthorityMutationV2,
) -> Result<AuthorityIntentV2, AgentError> {
    let operation_id = OperationIdV2::new(lease.authority_version, fresh_lease_random()?)
        .map_err(|_| AgentError::InstanceLeaseUnavailable)?;
    AuthorityIntentV2::new(operation_id, lease.authority_version, config, mutation)
        .map_err(|_| AgentError::InstanceLeaseUnavailable)
}

fn record_lease_receipt(
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
    receipt: AuthorityReceiptV2,
) -> Result<LeaseExchange, AgentError> {
    if receipt.intent() != intent {
        return Err(AgentError::InstanceLeaseUnavailable);
    }
    lease.authority_version = receipt.resulting_authority_version();
    // The lease view is RAM-only: after a crash the successor process starts a
    // fresh acquire cycle and never needs this receipt to reconcile its own
    // outcome. What the receipt still owes is an acknowledgement, which is the
    // only thing that ever removes it from the authority's bounded receipt
    // table (`HARD_MAX_RECEIPTS`). That obligation is durable: the operation
    // id was journaled in the repository before this dispatch
    // (`journal_lease_intent`), and its row stays until the receipt is
    // acknowledged and the next journal write forgets it, or until a later
    // start finds the receipt still held and acknowledges it then
    // (`reconcile_lease_journal`). This queue is only the fast path. The
    // journal has the same bound as the queue and every queued receipt has a
    // row, so the journal refuses the operation before the queue can fill;
    // should a receipt still fail to queue, its id goes to `unresolved` and
    // this process queries it again before the next guarded operation rather
    // than leaving it to the next start.
    if let Ok(retained) = DurablyRetainedAuthorityReceiptV2::after_durable_commit(receipt) {
        if lease.unacknowledged.len() < MAX_UNACKNOWLEDGED_LEASE_RECEIPTS
            && lease.unacknowledged.try_reserve(1).is_ok()
        {
            lease.unacknowledged.push_back(retained);
        } else {
            keep_unresolved(lease, intent.operation_id());
        }
    }
    Ok(LeaseExchange::Receipt(receipt))
}

pub(super) fn drain_acknowledgements<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
) {
    while let Some(retained) = lease.unacknowledged.front() {
        let operation_id = retained.locator().operation_id();
        match authority.acknowledge(retained) {
            Ok(AuthorityOutcomeV2::Known(_)) => {
                lease.unacknowledged.pop_front();
                settle(lease, operation_id);
            }
            // The authority holds no retained state matching this locator, so
            // there is nothing left to reclaim and no retry can change that:
            // its receipt table only ever shrinks. Keeping the entry would
            // block every acknowledgement behind it permanently -- the queue
            // drains strictly in order, this failure does not poison the store,
            // and acknowledgement is the only thing that ever removes a receipt
            // on either side. One unmatchable receipt would fill this bounded
            // queue and then leave the authority's own table to fill too, which
            // ends with the daemon unable to acquire a lease at all. Discard it
            // and carry on; its journal row is settled for the same reason.
            Ok(AuthorityOutcomeV2::KnownFailure(
                AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
            )) => {
                lease.unacknowledged.pop_front();
                settle(lease, operation_id);
            }
            // Everything else is a server-side condition that can clear: a full
            // nonce table, a failed allocation, an unavailable clock, or an
            // indeterminate response. Stop and retry on the next drain rather
            // than discarding an obligation that can still be honoured.
            Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_)) | Err(_) => {
                return;
            }
        }
    }
}

fn reconcile_lease_operation<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
) -> Result<LeaseExchange, AgentError> {
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        match authority.query(intent.operation_id()) {
            Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt))) => {
                return record_lease_receipt(lease, intent, *receipt);
            }
            Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version,
            })) => {
                // Provably never executed: the authority owes nothing for this
                // id, so its journal row is settled.
                lease.authority_version = authority_version;
                settle(lease, intent.operation_id());
                return Ok(LeaseExchange::Retry);
            }
            Ok(AuthorityOutcomeV2::KnownFailure(_)) => {
                keep_unresolved(lease, intent.operation_id());
                return Err(AgentError::InstanceLeaseUnavailable);
            }
            Ok(AuthorityOutcomeV2::Unknown(_)) | Err(_) => {}
        }
    }
    keep_unresolved(lease, intent.operation_id());
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Dispatch one lease mutation, journaling its intent durably first.
///
/// The journal write precedes every dispatch -- the acquire at start, each
/// renew, the re-acquire after a lapse, and the release -- so that whatever
/// happens next, a successor process can find this operation and discharge the
/// acknowledgement its receipt is owed. An outcome that proves the authority
/// never executed the operation settles the row at once; an outcome that
/// leaves it unknown keeps the id for a later query.
pub(super) fn lease_exchange<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
    call: LeaseCall,
    intent: AuthorityIntentV2,
) -> Result<LeaseExchange, AgentError> {
    journal_lease_intent(repository, lease, intent.operation_id())?;
    let outcome = match call {
        LeaseCall::Acquire => authority.acquire(intent),
        LeaseCall::Renew => authority.renew(intent),
        LeaseCall::Release => authority.release(intent),
    };
    match outcome {
        Ok(AuthorityOutcomeV2::Known(receipt)) => record_lease_receipt(lease, intent, receipt),
        Ok(AuthorityOutcomeV2::KnownFailure(AuthorityKnownFailureV2::AuthorityVersionMismatch)) => {
            // Refused on its precondition, never executed: settled.
            settle(lease, intent.operation_id());
            let snapshot = authority_snapshot(authority)?;
            lease.authority_version = snapshot.authority_version();
            Ok(LeaseExchange::Retry)
        }
        // Any other known failure says the authority declined to execute, but
        // the proof this code relies on elsewhere is a query, not a failure
        // code; keep the id and let the next drain ask.
        Ok(AuthorityOutcomeV2::KnownFailure(_)) => {
            keep_unresolved(lease, intent.operation_id());
            Err(AgentError::InstanceLeaseUnavailable)
        }
        Ok(AuthorityOutcomeV2::Unknown(_)) => reconcile_lease_operation(authority, lease, intent),
        Err(_) => {
            keep_unresolved(lease, intent.operation_id());
            Err(AgentError::InstanceLeaseUnavailable)
        }
    }
}

/// Durably journal one lease intent before it is dispatched, forgetting the
/// settled rows in the same transaction.
fn journal_lease_intent(
    repository: &StateRepository,
    lease: &mut InstanceLeaseState,
    operation_id: OperationIdV2,
) -> Result<(), AgentError> {
    match repository.journal_lease_intent(operation_id, &lease.settled) {
        Ok(()) => {
            lease.settled.clear();
            Ok(())
        }
        // The journal is full of intents whose acknowledgement the authority
        // has not accepted -- or, after enough crashes, could not answer for.
        // Nothing was committed, the settled list is still exact, and the
        // operation must not run: dispatching it would owe one more
        // acknowledgement with nowhere durable to record it. The drains before
        // the next attempt are what free the journal.
        Err(RepositoryError::CapacityExceeded) => Err(AgentError::InstanceLeaseUnavailable),
        Err(other) => Err(AgentError::from(other)),
    }
}

/// Mark one journaled operation as settled with the authority, so the next
/// journal write forgets its row.
///
/// Bounded by the journal: every id here has a row there. Should the list
/// itself fail to grow, the row stays until a later start finds the operation
/// absent and forgets it -- the authority has already forgotten its side.
fn settle(lease: &mut InstanceLeaseState, operation_id: OperationIdV2) {
    if lease.settled.try_reserve(1).is_ok() {
        lease.settled.push(operation_id);
    }
}

/// Keep one journaled operation whose outcome is not yet known, to be queried
/// again before the next guarded operation.
///
/// Bounded like `settle`, and the fallback is the same: a row that cannot be
/// tracked here is still journaled, and the next start queries it.
fn keep_unresolved(lease: &mut InstanceLeaseState, operation_id: OperationIdV2) {
    if lease.unresolved.try_reserve(1).is_ok() {
        lease.unresolved.push(operation_id);
    }
}

/// Durably forget every settled journal row now, rather than at the next
/// journal write. Used where no journal write follows: shutdown.
pub(super) fn forget_settled(
    repository: &StateRepository,
    lease: &mut InstanceLeaseState,
) -> Result<(), AgentError> {
    repository.forget_lease_intents(&lease.settled)?;
    lease.settled.clear();
    Ok(())
}

/// What one query told us about a journaled operation.
enum JournalResolution {
    /// The authority owes nothing further for this id: its receipt is now
    /// acknowledged, or it never saw the operation.
    Settled,
    /// The authority could not answer, or would not yet accept the
    /// acknowledgement; ask again later.
    Pending,
}

/// Ask the authority about one journaled operation and discharge what it owes.
fn resolve_journaled_intent<A: InstanceAuthorityPort>(
    authority: &A,
    operation_id: OperationIdV2,
) -> JournalResolution {
    match authority.query(operation_id) {
        Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt))) => {
            let Ok(retained) = DurablyRetainedAuthorityReceiptV2::after_durable_commit(*receipt)
            else {
                // This agent journals only lease mutations, so the authority
                // holds something under this id that no acknowledgement of
                // ours can ever discharge. The row buys nothing; let it go,
                // exactly as the drain discards an unmatchable receipt.
                return JournalResolution::Settled;
            };
            match authority.acknowledge(&retained) {
                Ok(AuthorityOutcomeV2::Known(_))
                | Ok(AuthorityOutcomeV2::KnownFailure(
                    AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
                )) => JournalResolution::Settled,
                Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_))
                | Err(_) => JournalResolution::Pending,
            }
        }
        Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion { .. })) => {
            JournalResolution::Settled
        }
        Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_)) | Err(_) => {
            JournalResolution::Pending
        }
    }
}

/// Settle the lease-intent journal a previous process left behind, before
/// this one dispatches anything.
///
/// A row left by a crash between the journal write and the dispatch is found
/// absent and forgotten. A row left by a crash after the dispatch names a
/// receipt the authority is still retaining; it is acknowledged here, and only
/// then forgotten. A row the authority cannot answer for stays journaled and
/// is carried as `unresolved`, to be asked about again before each guarded
/// operation.
///
/// The first unanswered query ends the pass: an unreachable authority would
/// otherwise cost one timeout per row before the acquire even starts, and the
/// acquire that follows asks the authority anyway. A journal that is still full
/// after this pass -- all `MAX_JOURNALED_LEASE_INTENTS` rows unanswerable --
/// fails the start closed with [`AgentError::InstanceLeaseUnavailable`]: the
/// acquire's own journal write, which every dispatch makes first, is refused,
/// so nothing is dispatched. The next start asks again.
fn reconcile_lease_journal<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
) -> Result<(), AgentError> {
    let journaled = repository.journaled_lease_intents()?;
    let mut settled = Vec::new();
    settled
        .try_reserve(journaled.len())
        .map_err(|_| AgentError::LocalResourceFailure)?;
    lease
        .unresolved
        .try_reserve(journaled.len())
        .map_err(|_| AgentError::LocalResourceFailure)?;
    let mut answering = true;
    for operation_id in journaled {
        // Once one query has gone unanswered, the rest are not asked at all:
        // evaluating the resolver first and consulting `answering` afterwards
        // would still cost one timeout per remaining row.
        if !answering {
            lease.unresolved.push(operation_id);
            continue;
        }
        match resolve_journaled_intent(authority, operation_id) {
            JournalResolution::Settled => settled.push(operation_id),
            JournalResolution::Pending => {
                answering = false;
                lease.unresolved.push(operation_id);
            }
        }
    }
    repository
        .forget_lease_intents(&settled)
        .map_err(AgentError::from)
}

/// Query the journaled operations whose outcome this process does not yet
/// know, settling those the authority can now answer for.
///
/// Stops at the first unanswered query for the same reason the start-up pass
/// does; the next guarded operation asks again.
fn drain_unresolved<A: InstanceAuthorityPort>(authority: &A, lease: &mut InstanceLeaseState) {
    while let Some(operation_id) = lease.unresolved.last().copied() {
        match resolve_journaled_intent(authority, operation_id) {
            JournalResolution::Settled => {
                lease.unresolved.pop();
                settle(lease, operation_id);
            }
            JournalResolution::Pending => return,
        }
    }
}

/// Adopt the authority's current lease when a lost response already acquired
/// it for this exact fresh process identity; fail closed on any other holder.
fn adopt_or_reject_active_lease(
    lease: &mut InstanceLeaseState,
    snapshot: &AuthoritySnapshotV2,
    expected_lease_generation: &mut u64,
) -> Result<bool, AgentError> {
    lease.authority_version = snapshot.authority_version();
    match snapshot.active_lease() {
        Some(active) if active.fence().instance_id() == lease.instance_id => {
            lease.fence = Some(active.fence());
            Ok(true)
        }
        Some(_) => Err(AgentError::InstanceFenced),
        None => {
            *expected_lease_generation = snapshot.lease_generation();
            Ok(false)
        }
    }
}

pub(super) fn acquire_instance_lease<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
) -> Result<InstanceLeaseState, AgentError> {
    let instance_id = ProcessInstanceIdV2::from_bytes(fresh_lease_random()?)
        .map_err(|_| AgentError::LocalCryptoFailure)?;
    let mut lease = InstanceLeaseState {
        instance_id,
        fence: None,
        authority_version: 1,
        fenced: false,
        unacknowledged: VecDeque::new(),
        settled: Vec::new(),
        unresolved: Vec::new(),
        covered_until: None,
    };
    reconcile_lease_journal(repository, authority, &mut lease)?;
    let snapshot = authority_snapshot(authority)?;
    lease.authority_version = snapshot.authority_version();
    if snapshot.active_lease().is_some() {
        return Err(AgentError::InstanceFenced);
    }
    let mut expected_lease_generation = snapshot.lease_generation();
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let intent = lease_intent(
            &lease,
            authority.wire_config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id,
            },
        )?;
        match lease_exchange(
            repository,
            authority,
            &mut lease,
            LeaseCall::Acquire,
            intent,
        )? {
            LeaseExchange::Receipt(receipt) => {
                drain_acknowledgements(authority, &mut lease);
                match receipt.disposition() {
                    AuthorityDispositionV2::Applied => {
                        let generation = expected_lease_generation
                            .checked_add(1)
                            .ok_or(AgentError::InstanceLeaseUnavailable)?;
                        lease.fence = Some(
                            InstanceFenceV2::new(generation, instance_id)
                                .map_err(|_| AgentError::InstanceLeaseUnavailable)?,
                        );
                        return Ok(lease);
                    }
                    AuthorityDispositionV2::Rejected(
                        AuthorityRejectionV2::LeaseHeld
                        | AuthorityRejectionV2::LeaseGenerationMismatch,
                    ) => {
                        let snapshot = authority_snapshot(authority)?;
                        if adopt_or_reject_active_lease(
                            &mut lease,
                            &snapshot,
                            &mut expected_lease_generation,
                        )? {
                            return Ok(lease);
                        }
                    }
                    AuthorityDispositionV2::Rejected(_) => {
                        return Err(AgentError::InstanceLeaseUnavailable);
                    }
                }
            }
            LeaseExchange::Retry => {
                let snapshot = authority_snapshot(authority)?;
                if adopt_or_reject_active_lease(
                    &mut lease,
                    &snapshot,
                    &mut expected_lease_generation,
                )? {
                    return Ok(lease);
                }
            }
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Acquire the instance lease, waiting up to `max_wait` for another holder's
/// lease to lapse; see [`PolicyAgent::new_with_lease_wait`].
///
/// Only [`AgentError::InstanceFenced`] is retried, and from the acquire it has
/// exactly one meaning: another instance held an active lease at the moment of
/// the attempt, whether the pre-acquire snapshot reported it or the acquire
/// itself was rejected as held and the snapshot that followed confirmed a
/// different holder. Transport failures, indeterminate outcomes, and every
/// other error return at once.
pub(super) fn acquire_instance_lease_within<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
    max_wait: Duration,
) -> Result<InstanceLeaseState, AgentError> {
    let deadline = Instant::now()
        .checked_add(max_wait)
        .ok_or(AgentError::InvalidConfiguration)?;
    loop {
        match acquire_instance_lease(repository, authority) {
            Err(AgentError::InstanceFenced) => {}
            outcome => return outcome,
        }
        let remaining_wait = deadline.saturating_duration_since(Instant::now());
        if remaining_wait.is_zero() {
            return Err(AgentError::InstanceFenced);
        }
        std::thread::sleep(lease_wait_pause(authority).min(remaining_wait));
    }
}

/// How long to pause before the next acquire attempt: the remaining life of
/// the lease the authority currently reports, clamped to
/// `LEASE_WAIT_MIN_PAUSE..=LEASE_WAIT_STEP`.
///
/// The remaining life is read from a fresh snapshot rather than guessed from a
/// TTL, because the authority's clock, not this host's, decides when a lease is
/// gone; `active_lease` is already filtered to unexpired leases, so the
/// subtraction cannot underflow for a lease it reports. A snapshot that cannot
/// be read gets the full step, and one that reports no lease at all -- it
/// lapsed or was released since the refused acquire -- gets the floor: the next
/// attempt is what decides, and the floor keeps an authority that flaps from
/// being polled at full speed.
fn lease_wait_pause<A: InstanceAuthorityPort>(authority: &A) -> Duration {
    let remaining = match authority_snapshot(authority) {
        Ok(snapshot) => snapshot.active_lease().map_or(Duration::ZERO, |active| {
            Duration::from_millis(
                active
                    .expires_at_millis()
                    .saturating_sub(snapshot.clock_floor_millis()),
            )
        }),
        Err(_) => LEASE_WAIT_STEP,
    };
    remaining.clamp(LEASE_WAIT_MIN_PAUSE, LEASE_WAIT_STEP)
}

/// Re-authorize key use behind the exclusive lease before every guarded operation.
///
/// Every guarded operation renews against the authority's trusted clock, so a
/// fenced or superseded instance is rejected before it can touch a pending or
/// accepted secret, and it erases every secret before the rejection returns.
///
/// A lease that merely lapsed -- nobody else holds it -- is handled in one of
/// two ways depending on where the lapse is first seen. If the renew itself is
/// rejected as expired, `recover_expired_lease` re-acquires at this instance's
/// own generation in the same call: every secret is erased, and the operation
/// then proceeds. If the renew applied but the coverage snapshot that follows
/// reports the lease gone at this instance's generation, the operation is
/// aborted with [`AgentError::InstanceLeaseCoverageElapsed`] and nothing is
/// erased; the next guarded operation's renew is what performs that re-acquire.
///
/// A successful renew also records how long the lease is provably still held,
/// which the operation re-checks before it retains anything. The renew alone
/// only authorizes the *start* of the operation; the work that follows is not
/// instantaneous, and the receipt carries no expiry with which to bound it.
pub(super) fn ensure_instance_lease<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.lease.fenced {
        return Err(AgentError::InstanceFenced);
    }
    let Some(fence) = inner.lease.fence else {
        return Err(AgentError::InstanceFenced);
    };
    drain_acknowledgements(&inner.authority, &mut inner.lease);
    drain_unresolved(&inner.authority, &mut inner.lease);
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let intent = lease_intent(
            &inner.lease,
            inner.authority.wire_config(),
            AuthorityMutationV2::RenewLease { fence },
        )?;
        match lease_exchange(
            &inner.repository,
            &inner.authority,
            &mut inner.lease,
            LeaseCall::Renew,
            intent,
        )? {
            LeaseExchange::Receipt(receipt) => {
                drain_acknowledgements(&inner.authority, &mut inner.lease);
                return match receipt.disposition() {
                    AuthorityDispositionV2::Applied
                    | AuthorityDispositionV2::Rejected(
                        // The fence was verified live; only the expiry could
                        // not strictly extend within this clock-floor instant.
                        AuthorityRejectionV2::LeaseRenewalNotExtended,
                    ) => prove_lease_coverage(inner, fence),
                    AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseExpired) => {
                        recover_expired_lease(inner, fence)
                    }
                    AuthorityDispositionV2::Rejected(
                        AuthorityRejectionV2::LeaseAbsent | AuthorityRejectionV2::FenceMismatch,
                    ) => {
                        fence_out(inner)?;
                        Err(AgentError::InstanceFenced)
                    }
                    AuthorityDispositionV2::Rejected(_) => {
                        Err(AgentError::InstanceLeaseUnavailable)
                    }
                };
            }
            LeaseExchange::Retry => {}
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Erase every in-process pending and accepted secret, reporting the first
/// failure only after all of them are gone.
///
/// Split out of `fence_out` because two situations need the erasure and only one
/// of them is a fence: losing the lease to a successor is permanent, while
/// re-acquiring a lease that merely lapsed is not.
pub(super) fn erase_all_secrets<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Option<AgentError> {
    let handles: Vec<_> = inner.pending_sessions.keys().copied().collect();
    let mut first_failure = None;
    for handle in handles {
        if let Err(error) = erase_pending(inner, handle) {
            first_failure = first_failure.or(Some(error));
        }
    }
    inner.confirmed_keys.clear();
    inner.completed_acceptances.clear();
    inner.lease.covered_until = None;
    first_failure
}

/// Recover a lease that merely lapsed, or fence if a successor really took it.
///
/// `LeaseExpired` says only that the lease had run out by the authority's clock
/// when the renew arrived. It does not say anyone else took it, and the two
/// were previously conflated: an authority unreachable for longer than the TTL
/// -- a fifteen-second restart is enough against the ten-second minimum -- made
/// the first successful renew after reconnect fence the agent permanently,
/// unattended, with no successor anywhere.
///
/// So this re-acquires at **our own** generation. `plan_acquire` admits that
/// only while the authority's `lease_generation` still equals it, and that
/// counter advances on acquire alone, so success is a proof that no other
/// instance ever held key-use authority in between. A successor -- even one that
/// has already released -- moves the counter and fails this, fencing exactly as
/// before. It is a proof, not a heuristic, and it never weakens exclusivity.
///
/// Every secret is still erased. Acquire clears the authority's key table and
/// key identity binds the lease generation, so material from the old generation
/// cannot be carried across. What is kept is the agent itself: it stays usable
/// instead of needing a process restart.
fn recover_expired_lease<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    fence: InstanceFenceV2,
) -> Result<(), AgentError> {
    let expected_lease_generation = fence.generation();
    let instance_id = inner.lease.instance_id;
    let intent = lease_intent(
        &inner.lease,
        inner.authority.wire_config(),
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation,
            instance_id,
        },
    )?;
    let outcome = lease_exchange(
        &inner.repository,
        &inner.authority,
        &mut inner.lease,
        LeaseCall::Acquire,
        intent,
    )?;
    let LeaseExchange::Receipt(receipt) = outcome else {
        // Indeterminate. Do not fence -- that is permanent and this is not
        // evidence of a successor -- and do not proceed either.
        return Err(AgentError::InstanceLeaseIndeterminate);
    };
    if !matches!(receipt.disposition(), AuthorityDispositionV2::Applied) {
        fence_out(inner)?;
        return Err(AgentError::InstanceFenced);
    }
    if let Some(error) = erase_all_secrets(inner) {
        return Err(error);
    }
    let generation = expected_lease_generation
        .checked_add(1)
        .ok_or(AgentError::InstanceLeaseUnavailable)?;
    let recovered = InstanceFenceV2::new(generation, instance_id)
        .map_err(|_| AgentError::InstanceLeaseUnavailable)?;
    inner.lease.fence = Some(recovered);
    drain_acknowledgements(&inner.authority, &mut inner.lease);
    prove_lease_coverage(inner, recovered)
}

/// Learn how long this instance can prove it still holds the lease.
///
/// A renew receipt reports only that the renew applied, never until when: the
/// wire receipt carries no expiry and widening it would break a released ABI.
/// The expiry is therefore read from a snapshot, which the port already offers.
///
/// The anchor is captured **before** the request is sent, so the recorded
/// coverage can only understate the truth. The authority's clock floor is
/// nondecreasing, so the elapsed time it implies is an upper bound, and the
/// snapshot's own `active_lease` is already filtered to unexpired leases. That
/// makes this a liveness check as well: no active lease, or one carrying a fence
/// that is not ours, means the lease is already gone.
///
/// The cost is one extra authority round trip per guarded operation. That is the
/// price of the expiry not being on the renew path; do not substitute a guessed
/// TTL for it. `HARD_MIN_LEASE_TTL_MILLIS` in particular would discard almost
/// all of a long configured lease and turn this check into key destruction on a
/// perfectly healthy lease.
///
/// A snapshot that reports **no** active lease is not, by itself, evidence of a
/// successor. The renew that preceded this call applied against the authority's
/// clock, and the lease can lapse between that renew and this snapshot -- an
/// authority clock jump, or simply the round trip taking longer than the lease
/// had left. Fencing on that alone was permanent and unrecoverable, with nobody
/// else ever having held the lease. So the lapse is told apart from a takeover
/// by the same proof `recover_expired_lease` relies on: the authority's
/// `lease_generation` advances on acquire alone, so while it still equals our
/// fence's generation no other instance has acquired since we did, and the
/// lease merely lapsed. That is a coverage lapse -- transient, and recovered by
/// the next guarded operation's renew, which the authority will reject as
/// expired and `recover_expired_lease` will re-acquire. Only an active lease
/// under a different fence, or a generation that has moved past ours, proves a
/// successor and fences.
fn prove_lease_coverage<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    fence: InstanceFenceV2,
) -> Result<(), AgentError> {
    let anchor = Instant::now();
    let snapshot = authority_snapshot(&inner.authority)?;
    let Some(active) = snapshot.active_lease() else {
        return match snapshot.lease_generation().cmp(&fence.generation()) {
            // Nobody has acquired since we did: the lease lapsed, and no
            // successor exists. Not a fence. The error aborts the operation
            // before anything is retained, and the previous operation's proof
            // is cleared so the field never claims coverage this snapshot just
            // contradicted.
            core::cmp::Ordering::Equal => {
                inner.lease.covered_until = None;
                Err(AgentError::InstanceLeaseCoverageElapsed)
            }
            // A later acquire happened -- even one that has since released or
            // expired -- so another instance held key-use authority after us.
            core::cmp::Ordering::Greater => {
                fence_out(inner)?;
                Err(AgentError::InstanceFenced)
            }
            // The authority's generation is *behind* the one it issued us. It
            // has been rolled back beneath a lease it already granted, which
            // means it could grant our generation again to someone else. That
            // lease can no longer be trusted; fail closed.
            core::cmp::Ordering::Less => {
                fence_out(inner)?;
                Err(AgentError::InstanceFenced)
            }
        };
    };
    if active.fence() != fence {
        fence_out(inner)?;
        return Err(AgentError::InstanceFenced);
    }
    let remaining = active
        .expires_at_millis()
        .checked_sub(snapshot.clock_floor_millis())
        .ok_or(AgentError::InstanceLeaseCoverageElapsed)?;
    inner.lease.covered_until = anchor.checked_add(Duration::from_millis(remaining));
    Ok(())
}

/// Refuse to retain or return a secret once the proven coverage has elapsed.
///
/// The lease is checked on the way in, but the work that follows is not
/// instantaneous: a witness round trip, two signature verifications, a KEM
/// operation, and finally a durable reservation or release -- a real fsync --
/// all sit between that check and the point where a secret first becomes
/// retained.
///
/// It is therefore consulted twice. Once before the durable write, as an
/// early-out that avoids paying for an fsync the operation is about to
/// discard. And once more *after* it, immediately before the in-memory
/// insert that makes the secret reachable (`reserve_pending`,
/// `retain_accepted_key`). The second check is the guarantee; the first is an
/// optimisation. What remains between the second check and retention is a
/// hash-map insert, not I/O.
///
/// It deliberately does not fence. A local deadline running out is no evidence
/// that any successor exists, and fencing is permanent.
pub(super) fn ensure_lease_covers<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<(), AgentError> {
    match inner.lease.covered_until {
        Some(until) if Instant::now() < until => Ok(()),
        _ => Err(AgentError::InstanceLeaseCoverageElapsed),
    }
}

/// Erase every in-process pending and accepted secret and retire this fence.
///
/// After this returns, the agent permanently refuses lease-guarded operations
/// and holds no pending or accepted secret.
///
/// Whether the erasure precedes a successor's acquire depends on which caller
/// ran it, and an earlier version of this comment asserted the strong form for
/// both:
///
/// * From `release_instance_lease` it holds. That path erases first and only
///   then tells the authority to release, so no successor can acquire until
///   after this instance is empty.
/// * From `ensure_instance_lease` it does not. That path runs when a renew was
///   already rejected, which means the successor acquired first: a successor's
///   acquire is gated purely on wall-clock expiry (`plan_acquire`), with no
///   interaction with the incumbent and no revocation, so this instance learns
///   it was fenced only by being rejected.
///
/// What both callers do guarantee is the erasure itself, before the rejected
/// call returns, and that no session secret was **retained or returned** outside
/// the window this instance could prove it held the lease -- see
/// `prove_lease_coverage` and `ensure_lease_covers`. That is narrower than "key
/// use has stopped": the KEM itself runs before the coverage check, and the
/// long-term ABI 2 executor keys are outside this mechanism entirely.
pub(super) fn fence_out<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    // Erase everything first, and report a failure only afterwards. This runs
    // when another instance holds the lease, which is precisely when this
    // process must not be left holding key material. Abandoning the sweep on the
    // first failed durable cancellation would skip both clears below and leave
    // every accepted application key live -- the opposite of what fencing out
    // exists to guarantee. `erase_pending` drops each secret before it touches
    // the repository, so continuing past a failure still erases.
    let first_failure = erase_all_secrets(inner);
    inner.lease.fence = None;
    // The process is fenced whether or not the durable bookkeeping succeeded;
    // that is a fact about the lease, not about the erasure.
    inner.lease.fenced = true;
    match first_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
