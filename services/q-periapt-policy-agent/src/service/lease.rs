//! Instance lease lifecycle: acquire, renew, journal reconciliation, coverage
//! proofs, and fencing for the one exclusive lease this process holds.

use super::*;

use crate::authority_codec::HARD_MIN_LEASE_TTL_MILLIS;

/// In-memory fast path for the acknowledgements lease receipts are owed. The
/// durable lease-intent journal in the repository has the same bound
/// (`MAX_JOURNALED_LEASE_INTENTS`) and every queued receipt has a row there,
/// so the journal refuses a lease operation before this queue could overflow.
const MAX_UNACKNOWLEDGED_LEASE_RECEIPTS: usize = 64;
const LEASE_VERSION_RESYNC_ATTEMPTS: usize = 2;
/// Longest pause between two acquire attempts while a predecessor's lease is
/// waited out; see `acquire_instance_lease_within`.
const LEASE_WAIT_STEP: Duration = Duration::from_secs(1);
/// Shortest such pause, so an authority whose lease is about to lapse, or that
/// reports none at all between two refused acquires, is not polled flat out.
const LEASE_WAIT_MIN_PAUSE: Duration = Duration::from_millis(10);

/// Most authority clock advance, beyond this host's elapsed time, that a
/// coverage proof tolerates between the authority's clock read behind a
/// snapshot and the local instant a secret is retained.
///
/// Two clocks are involved: the authority's, which alone decides when a lease
/// is gone, and this host's monotonic clock, which is all a check between two
/// round trips can read. Let `F` be the clock floor a snapshot reported and
/// `E` the lease's exclusive expiry, both authority time, and `anchor` the
/// local instant captured before that snapshot was requested. The model is
/// that from the clock read behind the snapshot to any later local instant
/// `t` inside the same guarded operation, the authority clock advances by at
/// most `(t - anchor) + B`; retention at `t` is then allowed only while
/// `F + (t - anchor) + B < E`, that is `t < anchor + (E - F - B)`
/// (`coverage_deadline`). Nothing bounds that divergence from outside -- a
/// forward step of the authority's wall clock is invisible to this host -- so
/// the bound is relied on only across the retention snapshot's own round trip
/// plus the hash-map inserts that retain the secret:
/// `prove_lease_covers_retention` re-takes the observation after the
/// operation's last I/O. An authority clock stepping
/// further than this within one such round trip is out of model.
pub(crate) const LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS: u64 = 1_000;
// A fresh renew at the shortest configurable TTL must leave usable coverage
// with room to spare, or the budget would turn a healthy lease into refusals.
const _: () = assert!(LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS * 4 <= HARD_MIN_LEASE_TTL_MILLIS);

/// The local instant until which a lease reported with clock floor
/// `clock_floor_millis` and expiry `expires_at_millis` is proven held under
/// the model above, when the snapshot was requested at `anchor`.
///
/// `None` when the lease had already lapsed by the authority's clock, when no
/// more than the budget is left, or when the instant cannot be represented:
/// nothing may be retained on it.
pub(crate) fn coverage_deadline(
    anchor: Instant,
    clock_floor_millis: u64,
    expires_at_millis: u64,
) -> Option<Instant> {
    let usable = expires_at_millis
        .checked_sub(clock_floor_millis)?
        .checked_sub(LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS)
        .filter(|usable| *usable > 0)?;
    anchor.checked_add(Duration::from_millis(usable))
}

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
///
/// A re-acquire dispatched after a lapse whose outcome is still unknown is
/// remembered in `pending_acquire`, with the fence it would have produced. That
/// record is RAM-only like the fence -- a successor process has a fresh
/// instance id and could not use it -- and its durable trace is the journal
/// row the dispatch already wrote.
pub(super) struct InstanceLeaseState {
    instance_id: ProcessInstanceIdV2,
    fence: Option<InstanceFenceV2>,
    authority_version: u64,
    /// Where the lease stands in its lifecycle; see [`LeasePhase`]. Only a
    /// `Serving` lease renews or runs a guarded operation.
    pub(super) phase: LeasePhase,
    /// A re-acquire this process dispatched whose outcome it has not learned;
    /// see [`PendingAcquire`]. While this is `Some`, no renew is dispatched
    /// and no receipt under its operation id is acknowledged unread.
    pending_acquire: Option<PendingAcquire>,
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
    /// Local instant until which this process has *proved* it holds the lease,
    /// under the two-clock model at `LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS`.
    /// `None` means nothing has been proven and no secret may be retained.
    ///
    /// The renew receipt carries no expiry, so the only way to learn one is a
    /// snapshot, which reports the authority's clock floor and the lease's
    /// expiry in authority time. The proof is anchored to a local instant
    /// captured before that request is sent and ends the budget short of the
    /// remaining life it reports (`coverage_deadline`): the authority's clock
    /// floor is nondecreasing, so the elapsed time it implies is an upper
    /// bound only while the authority's clock runs ahead of this host's by no
    /// more than the budget. That is why no secret is retained on this field
    /// alone: `prove_lease_covers_retention` re-observes the authority after
    /// the operation's last I/O and sets it afresh before the insert.
    covered_until: Option<Instant>,
}

/// Where this instance's lease stands.
///
/// `Serving` is the only phase that renews and runs guarded operations.
/// `Releasing` is entered by `release_lease_state` before its first dispatch
/// and kept whenever that release could not be settled: the fence stays, so a
/// later call can dispatch the release again, and guarded operations are
/// refused as fenced from the first attempt on. `Retired` is final -- the
/// fence is gone -- and is entered by `fence_out` (a successor, a rolled-back
/// authority, a foreign fence) or by a release the authority confirmed or a
/// snapshot proved. Releasing never returns to Serving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LeasePhase {
    Serving,
    Releasing,
    Retired,
}

/// Retire this instance's fence for good: no lease is held, nothing is left to
/// resolve, no coverage is proven, and every guarded operation is refused from
/// now on.
fn retire(lease: &mut InstanceLeaseState) {
    lease.fence = None;
    lease.pending_acquire = None;
    lease.covered_until = None;
    lease.phase = LeasePhase::Retired;
}

/// A re-acquire this process dispatched after its lease lapsed, whose outcome
/// it has not yet learned.
///
/// `expected_fence` is the fence `plan_acquire` produces if and only if this
/// exact acquire applied: the next generation under this process's own fresh
/// instance id, which no other process can produce. `intent` is the exact
/// intent dispatched, so the receipt found for it can be matched the way every
/// other receipt is. Only `resolve_pending_acquire_state` clears the record
/// with a verdict; `retire` drops it with the fence.
#[derive(Clone, Copy)]
struct PendingAcquire {
    intent: AuthorityIntentV2,
    expected_fence: InstanceFenceV2,
}

/// The least I/O a guarded operation performs once its lease is renewed, in
/// port round trips: what `ensure_instance_lease` reserves out of the
/// operation's deadline before it dispatches anything, and what every drain
/// leaves untouched.
#[derive(Clone, Copy)]
pub(super) struct OperationPlan {
    authority_round_trips: u32,
    witness_round_trips: u32,
}

impl OperationPlan {
    /// Begin and Accept: the renew, the post-renew coverage snapshot, the
    /// retention snapshot after the durable write, and one witness head read.
    pub(super) const RETAINING: Self = Self {
        authority_round_trips: 3,
        witness_round_trips: 1,
    };
    /// Advance, Reset and Reconcile: the renew, the coverage snapshot, and
    /// one witness call; Reconcile's conditional CAS after its query is
    /// admitted on its own in `execute_transition`.
    pub(super) const TRANSITION: Self = Self {
        authority_round_trips: 2,
        witness_round_trips: 1,
    };

    /// How long the plan can block at these port bounds.
    fn reserve(self, authority_bound: Duration, witness_bound: Duration) -> Duration {
        authority_bound
            .saturating_mul(self.authority_round_trips)
            .saturating_add(witness_bound.saturating_mul(self.witness_round_trips))
    }
}

/// What resolving a pending re-acquire established.
enum PendingAcquireOutcome {
    /// The acquire applied: the lease under its expected fence is this
    /// process's own, and that fence is now the one held.
    Adopted,
    /// The authority proved it never executed the acquire. The pre-acquire
    /// fence stands, and the next renew is what re-acquires.
    NotExecuted,
    /// The acquire was rejected, or the authority shows a lease this process
    /// did not produce: another instance has held key-use authority since.
    Superseded,
}

enum LeaseCall {
    Acquire,
    Renew,
    Release,
}

// The receipt stays `Copy` so one short-lived stack value can be compared and
// recorded without heap allocation, matching the wire payload discipline.
#[allow(clippy::large_enum_variant)]
/// Outcome of one lease exchange after exact-operation reconciliation.
enum LeaseExchange {
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

fn lease_intent(
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

/// Acknowledge the queued receipts, in order, while each acknowledgement can
/// end before `deadline` with `reserve` -- what the operation still needs
/// after this drain -- left over. A receipt that does not fit stays queued,
/// exactly as one the authority could not answer for; the next drain, or the
/// next start, discharges it.
fn drain_acknowledgements<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    deadline: OperationDeadline,
    reserve: Duration,
) {
    let bound = authority.round_trip_bound().saturating_add(reserve);
    while let Some(retained) = lease.unacknowledged.front() {
        if deadline.admit(bound).is_err() {
            return;
        }
        let operation_id = retained.locator().operation_id();
        match authority.acknowledge(retained) {
            Ok(AuthorityOutcomeV2::Known(_)) => {
                lease.unacknowledged.pop_front();
                settle(lease, operation_id);
            }
            // The authority holds a receipt under this id that our locator
            // cannot discharge: the resulting version it recorded is not the
            // one retained here (`ResultingVersionMismatch` -- the shape of an
            // authority restored from a backup). Absence is not this answer:
            // a vacant entry acknowledges as `AlreadyAbsent`, a `Known`
            // outcome. No retry of ours can change what the authority holds,
            // and keeping the entry would block every acknowledgement behind
            // it permanently, because the queue drains strictly in order. So
            // the entry is dropped and its journal row settled, to keep the
            // queue moving; the receipt itself stays in the authority's own
            // bounded table, which is that authority's to prune.
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

/// Learn what the authority did with a dispatched mutation whose response was
/// lost, by exact query. Each query is admitted against `deadline` first; a
/// refusal keeps the id unresolved -- the same fail-closed bookkeeping as an
/// exhausted loop, so the mutation is asked about again before the next
/// guarded operation and never silently abandoned -- and returns
/// [`AgentError::OperationDeadlineExceeded`].
fn reconcile_lease_operation<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
    deadline: OperationDeadline,
) -> Result<LeaseExchange, AgentError> {
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        if deadline.admit(authority.round_trip_bound()).is_err() {
            keep_unresolved(lease, intent.operation_id());
            return Err(AgentError::OperationDeadlineExceeded);
        }
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
///
/// The dispatch is admitted against `deadline` before the journal write, so a
/// refused dispatch leaves no row and nothing to settle; the snapshot that
/// resynchronises after an `AuthorityVersionMismatch` is admitted the same
/// way, with the refused row already settled.
fn lease_exchange<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
    call: LeaseCall,
    intent: AuthorityIntentV2,
    deadline: OperationDeadline,
) -> Result<LeaseExchange, AgentError> {
    deadline.admit(authority.round_trip_bound())?;
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
            deadline.admit(authority.round_trip_bound())?;
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
        Ok(AuthorityOutcomeV2::Unknown(_)) => {
            reconcile_lease_operation(authority, lease, intent, deadline)
        }
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
                // Acknowledged -- or held under a resulting version this
                // locator cannot discharge (`ResultingVersionMismatch`; a
                // vacant entry answers `AlreadyAbsent`, which is `Known`).
                // As in the drain, the row is settled to keep the journal
                // moving, and the receipt stays in the authority's own
                // bounded table.
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
///
/// Each row is a query and an acknowledgement, admitted together against
/// `deadline` with `reserve` -- what the acquire itself still needs -- left
/// over, exactly as `drain_unresolved` admits its rows. A row that no longer
/// fits is not asked about and stays unresolved, the same bookkeeping an
/// unanswered one gets: the next guarded operation retries it. Without that
/// admission a full journal of slow rows would cost the acquire its whole
/// budget before its first dispatch.
fn reconcile_lease_journal<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
    deadline: OperationDeadline,
    reserve: Duration,
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
    // Two round trips: a row costs a query and, when the authority still
    // holds its receipt, the acknowledgement that discharges it.
    let bound = authority
        .round_trip_bound()
        .saturating_mul(2)
        .saturating_add(reserve);
    let mut answering = true;
    for operation_id in journaled {
        // Once one query has gone unanswered, the rest are not asked at all:
        // evaluating the resolver first and consulting `answering` afterwards
        // would still cost one timeout per remaining row.
        if !answering || deadline.admit(bound).is_err() {
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
/// does; the next guarded operation asks again. A pending re-acquire's row is
/// skipped, not queried: its receipt is the one proof of what that acquire
/// did, so it must be read before it is acknowledged, and only
/// `resolve_pending_acquire_state` reads it.
///
/// Each row is a query and an acknowledgement, admitted together against
/// `deadline` with `reserve` -- what the operation still needs -- left over;
/// a row that does not fit stays unresolved, exactly as an unanswered one.
fn drain_unresolved<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    deadline: OperationDeadline,
    reserve: Duration,
) {
    let pending = lease
        .pending_acquire
        .map(|pending| pending.intent.operation_id());
    let bound = authority
        .round_trip_bound()
        .saturating_mul(2)
        .saturating_add(reserve);
    // Newest first, as before; removing the entry visited shifts only the
    // entries already visited.
    for index in (0..lease.unresolved.len()).rev() {
        let Some(operation_id) = lease.unresolved.get(index).copied() else {
            return;
        };
        if Some(operation_id) == pending {
            continue;
        }
        if deadline.admit(bound).is_err() {
            return;
        }
        match resolve_journaled_intent(authority, operation_id) {
            JournalResolution::Settled => {
                lease.unresolved.remove(index);
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

/// One acquire attempt, under its own fresh default budget: no caller has a
/// deadline to give the constructor, and `acquire_instance_lease_within`
/// bounds the retries on top.
pub(super) fn acquire_instance_lease<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
) -> Result<InstanceLeaseState, AgentError> {
    let deadline = OperationDeadline::fresh(DEFAULT_OPERATION_BUDGET)?;
    let instance_id = ProcessInstanceIdV2::from_bytes(fresh_lease_random()?)
        .map_err(|_| AgentError::LocalCryptoFailure)?;
    let mut lease = InstanceLeaseState {
        instance_id,
        fence: None,
        authority_version: 1,
        phase: LeasePhase::Serving,
        pending_acquire: None,
        unacknowledged: VecDeque::new(),
        settled: Vec::new(),
        unresolved: Vec::new(),
        covered_until: None,
    };
    // What the journal pass must leave the acquire: the pre-acquire snapshot
    // below, the acquire dispatch `lease_exchange` admits, and the snapshot
    // that follows a rejected or resynchronised attempt -- three authority
    // round trips.
    reconcile_lease_journal(
        repository,
        authority,
        &mut lease,
        deadline,
        authority.round_trip_bound().saturating_mul(3),
    )?;
    deadline.admit(authority.round_trip_bound())?;
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
        let exchange = match lease_exchange(
            repository,
            authority,
            &mut lease,
            LeaseCall::Acquire,
            intent,
            deadline,
        ) {
            Ok(exchange) => exchange,
            // Dispatched, and its outcome still unknown after reconciliation.
            // If it applied, the authority holds a lease under this fresh
            // instance id that nothing would ever release, and every retry
            // would be fenced until the TTL. So hand back the fence the
            // acquire would have granted: Applied retires it; LeaseAbsent or
            // FenceMismatch says it never applied and retires just the same;
            // an authority still unreachable leaves it to lapse at its TTL,
            // as after a crash. No secret exists yet, so there is nothing to
            // erase. The error reported is the acquire's own. The release
            // gets a fresh budget of its own, not this attempt's remainder.
            Err(AgentError::InstanceLeaseIndeterminate) => {
                let generation = expected_lease_generation
                    .checked_add(1)
                    .ok_or(AgentError::InstanceLeaseUnavailable)?;
                lease.fence = Some(
                    InstanceFenceV2::new(generation, instance_id)
                        .map_err(|_| AgentError::InstanceLeaseUnavailable)?,
                );
                if let Ok(release_deadline) = OperationDeadline::fresh(DEFAULT_OPERATION_BUDGET) {
                    let _ =
                        release_lease_state(repository, authority, &mut lease, release_deadline);
                }
                let _ = forget_settled(repository, &mut lease);
                return Err(AgentError::InstanceLeaseIndeterminate);
            }
            Err(error) => return Err(error),
        };
        match exchange {
            LeaseExchange::Receipt(receipt) => {
                drain_acknowledgements(authority, &mut lease, deadline, Duration::ZERO);
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
                        deadline.admit(authority.round_trip_bound())?;
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
                deadline.admit(authority.round_trip_bound())?;
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
/// An instance that is releasing its lease, or has retired it, is refused as
/// fenced before anything is dispatched: only a `Serving` lease renews.
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
/// A re-acquire whose outcome was left unknown is resolved first, before the
/// drains and before any renew (`resolve_pending_acquire`): its exact receipt,
/// or a snapshot showing the fence it would have produced, decides whether
/// the lease held is the re-acquired one. No renew is ever dispatched with the
/// pre-acquire fence while that outcome is unknown -- the authority may
/// already hold the next generation for this very instance, and a renew under
/// the old fence would be rejected as a fence mismatch and fence this instance
/// with no successor anywhere. While the authority can answer neither the
/// query nor the snapshot, the operation is refused with
/// [`AgentError::InstanceLeaseUnavailable`]; while a snapshot is had but
/// cannot decide it, with [`AgentError::InstanceLeaseIndeterminate`]. Either
/// way nothing is dispatched and the record is kept for the next attempt.
///
/// A successful renew also records how long the lease is provably still held
/// (`prove_lease_coverage`), which the operation checks before its durable
/// write. The renew alone only authorizes the *start* of the operation; the
/// work that follows is not instantaneous, the receipt carries no expiry with
/// which to bound it, and the recorded coverage holds only while the
/// authority's clock runs ahead of this host's by no more than
/// `LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS`. So nothing is retained on that
/// record alone: `prove_lease_covers_retention` takes a fresh snapshot after
/// the operation's last I/O, and a secret is retained only if that snapshot
/// shows the lease still held by this instance with more than the budget
/// left.
///
/// Admission comes first, right after the phase guard: the operation's
/// `plan` -- its least authority and witness round trips at the ports' own
/// bounds -- is reserved out of the operation's deadline, and an operation
/// that cannot fit is refused with [`AgentError::OperationDeadlineExceeded`]
/// before the resolution, the drains, any journal write or any dispatch.
/// Every round trip after that is admitted on its own, and the drains admit
/// each of theirs only with that reserve still left over, so settling old
/// obligations never starves the operation they precede.
pub(super) fn ensure_instance_lease<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    plan: OperationPlan,
) -> Result<(), AgentError> {
    if inner.lease.phase != LeasePhase::Serving {
        return Err(AgentError::InstanceFenced);
    }
    let reserve = plan.reserve(
        inner.authority.round_trip_bound(),
        inner.witness.round_trip_bound(),
    );
    inner.deadline.admit(reserve)?;
    let deadline = inner.deadline;
    resolve_pending_acquire(inner, reserve)?;
    // Read only now: the resolution may just have replaced the fence.
    let Some(fence) = inner.lease.fence else {
        return Err(AgentError::InstanceFenced);
    };
    // Every `Ok` from the resolution leaves nothing pending; the guard keeps
    // a renew under an unresolved re-acquire impossible even so.
    debug_assert!(inner.lease.pending_acquire.is_none());
    if inner.lease.pending_acquire.is_some() {
        return Err(AgentError::InstanceLeaseIndeterminate);
    }
    drain_acknowledgements(&inner.authority, &mut inner.lease, deadline, reserve);
    drain_unresolved(&inner.authority, &mut inner.lease, deadline, reserve);
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
            deadline,
        )? {
            LeaseExchange::Receipt(receipt) => {
                drain_acknowledgements(&inner.authority, &mut inner.lease, deadline, reserve);
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
///
/// An acquire whose outcome stays unknown after reconciliation is not
/// abandoned and not fenced: fencing is permanent and this is no evidence of a
/// successor, while abandoning it would leave the authority holding the next
/// generation under this very instance id with nothing here to recognise it.
/// The intent and the fence it would have produced are kept as
/// `pending_acquire` -- set before the dispatch, so that whatever happens to
/// the response they are known -- and the next guarded operation, or the
/// release, resolves them before dispatching anything
/// (`resolve_pending_acquire_state`).
/// The record is kept only while the outcome is really unknown, which is
/// exactly when the operation id was kept as unresolved; an acquire the
/// journal refused before dispatch, or whose outcome was proven, leaves
/// nothing to resolve.
fn recover_expired_lease<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    fence: InstanceFenceV2,
) -> Result<(), AgentError> {
    let expected_lease_generation = fence.generation();
    let instance_id = inner.lease.instance_id;
    let generation = expected_lease_generation
        .checked_add(1)
        .ok_or(AgentError::InstanceLeaseUnavailable)?;
    let expected = InstanceFenceV2::new(generation, instance_id)
        .map_err(|_| AgentError::InstanceLeaseUnavailable)?;
    let deadline = inner.deadline;
    // What the drain after a successful re-acquire must leave over: the
    // coverage snapshot that follows it.
    let reserve = inner.authority.round_trip_bound();
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let intent = lease_intent(
            &inner.lease,
            inner.authority.wire_config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id,
            },
        )?;
        inner.lease.pending_acquire = Some(PendingAcquire {
            intent,
            expected_fence: expected,
        });
        match lease_exchange(
            &inner.repository,
            &inner.authority,
            &mut inner.lease,
            LeaseCall::Acquire,
            intent,
            deadline,
        ) {
            Ok(LeaseExchange::Receipt(receipt)) => {
                inner.lease.pending_acquire = None;
                if !matches!(receipt.disposition(), AuthorityDispositionV2::Applied) {
                    fence_out(inner)?;
                    return Err(AgentError::InstanceFenced);
                }
                if let Some(error) = erase_all_secrets(inner) {
                    return Err(error);
                }
                inner.lease.fence = Some(expected);
                drain_acknowledgements(&inner.authority, &mut inner.lease, deadline, reserve);
                return prove_lease_coverage(inner, expected);
            }
            // Provably never executed; the loop rebuilds the intent at the
            // authority version the reconciliation reported.
            Ok(LeaseExchange::Retry) => inner.lease.pending_acquire = None,
            Err(error) => {
                if !inner.lease.unresolved.contains(&intent.operation_id()) {
                    inner.lease.pending_acquire = None;
                }
                return Err(error);
            }
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Learn the outcome of a re-acquire whose response was lost, before anything
/// else is dispatched under this lease.
///
/// The exact receipt query is the proof of record: `Found` says what the
/// authority did with this very intent, and `AbsentAtVersion` is the only
/// evidence ever accepted that it never executed. When the query cannot be
/// answered a snapshot stands in, and a snapshot can prove only the positive
/// cases. An active lease carrying exactly the expected fence -- the next
/// generation under this process's fresh instance id, which nothing else can
/// produce -- is this process's own and is adopted, as the constructor adopts
/// a lease whose acquire response was lost. An active lease under any other
/// fence, a generation past the expected one, or one behind the pre-acquire
/// generation (an authority rolled back beneath a lease it granted) all mean
/// another instance held key-use authority since. A snapshot showing no active
/// lease at the pre-acquire generation or at the expected one decides nothing
/// -- the acquire may still be in flight, or may have applied and lapsed -- so
/// the record is kept and the caller gets
/// [`AgentError::InstanceLeaseIndeterminate`]; a snapshot that goes unanswered
/// keeps it too, with [`AgentError::InstanceLeaseUnavailable`].
///
/// `Ok(None)` means nothing was pending. Adoption through the receipt queues
/// the acknowledgement it is owed and drains it here; adoption through a
/// snapshot leaves the operation `unresolved`, so `drain_unresolved` finds and
/// acknowledges its receipt once the authority answers queries again.
///
/// The query and the snapshot are each admitted against `deadline` with
/// `reserve` -- what the caller still needs afterwards -- left over; a
/// refusal is [`AgentError::OperationDeadlineExceeded`] with the record kept,
/// nothing having been dispatched.
fn resolve_pending_acquire_state<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    deadline: OperationDeadline,
    reserve: Duration,
) -> Result<Option<PendingAcquireOutcome>, AgentError> {
    let Some(pending) = lease.pending_acquire else {
        return Ok(None);
    };
    let operation_id = pending.intent.operation_id();
    let expected = pending.expected_fence;
    let bound = authority.round_trip_bound().saturating_add(reserve);
    deadline.admit(bound)?;
    match authority.query(operation_id) {
        Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt))) => {
            lease.unresolved.retain(|id| *id != operation_id);
            record_lease_receipt(lease, pending.intent, *receipt)?;
            drain_acknowledgements(authority, lease, deadline, reserve);
            lease.pending_acquire = None;
            Ok(Some(match receipt.disposition() {
                AuthorityDispositionV2::Applied => {
                    lease.fence = Some(expected);
                    PendingAcquireOutcome::Adopted
                }
                AuthorityDispositionV2::Rejected(_) => PendingAcquireOutcome::Superseded,
            }))
        }
        Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion {
            authority_version,
        })) => {
            lease.unresolved.retain(|id| *id != operation_id);
            settle(lease, operation_id);
            lease.authority_version = authority_version;
            lease.pending_acquire = None;
            Ok(Some(PendingAcquireOutcome::NotExecuted))
        }
        Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_)) | Err(_) => {
            deadline.admit(bound)?;
            let snapshot = authority_snapshot(authority)?;
            lease.authority_version = snapshot.authority_version();
            let previous_generation = expected.generation().saturating_sub(1);
            let outcome = match snapshot.active_lease() {
                Some(active) if active.fence() == expected => {
                    lease.fence = Some(expected);
                    PendingAcquireOutcome::Adopted
                }
                Some(_) => PendingAcquireOutcome::Superseded,
                None if snapshot.lease_generation() == previous_generation
                    || snapshot.lease_generation() == expected.generation() =>
                {
                    return Err(AgentError::InstanceLeaseIndeterminate);
                }
                None => PendingAcquireOutcome::Superseded,
            };
            lease.pending_acquire = None;
            Ok(Some(outcome))
        }
    }
}

/// Resolve a pending re-acquire on the live agent: adopt its lease and erase
/// every secret -- the acquire cleared the authority's key table, exactly as
/// when its receipt arrives in time -- or fence when another instance has
/// held the lease since. A verdict the authority cannot yet give is returned
/// as the state-level error, with the record kept. `reserve` is what the
/// operation still needs after the resolution.
fn resolve_pending_acquire<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    reserve: Duration,
) -> Result<(), AgentError> {
    let deadline = inner.deadline;
    match resolve_pending_acquire_state(&inner.authority, &mut inner.lease, deadline, reserve)? {
        None | Some(PendingAcquireOutcome::NotExecuted) => Ok(()),
        Some(PendingAcquireOutcome::Adopted) => erase_all_secrets(inner).map_or(Ok(()), Err),
        Some(PendingAcquireOutcome::Superseded) => {
            fence_out(inner)?;
            Err(AgentError::InstanceFenced)
        }
    }
}

/// Learn how long this instance can prove it still holds the lease.
///
/// A renew receipt reports only that the renew applied, never until when: the
/// wire receipt carries no expiry and widening it would break a released ABI.
/// The expiry is therefore read from a snapshot, which the port already offers.
///
/// The anchor is captured **before** the request is sent, and the recorded
/// coverage is `coverage_deadline(anchor, floor, expiry)`: the remaining life
/// the snapshot reports, less `LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS`, counted
/// from the anchor. The authority's clock floor is nondecreasing, so the
/// elapsed time it implies is an upper bound as long as the authority's clock
/// gains no more than the budget on this host's; the snapshot's own
/// `active_lease` is already filtered to unexpired leases. That makes this a
/// liveness check as well: no active lease, or one carrying a fence that is
/// not ours, means the lease is already gone. A lease with no more than the
/// budget left is refused here too, and every refusal clears the previous
/// proof, so the field never claims coverage the snapshot just contradicted.
///
/// The cost is one extra authority round trip per guarded operation, and a
/// second one for every operation that retains a secret: this call, after the
/// renew, bounds the work; `prove_lease_covers_retention` repeats it after the
/// durable write, immediately before the secret becomes reachable. That is the
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
///
/// The snapshot is admitted against the operation's deadline first. A refusal
/// takes no snapshot and proves nothing, so it clears the previous proof --
/// the conservative outcome, as after a lapse -- and returns
/// [`AgentError::OperationDeadlineExceeded`], which is not a fence.
fn prove_lease_coverage<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    fence: InstanceFenceV2,
) -> Result<(), AgentError> {
    if let Err(refused) = inner.deadline.admit(inner.authority.round_trip_bound()) {
        inner.lease.covered_until = None;
        return Err(refused);
    }
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
    inner.lease.covered_until = coverage_deadline(
        anchor,
        snapshot.clock_floor_millis(),
        active.expires_at_millis(),
    );
    if inner.lease.covered_until.is_none() {
        return Err(AgentError::InstanceLeaseCoverageElapsed);
    }
    Ok(())
}

/// Refuse to retain or return a secret once the proven coverage has elapsed,
/// or once the operation's own deadline has been reached.
///
/// The lease is checked on the way in, but the work that follows is not
/// instantaneous: a witness round trip, two signature verifications, a KEM
/// operation, and finally a durable reservation or release -- a real fsync --
/// all sit between that check and the point where a secret first becomes
/// retained.
///
/// Two rules, in this order. First the local, budgeted coverage rule against
/// the deadline `prove_lease_coverage` recorded
/// ([`AgentError::InstanceLeaseCoverageElapsed`]); then the operation's
/// deadline, admitted with a zero bound
/// ([`AgentError::OperationDeadlineExceeded`]). Coverage goes first so that a
/// lease lapse is never reported as a deadline. Both are consulted before the
/// durable write, as an early-out that avoids paying for an fsync the
/// operation is about to discard, and again inside
/// `prove_lease_covers_retention`, against the fresh snapshot that check
/// takes *after* the write. The pre-write call is an optimisation; the
/// guarantee is `prove_lease_covers_retention`, and what remains between its
/// snapshot and retention is that snapshot's own round trip plus the hash-map
/// inserts that retain it, all inside the divergence budget. The callers own
/// the cleanup that keeps both refusals equal in effect: nothing retained,
/// the reservation released.
///
/// It deliberately does not fence. A local deadline running out, the lease's
/// or the operation's, is no evidence that any successor exists, and fencing
/// is permanent.
pub(super) fn ensure_may_retain<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<(), AgentError> {
    match inner.lease.covered_until {
        Some(until) if Instant::now() < until => {}
        _ => return Err(AgentError::InstanceLeaseCoverageElapsed),
    }
    inner.deadline.admit(Duration::ZERO)
}

/// The retention check: a fresh authority observation taken after the last
/// I/O before a secret becomes reachable, then the budgeted local rule
/// against that observation.
///
/// The witness round trip, the KEM and the durable write -- a real fsync --
/// all sit between the post-renew snapshot and this point, and authority time
/// may have stepped past the lease's expiry during any of them without this
/// host's clock moving; nothing between two round trips could see it. So the
/// proof is re-taken here, after the operation's last I/O, and the divergence
/// budget is relied on only across this snapshot's own round trip and the
/// insert that follows. It never returns `Ok` on a stale observation.
///
/// Errors: [`AgentError::InstanceLeaseCoverageElapsed`] when the snapshot
/// reports the lease lapsed at this generation, or held with no more than the
/// budget left, or the deadline it yields has already passed;
/// [`AgentError::InstanceFenced`] when it shows a successor, a rolled-back
/// authority or a foreign fence -- `fence_out` has erased every other secret
/// by then -- or when this lease is releasing or retired;
/// [`AgentError::InstanceLeaseUnavailable`] when the snapshot is not `Known`;
/// and [`AgentError::OperationDeadlineExceeded`] when the snapshot's round
/// trip would not end before the operation's deadline (it is then not taken),
/// or the deadline is reached by the time the proof is checked. The caller
/// owns the cleanup of what it was about to retain (`reserve_pending`,
/// `retain_accepted_key`).
pub(super) fn prove_lease_covers_retention<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.lease.phase != LeasePhase::Serving {
        return Err(AgentError::InstanceFenced);
    }
    let Some(fence) = inner.lease.fence else {
        return Err(AgentError::InstanceFenced);
    };
    prove_lease_coverage(inner, fence)?;
    ensure_may_retain(inner)
}

/// Erase every in-process pending and accepted secret and retire this fence.
///
/// After this returns, the agent permanently refuses lease-guarded operations
/// and holds no pending or accepted secret.
///
/// This runs from `ensure_instance_lease`, `prove_lease_coverage`,
/// `recover_expired_lease` and `resolve_pending_acquire`, when a renew, a
/// re-acquire's receipt, or a snapshot has shown a successor, a rolled-back
/// authority, or a foreign fence. It is not on the release path:
/// `release_instance_lease`
/// erases through `erase_all_secrets` and retires the fence only once the
/// authority has confirmed the release or a snapshot has proved the lease gone
/// (`release_lease_state`), so on that path the erasure does precede any
/// successor's acquire. Here it does not: a successor's acquire is gated purely
/// on wall-clock expiry (`plan_acquire`), with no interaction with the incumbent
/// and no revocation, so this instance learns it was fenced only by being
/// rejected.
///
/// What is guaranteed is the erasure itself, before the rejected call returns,
/// and that no session secret was **retained or returned** outside the window
/// this instance could prove it held the lease -- proven against an authority
/// observation taken after the operation's last I/O, tolerating at most
/// `LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS` of authority clock advance beyond
/// the local elapsed time across that observation's round trip; see
/// `prove_lease_coverage`, `prove_lease_covers_retention` and
/// `ensure_may_retain`. That is narrower than "key use has stopped": the
/// KEM itself runs before the coverage check, and the long-term ABI 2 executor
/// keys are outside this mechanism entirely.
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
    // The process is fenced whether or not the durable bookkeeping succeeded;
    // that is a fact about the lease, not about the erasure.
    retire(&mut inner.lease);
    match first_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Hand this instance's lease back to the authority, retiring the fence only
/// once the authority has confirmed the release or a snapshot has proved that
/// no lease of this instance remains.
///
/// State-only, so the constructor can run it on a lease it acquired and then
/// could not use, with no `Inner` yet. A caller that holds secrets erases them
/// before calling this (`PolicyAgent::release_instance_lease`).
///
/// The phase moves to `Releasing` before the first dispatch and stays there on
/// every failure, with the fence kept: a release the transport could not send
/// or the journal could not take, one the authority declined on a condition
/// that can clear, and one whose outcome stayed unknown with no snapshot to
/// prove it can all be dispatched again by a later call. The fence is never
/// dropped ahead of that evidence -- dropping it early made the next call
/// succeed with nothing dispatched while the authority still held the lease.
///
/// A re-acquire whose outcome is still unknown is resolved first, by the same
/// exact query and snapshot the guarded operations use: adopted, its fence is
/// the one released; never executed, the pre-acquire fence is; superseded,
/// there is nothing of this instance's to release and it retires at once.
/// When the authority can answer neither, the release is dispatched with the
/// fence that re-acquire would have produced: the authority answers `Applied`
/// if the acquire applied, and `LeaseAbsent`, `LeaseExpired` or
/// `FenceMismatch` if it did not -- the pre-acquire lease had already lapsed
/// when the re-acquire was dispatched -- and each of those retires this
/// instance.
///
/// The fence dispatched is re-read on every attempt: when the release's own
/// outcome is lost, the snapshot that stands in for it reports the fence the
/// authority actually holds for this instance, and that is the one to release.
///
/// Every round trip is admitted against `deadline` first, the drains and the
/// resolution with one authority round trip -- the release itself -- kept in
/// reserve. A refusal once the release is under way leaves the phase
/// `Releasing` with the fence kept, exactly as an unreachable authority
/// does, and is reported as [`AgentError::OperationDeadlineExceeded`]: never
/// `Ok` without a receipt or a proof.
///
/// Returns `Ok(())` at once when the lease is already retired.
pub(super) fn release_lease_state<A: InstanceAuthorityPort>(
    repository: &StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
    deadline: OperationDeadline,
) -> Result<(), AgentError> {
    if lease.phase == LeasePhase::Retired {
        return Ok(());
    }
    lease.phase = LeasePhase::Releasing;
    lease.covered_until = None;
    let reserve = authority.round_trip_bound();
    drain_acknowledgements(authority, lease, deadline, reserve);
    drain_unresolved(authority, lease, deadline, reserve);
    match resolve_pending_acquire_state(authority, lease, deadline, reserve) {
        Ok(None | Some(PendingAcquireOutcome::Adopted | PendingAcquireOutcome::NotExecuted)) => {}
        Ok(Some(PendingAcquireOutcome::Superseded)) => {
            retire(lease);
            return Ok(());
        }
        // Unresolvable: release the fence the re-acquire would have produced.
        // Every answer that release can get retires this instance, so there is
        // nothing left for a later call to resolve.
        Err(_) => {
            if let Some(pending) = lease.pending_acquire.take() {
                lease.fence = Some(pending.expected_fence);
            }
        }
    }
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let Some(fence) = lease.fence else {
            return Err(AgentError::InstanceLeaseUnavailable);
        };
        let intent = lease_intent(
            lease,
            authority.wire_config(),
            AuthorityMutationV2::ReleaseLease { fence },
        )?;
        match lease_exchange(
            repository,
            authority,
            lease,
            LeaseCall::Release,
            intent,
            deadline,
        ) {
            Ok(LeaseExchange::Receipt(receipt)) => {
                drain_acknowledgements(authority, lease, deadline, reserve);
                return match receipt.disposition() {
                    AuthorityDispositionV2::Applied
                    | AuthorityDispositionV2::Rejected(
                        AuthorityRejectionV2::LeaseAbsent
                        | AuthorityRejectionV2::LeaseExpired
                        | AuthorityRejectionV2::FenceMismatch,
                    ) => {
                        retire(lease);
                        Ok(())
                    }
                    // Declined on a condition that can clear; the lease is
                    // still this instance's to release.
                    AuthorityDispositionV2::Rejected(_) => {
                        Err(AgentError::InstanceLeaseUnavailable)
                    }
                };
            }
            // Provably never executed; the loop rebuilds the intent.
            Ok(LeaseExchange::Retry) => {}
            Err(AgentError::InstanceLeaseIndeterminate) => {
                // The proof is one more round trip; refused, the outcome
                // stays unknown and the fence is kept for a later call.
                deadline.admit(reserve)?;
                match lease_gone_by_snapshot(authority, lease) {
                    Ok(None) => {
                        retire(lease);
                        return Ok(());
                    }
                    // Still held under this instance, so the release did not
                    // apply. Release the fence the authority reports.
                    Ok(Some(reported)) => lease.fence = Some(reported),
                    Err(()) => return Err(AgentError::InstanceLeaseIndeterminate),
                }
            }
            // Not sent, the journal full, or the repository failed: nothing
            // was dispatched, and the fence is kept.
            Err(error) => return Err(error),
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Ask a snapshot whether any lease of this instance remains, when a release's
/// own outcome could not be learned.
///
/// `Ok(None)` means gone: the authority reports no active lease -- it filters
/// expired ones itself -- or one under another instance. Either way this
/// instance holds nothing, and a successor's lease is not this code's to
/// touch; the secrets a fence would have erased were erased before the release
/// was dispatched. `Ok(Some(fence))` means still held under this instance,
/// with the fence the authority reports -- which may differ in generation from
/// the one retained here -- for the release that must follow. `Err(())` means
/// the snapshot itself went unanswered: nothing is known.
fn lease_gone_by_snapshot<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
) -> Result<Option<InstanceFenceV2>, ()> {
    let snapshot = authority_snapshot(authority).map_err(|_| ())?;
    lease.authority_version = snapshot.authority_version();
    Ok(match snapshot.active_lease() {
        Some(active) if active.fence().instance_id() == lease.instance_id => Some(active.fence()),
        Some(_) | None => None,
    })
}
