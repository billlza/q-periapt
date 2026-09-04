//! Lease-intent journal edge cases and crash cuts.

use std::net::SocketAddr;

use super::*;
use crate::authority::AuthorityEpochV2;
use crate::authority_protocol::{
    AuthorityClientIdV2, AuthorityServerIdV2, AuthorityWireIdentityV2,
};
use crate::authority_transport::{
    AuthenticatedTcpAuthorityV2, AuthorityServerProvisionV2, AuthorityTransportLimitsV2,
    ReferenceAuthorityServerV2,
};

/// The journal as the agent reports it, with the one row a steady agent keeps
/// read out for comparison.
fn journal_of(
    agent: &PolicyAgent<MemoryWitness, MemoryAuthority>,
) -> TestResult<Vec<OperationIdV2>> {
    Ok(agent.journaled_lease_intents_for_test()?)
}

fn only_row(journaled: &[OperationIdV2]) -> TestResult<OperationIdV2> {
    assert_eq!(journaled.len(), 1, "expected exactly one journal row");
    journaled
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("the journal is empty").into())
}

/// A store as a process that released its lease and exited leaves it: no
/// journal rows, nothing on the authority.
struct ReleasedStore {
    repository: StateRepository,
    witness: MemoryWitness,
    authority: MemoryAuthority,
    config: AgentConfig,
    /// Where that store lives, with the roots to reopen it: a test that
    /// expects the start to fail needs a second one on the same store.
    path: PathBuf,
    roots: MigrationTrustRoots,
}

fn release_and_drop(pair: AgentPair) -> TestResult<ReleasedStore> {
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    assert!(repository.journaled_lease_intents()?.is_empty());
    Ok(ReleasedStore {
        repository,
        witness,
        authority: initiator_authority,
        config: initiator_config,
        path: initiator_repository_path,
        roots: migration.roots,
    })
}

/// A store as a crash between a renew's dispatch and its acknowledgement
/// leaves it: the renew's row journaled, its receipt still retained by the
/// authority. Acknowledgements are left refused; the caller decides.
struct StrandedStore {
    repository: StateRepository,
    stranded: OperationIdV2,
    witness: MemoryWitness,
    authority: MemoryAuthority,
    config: AgentConfig,
}

fn strand_one_receipt(pair: AgentPair) -> TestResult<StrandedStore> {
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator_authority.refuse_acknowledgements(true);
    drive_one_lease_renew(&initiator)?;
    assert_eq!(initiator_authority.receipt_count()?, 1);
    // The crash: the process goes away with the acknowledgement still queued
    // in memory.
    drop(initiator);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let stranded = only_row(&repository.journaled_lease_intents()?)?;
    Ok(StrandedStore {
        repository,
        stranded,
        witness,
        authority: initiator_authority,
        config: initiator_config,
    })
}

#[test]
fn a_renew_whose_response_and_every_query_are_lost_is_indeterminate_and_settled_by_the_next_operation(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 148)?;
    let authority = &pair.initiator_authority;
    // Applied rather than not-extended, so the receipt is retained.
    authority.advance_clock(1_000);
    authority.make_next_unknown();
    authority.refuse_queries(true);
    let queries_before = authority.query_call_count();
    let calls_before = authority.lease_call_count();

    // The renew applied; the response and both resync queries were lost.
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );
    assert_eq!(authority.query_call_count(), queries_before + 2);
    assert_eq!(authority.lease_call_count(), calls_before + 1);
    assert_eq!(authority.receipt_count()?, 1);
    // The renew's row, unresolved; the acquire's settled row was forgotten by
    // that journal write.
    let lost = only_row(&journal_of(&pair.initiator)?)?;
    pair.initiator.public_keys()?;

    // Not a fence: once the authority answers, the next operation asks about
    // the lost renew once, acknowledges its receipt, and forgets the row.
    authority.refuse_queries(false);
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(authority.receipt_count()?, 0);
    let journaled = journal_of(&pair.initiator)?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&lost));
    assert_eq!(authority.query_call_count(), queries_before + 3);
    Ok(())
}

#[test]
fn a_lost_renew_whose_query_is_refused_closed_is_unavailable_not_indeterminate_and_asked_only_once(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 149)?;
    let authority = &pair.initiator_authority;
    authority.advance_clock(1_000);
    authority.make_next_unknown();
    authority.refuse_next_query_with(AuthorityKnownFailureV2::RateLimited);
    let queries_before = authority.query_call_count();
    let calls_before = authority.lease_call_count();

    // A closed refusal of the query ends the reconciliation at once: it does
    // not spend the second resync attempt, and it is not indeterminate.
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseUnavailable)
    );
    assert_eq!(authority.query_call_count(), queries_before + 1);
    assert_eq!(authority.lease_call_count(), calls_before + 1);
    assert_eq!(authority.receipt_count()?, 1);
    let lost = only_row(&journal_of(&pair.initiator)?)?;
    pair.initiator.public_keys()?;

    // The row is kept for the next operation, which settles it.
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(authority.receipt_count()?, 0);
    let journaled = journal_of(&pair.initiator)?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&lost));
    assert_eq!(authority.query_call_count(), queries_before + 2);
    Ok(())
}

#[test]
fn a_lease_call_lost_before_it_reached_the_authority_is_retried_once_the_query_proves_it_absent(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 150)?;
    let authority = &pair.initiator_authority;
    let calls_before = authority.lease_call_count();
    let queries_before = authority.query_call_count();
    authority.lose_next_lease_call_before_apply(LeaseCallFilter::Any);

    // The renew is lost on the wire; the query proves it absent, and the
    // operation retries it under the version the query reported.
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(authority.lease_call_count(), calls_before + 1);
    assert_eq!(authority.query_call_count(), queries_before + 1);
    let lost = authority
        .lost_operation()
        .ok_or_else(|| io::Error::other("no lease call was lost"))?;
    // The lost row was settled by the query and forgotten by the retry's
    // journal write.
    let journaled = journal_of(&pair.initiator)?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&lost));
    assert_eq!(authority.receipt_count()?, 0);
    Ok(())
}

#[test]
fn a_lease_call_lost_before_it_reached_the_authority_is_retried_once_the_query_proves_it_absent_at_construction(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let store = release_and_drop(agent_pair(&directory, 151)?)?;
    let before = store.authority.lock().authority.persistent_meta();
    let calls_before = store.authority.lease_call_count();
    store
        .authority
        .lose_next_lease_call_before_apply(LeaseCallFilter::Acquire);

    // The acquire is lost on the wire; the query proves it absent, the
    // snapshot shows no lease, and the second attempt applies.
    let restarted = PolicyAgent::new(
        store.repository,
        store.witness,
        store.authority.clone(),
        store.config,
    )?;
    assert_eq!(store.authority.lease_call_count(), calls_before + 1);
    let lost = store
        .authority
        .lost_operation()
        .ok_or_else(|| io::Error::other("no lease call was lost"))?;
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&lost));
    let after = store.authority.lock().authority.persistent_meta();
    assert_eq!(after.lease_generation, before.lease_generation + 1);
    assert_eq!(store.authority.receipt_count()?, 0);
    Ok(())
}

#[test]
fn an_unmatchable_receipt_is_dropped_from_the_queue_and_its_row_settled_without_fencing(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 152)?;
    let authority = &pair.initiator_authority;
    authority.advance_clock(1_000);
    authority.mismatch_next_acknowledgement();

    // The renew's receipt cannot be discharged by our locator: the drain drops
    // it and settles its row, and the operation itself is unaffected.
    drive_one_lease_renew(&pair.initiator)?;
    // The entry is dropped from our queue and its row settled; the receipt
    // itself is the authority's to prune, and it keeps holding it.
    assert_eq!(authority.receipt_count()?, 1);
    // Settled only marks the row; the next journal write forgets it.
    let first_renew = only_row(&journal_of(&pair.initiator)?)?;
    pair.initiator.public_keys()?;

    // Not a fence, and not unavailable: the next operations serve, and the
    // first renew's row is gone after the next journal write.
    drive_one_lease_renew(&pair.initiator)?;
    let journaled = journal_of(&pair.initiator)?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&first_renew));
    drive_one_lease_renew(&pair.initiator)?;
    // The unmatchable head was dropped, so the two later renews' receipts were
    // acknowledged normally and did not pile up behind it. Under a drain that
    // kept the unmatchable head queued the queue -- which drains strictly in
    // order -- would still be holding all three.
    assert_eq!(authority.receipt_count()?, 1);
    Ok(())
}

#[test]
fn an_unmatchable_receipt_is_dropped_from_the_queue_and_its_row_settled_without_fencing_at_the_next_start(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let store = strand_one_receipt(agent_pair(&directory, 153)?)?;
    store.authority.refuse_acknowledgements(false);
    store.authority.expire_active_lease();
    store.authority.mismatch_next_acknowledgement();

    // The start finds the stranded receipt, cannot discharge it, and settles
    // and forgets its row anyway; the acquire that follows is unaffected.
    let restarted = PolicyAgent::new(
        store.repository,
        store.witness,
        store.authority.clone(),
        store.config,
    )?;
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&store.stranded));
    // The stranded row is settled by the resolver and never re-queued; the
    // receipt stays in the authority's own bounded table.
    assert_eq!(store.authority.receipt_count()?, 1);
    drive_one_lease_renew(&restarted)?;
    Ok(())
}

fn refuse_closed(authority: &MemoryAuthority) {
    authority.refuse_next_lease_call_with(AuthorityKnownFailureV2::RateLimited);
}

fn fail_before_send(authority: &MemoryAuthority) {
    authority.fail_next_lease_call_before_send(LeaseCallFilter::Any);
}

fn refused_before_dispatch_keeps_its_row(
    session_byte: u8,
    arm: fn(&MemoryAuthority),
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, session_byte)?;
    let authority = &pair.initiator_authority;
    let acquire_row = only_row(&journal_of(&pair.initiator)?)?;
    let calls_before = authority.lease_call_count();
    let queries_before = authority.query_call_count();
    arm(authority);

    // Nothing reached the authority, but the journal write preceded the
    // refusal: the row is there, the acquire's settled row is not.
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseUnavailable)
    );
    assert_eq!(authority.lease_call_count(), calls_before);
    let refused = only_row(&journal_of(&pair.initiator)?)?;
    assert_ne!(refused, acquire_row);
    assert_eq!(authority.receipt_count()?, 0);
    pair.initiator.public_keys()?;

    // The next operation asks about the row once, finds it absent, and its
    // journal write forgets it.
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(authority.query_call_count(), queries_before + 1);
    let journaled = journal_of(&pair.initiator)?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&refused));
    assert_eq!(authority.receipt_count()?, 0);
    Ok(())
}

#[test]
fn a_lease_call_refused_before_dispatch_keeps_its_row_and_is_settled_by_the_next_query(
) -> TestResult {
    // A closed refusal the authority answered ...
    refused_before_dispatch_keeps_its_row(154, refuse_closed)?;
    // ... and a request that was never sent look the same from the journal.
    // The release case is a lease test of its own: a release that was never
    // sent keeps the fence and releases on retry.
    refused_before_dispatch_keeps_its_row(156, fail_before_send)
}

#[test]
fn a_journal_write_that_fails_for_storage_reasons_dispatches_nothing_and_does_not_poison(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 157)?;
    let authority = &pair.initiator_authority;
    let calls_before = authority.lease_call_count();
    let journal_before = journal_of(&pair.initiator)?;
    let acquire_row = only_row(&journal_before)?;
    pair.initiator.fail_next_lease_journal_write_for_test()?;

    // The repository's own error, not a capacity or lease failure; nothing
    // was dispatched, nothing committed, and the settled list is still exact.
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::CorruptStore))
    );
    assert_eq!(authority.lease_call_count(), calls_before);
    assert_eq!(journal_of(&pair.initiator)?, journal_before);
    assert_eq!(authority.receipt_count()?, 0);
    pair.initiator.public_keys()?;

    // Not poisoned: the next operation runs, and its journal write forgets
    // the acquire's row that the failed write did not.
    drive_one_lease_renew(&pair.initiator)?;
    let journaled = journal_of(&pair.initiator)?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&acquire_row));
    Ok(())
}

#[test]
fn a_stranded_receipt_the_authority_will_not_yet_release_stays_journaled_and_is_acknowledged_by_a_later_operation(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let store = strand_one_receipt(agent_pair(&directory, 158)?)?;
    // Acknowledgements stay refused across the restart.
    store.authority.expire_active_lease();
    let queries_before = store.authority.query_call_count();

    // A row the authority will not yet release is not fatal at start: it is
    // carried as unresolved, and the acquire's own receipt joins it.
    let restarted = PolicyAgent::new(
        store.repository,
        store.witness,
        store.authority.clone(),
        store.config,
    )?;
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 2);
    assert!(journaled.contains(&store.stranded));
    assert_eq!(store.authority.receipt_count()?, 2);
    assert_eq!(store.authority.query_call_count(), queries_before + 1);

    // Once accepted again: the next operation drains its own receipt, asks
    // about the stranded row again, acknowledges it, and forgets both.
    store.authority.refuse_acknowledgements(false);
    drive_one_lease_renew(&restarted)?;
    assert_eq!(store.authority.receipt_count()?, 0);
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&store.stranded));
    assert_eq!(store.authority.query_call_count(), queries_before + 2);
    Ok(())
}

#[test]
fn a_stranded_receipt_the_authority_will_not_yet_release_stays_journaled_and_is_acknowledged_by_a_later_operation_when_the_acknowledgement_response_is_lost(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let store = strand_one_receipt(agent_pair(&directory, 159)?)?;
    store.authority.refuse_acknowledgements(false);
    store.authority.expire_active_lease();
    store.authority.lose_next_acknowledgement();
    let queries_before = store.authority.query_call_count();

    // The start's acknowledgement of the stranded receipt goes unanswered:
    // the row stays, the receipt stays; the acquire's own is acknowledged.
    let restarted = PolicyAgent::new(
        store.repository,
        store.witness,
        store.authority.clone(),
        store.config,
    )?;
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 2);
    assert!(journaled.contains(&store.stranded));
    assert_eq!(store.authority.receipt_count()?, 1);
    assert_eq!(store.authority.query_call_count(), queries_before + 1);

    drive_one_lease_renew(&restarted)?;
    assert_eq!(store.authority.receipt_count()?, 0);
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&store.stranded));
    Ok(())
}

// ---- The crash cut: a real process death between a dispatch and its
// acknowledgement, over the real Authority Wire V2 transport. ----

const CRASH_REPOSITORY_ENV: &str = "Q_PERIAPT_TEST_LEASE_JOURNAL_CRASH_REPOSITORY";
const CRASH_ADDRESS_ENV: &str = "Q_PERIAPT_TEST_LEASE_JOURNAL_CRASH_ADDRESS";
const CRASH_EPOCH_ENV: &str = "Q_PERIAPT_TEST_LEASE_JOURNAL_CRASH_EPOCH";
const CRASH_CLIENT_SEED: [u8; 32] = [0xB1; 32];
const CRASH_SERVER_SEED: [u8; 32] = [0xB2; 32];
const CRASH_AUTHORITY_DEADLINE: Duration = Duration::from_secs(5);

fn crash_authority_head() -> TestResult<StateHeadV2> {
    Ok(StateHeadV2::new(
        StateRevisionV2::new(1, [41u8; 32], 1, [43u8; 32])?,
        StateFenceV2::from_bytes([44u8; 32])?,
    ))
}

fn crash_authority_config() -> TestResult<DeploymentConfigRevisionV2> {
    Ok(DeploymentConfigRevisionV2::new(1, [45u8; 32])?)
}

fn crash_authority_client_id() -> TestResult<AuthorityClientIdV2> {
    Ok(AuthorityClientIdV2::from_bytes([0x11; 32])?)
}

fn crash_authority_server_id() -> TestResult<AuthorityServerIdV2> {
    Ok(AuthorityServerIdV2::from_bytes([0x12; 32])?)
}

/// The identity both processes pin: everything fixed but the store epoch,
/// which only the process that provisioned the store knows.
fn crash_authority_identity(epoch: AuthorityEpochV2) -> TestResult<AuthorityWireIdentityV2> {
    Ok(AuthorityWireIdentityV2::new(
        crash_authority_client_id()?,
        crash_authority_server_id()?,
        epoch,
        crash_authority_head()?,
        crash_authority_config()?,
    )?)
}

fn crash_authority_server(path: &Path) -> TestResult<ReferenceAuthorityServerV2> {
    let (_, client_vk) = MlDsa65::generate(CRASH_CLIENT_SEED);
    let (server_sk, _) = MlDsa65::generate(CRASH_SERVER_SEED);
    let provision = AuthorityServerProvisionV2::new(
        crash_authority_client_id()?,
        crash_authority_server_id()?,
        crash_authority_head()?,
        crash_authority_config()?,
        AuthorityLimitsV2::new(64, 16, 16, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
    )?;
    Ok(ReferenceAuthorityServerV2::provision(
        path,
        provision,
        client_vk,
        ZeroizingBytes::from_bytes(server_sk),
        AuthorityTransportLimitsV2::new(CRASH_AUTHORITY_DEADLINE, Duration::from_secs(60), 256)?,
    )?)
}

fn crash_authority_client(
    address: SocketAddr,
    epoch: AuthorityEpochV2,
) -> TestResult<AuthenticatedTcpAuthorityV2> {
    let (client_sk, _) = MlDsa65::generate(CRASH_CLIENT_SEED);
    let (_, server_vk) = MlDsa65::generate(CRASH_SERVER_SEED);
    Ok(AuthenticatedTcpAuthorityV2::new(
        address,
        crash_authority_identity(epoch)?,
        ZeroizingBytes::from_bytes(client_sk),
        server_vk,
        CRASH_AUTHORITY_DEADLINE,
    )?)
}

/// The agent configuration both processes build from the same seeds, with
/// the trust roots the repository was provisioned under.
fn crash_agent_config() -> TestResult<(AgentConfig, MigrationMaterial)> {
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let (_, local_vk) = MlDsa65::generate([51u8; 32]);
    let (_, peer_vk) = MlDsa65::generate([52u8; 32]);
    let config = AgentConfig::new(
        AgentLimits::new(16, 16, Duration::from_secs(60))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([61u8; 32]), local_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([62u8; 32]), peer_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    )?;
    Ok((config, migration))
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(text: &str) -> TestResult<[u8; 32]> {
    if text.len() != 64 {
        return Err(io::Error::other("the epoch is not 32 hex bytes").into());
    }
    let mut bytes = [0u8; 32];
    for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}

fn known_snapshot(
    outcome: AuthorityOutcomeV2<AuthoritySnapshotV2>,
) -> TestResult<AuthoritySnapshotV2> {
    match outcome {
        AuthorityOutcomeV2::Known(snapshot) => Ok(snapshot),
        other => Err(format!("expected a known snapshot, got {other:?}").into()),
    }
}

#[test]
fn a_lease_receipt_stranded_by_a_real_process_crash_is_acknowledged_exactly_once_at_the_next_start(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let repository_path = directory.join("crash.redb");
    let (config, migration) = crash_agent_config()?;
    let (repository, head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    drop(repository);

    let server = crash_authority_server(&directory.join("authority.redb"))?;
    let epoch = server.identity().authority_epoch();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || {
        let mut server = server;
        server.serve(listener, &server_shutdown)
    });
    let client = crash_authority_client(address, epoch)?;
    let before = known_snapshot(client.snapshot()?)?;
    assert!(before.active_lease().is_none());

    // The child acquires, then dies inside its release's port call: the
    // release applied at the authority, its receipt is retained there, its
    // journal row is written, and the repository is still open.
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::lease_journal::lease_journal_crash_after_dispatch_child")
        .env(CRASH_REPOSITORY_ENV, &repository_path)
        .env(CRASH_ADDRESS_ENV, address.to_string())
        .env(CRASH_EPOCH_ENV, hex_encode(epoch.as_bytes()))
        .status()?;
    assert_eq!(status.code(), Some(86));
    assert_redb_file_left_unclean(&repository_path)?;

    // What the crash left: no active lease, one retained receipt, and one
    // journal row -- the release's; the acquire's was forgotten by the
    // release's own journal write.
    let crashed = known_snapshot(client.snapshot()?)?;
    assert!(
        crashed.active_lease().is_none(),
        "the release the child dispatched did not apply"
    );
    assert_eq!(crashed.receipt_count(), 1);
    assert_eq!(crashed.lease_generation(), before.lease_generation() + 1);
    let reopened = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
    let stranded = only_row(&reopened.journaled_lease_intents()?)?;
    let child_instance = match client.query(stranded)? {
        AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt)) => {
            match receipt.intent().mutation() {
                AuthorityMutationV2::ReleaseLease { fence } => fence.instance_id(),
                other => return Err(format!("the stranded row is not a release: {other:?}").into()),
            }
        }
        other => return Err(format!("the stranded receipt was not found: {other:?}").into()),
    };

    // The next start finds the row, acknowledges the receipt exactly once,
    // forgets the row, and acquires its own lease.
    let acknowledged = Arc::new(Mutex::new(Vec::new()));
    let counting = CountingAuthority::new(
        crash_authority_client(address, epoch)?,
        Arc::clone(&acknowledged),
    );
    let restarted = PolicyAgent::new(reopened, MemoryWitness::new(head), counting, config)?;
    let acknowledgements = acknowledged
        .lock()
        .map_err(|_| io::Error::other("acknowledgement log poisoned"))?
        .clone();
    assert_eq!(
        acknowledgements
            .iter()
            .filter(|operation| **operation == stranded)
            .count(),
        1,
        "the stranded receipt was acknowledged {} times",
        acknowledgements
            .iter()
            .filter(|operation| **operation == stranded)
            .count()
    );
    // The stranded release's receipt and the new acquire's own.
    assert_eq!(acknowledgements.len(), 2);
    let acquire = acknowledgements
        .iter()
        .find(|operation| **operation != stranded)
        .copied()
        .ok_or_else(|| io::Error::other("the new acquire's receipt was not acknowledged"))?;
    let restarted_view = known_snapshot(client.snapshot()?)?;
    assert_eq!(restarted_view.receipt_count(), 0);
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled, vec![acquire]);
    assert!(!journaled.contains(&stranded));
    // Two acquires since the start: the child's and this one's, under
    // different instance identities.
    assert_eq!(
        restarted_view.lease_generation(),
        before.lease_generation() + 2
    );
    let active = restarted_view
        .active_lease()
        .ok_or_else(|| io::Error::other("the restarted agent holds no lease"))?;
    assert_ne!(active.fence().instance_id(), child_instance);

    restarted.release_instance_lease()?;
    assert!(restarted.journaled_lease_intents_for_test()?.is_empty());
    assert_eq!(known_snapshot(client.snapshot()?)?.receipt_count(), 0);
    shutdown.store(true, Ordering::Release);
    join(server_thread)??;
    Ok(())
}

#[test]
fn lease_journal_crash_after_dispatch_child() -> TestResult {
    let Some(repository_path) = std::env::var_os(CRASH_REPOSITORY_ENV) else {
        return Ok(());
    };
    let address: SocketAddr = std::env::var(CRASH_ADDRESS_ENV)?.parse()?;
    let epoch = AuthorityEpochV2::from_bytes(hex_decode(&std::env::var(CRASH_EPOCH_ENV)?)?)?;
    let (config, migration) = crash_agent_config()?;
    let repository = StateRepository::open_existing(Path::new(&repository_path), migration.roots)?;
    let witness = MemoryWitness::new(repository.head()?);
    let authority = CrashAfterDispatchAuthority::new(crash_authority_client(address, epoch)?);
    let agent = PolicyAgent::new(repository, witness, authority, config)?;
    // Exits with 86 inside the release's port call, between the dispatch and
    // the receipt; returns only on failure.
    agent.release_instance_lease()?;
    Err(io::Error::other("the lease journal crash child did not exit").into())
}

/// A start whose acquire was dispatched and whose outcome was never learned
/// must hand back the fence that acquire would have granted, whatever error
/// carries that state out. The fence is the next generation under this
/// process's own fresh instance id: had the acquire applied, nothing else
/// could ever release it and every retry would be fenced until the TTL.
fn a_lost_acquire_releases_its_fence(
    session_byte: u8,
    expected: AgentError,
    arm: fn(&MemoryAuthority),
) -> TestResult {
    let directory = TestDirectory::new()?;
    let store = release_and_drop(agent_pair(&directory, session_byte)?)?;
    let calls_before = store.authority.lease_call_count();
    // The acquire applies and its response is lost; what the caller arms is
    // what stops the reconciliation from learning that it did.
    store.authority.make_next_unknown();
    arm(&store.authority);

    let outcome = PolicyAgent::new(
        store.repository,
        store.witness.clone(),
        store.authority.clone(),
        store.config.clone(),
    );
    assert_eq!(outcome.err(), Some(expected));
    // Three calls reached the authority: the acquire, then the release that
    // handed its fence straight back -- refused once on the authority version
    // the lost response never told this process about, which settles and
    // resynchronises, and applied at the refreshed one. Nothing is held, no
    // receipt is left retained, and the journal is empty again.
    assert_eq!(store.authority.lease_call_count(), calls_before + 3);
    assert_eq!(store.authority.active_lease()?, None);
    assert_eq!(store.authority.receipt_count()?, 0);
    let repository = StateRepository::open_existing(&store.path, store.roots.clone())?;
    assert!(repository.journaled_lease_intents()?.is_empty());

    // So the next start acquires at once instead of being fenced by a lease
    // this process left behind and would never have released.
    let restarted = PolicyAgent::new(
        repository,
        store.witness,
        store.authority.clone(),
        store.config,
    )?;
    restarted.release_instance_lease()?;
    Ok(())
}

#[test]
fn a_lost_acquire_whose_query_is_refused_closed_still_releases_the_fence() -> TestResult {
    // A closed refusal of the reconciling query is not an unknown outcome by
    // its error variant, but the acquire's own outcome is exactly as unknown
    // as it is after an exhausted reconciliation.
    a_lost_acquire_releases_its_fence(160, AgentError::InstanceLeaseUnavailable, |authority| {
        authority.refuse_next_query_with(AuthorityKnownFailureV2::RateLimited);
    })
}

#[test]
fn a_lost_acquire_whose_query_misses_the_budget_still_releases_the_fence() -> TestResult {
    // The reconciling query is the first round trip admitted after the lost
    // dispatch, and a bound larger than the constructor's whole budget makes
    // it the one that cannot fit. Every later read reports the usual zero, so
    // the compensating release runs on its own fresh budget.
    a_lost_acquire_releases_its_fence(161, AgentError::OperationDeadlineExceeded, |authority| {
        authority.report_bound_once_after_next_lease_call(Duration::from_secs(120));
    })
}

#[test]
fn an_acquire_whose_response_and_queries_are_lost_at_construction_releases_the_expected_fence(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let store = release_and_drop(agent_pair(&directory, 154)?)?;
    let before = store.authority.lock().authority.persistent_meta();
    let calls = store.authority.lease_call_count();
    // The acquire applies, its response is lost, and every query after it is
    // refused: the constructor can neither use the lease nor learn it has one.
    store.authority.lose_next_acquire_and_queries();
    assert_eq!(
        PolicyAgent::new(
            store.repository,
            store.witness.clone(),
            store.authority.clone(),
            store.config.clone(),
        )
        .err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );
    // The fence the acquire would have granted was handed back rather than
    // left to lapse. This is the assertion that fails if the release in the
    // indeterminate arm is ever dropped.
    assert_eq!(store.authority.active_lease()?, None);
    // And the acquire really did apply, so that release was not a no-op.
    assert_eq!(
        store
            .authority
            .lock()
            .authority
            .persistent_meta()
            .lease_generation,
        before.lease_generation + 1
    );
    // Three calls, deterministic under this fixture: the acquire (applied, its
    // response lost), a release refused on its stale authority version
    // (AuthorityVersionMismatch -> LeaseExchange::Retry), and the resynced
    // release that applies. Not a bound: leave it exact.
    assert_eq!(store.authority.lease_call_count(), calls + 3);

    // What the store is left holding is exactly the lost acquire's own row,
    // and what the authority is left holding is exactly that acquire's
    // receipt: the release's two rows were both settled -- the first proven
    // never to have run, the second acknowledged -- and forgotten, the first
    // by the second's journal write and the second by `forget_settled`. An
    // assertion that the journal is empty would be wrong, and an unbounded
    // one would not notice a dropped `forget_settled`.
    let repository = StateRepository::open_existing(&store.path, store.roots.clone())?;
    let journaled = repository.journaled_lease_intents()?;
    assert_eq!(journaled.len(), 1);
    assert_eq!(store.authority.receipt_count()?, 1);

    // With the queries answering again the next start acquires normally, on
    // its own acquire alone -- `new`, not `new_with_lease_wait`, so no TTL was
    // waited out -- and settles what the failed start left behind.
    store.authority.refuse_queries(false);
    let calls = store.authority.lease_call_count();
    let restarted = PolicyAgent::new(
        repository,
        store.witness.clone(),
        store.authority.clone(),
        store.config.clone(),
    )?;
    assert_eq!(store.authority.lease_call_count(), calls + 1);
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn a_dispatch_that_cannot_cover_its_journal_commit_leaves_no_row() -> TestResult {
    // Every lease mutation journals its intent durably -- one
    // `Durability::Immediate` two-phase commit -- and only then dispatches.
    // Admitting the dispatch on its bare round-trip bound before that commit
    // bounded the call from its own start, not from the admission: the commit
    // ran first and the mutation could end past the caller's deadline. The
    // commit is now admitted with the dispatch it precedes
    // (`DURABLE_COMMIT_RESERVE`), so a deadline that cannot cover both
    // refuses before the journal write, leaving no row and nothing to settle.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 176)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?)?;
    let journal = pair.initiator.journaled_lease_intents_for_test()?;
    let lease_calls = pair.initiator_authority.lease_call_count();

    // The pre-erase gate needs the release's round trip and its journal
    // commit -- two seconds -- and passes with half a second to spare. The
    // erase then sleeps 900 ms, so the release dispatch is admitted with
    // about 1.6 seconds left: enough for its bare one-second bound, which is
    // what used to let it through, and not for the commit it must pay first.
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_secs(1));
    pair.initiator
        .delay_each_session_cancel_for_test(Duration::from_millis(900))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(2_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.release_instance_lease_until(deadline),
        Err(AgentError::OperationDeadlineExceeded)
    );

    // Nothing was dispatched and nothing was journaled: the authority still
    // holds this instance's lease, and no row was added for an intent that
    // never left the process. (Rows may still *leave* the journal here: the
    // release forgets what earlier operations had already settled.)
    assert_eq!(pair.initiator_authority.lease_call_count(), lease_calls);
    assert!(
        pair.initiator
            .journaled_lease_intents_for_test()?
            .iter()
            .all(|row| journal.contains(row)),
        "the refused dispatch journaled a row"
    );
    assert!(pair.initiator_authority.active_lease()?.is_some());
    // The erase preceded the refusal, as the release contract says it does.
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // A retry under a budget of its own releases.
    pair.initiator.release_instance_lease()?;
    assert!(pair.initiator_authority.active_lease()?.is_none());
    Ok(())
}

#[test]
fn a_guarded_operation_reserves_the_journal_commit_its_renew_must_pay() -> TestResult {
    // The same reserve, at the plan gate. `OperationPlan` is what
    // `ensure_instance_lease` holds back before the resolution, the drains,
    // any journal write or any dispatch, so the renew's own journal commit
    // has to be part of it -- otherwise a drain could spend the second the
    // renew's commit needs and the operation would be refused after the
    // drains rather than before them.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 177)?;
    let journal = pair.initiator.journaled_lease_intents_for_test()?;
    let lease_calls = pair.initiator_authority.lease_call_count();

    // Reconcile's least plan at a one-second authority bound -- the memory
    // witness reports zero -- is two round trips plus one
    // DURABLE_COMMIT_RESERVE: three seconds.
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_secs(1));
    let short = Instant::now()
        .checked_add(Duration::from_millis(2_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.reconcile_transition_until(short),
        Err(AgentError::OperationDeadlineExceeded)
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), lease_calls);
    assert_eq!(pair.initiator.journaled_lease_intents_for_test()?, journal);

    // With room for the commit as well as the round trips the same call
    // renews and gets as far as finding nothing to reconcile.
    let long = Instant::now()
        .checked_add(Duration::from_millis(3_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.reconcile_transition_until(long),
        Err(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    assert_eq!(
        pair.initiator_authority.lease_call_count(),
        lease_calls + 1,
        "the renew must have been dispatched once the plan fitted"
    );
    Ok(())
}

#[test]
fn a_lease_intent_journaled_but_never_dispatched_is_forgotten_at_the_next_start() -> TestResult {
    // The journal row is written before the dispatch, so a crash between the
    // two leaves a row for an operation the authority never saw. The next
    // start must find it absent and forget it -- and must only ask the
    // authority about it, never dispatch anything on its behalf.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 83)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);

    // What the crash would have left: the row, and nothing on the authority.
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let orphan = OperationIdV2::new(1, [0x77u8; 32])?;
    repository.journal_lease_intent(orphan, &[])?;
    assert_eq!(repository.journaled_lease_intents()?, vec![orphan]);
    let before = initiator_authority.lock().authority.persistent_meta();
    let calls_before = initiator_authority.lease_call_count();

    let restarted = PolicyAgent::new(
        repository,
        witness,
        initiator_authority.clone(),
        initiator_config,
    )?;
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert!(
        !journaled.contains(&orphan),
        "the row for an operation the authority never saw survived the restart"
    );
    // What remains is the new acquire's own row, settled but not yet
    // forgotten: the next journal write does that.
    assert_eq!(journaled.len(), 1);
    // The authority saw exactly one new mutation, the acquire, and holds no
    // receipt for it either.
    let after = initiator_authority.lock().authority.persistent_meta();
    assert_eq!(after.authority_version, before.authority_version + 1);
    assert_eq!(initiator_authority.lease_call_count(), calls_before + 1);
    assert_eq!(initiator_authority.receipt_count()?, 0);
    Ok(())
}

#[test]
fn a_receipt_left_unacknowledged_by_a_crash_is_acknowledged_at_the_next_start() -> TestResult {
    // A crash after the dispatch and before the acknowledgement used to strand
    // the receipt in the authority's bounded table for good: the obligation
    // lived in RAM only, and the successor started a fresh acquire cycle that
    // never asked about the old operation. Now the successor finds the row,
    // finds the receipt, acknowledges it, and forgets the row.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 85)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);

    // With acknowledgements refused, the renew this operation drives stays
    // retained on both sides ...
    initiator_authority.refuse_acknowledgements(true);
    drive_one_lease_renew(&initiator)?;
    assert_eq!(initiator_authority.receipt_count()?, 1);
    // ... and this is the crash: the process goes away with the
    // acknowledgement still queued in memory.
    drop(initiator);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let journaled = repository.journaled_lease_intents()?;
    let stranded = journaled
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("the dispatched renew was not journaled"))?;
    assert_eq!(journaled.len(), 1);

    initiator_authority.refuse_acknowledgements(false);
    initiator_authority.expire_active_lease();
    let restarted = PolicyAgent::new(
        repository,
        witness,
        initiator_authority.clone(),
        initiator_config,
    )?;
    assert_eq!(
        initiator_authority.receipt_count()?,
        0,
        "the stranded receipt was not acknowledged at the restart"
    );
    assert!(!restarted
        .journaled_lease_intents_for_test()?
        .contains(&stranded));
    Ok(())
}

#[test]
fn a_full_lease_journal_refuses_the_operation_before_dispatch() -> TestResult {
    // While the authority refuses every acknowledgement, each guarded
    // operation adds a row the journal cannot yet forget. At the bound the
    // next lease operation is refused *before* dispatch: dispatching it would
    // owe one more acknowledgement with nowhere durable to record it. The
    // authority's own receipt table happens to fill at the same count in this
    // fixture, so the proof that the journal refused -- and not the authority
    // -- is that the authority was never asked.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 89)?;
    pair.initiator_authority.refuse_acknowledgements(true);
    let bound = usize::try_from(MAX_JOURNALED_LEASE_INTENTS)?;
    let calls_before = pair.initiator_authority.lease_call_count();
    for _ in 0..bound {
        drive_one_lease_renew(&pair.initiator)?;
    }
    assert_eq!(
        pair.initiator.journaled_lease_intents_for_test()?.len(),
        bound
    );
    assert_eq!(pair.initiator_authority.receipt_count()?, bound);
    let calls_at_bound = pair.initiator_authority.lease_call_count();
    assert_eq!(calls_at_bound, calls_before + u64::try_from(bound)?);

    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseUnavailable)
    );
    assert_eq!(
        pair.initiator_authority.lease_call_count(),
        calls_at_bound,
        "the refused operation reached the authority"
    );
    assert_eq!(
        pair.initiator.journaled_lease_intents_for_test()?.len(),
        bound
    );

    // Once acknowledgements go through again, the next operation drains the
    // queue, forgets every settled row in the journal write of its own renew,
    // and proceeds.
    pair.initiator_authority.refuse_acknowledgements(false);
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(pair.initiator.journaled_lease_intents_for_test()?.len(), 1);
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_clean_release_leaves_the_lease_journal_empty() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 87)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let accepted = pair
        .responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    pair.initiator
        .accept_responder_finished(encapsulated.handle, accepted.responder_finished)?;

    // In steady state the journal holds exactly one row: the last lease
    // operation's, settled and waiting for the next journal write to forget it.
    assert_eq!(pair.initiator.journaled_lease_intents_for_test()?.len(), 1);
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);

    // No journal write follows the release, so the release forgets its own
    // row and every other settled one itself.
    pair.initiator.release_instance_lease()?;
    assert!(pair
        .initiator
        .journaled_lease_intents_for_test()?
        .is_empty());
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    pair.initiator.release_instance_lease()?;
    assert!(pair
        .initiator
        .journaled_lease_intents_for_test()?
        .is_empty());
    Ok(())
}

#[test]
fn a_start_that_cannot_settle_a_full_lease_journal_fails_closed() -> TestResult {
    // Sixty-four rows the authority cannot answer for is where the journal
    // stops being able to record the next intent. Starting anyway would
    // dispatch an acquire the journal could not hold, so the start fails
    // closed, without dispatching, until the authority answers again.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 91)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let bound = u8::try_from(MAX_JOURNALED_LEASE_INTENTS)?;
    for byte in 1..=bound {
        repository.journal_lease_intent(OperationIdV2::new(1, [byte; 32])?, &[])?;
    }
    assert_eq!(
        repository.journaled_lease_intents()?.len(),
        usize::from(bound)
    );

    initiator_authority.refuse_queries(true);
    let calls_before = initiator_authority.lease_call_count();
    let queries_before = initiator_authority.query_call_count();
    assert!(matches!(
        PolicyAgent::new(
            repository,
            witness.clone(),
            initiator_authority.clone(),
            initiator_config.clone(),
        ),
        Err(AgentError::InstanceLeaseUnavailable)
    ));
    assert_eq!(initiator_authority.lease_call_count(), calls_before);
    // The first unanswered query ends the pass. Asking about every row would
    // cost one authority timeout per row before the start even fails -- with
    // the production five-second timeout, about five minutes for a full
    // journal -- which is exactly what the pass is documented not to do.
    assert_eq!(
        initiator_authority.query_call_count(),
        queries_before + 1,
        "an unanswering authority must be asked once, not once per row"
    );

    // With the authority answering, the same store starts: every row is found
    // absent and forgotten, and only the acquire's own row remains.
    initiator_authority.refuse_queries(false);
    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    let restarted = PolicyAgent::new(repository, witness, initiator_authority, initiator_config)?;
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn a_start_against_an_unanswering_authority_journals_nothing() -> TestResult {
    // The journal fills from lease operations that were *dispatched*: the
    // first row is written inside `lease_exchange`, and `acquire_instance_lease`
    // reaches it only after the pre-acquire snapshot. A start against an
    // authority that cannot answer at all is refused at that snapshot, before
    // any dispatch and before any journal write, so repeating such a start
    // never fills the 64 rows -- which is what the README's arithmetic now
    // says.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 172)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);
    initiator_authority.refuse_snapshots(true);
    initiator_authority.refuse_queries(true);
    let calls = initiator_authority.lease_call_count();
    for _ in 0..3 {
        let repository =
            StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
        assert_eq!(
            PolicyAgent::new(
                repository,
                witness.clone(),
                initiator_authority.clone(),
                initiator_config.clone(),
            )
            .err(),
            Some(AgentError::InstanceLeaseUnavailable)
        );
        let repository =
            StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
        assert!(
            repository.journaled_lease_intents()?.is_empty(),
            "a start refused at its pre-acquire snapshot must journal nothing"
        );
        assert_eq!(initiator_authority.lease_call_count(), calls);
    }
    Ok(())
}

#[test]
fn each_start_whose_acquire_stays_unsettled_journals_its_row() -> TestResult {
    // What a start does add to the journal, against an authority that answers
    // snapshots but no query: its acquire's row. The compensating release that
    // follows is answered, so `forget_settled` drops that row and one start
    // costs exactly one. A start whose own release goes unanswered too costs
    // two, which is the "half as many" in the README's row arithmetic.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 173)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);
    initiator_authority.refuse_queries(true);
    for expected_rows in 1..=2 {
        // Journaled, then refused by the transport before it was sent: the row
        // stays, because only a query could prove the acquire never ran.
        initiator_authority.fail_next_lease_call_before_send(LeaseCallFilter::Acquire);
        let repository =
            StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
        assert_eq!(
            PolicyAgent::new(
                repository,
                witness.clone(),
                initiator_authority.clone(),
                initiator_config.clone(),
            )
            .err(),
            Some(AgentError::InstanceLeaseUnavailable)
        );
        let repository =
            StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
        assert_eq!(repository.journaled_lease_intents()?.len(), expected_rows);
    }

    // Both dispatches lost on the wire this time: the acquire's row and the
    // compensating release's both stay, so this one start costs two.
    initiator_authority.lose_lease_calls_before_apply(LeaseCallFilter::Any, 2);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    assert_eq!(
        PolicyAgent::new(
            repository,
            witness.clone(),
            initiator_authority.clone(),
            initiator_config.clone(),
        )
        .err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    assert_eq!(repository.journaled_lease_intents()?.len(), 4);
    Ok(())
}

#[test]
fn rows_the_authority_could_not_answer_for_at_start_are_settled_by_a_later_operation() -> TestResult
{
    // Rows kept unresolved at start are not left for the *next* start: each
    // guarded operation asks about them again, alongside draining its
    // acknowledgements, and the renew's own journal write forgets whatever
    // was settled.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 95)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    for byte in [0x11u8, 0x22, 0x33] {
        repository.journal_lease_intent(OperationIdV2::new(1, [byte; 32])?, &[])?;
    }

    initiator_authority.refuse_queries(true);
    let restarted = PolicyAgent::new(
        repository,
        witness,
        initiator_authority.clone(),
        initiator_config,
    )?;
    // Three unresolved rows plus the acquire's.
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 4);

    // Still unanswered: the operation itself proceeds -- a renew is not a
    // query -- but the three rows stay.
    drive_one_lease_renew(&restarted)?;
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 4);

    // Answered: the next operation settles them, and its journal write forgets
    // them together with the previous renew's row.
    initiator_authority.refuse_queries(false);
    drive_one_lease_renew(&restarted)?;
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
    Ok(())
}
