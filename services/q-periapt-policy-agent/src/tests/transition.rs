//! Migration state transitions, reconciliation, and process-boundary recovery.

use super::*;

#[test]
fn floor_five_advance_is_rejected_before_durable_intent_or_witness_cas() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 8)?;
    let initial_state = pair.committed.state();
    let initial_head = pair.witness.read_head()?;
    let (_, floor_five_certificate) = signed_advance(
        initial_state,
        &pair.migration,
        MigrationSecurityPosture::new(SecurityFloor::Level5, ComponentMode::HybridRequired),
        MigrationSuiteSet::from_suites(&[HybridSuite::MlKem1024X25519])?,
    )?;

    assert_eq!(
        pair.initiator.apply_advance(&floor_five_certificate),
        Err(AgentError::Repository(
            crate::RepositoryError::InvalidCertificate
        ))
    );
    assert_eq!(pair.witness.read_head()?, initial_head);

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
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();

    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, initial_head);
    assert_eq!(repository.committed_state().state(), initial_state);

    let (floor_three_state, floor_three_certificate) = signed_advance(
        initial_state,
        &migration,
        initial_state.posture(),
        initial_state.allowed_suites(),
    )?;
    let agent = PolicyAgent::new(
        repository,
        witness.clone(),
        initiator_authority,
        initiator_config,
    )?;
    agent.apply_advance(&floor_three_certificate)?;
    drop(agent);

    let transitioned = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    assert_eq!(transitioned.pending_intent(), None);
    assert_eq!(transitioned.committed_state().state(), floor_three_state);
    assert_eq!(transitioned.head()?, witness.read_head()?);
    assert_ne!(transitioned.head()?, initial_head);
    Ok(())
}

#[test]
fn unknown_transition_reconciles_same_operation_and_stales_old_session() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 3)?;
    let pending = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.witness.make_next_unknown();
    assert_eq!(
        pair.initiator.apply_advance(&certificate),
        Err(AgentError::TransitionIndeterminate)
    );
    assert_eq!(
        pair.initiator
            .accept_responder_finished(pending.handle, ResponderFinishedV1::from_bytes([0u8; 32]),),
        Err(AgentError::TransitionPending)
    );
    pair.initiator.reconcile_transition()?;
    assert_eq!(
        pair.initiator
            .accept_responder_finished(pending.handle, ResponderFinishedV1::from_bytes([0u8; 32]),),
        Err(AgentError::UnknownHandle)
    );

    let old_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    // A fresh deployment authority isolates this assertion to the witness
    // rollback check; the shared-authority clone case is covered by the
    // dedicated instance-lease fencing tests.
    let rolled_back = PolicyAgent::new(
        old_repository,
        pair.witness,
        MemoryAuthority::new()?,
        pair.initiator_config,
    );
    assert!(matches!(rolled_back, Err(AgentError::RollbackOrFork)));
    Ok(())
}

#[test]
fn valid_incompatible_state_commits_without_executor_and_later_state_recovers() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 4)?;
    let (incompatible_state, incompatible_certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        MigrationSuiteSet::from_suites(&[HybridSuite::MlKem1024X25519])?,
    )?;
    pair.initiator.apply_advance(&incompatible_certificate)?;
    assert_eq!(
        pair.initiator.public_keys(),
        Err(AgentError::ExecutionUnavailable)
    );

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
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let restarted = PolicyAgent::new(repository, witness, initiator_authority, initiator_config)?;
    assert_eq!(
        restarted.public_keys(),
        Err(AgentError::ExecutionUnavailable)
    );
    let (_, recovery_certificate) = signed_advance(
        incompatible_state,
        &migration,
        incompatible_state.posture(),
        MigrationSuiteSet::from_suites(&[HybridSuite::MlKem768X25519])?,
    )?;
    restarted.apply_advance(&recovery_certificate)?;
    assert!(restarted.public_keys().is_ok());
    Ok(())
}

#[test]
fn execution_policy_identity_can_advance_while_old_bundle_remains_blocked() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 6)?;
    let policy_v2_text = POLICY.replace("policy_version = 1", "policy_version = 2");
    let policy_v2 = policy_material_from_text(23, &policy_v2_text)?;
    let (_, certificate) = signed_advance_with_execution(
        pair.committed.state(),
        &pair.migration,
        policy_v2.authenticated.trusted_state(),
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.initiator.apply_advance(&certificate)?;
    assert_eq!(
        pair.initiator.public_keys(),
        Err(AgentError::ExecutionUnavailable)
    );

    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_repository_path,
        endpoint_policy_bundle,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    let (_, initiator_vk) = MlDsa65::generate([51u8; 32]);
    let (_, responder_vk) = MlDsa65::generate([52u8; 32]);
    let updated_config = AgentConfig::new(
        AgentLimits::new(16, 16, Duration::from_secs(60))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([61u8; 32]), initiator_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([62u8; 32]), responder_vk)?,
        policy_v2.bundle,
        endpoint_policy_bundle.clone(),
        endpoint_policy_bundle,
    )?;
    let restarted = PolicyAgent::new(repository, witness, initiator_authority, updated_config)?;
    assert!(restarted.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_transition_the_witness_applied_before_the_deadline_lapsed_is_still_committed() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 139)?;
    let initial_head = pair.witness.read_head()?;
    let (advanced_state, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    // Every port is instantaneous by its bound, so the CAS is admitted while
    // the deadline stands; it then ends well past it. The three-second
    // deadline is the budget for everything before that admission -- the lease
    // renew and its coverage snapshot, `prepare_advance`'s durable commit, and
    // the debug build's executor provisioning -- which measures 200-300 ms
    // unloaded and up to 620 ms under a heavily contended suite, so this keeps
    // roughly five times the headroom a shared runner needs. The CAS delay is
    // that deadline plus a second and a half, and the two must stay coupled:
    // a delay that ended before the deadline lapsed would stop proving the
    // property, which is that a CAS admitted in time still commits when it
    // finishes late.
    pair.witness
        .delay_next_compare_and_advance(Duration::from_millis(4_500));
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(3))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    pair.initiator.apply_advance_until(&certificate, deadline)?;
    // Past the witness's applied receipt the transition is committed, and
    // committed locally too, with nothing left to reconcile: the truthful
    // answer is Ok whatever the clock said by then.
    let advanced_head = pair.witness.read_head()?;
    assert_ne!(advanced_head, initial_head);
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    assert!(pair.initiator.public_keys().is_ok());

    // Whereas a CAS that could not end before the deadline is never
    // dispatched: refused at admission, before the durable intent, with the
    // witness and the authority untouched.
    let (_, next_certificate) = signed_advance(
        advanced_state,
        &pair.migration,
        advanced_state.posture(),
        advanced_state.allowed_suites(),
    )?;
    pair.witness.set_round_trip_bound(Duration::from_secs(1));
    let lease_calls = pair.initiator_authority.lease_call_count();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(100))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator
            .apply_advance_until(&next_certificate, deadline),
        Err(AgentError::OperationDeadlineExceeded)
    );
    assert_eq!(pair.witness.read_head()?, advanced_head);
    assert_eq!(pair.initiator_authority.lease_call_count(), lease_calls);
    // Not a fence and nothing left behind: the same advance under the default
    // budget applies.
    pair.initiator.apply_advance(&next_certificate)?;
    assert_ne!(pair.witness.read_head()?, advanced_head);
    Ok(())
}

#[test]
fn reset_cannot_rotate_to_an_unprovisioned_migration_authority() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 5)?;
    let current = pair.committed;
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: MigrationChainId::from_bytes([99u8; 32]),
        protocol_id: current.state().protocol_id(),
        epoch: 1,
        previous_state_digest: current.revision().digest(),
        authority_key_id: MigrationAuthorityKeyId::from_bytes([100u8; 32]),
        execution_policy_state: current.state().execution_policy_state(),
        posture: current.state().posture(),
        allowed_suites: current.state().allowed_suites(),
    })?;
    let reset = MigrationResetV1::new(
        current.revision(),
        next,
        MigrationResetNonce::from_bytes([101u8; 32]),
        MigrationAuthorityKeyId::from_bytes([32u8; 32]),
    );
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed = SignedMigrationResetV1::sign(
        reset,
        &MlDsa65,
        &pair.migration.recovery_signing_key,
        &[0u8; 32],
        &mut signature,
    )?;
    assert_eq!(
        pair.initiator.apply_reset(&signed.encode()?),
        Err(AgentError::Repository(
            crate::RepositoryError::UnprovisionedAuthority
        ))
    );
    assert_eq!(pair.witness.read_head()?, pair.committed_head()?);
    Ok(())
}

#[test]
fn abrupt_process_exit_after_durable_intent_reopens_and_reconciles_exact_operation() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("repository.redb");
    let certificate_path = directory.join("advance.cert");
    let (repository, head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let current = repository.committed_state();
    drop(repository);
    let (_, certificate) = signed_advance(
        current.state(),
        &migration,
        current.state().posture(),
        current.state().allowed_suites(),
    )?;
    fs::write(&certificate_path, &certificate)?;
    fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))?;
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::transition::crash_after_durable_intent_child")
        .current_dir(directory.path())
        .env("Q_PERIAPT_TEST_CRASH_INTENT", "1")
        .status()?;
    assert_eq!(status.code(), Some(86));
    assert_redb_file_left_unclean(&repository_path)?;

    let reopened = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
    let operation = reopened
        .pending_intent()
        .ok_or_else(|| io::Error::other("crash lost durable transition intent"))?
        .operation_id();
    let witness = MemoryWitness::new(head);
    let (_, local_vk) = MlDsa65::generate([51u8; 32]);
    let (_, peer_vk) = MlDsa65::generate([52u8; 32]);
    let config = AgentConfig::new(
        AgentLimits::new(8, 8, Duration::from_secs(30))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([61u8; 32]), local_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([62u8; 32]), peer_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    )?;
    let agent = PolicyAgent::new(reopened, witness.clone(), MemoryAuthority::new()?, config)?;
    agent.reconcile_transition()?;
    assert!(matches!(
        witness.query(operation)?,
        WitnessOutcome::Known(receipt) if receipt.disposition() == crate::WitnessDisposition::Applied
    ));
    Ok(())
}

#[test]
fn crash_after_durable_intent_child() -> TestResult {
    if std::env::var_os("Q_PERIAPT_TEST_CRASH_INTENT").is_none() {
        return Ok(());
    }
    let directory_path = std::env::current_dir()?;
    let repository_path = directory_path.join("repository.redb");
    let directory = OwnedPrivateDirectory::open(&directory_path)
        .map_err(|_| io::Error::other("crash test directory is not private"))?;
    let (_, authority_vk) = MlDsa65::generate([21u8; 32]);
    let (_, recovery_vk) = MlDsa65::generate([22u8; 32]);
    let roots = MigrationTrustRoots::new(
        MigrationAuthorityKeyId::from_bytes([31u8; 32]),
        authority_vk,
        MigrationAuthorityKeyId::from_bytes([32u8; 32]),
        recovery_vk,
    )?;
    let mut repository = StateRepository::open_existing(&repository_path, roots)?;
    let mut certificate_file = directory
        .open_config_file(
            "advance.cert",
            q_periapt_migration::MAX_MIGRATION_SIGNATURE_BYTES
                + q_periapt_migration::MAX_MIGRATION_RESET_BODY_BYTES
                + 16,
        )
        .map_err(|_| io::Error::other("crash certificate is not private"))?;
    let mut certificate = Vec::new();
    certificate_file.read_to_end(&mut certificate)?;
    repository.prepare_advance(&certificate)?;
    std::process::exit(86);
}

/// A deadline that fits the transition plan but not the witness CAS once the
/// lease work has been paid for. Both ports report a zero authority bound, so
/// the TRANSITION plan reserve is the 500 ms witness bound plus the renew's
/// own journal commit (`DURABLE_COMMIT_RESERVE`, one second): 1.5 s, admitted
/// at t = 0 with a second of margin. The post-renew coverage snapshot then
/// burns 2.2 s, leaving about 300 ms, so the 500 ms CAS bound cannot be
/// admitted, with 200 ms of margin. The refusal must land before the durable
/// intent: journaled, it would leave a pending transition only Reconcile
/// clears.
#[test]
fn a_deadline_that_lapses_after_the_lease_leaves_no_durable_intent() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 141)?;
    let initial_head = pair.witness.read_head()?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.witness
        .set_round_trip_bound(Duration::from_millis(500));
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(2_200));
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(2_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.apply_advance_until(&certificate, deadline),
        Err(AgentError::OperationDeadlineExceeded)
    );

    // Nothing was dispatched to the witness and nothing was journaled: the
    // agent still answers, and there is no pending transition to reconcile.
    assert_eq!(pair.witness.read_head()?, initial_head);
    assert!(pair.initiator.public_keys().is_ok());
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    // And the same advance under a budget of its own applies.
    pair.witness.set_round_trip_bound(Duration::ZERO);
    pair.initiator.apply_advance(&certificate)?;
    assert_ne!(pair.witness.read_head()?, initial_head);
    Ok(())
}

/// The same arithmetic as `a_deadline_that_lapses_after_the_lease_leaves_no_
/// durable_intent`, on the reset path, which prepares its own durable intent
/// the same way.
#[test]
fn a_reset_refused_after_the_lease_leaves_no_durable_intent() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 142)?;
    let initial_head = pair.witness.read_head()?;
    let current = pair.committed;
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: MigrationChainId::from_bytes([99u8; 32]),
        protocol_id: current.state().protocol_id(),
        epoch: 1,
        previous_state_digest: current.revision().digest(),
        authority_key_id: current.state().authority_key_id(),
        execution_policy_state: current.state().execution_policy_state(),
        posture: current.state().posture(),
        allowed_suites: current.state().allowed_suites(),
    })?;
    let reset = MigrationResetV1::new(
        current.revision(),
        next,
        MigrationResetNonce::from_bytes([102u8; 32]),
        MigrationAuthorityKeyId::from_bytes([32u8; 32]),
    );
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed = SignedMigrationResetV1::sign(
        reset,
        &MlDsa65,
        &pair.migration.recovery_signing_key,
        &[0u8; 32],
        &mut signature,
    )?;
    let encoded = signed.encode()?;

    pair.witness
        .set_round_trip_bound(Duration::from_millis(500));
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(2_200));
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(2_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.apply_reset_until(&encoded, deadline),
        Err(AgentError::OperationDeadlineExceeded)
    );

    assert_eq!(pair.witness.read_head()?, initial_head);
    assert!(pair.initiator.public_keys().is_ok());
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    // The same reset under a budget of its own applies.
    pair.witness.set_round_trip_bound(Duration::ZERO);
    pair.initiator.apply_reset(&encoded)?;
    assert_ne!(pair.witness.read_head()?, initial_head);
    Ok(())
}
