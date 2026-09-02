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
