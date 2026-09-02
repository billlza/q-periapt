//! Session, confirmation, and acceptance state machine.

use super::*;

#[test]
fn constructors_reject_collapsed_identity_domains_and_zero_timeouts() -> TestResult {
    let (_, shared_vk) = MlDsa65::generate([90u8; 32]);
    assert_eq!(
        MigrationTrustRoots::new(
            MigrationAuthorityKeyId::from_bytes([1u8; 32]),
            shared_vk,
            MigrationAuthorityKeyId::from_bytes([1u8; 32]),
            shared_vk,
        ),
        Err(crate::RepositoryError::UnprovisionedAuthority)
    );

    let policy = policy_material(20)?;
    let config = AgentConfig::new(
        AgentLimits::new(2, 2, Duration::from_secs(1))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([2u8; 32]), shared_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([3u8; 32]), shared_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    );
    assert!(matches!(config, Err(AgentError::InvalidConfiguration)));

    let (client_sk, _) = MlDsa65::generate([91u8; 32]);
    assert_eq!(
        AuthenticatedTcpWitness::new(
            "127.0.0.1:9".parse()?,
            ZeroizingBytes::from_bytes(client_sk),
            shared_vk,
            Duration::ZERO,
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    assert_eq!(
        AuthenticatedTcpWitness::new(
            "127.0.0.1:9".parse()?,
            ZeroizingBytes::zeroed(),
            shared_vk,
            Duration::from_secs(1),
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    assert_eq!(
        AuthenticatedTcpWitness::new(
            "127.0.0.1:9".parse()?,
            ZeroizingBytes::from_bytes(client_sk),
            [0u8; ML_DSA_65_VK_LEN],
            Duration::from_secs(1),
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    let directory = TestDirectory::new()?;
    let (server_sk, server_vk) = MlDsa65::generate([92u8; 32]);
    let head = StateHead::new(
        StateRevision::new(1, 1, [1u8; 32])?,
        FenceToken::generate()?,
    );
    assert_eq!(
        ReferenceWitnessServer::provision(
            &directory.join("witness.redb"),
            head,
            shared_vk,
            ZeroizingBytes::from_bytes(server_sk),
            server_vk,
            Duration::ZERO,
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    Ok(())
}

#[test]
fn mutual_confirmation_releases_only_handles_and_replay_tombstone_survives_restart() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 1)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated =
        responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
            pair.responder_authorization.clone(),
            encapsulated.ciphertexts.clone(),
        ))?)?;

    assert_eq!(
        pair.initiator
            .accept_initiator_finished(encapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::UnexpectedFlight)
    );
    assert_eq!(
        pair.responder.accept_responder_finished(
            decapsulated.handle,
            ResponderFinishedV1::from_bytes([9u8; 32]),
        ),
        Err(AgentError::UnexpectedFlight)
    );

    let responder_acceptance = pair
        .responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,)?,
        responder_acceptance
    );
    assert_eq!(
        pair.responder.accept_initiator_finished(
            decapsulated.handle,
            InitiatorFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::ConflictingAcceptanceReplay)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,)?,
        responder_acceptance
    );
    let initiator_key = pair
        .initiator
        .accept_responder_finished(encapsulated.handle, responder_acceptance.responder_finished)?;
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            responder_acceptance.responder_finished,
        )?,
        initiator_key
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            ResponderFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::ConflictingAcceptanceReplay)
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            responder_acceptance.responder_finished,
        )?,
        initiator_key
    );
    pair.initiator.destroy_key(initiator_key)?;
    pair.responder
        .destroy_key(responder_acceptance.key_handle)?;
    let replay = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(replay, Err(AgentError::AuthorizationRejected));

    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        initiator_authorization,
        responder_public_keys,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let reopened_repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    let reopened = PolicyAgent::new(
        reopened_repository,
        witness,
        initiator_authority,
        initiator_config,
    )?;
    let replay_after_restart = reopened.begin_encapsulation(BeginEncapsulation::new(
        initiator_authorization,
        responder_public_keys,
    ));
    assert_eq!(replay_after_restart, Err(AgentError::AuthorizationRejected));
    Ok(())
}

#[test]
fn protocol_role_not_kem_direction_controls_finished_order() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 12)?;
    let encapsulated = responder_encapsulation(pair.responder.begin_encapsulation(
        BeginEncapsulation::new(pair.responder_authorization, pair.initiator_public_keys),
    )?)?;
    let decapsulated = initiator_decapsulation(pair.initiator.begin_decapsulation(
        BeginDecapsulation::new(pair.initiator_authorization, encapsulated.ciphertexts),
    )?)?;

    let responder_acceptance = pair
        .responder
        .accept_initiator_finished(encapsulated.handle, decapsulated.initiator_finished)?;
    let initiator_key = pair
        .initiator
        .accept_responder_finished(decapsulated.handle, responder_acceptance.responder_finished)?;
    pair.initiator.destroy_key(initiator_key)?;
    pair.responder
        .destroy_key(responder_acceptance.key_handle)?;
    Ok(())
}

#[test]
fn concurrent_exact_responder_acceptance_returns_one_stable_result() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 15)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let responder = Arc::new(pair.responder);
    let barrier = Arc::new(Barrier::new(3));

    let first_agent = Arc::clone(&responder);
    let first_barrier = Arc::clone(&barrier);
    let first_finished = encapsulated.initiator_finished;
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_agent.accept_initiator_finished(decapsulated.handle, first_finished)
    });
    let second_agent = Arc::clone(&responder);
    let second_barrier = Arc::clone(&barrier);
    let second_finished = encapsulated.initiator_finished;
    let second = thread::spawn(move || {
        second_barrier.wait();
        second_agent.accept_initiator_finished(decapsulated.handle, second_finished)
    });
    barrier.wait();
    let first_result = join(first)??;
    let second_result = join(second)??;
    assert_eq!(first_result, second_result);
    responder.destroy_key(first_result.key_handle)?;
    assert_eq!(
        responder.destroy_key(first_result.key_handle),
        Err(AgentError::UnknownHandle)
    );
    Ok(())
}

#[test]
fn abi2_secret_mismatch_rejects_finished_and_terminally_erases_session() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 2)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let mut damaged_pq = *encapsulated.ciphertexts.pq();
    if let Some(first) = damaged_pq.first_mut() {
        *first ^= 1;
    }
    let damaged =
        EncapsulationCiphertexts::from_slices(&damaged_pq, encapsulated.ciphertexts.traditional())?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, damaged),
    )?)?;
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::FinishedRejected)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::UnknownHandle)
    );
    pair.initiator.cancel(encapsulated.handle)?;
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys,
        )),
        Err(AgentError::AuthorizationRejected)
    );
    Ok(())
}

#[test]
fn durable_release_failure_never_returns_responder_finished_or_retained_handle() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 13)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;

    pair.responder
        .remove_durable_reservation_for_test(decapsulated.handle)?;
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::InternalPoisoned)
    );
    Ok(())
}

#[test]
fn durable_cancel_failure_poisoning_prevents_further_service() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 18)?;
    let pending = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    pair.initiator
        .remove_durable_reservation_for_test(pending.handle)?;
    assert_eq!(
        pair.initiator.cancel(pending.handle),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(
        pair.initiator.public_keys(),
        Err(AgentError::InternalPoisoned)
    );
    Ok(())
}

#[test]
fn stale_witness_is_rejected_before_finished_verification_and_consumes_session() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 14)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated =
        responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
            pair.responder_authorization,
            encapsulated.ciphertexts.clone(),
        ))?)?;
    pair.witness.replace_head(StateHead::new(
        StateRevision::new(2, 2, [14u8; 32])?,
        FenceToken::generate()?,
    ))?;

    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::StaleSession)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::UnknownHandle)
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            ResponderFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::StaleSession)
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            ResponderFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::UnknownHandle)
    );
    Ok(())
}

#[test]
fn restart_rejects_secretless_pending_handle_but_preserves_capability_tombstone() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 16)?;
    let pending =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        initiator_authorization,
        responder_public_keys,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();

    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    assert_eq!(repository.restart_rejections(), 1);
    let reopened = PolicyAgent::new(repository, witness, initiator_authority, initiator_config)?;
    assert_eq!(
        reopened
            .accept_responder_finished(pending.handle, ResponderFinishedV1::from_bytes([0u8; 32]),),
        Err(AgentError::UnknownHandle)
    );
    assert_eq!(
        reopened.begin_encapsulation(BeginEncapsulation::new(
            initiator_authorization,
            responder_public_keys,
        )),
        Err(AgentError::AuthorizationRejected)
    );
    Ok(())
}
