//! Instance lease, coverage, fencing, and recovery.

use super::*;

#[test]
fn a_coverage_lapse_at_acceptance_releases_the_durable_reservation() -> TestResult {
    // By the acceptance point the session has already left the in-memory map
    // and its confirmation is consumed, but its durable reservation is still
    // held. Refusing there without releasing it would orphan the row --
    // `erase_pending` can no longer find the handle and `fence_out` iterates the
    // map -- permanently burning one of the bounded SESSION_TABLE slots, and
    // surviving restart. That would make this fix worse than the gap it closes.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 63)?;
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

    // Lapse the coverage for the initiator's acceptance specifically.
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 1);
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(20));
    assert_eq!(
        pair.initiator
            .accept_responder_finished(encapsulated.handle, accepted.responder_finished)
            .err(),
        Some(AgentError::InstanceLeaseCoverageElapsed)
    );

    // The durable row is gone: cancelling it again must fail, because there is
    // nothing left to cancel. If the reservation had leaked this would succeed.
    assert!(
        pair.initiator
            .desynchronize_session_for_test(encapsulated.handle)
            .is_err(),
        "the durable reservation was orphaned instead of released"
    );
    assert_eq!(pair.initiator.pending_session_count(), 0);
    Ok(())
}

#[test]
fn a_lease_that_lapsed_without_a_successor_is_recovered_not_fenced() -> TestResult {
    // An authority unreachable for longer than the lease TTL used to brick the
    // agent permanently: the first successful renew after reconnect returned
    // LeaseExpired, which was treated as supersession and fenced the instance
    // for the life of the process. A fifteen-second restart of the authority is
    // more than the ten-second minimum TTL, so this happened unattended and to
    // every agent at once.
    //
    // LeaseExpired says the lease had run out, not that anyone took it. Here
    // nobody did.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 67)?;
    pair.initiator_authority.expire_active_lease();

    // The guarded operation drives the renew, which is rejected as expired and
    // recovers by re-acquiring at this instance's own generation.
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    assert!(!encapsulated
        .initiator_finished
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0));

    // Still usable, and holding the session it just created.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_lapse_between_renew_and_snapshot_is_not_a_permanent_fence() -> TestResult {
    // A different path from the one above, and it used to end worse. The renew
    // *succeeds* and extends the lease; then, before the coverage snapshot is
    // taken, the authority's clock passes the new expiry. The snapshot reports
    // no active lease, and that was treated as proof of a successor: the
    // instance fenced itself permanently, with no successor anywhere, and no
    // later request could recover it because the process-local fenced flag is
    // checked before anything else.
    //
    // No active lease is not evidence of a takeover. The authority's lease
    // generation advances on acquire alone, so while it still equals ours
    // nobody acquired after us: the lease merely lapsed.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 69)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    let before_lease = before.lease.expect("the initial agent acquired its lease");

    // Let this renew really extend the lease, then lapse it before the
    // coverage snapshot. No successor is ever constructed or acquired.
    pair.initiator_authority.advance_clock(1);
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
    let first = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(
        first.err(),
        Some(AgentError::InstanceLeaseCoverageElapsed),
        "a lapse with no successor must be reported as transient, not as a fence"
    );

    // The renew applied and extended this same instance's lease; nothing
    // acquired after it. That is what "no successor" looks like on the
    // authority.
    let after = pair.initiator_authority.lock().authority.persistent_meta();
    let after_lease = after
        .lease
        .expect("expiry retains the authority lease record");
    assert_eq!(after.lease_generation, before.lease_generation);
    assert_eq!(after_lease.fence(), before_lease.fence());
    assert_eq!(after.authority_version, before.authority_version + 1);
    assert_eq!(
        after_lease.expires_at_millis(),
        before_lease.expires_at_millis() + 1
    );
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // Ordinary time passes and the next guarded operation recovers on its own:
    // the renew is rejected as expired, and the instance re-acquires at its own
    // generation. It was never fenced.
    pair.initiator_authority.advance_clock(1);
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    assert!(!encapsulated
        .initiator_finished
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert!(pair.initiator.public_keys().is_ok());

    // And that recovery was a re-acquire by the same instance, not a takeover.
    let recovered = pair.initiator_authority.lock().authority.persistent_meta();
    assert_eq!(recovered.lease_generation, before.lease_generation + 1);
    assert_eq!(
        recovered
            .lease
            .expect("the re-acquired lease is active")
            .fence()
            .instance_id(),
        before_lease.fence().instance_id()
    );
    Ok(())
}

#[test]
fn a_successor_between_renew_and_snapshot_is_a_real_fence() -> TestResult {
    // The complement of the lapse test above. Same observation -- the
    // coverage snapshot reports no active lease -- but this time the
    // authority's lease generation has moved past ours, because another
    // instance acquired after our renew and has since lapsed itself. That is
    // proof a successor held key-use authority after us, and it fences.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 73)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    let incumbent = before
        .lease
        .expect("the initial agent acquired its lease")
        .fence()
        .instance_id();
    pair.initiator_authority
        .successor_acquires_before_next_snapshot();
    let first = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(first.err(), Some(AgentError::InstanceFenced));
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // The authority confirms the story: one acquire happened, by someone
    // else, and that successor had itself lapsed by the time of the snapshot
    // -- so the snapshot showed no active lease and a generation past ours,
    // which is the branch under test, not a live foreign fence.
    let after = pair.initiator_authority.lock().authority.persistent_meta();
    assert_eq!(after.lease_generation, before.lease_generation + 1);
    let successor = after
        .lease
        .expect("the successor's lease record is retained after it lapses");
    assert_ne!(successor.fence().instance_id(), incumbent);
    assert!(
        successor.expires_at_millis() <= pair.initiator_authority.lock().now_millis,
        "the successor must have lapsed before the snapshot"
    );
    // And the fence is permanent, whatever the clock does next.
    pair.initiator_authority.advance_clock(1);
    let second = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(second.err(), Some(AgentError::InstanceFenced));
    Ok(())
}

#[test]
fn a_coverage_lapse_during_the_durable_reservation_retains_no_session() -> TestResult {
    // The coverage check before the durable reservation cannot see a lapse
    // that happens *during* it. The reservation is a real fsync, so nothing
    // in a test can make it slow on demand; the repository's test hook sleeps
    // after the commit instead. Coverage is cut to two seconds and the write
    // is made to take two and a half, so the check before the write passes and
    // only the one after it can refuse.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 75)?;
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 2_000);
    pair.initiator
        .delay_next_durable_write_for_test(Duration::from_millis(2_500))?;

    let started = Instant::now();
    let outcome = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(
        outcome.err(),
        Some(AgentError::InstanceLeaseCoverageElapsed)
    );
    // The delay ran, so the durable write happened and the check before it
    // had passed: this refusal came from the check after the write.
    assert!(
        started.elapsed() >= Duration::from_millis(2_400),
        "the durable write did not run; the early check refused instead"
    );
    // Nothing retained in memory, and the reservation the write created was
    // released again rather than orphaned.
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_coverage_lapse_during_the_durable_release_retains_no_key() -> TestResult {
    // Same shape at acceptance: the durable release of the reservation is the
    // last write before the accepted key becomes retained. A lapse during it
    // must drop the key without retaining it, leave the reservation released,
    // and neither fence nor poison the agent.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 77)?;
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

    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 2_000);
    pair.initiator
        .delay_next_durable_write_for_test(Duration::from_millis(2_500))?;
    let started = Instant::now();
    assert_eq!(
        pair.initiator
            .accept_responder_finished(encapsulated.handle, accepted.responder_finished)
            .err(),
        Some(AgentError::InstanceLeaseCoverageElapsed)
    );
    assert!(
        started.elapsed() >= Duration::from_millis(2_400),
        "the durable release did not run; the early check refused instead"
    );
    assert_eq!(pair.initiator.confirmed_key_count(), 0);
    assert_eq!(pair.initiator.pending_session_count(), 0);
    // The reservation was released by the write, not orphaned: there is
    // nothing left to cancel.
    assert!(pair
        .initiator
        .desynchronize_session_for_test(encapsulated.handle)
        .is_err());
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn an_operation_that_outlives_its_proven_lease_coverage_retains_nothing() -> TestResult {
    // The lease is checked on the way in, but a witness round trip, two
    // signature verifications and a KEM operation all run before a secret first
    // becomes retained. The renew receipt carries no expiry, so the agent takes
    // one snapshot to learn how long it can prove it still holds the lease, and
    // refuses to retain anything past that point.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 61)?;

    // The renew applies, and then the authority's clock jumps to one
    // millisecond before the new expiry. That is the shape of the real race:
    // the renew succeeded, and time passed before the agent learned the expiry.
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 1);
    // Spend that last millisecond inside the snapshot, so the coverage has
    // provably lapsed by the time the operation checks it. Without this the
    // test would be racing the real work between the snapshot and the check --
    // key generation, the witness round trip, the contract's signature
    // verifications -- and would start passing for the wrong reason, or fail
    // outright, once a release build brings that work under a millisecond.
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(20));

    let outcome = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(
        outcome.err(),
        Some(AgentError::InstanceLeaseCoverageElapsed),
        "an operation past its proven coverage must not return a handle"
    );

    // Nothing was retained. A coverage lapse is not a fence: it is a local
    // deadline running out, which is no evidence that a successor exists, so
    // the agent stays usable rather than being permanently retired.
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.confirmed_key_count(), 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn fencing_out_erases_every_key_even_when_a_durable_cancel_fails() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 41)?;

    // Carry one session through to a confirmed application key.
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    pair.responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    assert_eq!(pair.responder.confirmed_key_count(), 1);

    // And leave a second session pending, so the sweep has something to fail on
    // before it reaches the retained key.
    let second =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.second_initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    let second_pending = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.second_responder_authorization, second.ciphertexts),
    )?)?;
    assert_eq!(pair.responder.pending_session_count(), 1);

    // Make that session's durable cancellation fail the way a diverged store
    // would: its row is gone, but the session is still held in memory.
    pair.responder
        .desynchronize_session_for_test(second_pending.handle)?;

    // Fencing out happens when another instance holds the lease, so this
    // process must not be left holding key material. The durable failure is
    // still reported, but it must not be reported instead of erasing.
    assert!(pair.responder.fence_out_for_test().is_err());
    assert_eq!(pair.responder.pending_session_count(), 0);
    assert_eq!(
        pair.responder.confirmed_key_count(),
        0,
        "a failed durable cancel left accepted application keys in memory"
    );
    Ok(())
}

#[test]
fn an_idle_agent_erases_expired_session_secrets_without_being_asked() -> TestResult {
    let directory = TestDirectory::new()?;
    // Short enough that the session is past its deadline almost immediately, so
    // the test observes the expiry rather than waiting out a realistic TTL.
    let pair = agent_pair_with_session_ttl(&directory, 9, Duration::from_millis(1))?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);

    thread::sleep(Duration::from_millis(20));

    // The deadline has passed and the session is still here. That is the whole
    // problem: every purge so far has been a side effect of some request, so an
    // agent nobody is talking to holds its expired key material indefinitely.
    assert_eq!(pair.initiator.pending_session_count(), 1);

    // This is what the serving loop calls when its accept wait times out.
    pair.initiator.expire_idle_sessions();
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // The sweep releases the durable reservation too, so the freed capacity is
    // real and not just a forgotten map entry.
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn second_instance_on_same_authority_is_fenced_at_construction() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 33)?;
    // No transition has happened, so the snapshot copy equals the live state
    // and only the instance lease separates the clone from the live holder.
    let clone_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let clone = PolicyAgent::new(
        clone_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    );
    assert!(matches!(clone, Err(AgentError::InstanceFenced)));
    // The live holder keeps its lease-guarded operations.
    let _live = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?;
    Ok(())
}

#[test]
fn expired_lease_successor_fences_out_live_instance_and_erases_secrets() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 34)?;
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
    let responder_acceptance = pair
        .responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    pair.initiator
        .accept_responder_finished(encapsulated.handle, responder_acceptance.responder_finished)?;
    assert_eq!(pair.initiator.acceptance_counts_for_test()?, (1, 1));

    // The holder's lease reaches witness-clock expiry; a successor clone
    // acquires the next generation over the identical migration state.
    pair.initiator_authority.expire_active_lease();
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;

    // The superseded instance is fenced on its next guarded operation and
    // erases every in-process pending and accepted secret first.
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    assert_eq!(pair.initiator.acceptance_counts_for_test()?, (0, 0));
    // Fencing is permanent for this instance, even after the successor stops.
    successor.release_instance_lease()?;
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    Ok(())
}

#[test]
fn released_lease_is_idempotent_and_hands_over_without_ttl_wait() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 35)?;
    pair.initiator.release_instance_lease()?;
    pair.initiator.release_instance_lease()?;
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    successor.release_instance_lease()?;
    Ok(())
}

#[test]
fn lost_lease_responses_reconcile_by_exact_operation_query() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 36)?;
    // Advance the trusted clock so the next renewal strictly extends and is
    // Applied rather than short-circuited as not-extended.
    pair.initiator_authority.advance_clock(1_000);
    pair.initiator_authority.make_next_unknown();
    let _encapsulated = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?;

    // A lost acquire response is likewise reconciled by the successor itself.
    pair.initiator.release_instance_lease()?;
    pair.initiator_authority.make_next_unknown();
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    successor.release_instance_lease()?;
    Ok(())
}

#[test]
fn concurrent_instances_race_to_exactly_one_lease() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 38)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        old_snapshot_path,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let repository_a =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let repository_b = StateRepository::open_existing(&old_snapshot_path, migration.roots)?;
    let barrier = Arc::new(Barrier::new(2));
    let spawn_instance = |repository: StateRepository| {
        let witness = witness.clone();
        let authority = initiator_authority.clone();
        let config = initiator_config.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            PolicyAgent::new(repository, witness, authority, config).map(drop)
        })
    };
    let first = spawn_instance(repository_a);
    let second = spawn_instance(repository_b);
    let outcomes = [
        first.join().map_err(|_| io::Error::other("join failed"))?,
        second.join().map_err(|_| io::Error::other("join failed"))?,
    ];
    let acquired = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    let fenced = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(AgentError::InstanceFenced)))
        .count();
    assert_eq!((acquired, fenced), (1, 1));
    Ok(())
}

#[test]
fn an_authority_rolled_back_behind_our_generation_is_a_fence() -> TestResult {
    // The third shape a coverage snapshot with no active lease can take: the
    // authority's lease generation is *behind* the one it issued us. That is
    // an authority restored from before our acquire, and it could grant our
    // generation again to someone else. The lease can no longer be trusted, so
    // this fails closed -- permanently, like a takeover.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 79)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    pair.initiator_authority
        .authority_rolls_back_before_next_snapshot();
    let first = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(first.err(), Some(AgentError::InstanceFenced));
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // What the snapshot saw: no lease, and a generation behind ours.
    let rolled_back = pair.initiator_authority.lock().authority.persistent_meta();
    assert!(rolled_back.lease.is_none());
    assert!(rolled_back.lease_generation < before.lease_generation);

    pair.initiator_authority.advance_clock(1);
    let second = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(second.err(), Some(AgentError::InstanceFenced));
    Ok(())
}

/// The cheapest lease-guarded operation: it renews, journals, and then fails
/// on the absence of a pending transition before touching anything else.
fn drive_one_lease_renew(agent: &PolicyAgent<MemoryWitness, MemoryAuthority>) -> TestResult {
    assert_eq!(
        agent.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
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

    // With the authority answering, the same store starts: every row is found
    // absent and forgotten, and only the acquire's own row remains.
    initiator_authority.refuse_queries(false);
    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    let restarted = PolicyAgent::new(repository, witness, initiator_authority, initiator_config)?;
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
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
