//! Instance lease, coverage, fencing, and recovery.

use super::*;
use crate::service::lease::{coverage_deadline, LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS};

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

    // Lapse the coverage for the initiator's acceptance specifically. The
    // renew sets the expiry to (renew clock + TTL); the first push moves the
    // authority clock to (renew + TTL - 4B) before the post-renew snapshot, so
    // `coverage_deadline` records anchor + (TTL - (TTL - 4B) - B) = anchor +
    // three seconds of local coverage. That is what the checks and the durable
    // release before the retention snapshot have to fit in -- measured at 83
    // to 258 ms in a debug build -- rather than the one budget this used to
    // leave. The two pushes still sum to exactly the TTL, so the retention
    // snapshot after the durable release sees the authority's clock reach the
    // expiry, and that is where the refusal comes from.
    pair.initiator_authority.advance_clock_before_next_snapshot(
        MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 4 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS,
    );
    pair.initiator_authority
        .advance_clock_before_next_snapshot(4 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS);
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
    // after the commit instead. The lapse is an authority-clock event. The
    // renew sets the expiry to (renew clock + TTL); the first push moves the
    // authority clock to (renew + TTL - 4B) before the post-renew snapshot, so
    // `coverage_deadline` records anchor + (TTL - (TTL - 4B) - B) = anchor +
    // three seconds of local coverage: enough for the witness read, the
    // capability verifications and the KEM that run before the pre-write
    // `ensure_may_retain` -- measured at 83 to 258 ms in a debug build -- so
    // the check before the write passes for the right reason. The write is
    // then made to take two and a half seconds. The two pushes still sum to
    // exactly the TTL, so the retention snapshot after the write sees the
    // authority's clock reach the expiry, and the local clock alone no longer
    // decides.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 75)?;
    pair.initiator_authority.advance_clock_before_next_snapshot(
        MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 4 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS,
    );
    pair.initiator_authority
        .advance_clock_before_next_snapshot(4 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS);
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
    // -- seen by the retention snapshot after the write -- must drop the key
    // without retaining it, leave the reservation released, and neither fence
    // nor poison the agent. The same arithmetic as above: the first push
    // leaves anchor + 3 s of local coverage for the release-path checks, which
    // cost about a millisecond, and the two pushes sum to exactly the TTL so
    // the retention snapshot still lands on the expiry.
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

    pair.initiator_authority.advance_clock_before_next_snapshot(
        MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 4 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS,
    );
    pair.initiator_authority
        .advance_clock_before_next_snapshot(4 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS);
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
fn coverage_refuses_before_the_write_once_only_the_divergence_budget_is_left() -> TestResult {
    // The lease is checked on the way in, but a witness round trip, two
    // signature verifications and a KEM operation all run before a secret first
    // becomes retained, and the authority's clock may gain on this host's
    // meanwhile. The renew receipt carries no expiry, so the agent takes one
    // snapshot to learn how long it can prove it still holds the lease, and a
    // lease with no more than the divergence budget left proves nothing: the
    // operation is refused before it starts.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 61)?;

    // The renew applies, and then the authority's clock jumps to exactly the
    // budget before the new expiry. That is the shape of the real race: the
    // renew succeeded, and time passed before the agent learned the expiry.
    pair.initiator_authority.advance_clock_before_next_snapshot(
        MEMORY_AUTHORITY_LEASE_TTL_MILLIS - LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS,
    );
    // Armed but never paid: the refusal comes before the durable write.
    pair.initiator
        .delay_next_durable_write_for_test(Duration::from_millis(2_000))?;

    let started = Instant::now();
    let outcome = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(
        outcome.err(),
        Some(AgentError::InstanceLeaseCoverageElapsed),
        "an operation without provable coverage must not return a handle"
    );
    // The delay is still armed, so no durable session write ran: this is the
    // deterministic half of the check, and the one that fails if the refusal
    // ever moves after the write. `durable_session_count_for_test` below
    // cannot tell the two apart -- the write-then-release path leaves zero
    // rows as well.
    assert!(
        pair.initiator.durable_write_delay_armed_for_test()?,
        "the durable write ran; the post-renew proof should have refused first"
    );
    // And the refusal stayed on the in-memory path: a lock, a memory-authority
    // renew, one snapshot and the budgeted local rule, measured at 15-135 ms
    // in a debug build. One second is roughly seven times that, for a slower
    // runner, and still half the two seconds a run of the durable write would
    // have cost, so the two outcomes stay a second apart in both directions.
    assert!(
        started.elapsed() < Duration::from_millis(1_000),
        "the refusal took longer than the in-memory path should: {:?}",
        started.elapsed()
    );

    // Nothing was retained and nothing was written. A coverage lapse is not a
    // fence: it is no evidence that a successor exists, so the agent stays
    // usable rather than being permanently retired.
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert_eq!(pair.initiator.confirmed_key_count(), 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_lease_with_more_than_the_budget_left_still_serves() -> TestResult {
    // The companion: the budget must never eat a healthy lease. With three
    // budgets left the post-renew proof passes, the retention snapshot after
    // the durable write passes too, and the session is retained.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 135)?;
    pair.initiator_authority.advance_clock_before_next_snapshot(
        MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 3 * LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS,
    );
    let snapshots_before = pair.initiator_authority.snapshot_call_count();
    let outcome = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert!(outcome.is_ok(), "unexpected result: {outcome:?}");
    assert_eq!(pair.initiator.pending_session_count(), 1);
    // One snapshot after the renew, one after the durable reservation.
    assert_eq!(
        pair.initiator_authority.snapshot_call_count() - snapshots_before,
        2
    );
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

#[test]
fn a_successor_waits_for_a_lapsed_lease_instead_of_failing_at_construction() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 41)?;
    // The holder is neither renewing nor releasing: a process that was killed,
    // whose lease the authority will only let lapse at its TTL.
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let authority = pair.initiator_authority.clone();
    let lapse = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        authority.expire_active_lease();
    });
    let started = Instant::now();
    let successor = PolicyAgent::new_with_lease_wait(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
        Duration::from_secs(10),
    )?;
    let waited = started.elapsed();
    join(lapse)?;
    assert!(
        waited >= Duration::from_millis(300),
        "the successor acquired after {waited:?}, before the lease had lapsed"
    );
    assert!(
        waited < Duration::from_secs(5),
        "the successor took {waited:?} to notice the lapse"
    );
    // The successor holds key-use authority now, and the predecessor is the
    // instance that is fenced.
    successor.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?;
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.second_initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    Ok(())
}

#[test]
fn a_successor_waiting_on_a_renewing_holder_is_refused_after_max_wait() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 42)?;
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let max_wait = Duration::from_millis(1_500);
    let stop = AtomicBool::new(false);
    let (outcome, waited) =
        thread::scope(|scope| -> TestResult<(Result<(), AgentError>, Duration)> {
            // The holder is alive and keeps renewing, with the authority's
            // clock moving on between renewals so that each one strictly
            // extends the lease. Any guarded operation renews first; with no
            // transition pending, this one then returns without touching
            // anything else.
            let holder = scope.spawn(|| -> TestResult {
                while !stop.load(Ordering::Acquire) {
                    pair.initiator_authority.advance_clock(500);
                    let renewed = pair.initiator.reconcile_transition();
                    assert!(
                        !matches!(renewed, Err(AgentError::InstanceFenced)),
                        "the holder lost its lease while it was still renewing"
                    );
                    thread::sleep(Duration::from_millis(100));
                }
                Ok(())
            });
            let started = Instant::now();
            let outcome = PolicyAgent::new_with_lease_wait(
                successor_repository,
                pair.witness.clone(),
                pair.initiator_authority.clone(),
                pair.initiator_config.clone(),
                max_wait,
            );
            let waited = started.elapsed();
            stop.store(true, Ordering::Release);
            holder
                .join()
                .map_err(|_| io::Error::other("holder thread panicked"))??;
            Ok((outcome.map(drop), waited))
        })?;
    assert!(
        matches!(outcome, Err(AgentError::InstanceFenced)),
        "a live, renewing holder must still fence the successor: {outcome:?}"
    );
    assert!(
        waited >= max_wait,
        "the successor gave up after {waited:?}, before max_wait {max_wait:?}"
    );
    assert!(
        waited < Duration::from_secs(10),
        "the successor kept waiting for {waited:?} past max_wait {max_wait:?}"
    );
    Ok(())
}

#[test]
fn a_constructor_failure_after_the_acquire_releases_the_lease() -> TestResult {
    // The acquire is dispatched before the witness is read, the executor is
    // built, and the policies are authenticated. A failure there used to drop
    // the acquired lease on the floor: the authority kept it under an instance
    // id no process would ever release, and a healthy retry was fenced until
    // the TTL.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 117)?;
    pair.initiator.release_instance_lease()?;
    let calls = pair.initiator_authority.lease_call_count();
    pair.witness.fail_reads.store(true, Ordering::Release);
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let failed = PolicyAgent::new(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    );
    assert_eq!(
        failed.err(),
        Some(AgentError::Witness(WitnessError::Unavailable))
    );
    // The constructor's own error is what comes back, and the lease it had
    // acquired is gone again: one acquire, one release, the release's receipt
    // acknowledged and its row forgotten.
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 2);
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    assert!(
        repository.journaled_lease_intents()?.is_empty(),
        "the failed constructor left lease-intent rows behind"
    );

    // With the witness back, the retry acquires at once.
    pair.witness.fail_reads.store(false, Ordering::Release);
    let second = PolicyAgent::new(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    second.release_instance_lease()?;
    Ok(())
}

#[test]
fn a_constructor_failure_through_the_lease_wait_releases_the_lease() -> TestResult {
    // The daemon's own entry point takes the same path after its acquire.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 121)?;
    pair.initiator.release_instance_lease()?;
    pair.witness.fail_reads.store(true, Ordering::Release);
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let failed = PolicyAgent::new_with_lease_wait(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
        Duration::ZERO,
    );
    assert_eq!(
        failed.err(),
        Some(AgentError::Witness(WitnessError::Unavailable))
    );
    assert_eq!(pair.initiator_authority.active_lease()?, None);

    // Nothing is left to wait out: with no wait allowed at all, the retry
    // still starts.
    pair.witness.fail_reads.store(false, Ordering::Release);
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let second = PolicyAgent::new_with_lease_wait(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
        Duration::ZERO,
    )?;
    second.release_instance_lease()?;
    Ok(())
}

#[test]
fn a_release_that_was_never_sent_keeps_the_fence_and_releases_on_retry() -> TestResult {
    // A release the transport could not send used to retire the fence first
    // and report the failure second, so the retry found no fence, dispatched
    // nothing, and succeeded -- with the authority still holding the lease.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 118)?;
    let before = pair.initiator_authority.active_lease()?;
    assert!(before.is_some());
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator_authority
        .fail_next_lease_call_before_send(LeaseCallFilter::Release);
    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InstanceLeaseUnavailable)
    );
    // Nothing reached the authority, and the lease is still ours to release.
    assert_eq!(pair.initiator_authority.active_lease()?, before);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls);
    // A stop was asked for and every secret is already gone, so guarded
    // operations are refused from the first attempt on.
    assert_eq!(
        pair.initiator
            .begin_encapsulation(BeginEncapsulation::new(
                pair.initiator_authorization.clone(),
                pair.responder_public_keys.clone(),
            ))
            .err(),
        Some(AgentError::InstanceFenced)
    );
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // The retry dispatches exactly one release, with the fence it kept.
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert!(pair
        .initiator
        .journaled_lease_intents_for_test()?
        .is_empty());
    // And once the lease is retired, a further call dispatches nothing.
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    Ok(())
}

#[test]
fn a_release_whose_response_and_queries_are_lost_is_proven_gone_by_snapshot() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 122)?;
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

    // The release applies at the authority, but its response is lost and both
    // reconciling queries go unanswered. A snapshot showing no active lease is
    // the proof that settles it.
    initiator_authority.make_next_unknown();
    initiator_authority.refuse_queries(true);
    initiator.release_instance_lease()?;
    assert_eq!(initiator_authority.active_lease()?, None);
    // The release's own row is kept, unresolved: its receipt is still retained
    // by the authority and still owed an acknowledgement.
    let journaled = initiator.journaled_lease_intents_for_test()?;
    let release_row = journaled
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("the release's row was forgotten"))?;
    assert_eq!(journaled.len(), 1);
    assert_eq!(initiator_authority.receipt_count()?, 1);

    // The next start finds the row, acknowledges the receipt, and forgets it;
    // what remains is the new acquire's own row.
    initiator_authority.refuse_queries(false);
    drop(initiator);
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let restarted = PolicyAgent::new(
        repository,
        witness,
        initiator_authority.clone(),
        initiator_config,
    )?;
    assert_eq!(initiator_authority.receipt_count()?, 0);
    let journaled = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(journaled.len(), 1);
    assert!(!journaled.contains(&release_row));
    restarted.release_instance_lease()?;
    Ok(())
}

/// A release the authority applied whose response was lost, with the
/// reconciliation then stopped in `arm`'s way.
///
/// Every such stop leaves the same evidence -- the release was dispatched and
/// what it did was never learned -- and none of them may be reported as a
/// lease still held: `release_instance_lease_until` promises that `Err` never
/// means this call released the lease, and the stop path turns an `Err` into
/// exit 1 and an operator-facing line saying the release was not confirmed.
/// So each one is settled by the same snapshot proof.
///
/// `budget` is the release budget to run under, `None` for the default one.
/// `reconciling_queries` is how many exact queries the route is supposed to
/// spend before it gives up and proves the release by snapshot; asserting it
/// is what distinguishes a query that was refused from one that was answered.
fn a_lost_release_is_proven_gone_by_snapshot(
    session_byte: u8,
    arm: fn(&MemoryAuthority),
    budget: Option<Duration>,
    reconciling_queries: u64,
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, session_byte)?;
    assert!(pair.initiator_authority.active_lease()?.is_some());
    // The release reaches the authority and applies; its response is lost, and
    // what the caller arms is what stops the reconciliation from learning that
    // it did.
    pair.initiator_authority.make_next_unknown();
    arm(&pair.initiator_authority);

    let snapshots_before = pair.initiator_authority.snapshot_call_count();
    let queries_before = pair.initiator_authority.query_call_count();
    match budget {
        None => pair.initiator.release_instance_lease()?,
        Some(budget) => assert_eq!(
            pair.initiator.release_instance_lease_within(budget)?,
            LeaseReleaseOutcome::Released
        ),
    }
    assert_eq!(
        pair.initiator_authority.query_call_count(),
        queries_before + reconciling_queries
    );
    // Exactly one snapshot, taken by the release itself: this is the assertion
    // that fails when the release decides on the error variant instead, which
    // takes no snapshot and reports the applied release as a lease still held.
    assert_eq!(
        pair.initiator_authority.snapshot_call_count(),
        snapshots_before + 1
    );
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    // The release's own row is kept, unresolved: the authority still retains
    // its receipt and is still owed the acknowledgement.
    assert_eq!(pair.initiator.journaled_lease_intents_for_test()?.len(), 1);
    assert_eq!(pair.initiator_authority.receipt_count()?, 1);
    // And the retired lease dispatches nothing on a further call.
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.lease_call_count(), calls);
    Ok(())
}

#[test]
fn a_release_whose_response_is_lost_and_query_refused_closed_is_proven_gone_by_snapshot(
) -> TestResult {
    // A server-side condition that clears on its own -- a failed allocation
    // while the query response was being built -- so the query is closed-
    // failed and the snapshot right after it is answered. The query returns
    // `InstanceLeaseUnavailable`, whose variant alone would say the lease is
    // still this instance's to release, and the lease is already gone.
    //
    // A condition that refuses the snapshot too is a different route, and it
    // is not closed by a proof: see
    // `a_release_the_authority_rate_limits_outright_is_reported_unproven`.
    a_lost_release_is_proven_gone_by_snapshot(
        179,
        |authority| {
            authority.refuse_next_query_with(AuthorityKnownFailureV2::AllocationFailed);
        },
        None,
        1,
    )
}

/// The constant `round_trip_bound` the budget route runs against. Production
/// reports one number from every read (`AuthorityTransportV2::round_trip_bound`
/// returns the transport's own deadline), so the test does too.
const LOST_RELEASE_ROUND_TRIP: Duration = Duration::from_millis(1_200);
/// What the release dispatch really spends. `round_trip_bound` says only how
/// much a call *may* cost; this is what a dispatch whose answer never comes
/// back actually takes out of the budget.
const LOST_RELEASE_DISPATCH_COST: Duration = Duration::from_millis(2_200);
/// The release budget: above the commit plus two bounds `lease_exchange`
/// admits with the proof reserved (3.4s), and below what would still leave
/// the reconciling query its own admission after the dispatch above (5.8s).
const LOST_RELEASE_BUDGET: Duration = Duration::from_millis(4_200);

#[test]
fn a_release_whose_response_is_lost_and_query_misses_the_budget_is_proven_gone_by_snapshot(
) -> TestResult {
    // The production shape: one constant bound from every read, and a
    // dispatch that really spends a round trip. What is left then admits the
    // proof (one bound) but not a reconciling query (a bound with the proof
    // reserved behind it), so the release gives up learning its outcome and
    // proves it instead -- and the zero queries asserted below are what says
    // the query was refused rather than answered.
    //
    // Reserving the proof through the dispatch and the query is exactly what
    // makes this reachable. Unreserved, the query and the proof are admitted
    // on identical terms, so no budget can refuse one and admit the other:
    // every deadline that stopped the reconciliation would also take away the
    // proof, and an applied release would be reported as a lease still held.
    a_lost_release_is_proven_gone_by_snapshot(
        180,
        |authority| {
            authority.set_round_trip_bound(LOST_RELEASE_ROUND_TRIP);
            authority.delay_next_lease_call(LOST_RELEASE_DISPATCH_COST);
        },
        Some(LOST_RELEASE_BUDGET),
        0,
    )
}

#[test]
fn a_failed_durable_cancel_at_release_still_releases_the_lease() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 123)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    // Make the session's durable cancellation fail the way a diverged store
    // would: its row is gone, but the session is still held in memory.
    pair.initiator
        .desynchronize_session_for_test(encapsulated.handle)?;
    let calls = pair.initiator_authority.lease_call_count();

    // The durable failure is reported -- after the release, not instead of
    // it: the lease is gone, and so is the secret.
    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    // A poisoned agent refuses the repeat before it reaches the lease.
    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    Ok(())
}

/// Lapse the initiator's lease and let its re-acquire apply with the response
/// lost and every query refused from then on: the authority holds the next
/// generation under the initiator's own instance id, and the initiator cannot
/// yet learn that it does. Returns the lease before and after.
fn lose_the_reacquire_response(pair: &AgentPair) -> TestResult<(InstanceLeaseV2, InstanceLeaseV2)> {
    let before = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("initial lease missing"))?;
    pair.initiator_authority.expire_active_lease();
    pair.initiator_authority.lose_next_acquire_and_queries();
    let calls = pair.initiator_authority.lease_call_count();
    let queries = pair.initiator_authority.query_call_count();
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );
    let after = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("reacquired lease missing"))?;
    // Only this same instance advanced the generation: the renew was rejected
    // as expired and the re-acquire applied, one call each, and both
    // reconciling queries went unanswered.
    assert_eq!(after.fence().instance_id(), before.fence().instance_id());
    assert_eq!(after.fence().generation(), before.fence().generation() + 1);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 2);
    assert!(pair.initiator_authority.query_call_count() >= queries + 2);
    Ok((before, after))
}

#[test]
fn a_lost_reacquire_is_recognized_as_our_own_lease_once_the_authority_answers() -> TestResult {
    // The re-acquire after a lapse applied, but its response and both
    // reconciling queries were lost. Nothing remembered what that acquire
    // would have produced, so the next operation acknowledged its receipt
    // unread and renewed with the old fence -- which the authority, holding
    // the next generation under this very instance, rejected as a fence
    // mismatch. The instance fenced itself permanently, with its own lease
    // active and no successor anywhere.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 119)?;
    let (before, after) = lose_the_reacquire_response(&pair)?;

    // Once the authority answers again, the exact receipt says the acquire
    // applied: the lease is adopted, and the renew that follows carries the
    // re-acquired fence. One renew, no acquire, no release, and the receipt
    // acknowledged only after it was read.
    pair.initiator_authority.refuse_queries(false);
    let calls = pair.initiator_authority.lease_call_count();
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(pair.initiator_authority.active_lease()?, Some(after));
    let meta = pair.initiator_authority.lock().authority.persistent_meta();
    assert_eq!(meta.lease_generation, before.fence().generation() + 1);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 2);
    assert_eq!(pair.initiator_authority.active_lease()?, Some(after));

    // Fully usable.
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    Ok(())
}

#[test]
fn a_lost_reacquire_is_adopted_from_the_snapshot_while_queries_stay_refused() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 124)?;
    let (_, after) = lose_the_reacquire_response(&pair)?;
    // What the journal holds now is the re-acquire's own row, unresolved.
    let journaled = pair.initiator.journaled_lease_intents_for_test()?;
    let acquire_row = journaled
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("the re-acquire's row was forgotten"))?;
    assert_eq!(journaled.len(), 1);

    // With the queries still refused, the snapshot shows an active lease under
    // exactly the fence the re-acquire would have produced -- this instance's
    // own fresh id at the next generation, which nothing else can produce.
    // That is adopted, and the operation runs under it: one renew, no acquire.
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(
        pair.initiator_authority
            .active_lease()?
            .map(|lease| lease.fence()),
        Some(after.fence())
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    // The receipt could not be read, so it was not acknowledged either: the
    // authority still retains it, and its row stays journaled.
    assert!(pair
        .initiator
        .journaled_lease_intents_for_test()?
        .contains(&acquire_row));
    assert_eq!(pair.initiator_authority.receipt_count()?, 1);

    // Once queries are answered, the next operation's drain discharges it.
    pair.initiator_authority.refuse_queries(false);
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    assert!(pair.initiator.journaled_lease_intents_for_test()?.len() <= 1);
    Ok(())
}

#[test]
fn a_lost_reacquire_never_dispatches_a_renew_with_the_old_fence_while_unresolvable() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 125)?;
    let (before, _) = lose_the_reacquire_response(&pair)?;
    pair.initiator_authority.refuse_snapshots(true);

    // Neither the exact query nor a snapshot can be had. The operation is
    // refused as unavailable -- never as fenced -- and nothing is dispatched:
    // a renew under the pre-acquire fence would be answered with a fence
    // mismatch by this instance's own re-acquired lease.
    let calls = pair.initiator_authority.lease_call_count();
    for _ in 0..3 {
        assert_eq!(
            pair.initiator
                .begin_encapsulation(BeginEncapsulation::new(
                    pair.initiator_authorization.clone(),
                    pair.responder_public_keys.clone(),
                ))
                .err(),
            Some(AgentError::InstanceLeaseUnavailable)
        );
        assert_eq!(pair.initiator_authority.lease_call_count(), calls);
    }

    // Queries answered, snapshots still refused: the exact receipt adopts the
    // lease, one renew is dispatched under the re-acquired fence, and the
    // operation then fails at its coverage snapshot.
    pair.initiator_authority.refuse_queries(false);
    assert_eq!(
        pair.initiator
            .begin_encapsulation(BeginEncapsulation::new(
                pair.initiator_authorization.clone(),
                pair.responder_public_keys.clone(),
            ))
            .err(),
        Some(AgentError::InstanceLeaseUnavailable)
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);

    // Snapshots back: the next operation runs under the re-acquired lease.
    pair.initiator_authority.refuse_snapshots(false);
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?;
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 2);
    let meta = pair.initiator_authority.lock().authority.persistent_meta();
    assert_eq!(meta.lease_generation, before.fence().generation() + 1);
    assert_eq!(pair.initiator.pending_session_count(), 1);
    Ok(())
}

#[test]
fn a_reacquire_lost_on_the_wire_is_retried_not_adopted() -> TestResult {
    // The complement: the re-acquire never reached the authority. A snapshot
    // cannot tell this apart from an acquire that applied and then lapsed, so
    // only the exact query's proof of absence clears the record -- and the
    // ordinary path then re-acquires afresh.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 126)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    let instance_id = before
        .lease
        .expect("the initial agent acquired its lease")
        .fence()
        .instance_id();
    pair.initiator_authority.expire_active_lease();
    pair.initiator_authority
        .lose_next_lease_call_before_apply(LeaseCallFilter::Acquire);
    pair.initiator_authority.refuse_queries(true);

    let calls = pair.initiator_authority.lease_call_count();
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );
    let lost = pair
        .initiator_authority
        .lost_operation()
        .ok_or_else(|| io::Error::other("no acquire was lost"))?;
    // Only the renew reached the authority: its lease is gone, its generation
    // unmoved, and the lost acquire's row is journaled.
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert_eq!(
        pair.initiator_authority
            .lock()
            .authority
            .persistent_meta()
            .lease_generation,
        before.lease_generation
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    assert!(pair
        .initiator
        .journaled_lease_intents_for_test()?
        .contains(&lost));

    // Absent at the authority's version: the record is cleared, the renew is
    // rejected as expired again, and a fresh acquire takes the next
    // generation. Two calls; nothing is left retained or journaled for the
    // lost one.
    pair.initiator_authority.refuse_queries(false);
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?;
    let active = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the fresh acquire left no lease"))?;
    assert_eq!(active.fence().instance_id(), instance_id);
    assert_eq!(active.fence().generation(), before.lease_generation + 1);
    assert_eq!(
        pair.initiator_authority
            .lock()
            .authority
            .persistent_meta()
            .lease_generation,
        before.lease_generation + 1
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 2);
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    assert!(!pair
        .initiator
        .journaled_lease_intents_for_test()?
        .contains(&lost));
    Ok(())
}

#[test]
fn a_successor_after_a_lost_reacquire_still_fences() -> TestResult {
    // Remembering the re-acquire must not weaken exclusivity: a successor
    // that acquires after it still fences this instance.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 127)?;
    let (before, _) = lose_the_reacquire_response(&pair)?;
    pair.initiator_authority.refuse_queries(false);
    pair.initiator_authority.expire_active_lease();
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    let taken = pair.initiator_authority.lock().authority.persistent_meta();
    assert_eq!(taken.lease_generation, before.fence().generation() + 2);
    assert_ne!(
        taken
            .lease
            .expect("the successor holds the lease")
            .fence()
            .instance_id(),
        before.fence().instance_id()
    );

    // The exact receipt adopts the re-acquired fence; the renew under it is
    // rejected as a fence mismatch by the successor's lease, and that fences.
    assert_eq!(
        pair.initiator
            .begin_encapsulation(BeginEncapsulation::new(
                pair.initiator_authorization.clone(),
                pair.responder_public_keys.clone(),
            ))
            .err(),
        Some(AgentError::InstanceFenced)
    );
    assert_eq!(pair.initiator.acceptance_counts_for_test()?, (0, 0));
    assert_eq!(pair.initiator.pending_session_count(), 0);
    // Permanently, even once the successor is gone.
    successor.release_instance_lease()?;
    assert_eq!(
        pair.initiator
            .begin_encapsulation(BeginEncapsulation::new(
                pair.initiator_authorization,
                pair.responder_public_keys.clone(),
            ))
            .err(),
        Some(AgentError::InstanceFenced)
    );
    Ok(())
}

#[test]
fn a_recovery_copy_that_acknowledges_a_live_reacquire_does_not_fence_the_original() -> TestResult {
    // Round-4 finding #3 resurfacing through acknowledgement. The re-acquire
    // after a lapse applied, but its response and both reconciling queries were
    // lost. Before the original learns the outcome, a recovery copy sharing this
    // journal settles it on start-up: it queries the re-acquire, finds the
    // receipt, acknowledges it away, then exits because this instance still
    // holds the lease. The original's exact query now reports the receipt
    // absent -- and reading that as "never executed" kept the pre-acquire fence,
    // whose renew the authority (holding the next generation under this very
    // instance) rejected as a fence mismatch, fencing the original permanently
    // with its own lease live and no successor anywhere. It must instead adopt
    // the lease the snapshot still shows under its own fence.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 130)?;
    let (before, after) = lose_the_reacquire_response(&pair)?;
    assert_eq!(pair.initiator_authority.receipt_count()?, 1);

    // The recovery copy acknowledges the re-acquire's receipt away, then the
    // original's transport recovers.
    let journaled = pair.initiator.journaled_lease_intents_for_test()?;
    pair.initiator_authority
        .acknowledge_journaled_receipts(&journaled)?;
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);
    pair.initiator_authority.refuse_queries(false);

    // The absent receipt is resolved against the snapshot, which still shows the
    // re-acquired lease under this instance's own fence: adopt it, renew under
    // it, and stay usable. One renew, no acquire, no fence.
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(
        pair.initiator_authority
            .active_lease()?
            .map(|lease| lease.fence()),
        Some(after.fence())
    );
    assert_ne!(after.fence().generation(), before.fence().generation());
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    Ok(())
}

#[test]
fn a_recovery_copy_that_acknowledges_a_reacquire_reconciled_inline_does_not_fence_it() -> TestResult
{
    // The same acknowledgement race on the sibling path. Here only the
    // acquire's *response* is lost: the authority keeps answering queries, so
    // `lease_exchange` reconciles inline instead of deferring to
    // `resolve_pending_acquire_state`. A recovery copy sharing this journal
    // lands between the dispatch and that reconciling query and acknowledges
    // the receipt away, so the query answers absent for an acquire that
    // applied. Reading that as "provably never executed" re-dispatched the
    // acquire at the pre-acquire generation, which the authority -- holding the
    // next generation under this very instance -- rejects as held, and
    // `recover_expired_lease` fenced the instance permanently on that
    // rejection, with its own lease live and no successor anywhere. It must
    // instead adopt the lease the snapshot shows under its own fence.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 136)?;
    let before = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("initial lease missing"))?;
    pair.initiator_authority.expire_active_lease();
    pair.initiator_authority.lose_next_acquire_response();
    pair.initiator_authority.acknowledge_before_next_query();

    // One renew (rejected as expired) and one acquire (applied, response lost),
    // and the operation still completes under the adopted fence.
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 2);
    let adopted = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the re-acquired lease is gone"))?;
    assert_eq!(
        adopted.fence().instance_id(),
        before.fence().instance_id(),
        "the live lease is this instance's own re-acquire"
    );
    assert_eq!(
        adopted.fence().generation(),
        before.fence().generation() + 1
    );
    // And permanently usable: the next operation renews under the adopted
    // fence rather than acquiring or fencing.
    let calls = pair.initiator_authority.lease_call_count();
    drive_one_lease_renew(&pair.initiator)?;
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    assert_eq!(
        pair.initiator_authority
            .active_lease()?
            .map(|lease| lease.fence()),
        Some(adopted.fence())
    );
    Ok(())
}

#[test]
fn a_lost_reacquire_fences_when_a_foreign_successor_took_the_next_generation() -> TestResult {
    // The other side of the acknowledgement coin: an absent receipt must not be
    // read as "our own lapse to recover from". The re-acquire never reached the
    // authority, so its receipt is absent; meanwhile a foreign instance acquired
    // the next generation and then lapsed too, leaving the snapshot showing no
    // active lease at that advanced generation. With no live fence to read an
    // instance id from, the advance cannot be attributed to this process -- our
    // own re-acquire and a foreign acquire from the same generation both produce
    // it -- so it must fence, not adopt a generation another instance held.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 131)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    pair.initiator_authority.expire_active_lease();
    pair.initiator_authority
        .lose_next_lease_call_before_apply(LeaseCallFilter::Acquire);
    pair.initiator_authority.refuse_queries(true);
    assert_eq!(
        pair.initiator.reconcile_transition().err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );
    // The re-acquire is journaled but never executed, so the generation is
    // unmoved.
    assert_eq!(
        pair.initiator_authority
            .lock()
            .authority
            .persistent_meta()
            .lease_generation,
        before.lease_generation
    );

    // A foreign instance takes the next generation and lapses.
    pair.initiator_authority
        .foreign_successor_acquires_and_lapses()?;
    assert_eq!(
        pair.initiator_authority
            .lock()
            .authority
            .persistent_meta()
            .lease_generation,
        before.lease_generation + 1
    );
    assert_eq!(pair.initiator_authority.active_lease()?, None);

    // The original's query now answers AbsentAtVersion and the snapshot shows an
    // advanced generation with no live lease: fence, not recover.
    pair.initiator_authority.refuse_queries(false);
    let calls = pair.initiator_authority.lease_call_count();
    assert_eq!(
        pair.initiator
            .begin_encapsulation(BeginEncapsulation::new(
                pair.initiator_authorization,
                pair.responder_public_keys.clone(),
            ))
            .err(),
        Some(AgentError::InstanceFenced)
    );
    // And the resolution is what decided it, not a later rejection: reading the
    // absent receipt as "never executed" instead kept the pre-acquire fence and
    // reached the same error only through a renew dispatched under it. Not one
    // lease call left this instance.
    assert_eq!(pair.initiator_authority.lease_call_count(), calls);
    Ok(())
}

#[test]
fn release_after_a_lost_reacquire_releases_the_new_lease() -> TestResult {
    // (a) The authority answers queries again by the time of the release: the
    // exact receipt adopts the re-acquired fence, and that lease is released,
    // its receipt acknowledged and the journal left empty.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 129)?;
    lose_the_reacquire_response(&pair)?;
    pair.initiator_authority.refuse_queries(false);
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert!(pair
        .initiator
        .journaled_lease_intents_for_test()?
        .is_empty());
    assert_eq!(pair.initiator_authority.receipt_count()?, 0);

    // (b) Queries still refused: the snapshot shows the expected fence, and
    // releasing it hands the lease over at once -- no TTL wait for the next
    // start.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 131)?;
    lose_the_reacquire_response(&pair)?;
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    // The release itself was confirmed `Applied`, yet this clean shutdown
    // leaves the journal non-empty: the adoption proves the fence, not the
    // receipt, so the re-acquire's row -- skipped by `drain_unresolved`,
    // because it is the pending record's -- and the receipt it owes both
    // survive a release that could not ask a question the authority was still
    // refusing. Case (a)'s empty journal above is the contrast; the next start
    // on this store settles both, once a query can be answered.
    assert_eq!(pair.initiator.journaled_lease_intents_for_test()?.len(), 1);
    assert_eq!(pair.initiator_authority.receipt_count()?, 1);
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    successor.release_instance_lease()?;

    // (c) Queries and snapshots both refused: nothing can be resolved, so the
    // release is dispatched with the fence the re-acquire would have produced.
    // Against an authority that cannot even be asked for its version that
    // release does not settle, and the fence is kept; once the authority
    // answers snapshots again the retry releases exactly that lease, with no
    // resolution left to do.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 133)?;
    lose_the_reacquire_response(&pair)?;
    pair.initiator_authority.refuse_snapshots(true);
    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InstanceLeaseUnavailable)
    );
    pair.initiator_authority.refuse_snapshots(false);
    assert!(pair.initiator_authority.active_lease()?.is_some());
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.active_lease()?, None);
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
fn a_release_whose_budget_excludes_the_resolution_releases_the_expected_fence() -> TestResult {
    // The resolution is best-effort against the release's own budget, and a
    // budget with room for the release but not for the resolution on top of
    // it takes the same path as an authority that can answer neither: the
    // pending record is dropped and the fence the re-acquire would have
    // produced is the one released. The docs on `release_lease_state` and
    // `PolicyAgent::release_instance_lease` name both triggers.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 168)?;
    lose_the_reacquire_response(&pair)?;
    // The authority demonstrably *can* answer now: only the budget refuses
    // the resolution, and the unchanged query count below proves it was never
    // dispatched.
    pair.initiator_authority.refuse_queries(false);
    let queries = pair.initiator_authority.query_call_count();

    // The arithmetic, not a timing guess: the release keeps its own dispatch
    // in reserve -- one round-trip bound (30 s), the journal commit it is
    // admitted with (1 s), and the snapshot proof reserved behind them
    // (another 30 s) -- so the resolution is admitted only with more than 91 s
    // left, while the release itself needs more than 61. A 75-second budget
    // therefore refuses the one and admits the other, with about fourteen
    // seconds of slack on each comparison, and both fake ports answer in
    // process without blocking. Never narrow this margin to make the test
    // quicker: nothing here waits for it.
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_secs(30));
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(75))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.release_instance_lease_until(deadline)?,
        LeaseReleaseOutcome::Released
    );
    assert_eq!(
        pair.initiator_authority.query_call_count(),
        queries,
        "the resolution must not have been dispatched"
    );
    // The expected fence was the one released: the authority holds the lease
    // that re-acquire took, and only a release naming its fence retires it.
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    Ok(())
}

#[test]
fn a_forward_authority_clock_step_after_the_coverage_snapshot_retains_no_session() -> TestResult {
    // The post-renew snapshot proves coverage in authority time, and every
    // check after it used to be local: the authority's clock stepping past
    // the expiry during the witness round trip -- invisible to this host's
    // clock -- left a Begin retaining a session under a lease the authority
    // no longer held. Retention re-observes the authority after the durable
    // write, so the step is seen and nothing is retained.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 120)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    let before_lease = before.lease.expect("the initial agent acquired its lease");
    *pair
        .witness
        .advance_authority_on_read
        .lock()
        .map_err(|_| io::Error::other("witness hook poisoned"))? =
        Some(pair.initiator_authority.clone());

    let snapshots_before = pair.initiator_authority.snapshot_call_count();
    let outcome = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    let snapshots_after = pair.initiator_authority.snapshot_call_count();
    assert_eq!(
        outcome.err(),
        Some(AgentError::InstanceLeaseCoverageElapsed)
    );
    // The lease really lapsed by the authority's clock, and both proofs were
    // taken: one after the renew, one after the durable reservation.
    assert!(pair.initiator_authority.active_lease()?.is_none());
    assert_eq!(snapshots_after - snapshots_before, 2);
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert_eq!(pair.initiator.confirmed_key_count(), 0);
    assert!(pair.initiator.public_keys().is_ok());

    // Not a fence: the next operation's renew is rejected as expired and the
    // instance re-acquires at its own generation.
    pair.initiator_authority.advance_clock(1);
    let second = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.second_initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert!(second.is_ok(), "unexpected result: {second:?}");
    assert_eq!(pair.initiator.pending_session_count(), 1);
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
fn a_forward_authority_clock_step_after_the_coverage_snapshot_retains_no_key() -> TestResult {
    // The same step at acceptance: the authority's clock passes the expiry
    // during the witness read that precedes the durable release, and the
    // retention snapshot after that release is what sees it. The key is
    // dropped unretained, the reservation is released rather than orphaned,
    // and the agent is neither fenced nor poisoned.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 134)?;
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

    *pair
        .witness
        .advance_authority_on_read
        .lock()
        .map_err(|_| io::Error::other("witness hook poisoned"))? =
        Some(pair.initiator_authority.clone());
    assert_eq!(
        pair.initiator
            .accept_responder_finished(encapsulated.handle, accepted.responder_finished)
            .err(),
        Some(AgentError::InstanceLeaseCoverageElapsed)
    );
    assert_eq!(pair.initiator.confirmed_key_count(), 0);
    assert_eq!(pair.initiator.pending_session_count(), 0);
    // The reservation was released by the durable release, not orphaned:
    // there is nothing left to cancel.
    assert!(pair
        .initiator
        .desynchronize_session_for_test(encapsulated.handle)
        .is_err());
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_successor_observed_by_the_retention_snapshot_fences_and_releases_the_reservation() -> TestResult
{
    // The post-renew snapshot is clean; the successor acquires -- and lapses
    // -- while the durable reservation is written, so only the retention
    // snapshot sees the generation move past ours. That is a real fence, and
    // the reservation it interrupts is cancelled explicitly: `fence_out`
    // iterates the in-memory map, which this handle never reached.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 130)?;
    let before = pair.initiator_authority.lock().authority.persistent_meta();
    let incumbent = before
        .lease
        .expect("the initial agent acquired its lease")
        .fence()
        .instance_id();
    pair.initiator_authority
        .successor_acquires_before_snapshot_after(1);
    let first = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(first.err(), Some(AgentError::InstanceFenced));
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);

    // Permanent.
    let second = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.second_initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(second.err(), Some(AgentError::InstanceFenced));
    let after = pair.initiator_authority.lock().authority.persistent_meta();
    assert_eq!(after.lease_generation, before.lease_generation + 1);
    assert_ne!(
        after
            .lease
            .expect("the successor's lease record is retained after it lapses")
            .fence()
            .instance_id(),
        incumbent
    );
    Ok(())
}

#[test]
fn an_authority_unreachable_at_the_retention_snapshot_retains_nothing() -> TestResult {
    // The retention proof needs a fresh observation; an authority that cannot
    // give one fails the operation closed. The reservation is released, the
    // consumed offer is spent, and the agent is neither fenced nor poisoned:
    // the next operation, with the authority answering again, serves.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 132)?;
    pair.initiator_authority.lose_snapshot_after(1);
    let first = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(first.err(), Some(AgentError::InstanceLeaseUnavailable));
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert!(pair.initiator.public_keys().is_ok());
    // The lease itself was never in doubt.
    assert!(pair.initiator_authority.active_lease()?.is_some());

    let second = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.second_initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert!(second.is_ok(), "unexpected result: {second:?}");
    assert_eq!(pair.initiator.pending_session_count(), 1);
    Ok(())
}

#[test]
fn a_release_refused_by_its_deadline_keeps_the_lease_and_erases_nothing() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 140)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    let before = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the fixture's holder must start out holding its lease"))?;
    let lease_calls = pair.initiator_authority.lease_call_count();

    // One release dispatch is the least a release needs, and at the real
    // transport's bound it cannot end before a deadline that has already
    // arrived.
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_secs(5));
    assert_eq!(
        pair.initiator.release_instance_lease_until(Instant::now()),
        Err(AgentError::OperationDeadlineExceeded)
    );
    // Refused before anything happened: nothing dispatched, the lease still
    // held under the same fence, the secret still there.
    assert_eq!(pair.initiator_authority.lease_call_count(), lease_calls);
    let after = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the refused release dropped the lease"))?;
    assert_eq!(after.fence(), before.fence());
    assert_eq!(pair.initiator.pending_session_count(), 1);
    // And the lease still serves: the refusal did not start the release.
    drive_one_lease_renew(&pair.initiator)?;

    // With a budget of its own the release goes through.
    pair.initiator.release_instance_lease()?;
    assert!(pair.initiator_authority.active_lease()?.is_none());
    assert_eq!(pair.initiator.pending_session_count(), 0);
    Ok(())
}

#[test]
fn a_release_refused_at_the_pre_erase_gate_keeps_every_secret() -> TestResult {
    // The sibling above is refused by `lock_until`, at the door: its deadline
    // has already arrived, so `release_under_lock` is never entered and the
    // gate that names this behaviour never runs. A deadline still in the
    // future but shorter than the release's own least plan is what reaches
    // it, and it is the only thing standing between a short deadline and an
    // unbounded erase of every live key for nothing.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 181)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);
    let before = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the fixture's holder must start out holding its lease"))?;
    let lease_calls = pair.initiator_authority.lease_call_count();

    // One second of budget against a five-second round trip: the lock is
    // taken, `release_under_lock` is entered, and the release's round trip
    // plus its journal commit do not fit.
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_secs(5));
    assert_eq!(
        pair.initiator
            .release_instance_lease_until(Instant::now() + Duration::from_secs(1)),
        Err(AgentError::OperationDeadlineExceeded)
    );
    // Nothing dispatched, and -- this is what the gate buys -- the pending
    // secret and its durable reservation are both still there.
    assert_eq!(pair.initiator_authority.lease_call_count(), lease_calls);
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);
    let after = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the refused release dropped the lease"))?;
    assert_eq!(after.fence(), before.fence());

    // And with a budget that fits, the same call releases and erases.
    pair.initiator_authority
        .set_round_trip_bound(Duration::ZERO);
    pair.initiator.release_instance_lease()?;
    assert!(pair.initiator_authority.active_lease()?.is_none());
    assert_eq!(pair.initiator.pending_session_count(), 0);
    Ok(())
}

#[test]
fn the_stops_erase_is_not_charged_to_the_release_budget() -> TestResult {
    // The erase before a release is one durable commit per pending session,
    // up to HARD_MAX_SESSIONS of them, and no deadline bounds it: nothing may
    // be skipped, every secret must go. So the budget the stop gives the
    // release is measured from after the erase. Charged to the release
    // instead, a large session table on a slow store would spend it before
    // the release was dispatched and leave the lease to lapse at its TTL.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 168)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    // One session whose cancellation alone outlasts the whole budget. The
    // budget itself has to exceed what the release really needs -- one
    // authority round trip and the DURABLE_COMMIT_RESERVE its journal write
    // is admitted with, 1.02 seconds here -- because the pre-erase gate is
    // what a budget too short to release is refused by.
    pair.initiator
        .delay_each_session_cancel_for_test(Duration::from_millis(1_600))?;
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_millis(20));
    let lease_calls = pair.initiator_authority.lease_call_count();

    let started = Instant::now();
    assert_eq!(
        pair.initiator
            .release_instance_lease_within(Duration::from_millis(1_500))?,
        LeaseReleaseOutcome::Released
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_600),
        "the erase did not run at all: {elapsed:?}"
    );
    // The release was dispatched and settled even so, and the secret is gone.
    assert_eq!(pair.initiator_authority.lease_call_count(), lease_calls + 1);
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert_eq!(pair.initiator.pending_session_count(), 0);
    Ok(())
}

#[test]
fn drains_yield_to_the_operation_budget_and_keep_their_obligations() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 141)?;
    let authority = &pair.initiator_authority;
    // Three renews whose receipts the authority will not let go of: three
    // acknowledgements owed, three journal rows kept.
    authority.refuse_acknowledgements(true);
    for _ in 0..3 {
        drive_one_lease_renew(&pair.initiator)?;
    }
    authority.refuse_acknowledgements(false);
    let owed = pair.initiator.journaled_lease_intents_for_test()?;
    assert!(owed.len() >= 3);
    let receipts = authority.receipt_count()?;
    assert!(receipts >= 3);
    let lease_calls = authority.lease_call_count();

    // Begin's least plan at a one-second authority bound is four seconds --
    // three round trips plus the renew's own journal commit, reserved at
    // DURABLE_COMMIT_RESERVE -- so give it that and a sliver: the plan fits
    // but no acknowledgement, which needs a round trip on top of the whole
    // reserve, fits with it.
    authority.set_round_trip_bound(Duration::from_secs(1));
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(4_200))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    initiator_encapsulation(pair.initiator.begin_encapsulation_until(
        BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ),
        deadline,
    )?)?;
    // The operation ran on its plan alone -- one renew -- and every
    // obligation it had no room for is still owed, not dropped.
    assert_eq!(authority.lease_call_count(), lease_calls + 1);
    assert_eq!(authority.receipt_count()?, receipts + 1);
    let journal = pair.initiator.journaled_lease_intents_for_test()?;
    assert!(
        owed.iter().all(|row| journal.contains(row)),
        "a drain that could not fit dropped a journal row"
    );

    // A budget with room drains them: every receipt acknowledged, every row
    // but the last operation's own forgotten.
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.second_initiator_authorization,
        pair.responder_public_keys,
    ))?)?;
    assert_eq!(authority.receipt_count()?, 0);
    let journal = pair.initiator.journaled_lease_intents_for_test()?;
    assert!(owed.iter().all(|row| !journal.contains(row)));
    assert_eq!(journal.len(), 1);
    Ok(())
}

#[test]
fn a_coverage_lapse_on_a_begin_retry_returns_no_handle_and_erases_nothing() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 147)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);

    // The retry renews, and the authority's clock passes the new expiry
    // before the post-renew proof. The handle refers to a retained secret,
    // so returning it is a lease-guarded disclosure exactly like retaining
    // it was: no handle without proven coverage.
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceLeaseCoverageElapsed)
    );
    // A lapse is no evidence of a successor: nothing erased, nothing
    // released.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);

    // A fence is: the session went with every other secret, and the retry is
    // refused before the index is consulted. This pins the fencing clause of
    // the exact-retry contract on `begin_encapsulation` -- refused with
    // `InstanceFenced` at the lease phase guard, never answered by the
    // tombstone.
    pair.initiator.fence_out_for_test()?;
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys,
        )),
        Err(AgentError::InstanceFenced)
    );
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    Ok(())
}

#[test]
fn a_reacquire_after_a_lapse_ends_the_begin_retry_window() -> TestResult {
    // The other clause of the exact-retry contract that is not the tombstone's
    // doing: a lease lapse recovered by re-acquire. The re-acquire erases
    // every in-process secret -- the acquire clears the authority's key table,
    // so nothing may be carried across it -- and that takes the pending
    // session and the retry index with it. The durable tombstone the Begin
    // wrote is untouched by any of it, so the byte-identical retry is refused
    // as the consumed authorization it is, rather than answered with the
    // handle of a session that no longer exists.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 171)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);

    // The retry's own renew is rejected as expired and recovers by
    // re-acquiring at this instance's own generation: no successor exists, so
    // this is a recovery, not a fence.
    pair.initiator_authority.expire_active_lease();
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys,
        )),
        Err(AgentError::AuthorizationRejected)
    );
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn a_coverage_lapse_after_the_post_renew_proof_returns_no_handle_on_a_retry() -> TestResult {
    // The cut above lands before the post-renew proof, so it never reaches the
    // gate that guards the replay itself. This one lands after it. The renew
    // applies and the proof succeeds -- with almost nothing left: the clock
    // step leaves the snapshot reporting TTL - (TTL - B - 200) = B + 200 ms of
    // life, so `coverage_deadline` records anchor + 200 ms, and the anchor is
    // taken before the snapshot request. That same snapshot then sleeps 600
    // ms, so the proven coverage is already some 400 ms in the past by the
    // time the head read and the two ML-DSA-65 verifications in
    // `build_contract` are done and the replay index is consulted. The bound
    // is one-sided: only 400 ms of backwards clock drift could make this pass
    // for the wrong reason.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 160)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    pair.initiator_authority.advance_clock_before_next_snapshot(
        MEMORY_AUTHORITY_LEASE_TTL_MILLIS - LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS - 200,
    );
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(600));
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys,
        )),
        Err(AgentError::InstanceLeaseCoverageElapsed)
    );
    // The lapse is not evidence of a successor: the session and its durable
    // reservation both survive, and the handle was simply not returned.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);
    Ok(())
}

#[test]
fn a_deadline_reached_after_the_witness_read_returns_no_handle_on_a_retry() -> TestResult {
    // The other half of the same gate: coverage stands, but the operation's
    // own deadline is gone. The witness head read is the last I/O before the
    // replay index, and it is admitted against the deadline before it runs --
    // so a read that ends after the deadline leaves the replay to be refused
    // by the gate and nothing else.
    //
    // Arithmetic: everything before that admission -- the renew, the coverage
    // snapshot and the purge -- has to fit in the two-second deadline, which
    // is several times what it costs even under a contended suite; the read
    // then takes four seconds, so the gate is reached two seconds past the
    // deadline however the prologue was scheduled. The armed-delay assertion
    // is what makes that sound: had the prologue overrun instead, the refusal
    // would have come from the admission before the read and the delay would
    // still be armed.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 161)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    pair.witness.delay_next_read_head(Duration::from_secs(4));
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.begin_encapsulation_until(
            BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
            deadline,
        ),
        Err(AgentError::OperationDeadlineExceeded)
    );
    assert!(
        !pair.witness.read_head_delay_armed(),
        "the read never ran; the refusal came before the gate under test"
    );
    // Nothing erased, nothing released: a lapsed budget is not a fence.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);
    Ok(())
}

#[test]
fn an_authority_clock_step_inside_the_retry_witness_read_returns_no_handle() -> TestResult {
    // The stale post-renew proof cannot see an authority clock step that lands
    // inside the witness read a Begin retry makes: the coverage deadline it
    // recorded is local, and this host's clock does not move while the
    // authority's runs the lease out. So the retry re-proves coverage against a
    // fresh snapshot taken after that read -- exactly as the fresh path does
    // before it retains -- and refuses when the lease has lapsed. Without that
    // fresh proof the budgeted local rule passed and the same handle was
    // returned outside the lease.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 162)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);

    // The retry renews and proves coverage cleanly; then the witness read lets
    // the authority's lease run out. No local time passes, so the deadline the
    // post-renew proof recorded still stands and the budgeted rule alone would
    // disclose. The fresh proof after the read is what sees the lapse.
    pair.witness
        .advance_authority_on_next_read(pair.initiator_authority.clone());
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys,
        )),
        Err(AgentError::InstanceLeaseCoverageElapsed)
    );
    // A lapse is no evidence of a successor: the session and its reservation
    // survive, and the handle was simply not returned.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);
    Ok(())
}

#[test]
fn coverage_deadline_subtracts_the_divergence_budget() {
    let anchor = Instant::now();
    let budget = LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS;
    let floor = 5_000;
    // No more than the budget left proves nothing.
    assert_eq!(coverage_deadline(anchor, floor, floor + budget), None);
    assert_eq!(coverage_deadline(anchor, floor, floor + budget - 1), None);
    assert_eq!(coverage_deadline(anchor, floor, floor), None);
    // One millisecond past the budget is one millisecond of coverage.
    assert_eq!(
        coverage_deadline(anchor, floor, floor + budget + 1),
        Some(anchor + Duration::from_millis(1))
    );
    // Already lapsed by the authority's clock.
    assert_eq!(coverage_deadline(anchor, floor + 1, floor), None);
    // The budget comes off the remaining life, not the anchor.
    let expiry = 20_000;
    assert_eq!(
        coverage_deadline(anchor, expiry - budget - 500, expiry),
        Some(anchor + Duration::from_millis(500))
    );
}

#[test]
fn a_start_journal_pass_that_cannot_fit_the_budget_leaves_its_rows_for_later() -> TestResult {
    // The start's journal pass runs inside the acquire's own 60-second
    // budget. Each row is a query plus an acknowledgement -- two round trips
    // -- and the acquire needs three of its own kept in reserve: the
    // pre-acquire snapshot, the acquire dispatch, and the snapshot after a
    // rejected or resynchronised attempt. At a 25-second bound that is
    // 2 * 25 + 3 * 25 = 125 seconds against 60, so no row fits and none is
    // asked about; the acquire still happens, and the rows wait for a later
    // guarded operation exactly as unanswered ones do.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 169)?;
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
    let mut journaled = Vec::new();
    for byte in 1..=4u8 {
        let operation_id = OperationIdV2::new(1, [byte; 32])?;
        repository.journal_lease_intent(operation_id, &[])?;
        journaled.push(operation_id);
    }

    initiator_authority.set_round_trip_bound(Duration::from_secs(25));
    let queries_before = initiator_authority.query_call_count();
    let restarted = PolicyAgent::new(
        repository,
        witness.clone(),
        initiator_authority.clone(),
        initiator_config.clone(),
    )?;
    assert_eq!(
        initiator_authority.query_call_count(),
        queries_before,
        "a row that cannot fit the budget must not be asked about"
    );
    let after = restarted.journaled_lease_intents_for_test()?;
    for operation_id in &journaled {
        assert!(
            after.contains(operation_id),
            "a row refused admission must stay journaled for the next attempt"
        );
    }

    // And the admission is not a refusal of everything unconditionally: with
    // a bound that leaves room, the same rows are settled and forgotten.
    restarted.release_instance_lease()?;
    drop(restarted);
    initiator_authority.set_round_trip_bound(Duration::ZERO);
    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    assert_eq!(repository.journaled_lease_intents()?.len(), journaled.len());
    let restarted = PolicyAgent::new(
        repository,
        witness,
        initiator_authority.clone(),
        initiator_config,
    )?;
    let after = restarted.journaled_lease_intents_for_test()?;
    assert_eq!(
        after.len(),
        1,
        "with room in the budget every row is settled and forgotten"
    );
    for operation_id in &journaled {
        assert!(!after.contains(operation_id));
    }
    Ok(())
}

#[test]
fn a_renew_refused_on_its_version_precondition_every_attempt_is_unavailable() -> TestResult {
    // `AuthorityVersionMismatch` is a proven non-execution: the authority
    // refused the mutation on its precondition and settled its journal row.
    // A resync loop exhausted by nothing but those has learned that the renew
    // never ran, which is not an unknown outcome -- reporting it as one would
    // send an operator looking for a mutation that never happened.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 170)?;
    let before = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the fixture's holder must hold its lease"))?;
    pair.initiator_authority
        .refuse_lease_calls_with(AuthorityKnownFailureV2::AuthorityVersionMismatch, 2);

    // The cheapest lease-guarded operation: it renews before it looks for a
    // pending transition, so the renew's own error is what comes back.
    assert_eq!(
        pair.initiator.reconcile_transition(),
        Err(AgentError::InstanceLeaseUnavailable)
    );
    // Nothing executed: the same lease, at the same generation.
    let after = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the refused renews dropped the lease"))?;
    assert_eq!(after.fence(), before.fence());
    // And the lease still serves: the next renew goes through.
    drive_one_lease_renew(&pair.initiator)?;
    Ok(())
}

#[test]
fn a_release_refused_on_its_version_precondition_every_attempt_is_unavailable() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 171)?;
    let before = pair.initiator_authority.active_lease()?;
    assert!(before.is_some());
    pair.initiator_authority
        .refuse_lease_calls_with(AuthorityKnownFailureV2::AuthorityVersionMismatch, 2);

    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InstanceLeaseUnavailable)
    );
    // Provably never executed, so the lease is still this instance's to
    // release and the call may simply be repeated.
    assert_eq!(pair.initiator_authority.active_lease()?, before);
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    Ok(())
}

#[test]
fn a_release_whose_every_dispatch_stays_unknown_is_indeterminate() -> TestResult {
    // The other route out of the same loop: each release was dispatched, its
    // response lost, and the queries that would have resolved it refused, so
    // its journal id is genuinely unresolved and the snapshot that follows
    // reports the lease still held. That is the strict unknown case and must
    // stay `InstanceLeaseIndeterminate`.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 172)?;
    let before = pair.initiator_authority.active_lease()?;
    assert!(before.is_some());
    pair.initiator_authority
        .lose_lease_calls_before_apply(LeaseCallFilter::Release, 2);
    pair.initiator_authority.refuse_queries(true);

    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InstanceLeaseIndeterminate)
    );
    assert_eq!(pair.initiator_authority.active_lease()?, before);
    // Once the authority answers again the retry releases that same lease.
    pair.initiator_authority.refuse_queries(false);
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    Ok(())
}

#[test]
fn a_constructor_acquire_whose_outcome_is_lost_releases_the_lease() -> TestResult {
    // The acquire applies but its response and every query after it are lost,
    // so the constructor cannot learn whether it holds a lease. Without the
    // release in the indeterminate arm the authority keeps one under a fresh
    // instance id no process will ever release, and every restart is fenced
    // until the TTL.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 162)?;
    pair.initiator.release_instance_lease()?;
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator_authority.lose_next_acquire_and_queries();
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let failed = PolicyAgent::new(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    );
    assert_eq!(failed.err(), Some(AgentError::InstanceLeaseIndeterminate));
    // With the queries answering again, the lease the lost acquire took is
    // gone: the expected fence was released before the error returned.
    pair.initiator_authority.refuse_queries(false);
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    // Three calls: the acquire, a release still carrying the authority version
    // from before the lost acquire -- answered AuthorityVersionMismatch -- and
    // the resync retry that applies. Do not simplify this to two.
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 3);

    // The successor starts at once, with no wait allowed at all.
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let second = PolicyAgent::new_with_lease_wait(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
        Duration::ZERO,
    )?;
    second.release_instance_lease()?;
    Ok(())
}

#[test]
fn a_constructor_release_that_cannot_settle_leaves_the_lease_to_lapse() -> TestResult {
    // The compensating release in the indeterminate arm is best-effort, and
    // the `InstanceLeaseIndeterminate` doc says so rather than promising the
    // fence was released. Here the acquire applies with its response lost and
    // every query refused, the release is lost on the wire too, and the
    // snapshot that would have stood in for it is unanswered: nothing
    // settles, so the lease the acquire took stays at the authority until its
    // TTL and the next start is fenced, exactly as after a crash.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 169)?;
    pair.initiator.release_instance_lease()?;
    let before = pair
        .initiator_authority
        .lock()
        .authority
        .persistent_meta()
        .lease_generation;
    pair.initiator_authority.lose_next_acquire_and_queries();
    pair.initiator_authority
        .lose_next_lease_call_before_apply(LeaseCallFilter::Release);
    // One snapshot passes -- the pre-acquire one, without which nothing is
    // dispatched -- and the next, the one the lost release asks for, does not.
    pair.initiator_authority.lose_snapshot_after(1);
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    assert_eq!(
        PolicyAgent::new(
            repository,
            pair.witness.clone(),
            pair.initiator_authority.clone(),
            pair.initiator_config.clone(),
        )
        .err(),
        Some(AgentError::InstanceLeaseIndeterminate)
    );

    // The release really was dispatched, and left unsettled: the store holds
    // its journal row beside the acquire's.
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    assert_eq!(repository.journaled_lease_intents()?.len(), 2);
    drop(repository);

    // The fence was not released: the authority still holds the lease the
    // lost acquire took, one generation past the pre-acquire one.
    let held = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the lost acquire's lease is gone"))?;
    assert_eq!(held.fence().generation(), before + 1);

    // So a restart before the TTL is refused, and only the lapse frees it.
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    assert_eq!(
        PolicyAgent::new(
            repository,
            pair.witness.clone(),
            pair.initiator_authority.clone(),
            pair.initiator_config.clone(),
        )
        .err(),
        Some(AgentError::InstanceFenced)
    );
    pair.initiator_authority
        .advance_clock(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
    let repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let restarted = PolicyAgent::new_with_lease_wait(
        repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
        Duration::ZERO,
    )?;
    restarted.release_instance_lease()?;
    Ok(())
}

#[test]
fn a_release_with_no_receipt_and_no_proof_is_indeterminate_and_keeps_the_fence() -> TestResult {
    // The release applies at the authority, its response is lost, the
    // reconciling queries are refused, and the snapshot that stands in for
    // the missing receipt is unanswered too: nothing is proved, so the call
    // must not report success and must not drop the fence -- an `Ok` here
    // exits stop(8) 0 while the authority may still hold the lease.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 163)?;
    let calls = pair.initiator_authority.lease_call_count();
    pair.initiator_authority.make_next_unknown();
    pair.initiator_authority.refuse_queries(true);
    pair.initiator_authority.refuse_snapshots(true);
    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InstanceLeaseIndeterminate)
    );
    assert_eq!(pair.initiator_authority.lease_call_count(), calls + 1);
    // The fence is kept: the phase stayed `Releasing`.
    assert_eq!(
        pair.initiator
            .begin_encapsulation(BeginEncapsulation::new(
                pair.initiator_authorization.clone(),
                pair.responder_public_keys.clone(),
            ))
            .err(),
        Some(AgentError::InstanceFenced)
    );
    // The release's row is still journaled, unresolved.
    assert_eq!(pair.initiator.journaled_lease_intents_for_test()?.len(), 1);
    // Once snapshots are answered again, a later call settles it. That retry
    // re-dispatches, so it costs further lease calls; what matters is that
    // this call, and not the indeterminate one, is the one that reports Ok.
    pair.initiator_authority.refuse_snapshots(false);
    pair.initiator.release_instance_lease()?;
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    Ok(())
}

#[test]
fn a_lapsed_own_reacquire_is_indeterminate_not_a_permanent_fence() -> TestResult {
    // The re-acquire applied at G+1 under this instance's own id, its response
    // and every query were lost, and then that lease itself lapsed. The
    // snapshot now shows no active lease at exactly the expected generation --
    // indistinguishable from an acquire still in flight -- so it decides
    // nothing: the record is kept and the caller is told indeterminate.
    // Fencing here would retire the instance permanently with no successor
    // anywhere.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 164)?;
    let (before, after) = lose_the_reacquire_response(&pair)?;
    pair.initiator_authority.expire_active_lease();
    assert_eq!(pair.initiator_authority.active_lease()?, None);
    assert_eq!(
        pair.initiator_authority
            .lock()
            .authority
            .persistent_meta()
            .lease_generation,
        after.fence().generation()
    );
    let calls = pair.initiator_authority.lease_call_count();
    for _ in 0..2 {
        assert_eq!(
            pair.initiator
                .begin_encapsulation(BeginEncapsulation::new(
                    pair.initiator_authorization.clone(),
                    pair.responder_public_keys.clone(),
                ))
                .err(),
            Some(AgentError::InstanceLeaseIndeterminate)
        );
        assert_eq!(pair.initiator_authority.lease_call_count(), calls);
    }
    // Queries answered: the exact receipt adopts (G+1, I), the renew under it
    // is rejected as expired, and a fresh acquire yields G+2 under the same
    // instance id -- recovery, not a fence.
    pair.initiator_authority.refuse_queries(false);
    pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ))?;
    let active = pair
        .initiator_authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("no lease after recovery"))?;
    assert_eq!(active.fence().instance_id(), before.fence().instance_id());
    assert_eq!(active.fence().generation(), before.fence().generation() + 2);
    assert_eq!(pair.initiator.pending_session_count(), 1);
    Ok(())
}

#[test]
fn a_drain_refused_by_the_budget_keeps_every_unresolved_row() -> TestResult {
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
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 4);

    // The authority answers again, so only the budget can stop the drain.
    // Reconcile's least plan at a one-second authority bound -- its witness
    // bound is zero -- is two authority round trips plus the renew's own
    // journal commit (`DURABLE_COMMIT_RESERVE`): three seconds. The drain
    // admits a round trip *on top of* that reserve, four seconds, so a
    // 3.5-second deadline lets the operation in and refuses every row, with
    // half a second of slack for the setup between `now()` and the plan's own
    // admission.
    initiator_authority.refuse_queries(false);
    initiator_authority.set_round_trip_bound(Duration::from_secs(1));
    let queries = initiator_authority.query_call_count();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(3_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert!(restarted.reconcile_transition_until(deadline).is_err());
    // Refused before it asked anything, and nothing forgotten.
    assert_eq!(initiator_authority.query_call_count(), queries);
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 4);
    // Still owed, not dropped: the next default-budget operation asks about
    // all three and its journal write forgets them. The query count is what
    // fails if a regression settles or forgets a row before the admit; the
    // journal length is what fails if one is taken off `unresolved` without
    // being settled, and neither alone tells those apart.
    initiator_authority.set_round_trip_bound(Duration::ZERO);
    drive_one_lease_renew(&restarted)?;
    assert_eq!(initiator_authority.query_call_count(), queries + 3);
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn a_pending_reacquire_refused_by_the_budget_is_kept_and_dispatches_nothing() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 166)?;
    let (_before, _after) = lose_the_reacquire_response(&pair)?;
    // The plan's reserve at a one-second authority bound is two round trips
    // plus the renew's own journal commit -- three seconds -- and the
    // resolution admits one more round trip on top of it, four. A 3.5-second
    // deadline therefore admits the operation and refuses the resolution,
    // with half a second of slack on each comparison for the setup between
    // `now()` and the plan's own admission (a path of a few microseconds).
    pair.initiator_authority
        .set_round_trip_bound(Duration::from_secs(1));
    let queries = pair.initiator_authority.query_call_count();
    let calls = pair.initiator_authority.lease_call_count();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(3_500))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        pair.initiator.reconcile_transition_until(deadline),
        Err(AgentError::OperationDeadlineExceeded)
    );
    assert_eq!(pair.initiator_authority.query_call_count(), queries);
    assert_eq!(pair.initiator_authority.lease_call_count(), calls);
    // The record survives: under the default budget the same lost re-acquire
    // is adopted rather than lost.
    pair.initiator_authority
        .set_round_trip_bound(Duration::ZERO);
    pair.initiator_authority.refuse_queries(false);
    drive_one_lease_renew(&pair.initiator)?;
    Ok(())
}

#[test]
fn a_release_declined_on_a_clearable_condition_keeps_the_lease() -> TestResult {
    // A deployment config that advanced under a running process: every lease
    // intent this agent builds now names a revision the authority does not
    // hold, and the authority declines it with `ConfigurationMismatch` before
    // it ever looks at the lease. That is a condition that can clear, so the
    // lease is still this instance's to release: the call must report the
    // refusal and keep the fence, never retire on it.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 167)?;
    let authority = &pair.initiator_authority;
    let held = authority
        .active_lease()?
        .ok_or_else(|| io::Error::other("the fixture must start out holding its lease"))?;
    authority.drift_wire_config(true)?;
    let calls = authority.lease_call_count();

    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::InstanceLeaseUnavailable)
    );
    // The declined arm returns without re-looping: one dispatch, no resync.
    assert_eq!(authority.lease_call_count(), calls + 1);
    // And the authority still holds this instance's lease, under the same
    // fence it held before.
    assert_eq!(
        authority.active_lease()?.map(|lease| lease.fence()),
        Some(held.fence())
    );

    // Config back in step: the release goes through and dispatches to do it.
    // Under a mutation that retired the lease on the decline this second call
    // short-circuits on the retired phase, dispatches nothing, and leaves the
    // authority holding the lease -- which both of the next two assertions
    // catch.
    authority.drift_wire_config(false)?;
    let calls = authority.lease_call_count();
    pair.initiator.release_instance_lease()?;
    // Exactly one dispatch: the declined receipt already resynced the
    // authority version, so this release needs no retry of its own.
    assert_eq!(authority.lease_call_count(), calls + 1);
    assert_eq!(authority.active_lease()?, None);
    Ok(())
}
