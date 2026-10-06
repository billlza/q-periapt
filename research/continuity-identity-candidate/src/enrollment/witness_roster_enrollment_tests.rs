// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment terminal/ACK/cleanup on the actual R target.
use super::*;
use crate::{
    WitnessedRosterRefreshDisposition as RDisposition, WitnessedRosterRefreshProgress as RProgress,
};
fn prepare_original(c: &Case) -> RProposal {
    let mut owner = open(&c.f.c);
    let client = policy_client(&c.f, &mut owner);
    let p = owner
        .prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("R operation"),
            c.f.c.policy.historical(),
            &c.policy,
            &c.target,
            150,
            client,
        )
        .expect("original enrollment preparation");
    assert_eq!(
        owner.witnessed_roster_refresh_progress().expect("progress"),
        Some(RProgress::Reserved(p))
    );
    owner.close();
    p
}
fn run(
    c: &Case,
    p: RProposal,
    owner: &mut DeviceEnrollment,
    client: &mut AnchorClient,
    closed: bool,
) -> Result<RState, DurableError> {
    if closed {
        owner.close_witnessed_roster_refresh(&p, c.f.c.policy.historical(), client)
    } else {
        owner.commit_witnessed_roster_refresh(&p, c.f.c.policy.historical(), &c.policy, 150, client)
    }
}
fn check_terminal(c: &Case, p: RProposal, closed: bool, retired: bool) {
    let mut owner = open(&c.f.c);
    assert_eq!(
        owner.witnessed_roster_refresh_progress().expect("terminal"),
        Some(RProgress::Terminal {
            proposal: p,
            disposition: if closed {
                RDisposition::Closed
            } else {
                RDisposition::Applied
            },
            retired
        })
    );
    let image = owner.image().expect("original image");
    let (admission, stage) = match image.phase {
        Phase::Accepted {
            admission, stage, ..
        } => Ok((admission, stage)),
        _ => Err("original active configuration"),
    }
    .expect("original active configuration");
    assert!(matches!(stage, AdmissionPhase::Active));
    assert_eq!(
        admission.checkpoint,
        if closed {
            p.scope().previous
        } else {
            p.scope().target
        }
    );
}
#[test]
fn original_roster_terminal_precedes_ack_and_releases_only_the_current_original_owner() {
    for adopted in [false, true] {
        for closed in [false, true] {
            let c = case(adopted);
            let signer = fs::read(&c.f.c.paths.signer).expect("signer");
            let key = fs::read(&c.f.c.paths.wrapping).expect("wrapping");
            let p = prepare_original(&c);
            let saved = journal(&c.f);
            let mut owner = open(&c.f.c);
            let client = policy_client(&c.f, &mut owner);
            assert_eq!(
                owner
                    .prepare_witnessed_roster_refresh(
                        p.scope().operation,
                        c.f.c.policy.historical(),
                        &c.policy,
                        &c.target,
                        150,
                        client
                    )
                    .expect("same exact prep"),
                p
            );
            owner.close();
            assert_eq!(journal(&c.f), saved, "no reseal");
            witness_prepare(&c, p);
            let calls = c.f.carrier.requests.lock().expect("calls").len();
            let mut owner = open(&c.f.c);
            let mut client = policy_client(&c.f, &mut owner);
            assert_eq!(
                run(&c, p, &mut owner, &mut client, closed).expect("original terminal flow"),
                if closed {
                    RState::Closed
                } else {
                    RState::Applied
                }
            );
            owner.close();
            assert_eq!(
                c.f.carrier.requests.lock().expect("calls").get(calls..),
                Some([if closed { 18 } else { 16 }, 17, 19].as_slice())
            );
            check_terminal(&c, p, closed, true);
            let expected = if closed {
                saved.0
            } else {
                target_image(&saved)
            };
            assert_eq!(journal(&c.f), (expected.clone(), None));
            let mut active = active(&c);
            assert!(
                DeviceEnrollment::open(c.f.c.paths.clone(), c.f.c.intent.clone()).is_err(),
                "same enrollment lease"
            );
            let (service, signing, device) = active.parts().expect("owner release");
            signing.check_device(device).expect("same signer");
            assert_eq!(device.credential_digest(), c.f.original.credential_digest());
            assert_eq!(
                device.roster().checkpoint(),
                if closed {
                    p.scope().previous
                } else {
                    p.scope().target
                }
            );
            assert_eq!(
                service
                    .stores()
                    .expect("stores")
                    .0
                    .identity()
                    .expect("journal"),
                c.f.id
            );
            active.close();
            assert_eq!(
                journal(&c.f),
                (expected, None),
                "owner release does not rewrite original target"
            );
            assert_eq!(fs::read(&c.f.c.paths.signer).expect("signer"), signer);
            assert_eq!(fs::read(&c.f.c.paths.wrapping).expect("key"), key);
        }
    }
}
#[test]
fn lost_commit_close_and_ack_replies_recover_only_original_roster_after_expiry() {
    for closed in [false, true] {
        for command in [if closed { 18 } else { 16 }, 19] {
            for after in [false, true] {
                let c = case(true);
                let p = prepare_original(&c);
                let saved = journal(&c.f);
                witness_prepare(&c, p);
                *c.f.carrier.cut.lock().expect("cut") = Some((command, after));
                let mut owner = open(&c.f.c);
                let mut client = policy_client(&c.f, &mut owner);
                assert!(run(&c, p, &mut owner, &mut client, closed).is_err());
                assert!(owner.active.is_none());
                assert!(journal(&c.f).1.is_some(), "lost ACK cannot delete pending");
                if command == 19 {
                    check_terminal(&c, p, closed, false);
                    assert!(
                        activate(&c.f, &c.policy, 150).is_err(),
                        "unretired R denies original owner release"
                    );
                }
                c.f.carrier.clock.store(401, Ordering::SeqCst);
                c.policy.close();
                c.f.c.policy.close();
                let mut owner = open(&c.f.c);
                let mut client = policy_client(&c.f, &mut owner);
                let observed = owner
                    .reconcile_witnessed_roster_refresh(&p, c.f.c.policy.historical(), &mut client)
                    .expect("original status/cleanup");
                if command != 19 && !after {
                    assert_eq!(observed, RState::Prepared);
                    assert_eq!(
                        owner
                            .close_witnessed_roster_refresh(
                                &p,
                                c.f.c.policy.historical(),
                                &mut client
                            )
                            .expect("historical close"),
                        RState::Closed
                    );
                } else {
                    assert_eq!(
                        observed,
                        if closed {
                            RState::Closed
                        } else {
                            RState::Applied
                        }
                    );
                }
                owner.close();
                let finally_closed = closed || (command != 19 && !after);
                check_terminal(&c, p, finally_closed, true);
                assert_eq!(
                    journal(&c.f),
                    (
                        if finally_closed {
                            saved.0
                        } else {
                            target_image(&saved)
                        },
                        None
                    )
                );
            }
        }
    }
}
#[test]
fn unavailable_roster_history_never_becomes_an_enrollment_terminal() {
    let c = case(true);
    let p = prepare_original(&c);
    let before = journal(&c.f);
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    assert_eq!(
        owner
            .reconcile_witnessed_roster_refresh(&p, c.f.c.policy.historical(), &mut client)
            .expect("fresh unavailable"),
        RState::Unavailable
    );
    assert_eq!(
        owner
            .witnessed_roster_refresh_progress()
            .expect("unchanged reserved"),
        Some(RProgress::Reserved(p))
    );
    owner.close();
    assert_eq!(journal(&c.f), before);
    assert!(activate(&c.f, &c.policy, 150).is_err());
    let mut owner = open(&c.f.c);
    let client = policy_client(&c.f, &mut owner);
    assert!(owner
        .witnessed_policy_renewal_request(
            PolicyRenewalId::generate().expect("P ID"),
            c.f.c.policy.historical(),
            client
        )
        .is_err());
    witness_prepare(&c, p);
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    assert_eq!(
        run(&c, p, &mut owner, &mut client, false).expect("same reserved target"),
        RState::Applied
    );
}
#[test]
fn substituted_full_roster_proposal_is_refused_before_dispatch_in_every_phase() {
    for phase in 0..3 {
        let c = case(true);
        let p = prepare_original(&c);
        witness_prepare(&c, p);
        if phase > 0 {
            if phase == 1 {
                *c.f.carrier.cut.lock().expect("cut") = Some((19, false));
            }
            let mut owner = open(&c.f.c);
            let mut client = policy_client(&c.f, &mut owner);
            let result = run(&c, p, &mut owner, &mut client, false);
            if phase == 1 {
                assert!(result.is_err());
            } else {
                assert_eq!(result.expect("retired"), RState::Applied);
            }
        }
        let before = journal(&c.f);
        let mut bytes = p.to_bytes();
        *bytes.last_mut().expect("target digest") ^= 1;
        let changed = RProposal::from_trusted_state(&bytes).expect("different valid descriptor");
        let count = c.f.carrier.requests.lock().expect("calls").len();
        let mut owner = open(&c.f.c);
        let mut client = policy_client(&c.f, &mut owner);
        assert!(matches!(
            owner.reconcile_witnessed_roster_refresh(
                &changed,
                c.f.c.policy.historical(),
                &mut client
            ),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.f.carrier.requests.lock().expect("calls").len(), count);
        assert_eq!(journal(&c.f), before);
    }
}
#[test]
fn independent_policy_after_completed_roster_uses_the_actual_new_predecessor() {
    let c = case(true);
    let p = prepare_original(&c);
    witness_prepare(&c, p);
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    assert_eq!(
        run(&c, p, &mut owner, &mut client, false).expect("R applied"),
        RState::Applied
    );
    owner.close();
    let a = approved_at(&c.f, &c.policy, 3, 350, 150);
    assert_eq!(a.request.scope().current_roster, p.scope().target);
    let next = prepared_at(&c.f, &a, &c.policy, 150);
    applied_at(&c.f, &a, next, 150);
    let mut active = activate(&c.f, &a.target, 150).expect("P after actual R");
    assert_eq!(
        active.parts().expect("owners").2.roster().checkpoint(),
        p.scope().target
    );
    active.close();
    check_terminal(&c, p, false, true);
}

fn terminal_before_roster_ack(c: &Case, p: RProposal, closed: bool) -> DeviceEnrollment {
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    *c.f.carrier.cut.lock().expect("ACK cut") = Some((19, false));
    assert!(run(c, p, &mut owner, &mut client, closed).is_err());
    assert!(owner.active.is_none());
    check_terminal(c, p, closed, false);
    open(&c.f.c)
}
#[test]
fn original_roster_enrollment_sync_errors_never_ack_without_durable_terminal() {
    let mut faults = 0;
    for closed in [false, true] {
        let c = case(true);
        let p = prepare_original(&c);
        witness_prepare(&c, p);
        let (mut owner, _, count) = faulty(&c.f.c, false);
        let mut client = policy_client(&c.f, &mut owner);
        let terminal_count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&terminal_count);
        let counter = Arc::clone(&count);
        *c.f.carrier.after_reply.lock().expect("hook") = Some((
            19,
            Box::new(move || {
                seen.store(counter.load(Ordering::SeqCst), Ordering::SeqCst);
            }),
        ));
        let state = if closed {
            RState::Closed
        } else {
            RState::Applied
        };
        assert_eq!(
            run(&c, p, &mut owner, &mut client, closed).expect("calibration"),
            state
        );
        let barriers = count.load(Ordering::SeqCst);
        let before_ack = terminal_count.load(Ordering::SeqCst);
        assert!(before_ack > 0 && barriers > before_ack && barriers <= 16);
        owner.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                let c = case(true);
                let p = prepare_original(&c);
                let saved = journal(&c.f);
                witness_prepare(&c, p);
                let (mut owner, remaining, _) = faulty(&c.f.c, after);
                let mut client = policy_client(&c.f, &mut owner);
                let calls = c.f.carrier.requests.lock().expect("calls").len();
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(run(&c, p, &mut owner, &mut client, closed), after);
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                assert!(owner.active.is_none());
                let ack =
                    c.f.carrier
                        .requests
                        .lock()
                        .expect("calls")
                        .get(calls..)
                        .expect("new calls")
                        .contains(&19);
                if cut <= before_ack {
                    assert!(!ack, "ACK escaped an unacknowledged terminal save");
                }
                let mut owner = open(&c.f.c);
                let progress = owner.witnessed_roster_refresh_progress().expect("readback");
                if ack {
                    assert!(
                        matches!(progress, Some(RProgress::Terminal { .. })),
                        "ACK without original terminal"
                    );
                }
                owner.close();
                c.f.carrier.clock.store(401, Ordering::SeqCst);
                c.policy.close();
                c.f.c.policy.close();
                let mut owner = open(&c.f.c);
                let mut client = policy_client(&c.f, &mut owner);
                assert_eq!(
                    owner
                        .reconcile_witnessed_roster_refresh(
                            &p,
                            c.f.c.policy.historical(),
                            &mut client
                        )
                        .expect("historical retry"),
                    state
                );
                owner.close();
                check_terminal(&c, p, closed, true);
                assert_eq!(
                    journal(&c.f),
                    (
                        if closed {
                            saved.0
                        } else {
                            target_image(&saved)
                        },
                        None
                    )
                );
                faults += 1;
            }
        }
    }
    eprintln!("ROSTER_ENROLLMENT_SYNC terminal_retired_faults={faults} no_ack_before_terminal=true exact_original_target=true");
}
#[test]
fn original_roster_cleanup_sync_errors_retry_with_the_same_persisted_terminal() {
    let mut faults = 0;
    for closed in [false, true] {
        let c = case(true);
        let p = prepare_original(&c);
        let _saved = journal(&c.f);
        witness_prepare(&c, p);
        let mut owner = terminal_before_roster_ack(&c, p, closed);
        let terminal = owner
            .persisted_roster_terminal(c.f.c.policy.historical())
            .expect("original terminal capability");
        let mut client = policy_client(&c.f, &mut owner);
        let lease = owner
            .witness_lease(&c.f.original, c.f.c.policy.historical(), c.f.id)
            .expect("lease");
        let (db, _, count, _) = fault_database_path(c.f.c.paths.installation.files()[1], false);
        let key = JournalKey::open(&c.f.c.paths.wrapping).expect("key");
        DeviceJournal::retire_roster_refresh_in_database(
            &db,
            &key,
            &c.f.original,
            c.f.c.policy.historical(),
            c.f.id,
            &terminal,
            &mut client,
        )
        .expect("calibration");
        let barriers = count.load(Ordering::SeqCst);
        assert!((1..=8).contains(&barriers));
        drop(db);
        drop(lease);
        owner.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                let c = case(true);
                let p = prepare_original(&c);
                let saved = journal(&c.f);
                witness_prepare(&c, p);
                let mut owner = terminal_before_roster_ack(&c, p, closed);
                let terminal = owner
                    .persisted_roster_terminal(c.f.c.policy.historical())
                    .expect("original readback");
                let mut client = policy_client(&c.f, &mut owner);
                let lease = owner
                    .witness_lease(&c.f.original, c.f.c.policy.historical(), c.f.id)
                    .expect("lease");
                let (db, remaining, _, _) =
                    fault_database_path(c.f.c.paths.installation.files()[1], after);
                let key = JournalKey::open(&c.f.c.paths.wrapping).expect("key");
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    DeviceJournal::retire_roster_refresh_in_database(
                        &db,
                        &key,
                        &c.f.original,
                        c.f.c.policy.historical(),
                        c.f.id,
                        &terminal,
                        &mut client,
                    ),
                    after,
                );
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                drop(db);
                drop(lease);
                owner.close();
                let expected = if closed {
                    saved.0.clone()
                } else {
                    target_image(&saved)
                };
                let actual = journal(&c.f);
                assert_eq!(actual.0, expected);
                assert!(actual.1.is_none() || actual.1 == saved.1);
                c.f.carrier.clock.store(401, Ordering::SeqCst);
                c.policy.close();
                c.f.c.policy.close();
                let mut owner = open(&c.f.c);
                let mut client = policy_client(&c.f, &mut owner);
                assert_eq!(
                    owner
                        .reconcile_witnessed_roster_refresh(
                            &p,
                            c.f.c.policy.historical(),
                            &mut client
                        )
                        .expect("exact recovery"),
                    if closed {
                        RState::Closed
                    } else {
                        RState::Applied
                    }
                );
                owner.close();
                assert_eq!(journal(&c.f), (expected, None));
                check_terminal(&c, p, closed, true);
                faults += 1;
            }
        }
    }
    eprintln!("ROSTER_CLEANUP_SYNC faults={faults} exact_terminal=true original_pending=true historical_retry=true");
}

#[test]
fn staged_but_unprepared_roster_can_be_abandoned_without_inventing_a_witness_result() {
    let c = case(true);
    let before = journal(&c.f);
    let operation = RosterRefreshId::generate().expect("original ID");
    let (mut owner, remaining, _) = faulty(&c.f.c, true);
    let client = policy_client(&c.f, &mut owner);
    remaining.store(2, Ordering::SeqCst);
    assert_sync_failure(
        owner.prepare_witnessed_roster_refresh(
            operation,
            c.f.c.policy.historical(),
            &c.policy,
            &c.target,
            150,
            client,
        ),
        true,
    );
    assert_eq!(remaining.load(Ordering::SeqCst), 0);
    assert!(owner.active.is_none());
    let mut owner = open(&c.f.c);
    let scope = match owner
        .witnessed_roster_refresh_progress()
        .expect("durable stage")
    {
        Some(RProgress::Staged(scope)) => Ok(scope),
        _ => Err("staged before journal preparation"),
    }
    .expect("staged before journal preparation");
    assert_eq!(scope.operation, operation);
    assert_eq!(
        owner
            .recover_witnessed_roster_refresh_preparation(c.f.c.policy.historical())
            .expect("inspect original"),
        None
    );
    assert_eq!(journal(&c.f), before);
    c.f.carrier.clock.store(401, Ordering::SeqCst);
    c.policy.close();
    c.f.c.policy.close();
    let calls = c.f.carrier.requests.lock().expect("calls").len();
    assert_eq!(
        owner
            .abandon_unprepared_roster_refresh(operation, c.f.c.policy.historical())
            .expect("unprepared only"),
        RProgress::AbandonedBeforePreparation(scope)
    );
    owner.close();
    assert_eq!(c.f.carrier.requests.lock().expect("calls").len(), calls);
    assert_eq!(journal(&c.f), before);
    let mut owner = open(&c.f.c);
    assert_eq!(
        owner
            .abandon_unprepared_roster_refresh(operation, c.f.c.policy.historical())
            .expect("same historical abandonment"),
        RProgress::AbandonedBeforePreparation(scope)
    );
    owner.close();
    let c = case(true);
    let p = prepare_original(&c);
    let before = journal(&c.f);
    let mut owner = open(&c.f.c);
    assert!(owner
        .abandon_unprepared_roster_refresh(p.scope().operation, c.f.c.policy.historical())
        .is_err());
    assert_eq!(
        journal(&c.f),
        before,
        "reserved target cannot be abandoned locally"
    );
}

#[path = "witness_roster_enrollment_process_tests.rs"]
mod process;

fn new_target(c: &Case, version: u64, from: u64, until: u64, now: u64) -> VerifiedDevice {
    let mut owner = open(&c.f.c);
    let admission = match owner.image().expect("original identity").phase {
        Phase::Accepted { admission, .. } => Ok(admission),
        _ => Err("active original"),
    }
    .expect("active original");
    owner.close();
    let roster =
        c.f.c
            .root
            .issue_roster(
                version,
                Validity::new(from, until).expect("range"),
                &[c.f
                    .c
                    .root
                    .roster_entry(&admission.certificate)
                    .expect("original member")],
            )
            .expect("root roster");
    AccountPin::new(
        c.f.original.account_id(),
        c.f.c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent pin")
    .verify_device(&admission.certificate, roster.as_bytes(), now)
    .expect("same C and root-approved R")
}
#[test]
fn next_roster_after_expired_applied_or_closed_target_uses_actual_original_admission() {
    for closed in [false, true] {
        let mut c = case(true);
        c.target = new_target(&c, 2, 100, 152, 150);
        let p = prepare_original(&c);
        witness_prepare(&c, p);
        let mut owner = open(&c.f.c);
        let mut client = policy_client(&c.f, &mut owner);
        assert_eq!(
            run(&c, p, &mut owner, &mut client, closed).expect("first R"),
            if closed {
                RState::Closed
            } else {
                RState::Applied
            }
        );
        owner.close();
        let prior = if closed {
            c.previous.clone()
        } else {
            c.target.clone()
        };
        let stale = new_target(&c, 2, 100, 159, 150);
        let mut owner = open(&c.f.c);
        let client = policy_client(&c.f, &mut owner);
        assert!(
            owner
                .prepare_witnessed_roster_refresh(
                    RosterRefreshId::generate().expect("ID"),
                    c.f.c.policy.historical(),
                    &c.policy,
                    &stale,
                    150,
                    client
                )
                .is_err(),
            "attempted target version floor persists"
        );
        c.f.carrier.clock.store(155, Ordering::SeqCst);
        let target = new_target(&c, 3, 153, 400, 155);
        let mut owner = open(&c.f.c);
        let client = policy_client(&c.f, &mut owner);
        let next = owner
            .prepare_witnessed_roster_refresh(
                RosterRefreshId::generate().expect("next ID"),
                c.f.c.policy.historical(),
                &c.policy,
                &target,
                155,
                client,
            )
            .expect("new R from historical actual predecessor");
        owner.close();
        assert_eq!(next.scope().previous, prior.roster().checkpoint());
        assert_eq!(
            c.f.carrier
                .store
                .lock()
                .expect("witness")
                .prepare_roster_refresh(next, &prior, &target, &c.policy, 155)
                .expect("root-approved original predecessor"),
            RState::Prepared
        );
        let mut owner = open(&c.f.c);
        let mut client = policy_client(&c.f, &mut owner);
        assert_eq!(
            owner
                .commit_witnessed_roster_refresh(
                    &next,
                    c.f.c.policy.historical(),
                    &c.policy,
                    155,
                    &mut client
                )
                .expect("new actual R"),
            RState::Applied
        );
        owner.close();
        let mut active = activate(&c.f, &c.policy, 155).expect("current same original owner");
        assert_eq!(
            active.parts().expect("parts").2.roster().checkpoint(),
            target.roster().checkpoint()
        );
        active.close();
    }
}
#[test]
fn roster_after_closed_policy_retains_the_original_adopted_policy_completion() {
    let c = case(true);
    let next = approved_at(&c.f, &c.policy, 3, 350, 150);
    let pp = prepared_at(&c.f, &next, &c.policy, 150);
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    assert_eq!(
        owner
            .close_witnessed_policy_renewal(
                pp.operation(),
                pp.statement(),
                c.f.c.policy.historical(),
                &mut client
            )
            .expect("close new P"),
        State::Closed
    );
    owner.close();
    let p = prepare_original(&c);
    witness_prepare(&c, p);
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    assert_eq!(
        run(&c, p, &mut owner, &mut client, false).expect("R after P close"),
        RState::Applied
    );
    owner.close();
    let mut active = activate(&c.f, &c.policy, 150).expect("original P survives closure and R");
    assert_eq!(
        active.parts().expect("current").2.roster().checkpoint(),
        p.scope().target
    );
    active.close();
}
#[test]
fn authenticated_roster_codec_refuses_inconsistent_scope_tail_target_and_phase() {
    use crate::enrollment::tests::policy_renewal::{replace_authenticated, row};
    let c = case(true);
    let p = prepare_original(&c);
    let saved = row(&open(&c.f.c));
    assert_eq!(saved.get(..8), Some(b"QPENST17".as_slice()));
    let proposal = p.to_bytes();
    let offset = saved
        .windows(proposal.len())
        .position(|s| s == proposal)
        .expect("full proposal");
    let mut bad_tag = saved.clone();
    *bad_tag.get_mut(offset - 1).expect("coordination tag") = 255;
    let mut changed = saved.clone();
    *changed
        .get_mut(offset + proposal.len() - 1)
        .expect("target digest") ^= 1;
    // A different canonical proposal is structurally valid but does not bind the
    // target currently retained in the actual journal. Readback may expose it as
    // historical metadata; reconciliation must reject before any dispatch.
    replace_authenticated(&c.f.c, &changed);
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    let calls = c.f.carrier.requests.lock().expect("calls").len();
    assert!(owner
        .reconcile_witnessed_roster_refresh(&p, c.f.c.policy.historical(), &mut client)
        .is_err());
    assert_eq!(c.f.carrier.requests.lock().expect("calls").len(), calls);
    replace_authenticated(&c.f.c, &saved);
    let mut wrong_scope = saved.clone();
    *wrong_scope
        .get_mut(offset + 8 + 32 + 96 + 32 + 8)
        .expect("previous roster digest") ^= 1;
    let mut tail = saved.clone();
    tail.insert(tail.len() - 32, 0);
    let roster = c.target.roster().as_bytes();
    let roster_offset = saved
        .windows(roster.len())
        .rposition(|s| s == roster)
        .expect("target signed roster");
    let mut invalid_signature = saved.clone();
    *invalid_signature
        .get_mut(roster_offset + roster.len() - 1)
        .expect("target signature") ^= 1;
    let mut missing = saved.clone();
    missing.drain(offset..offset + proposal.len());
    for malformed in [bad_tag, wrong_scope, tail, invalid_signature, missing] {
        replace_authenticated(&c.f.c, &malformed);
        assert!(
            DeviceEnrollment::open(c.f.c.paths.clone(), c.f.c.intent.clone()).is_err(),
            "authenticated malformed record accepted"
        );
        replace_authenticated(&c.f.c, &saved);
        assert_eq!(row(&open(&c.f.c)), saved, "no implicit repair");
    }
    let mut owner = open(&c.f.c);
    let mut image = owner.image().expect("restored exact image");
    let stage = match &mut image.phase {
        Phase::Accepted { stage, .. } => Ok(stage),
        _ => Err("active original"),
    }
    .expect("active original");
    *stage = AdmissionPhase::Activating;
    assert!(encode(&owner.key().expect("key"), owner.binding, &image).is_err());
}

#[path = "witness_roster_operational_tests.rs"]
mod operational;
