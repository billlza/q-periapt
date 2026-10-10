// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorPolicyRenewalProposal as PolicyProposal, AnchorPolicyRenewalState as State,
    PolicyRenewalId, PolicyRenewalRequest, PolicyRenewalStatement, VerifiedPolicyRenewal,
    WitnessedPolicyRenewalDisposition as Disposition, WitnessedPolicyRenewalProgress as Progress,
};
struct Approval {
    request: PolicyRenewalRequest,
    target: VerifiedSessionPolicy,
    proof: VerifiedPolicyRenewal,
}
fn policy_client(f: &Fixture, owner: &mut DeviceEnrollment) -> AnchorClient {
    owner
        .policy_renewal_anchor_client(
            f.c.policy.historical(),
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("original P control client")
}
fn approval(f: &Fixture) -> Approval {
    let mut owner = open(&f.c);
    approval_with_owner(f, &mut owner)
}
fn approval_with_owner(f: &Fixture, owner: &mut DeviceEnrollment) -> Approval {
    let client = policy_client(f, owner);
    let request = owner
        .witnessed_policy_renewal_request(
            PolicyRenewalId::generate().expect("P operation"),
            f.c.policy.historical(),
            client,
        )
        .expect("actual witnessed issuer request");
    owner.close();
    let target = super::super::policy_continuation::policy(&f.c, 2, 300, 150);
    let materials = request.materials(f.c.policy.historical(), f.c.policy.historical(), &target);
    let s = PolicyRenewalStatement::new(request.scope(), &materials, 150).expect("public request");
    let issuer =
        crate::PolicySigningKey::deterministic([82; 32], [83; 32]).expect("independent issuer");
    let proof = VerifiedPolicyRenewal::verify(
        &f.c.root
            .approve_policy_renewal(&s)
            .expect("account approval"),
        &issuer.approve_policy_renewal(&s).expect("policy approval"),
        request.scope(),
        &materials,
        150,
    )
    .expect("two roots");
    Approval {
        request,
        target,
        proof,
    }
}
fn stage(f: &Fixture, a: &Approval) {
    let mut owner = open(&f.c);
    let operation = a.proof.scope().operation;
    assert_eq!(
        owner
            .stage_policy_renewal(&a.proof, operation, f.c.policy.historical(), &a.target, 150)
            .expect("durable original P"),
        crate::PolicyRenewalStatus::Pending {
            operation,
            statement: a.proof.statement_digest(),
            target: a.proof.target_policy()
        }
    );
    owner.close();
}
fn prepare(f: &Fixture, a: &Approval) -> PolicyProposal {
    let mut owner = open(&f.c);
    let carrier = policy_client(f, &mut owner);
    let p = owner
        .prepare_witnessed_policy_renewal(
            f.c.policy.historical(),
            f.c.policy.historical(),
            &a.target,
            150,
            carrier,
        )
        .expect("seal and retain original proposal");
    owner.close();
    p
}
fn approve_witness(f: &Fixture, a: &Approval, p: PolicyProposal) {
    let materials =
        a.request
            .materials(f.c.policy.historical(), f.c.policy.historical(), &a.target);
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_policy_renewal(p, &a.proof, &materials, 150)
            .expect("independent witness decision"),
        State::Prepared
    );
}
fn journal(f: &Fixture) -> (Vec<u8>, Option<Vec<u8>>) {
    let db = open_private_database(f.c.paths.installation.files()[1]).expect("original journal");
    let tx = db.begin_read().expect("read");
    let t = tx.open_table(JOURNAL).expect("table");
    let image = t
        .get("image")
        .expect("lookup")
        .expect("image")
        .value()
        .to_vec();
    let pending = t
        .get("pending")
        .expect("pending")
        .map(|p| p.value().to_vec());
    (image, pending)
}
fn target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let p = saved.1.as_ref().expect("original intent");
    assert_eq!(p.get(..8), Some(b"QPWINT06".as_slice()));
    p.get(220..p.len().checked_sub(32).expect("MAC"))
        .expect("original sealed target")
        .to_vec()
}
#[test]
fn original_enrollment_owns_independent_policy_terminal_ack_and_pending_cleanup() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    let sealed = journal(&f);
    assert_eq!(prepare(&f, &a), p);
    assert_eq!(journal(&f), sealed, "retry resealed original target");
    approve_witness(&f, &a, p);
    let start = f.carrier.requests.lock().expect("requests").len();
    let mut owner = open(&f.c);
    let mut carrier = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                150,
                &mut carrier
            )
            .expect("original witnessed commit"),
        State::Applied
    );
    assert_eq!(
        owner.witnessed_policy_renewal_progress().expect("progress"),
        Some(Progress::Terminal {
            proposal: p,
            target: a.target.checkpoint(),
            disposition: Disposition::Applied,
            retired: true
        })
    );
    assert_eq!(
        owner.policy_renewal_status().expect("P history"),
        crate::PolicyRenewalStatus::Committed {
            operation: p.operation(),
            statement: p.statement(),
            target: a.target.checkpoint()
        }
    );
    owner.close();
    assert_eq!(journal(&f), (target(&sealed), None));
    assert_eq!(
        f.carrier.requests.lock().expect("requests").get(start..),
        Some([11, 12, 14].as_slice())
    );
    assert!(
        open(&f.c)
            .activate_policy_renewal(f.c.policy.historical(), &a.target, 150)
            .is_err(),
        "local activation cannot replace required P owner admission"
    );
}
#[test]
fn witnessed_close_is_retained_separately_from_a_policy_commit() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    let before = journal(&f);
    approve_witness(&f, &a, p);
    let mut owner = open(&f.c);
    let mut carrier = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .close_witnessed_policy_renewal(
                p.operation(),
                p.statement(),
                f.c.policy.historical(),
                &mut carrier
            )
            .expect("close original"),
        State::Closed
    );
    assert_eq!(
        owner.policy_renewal_status().expect("no policy adoption"),
        crate::PolicyRenewalStatus::Absent
    );
    assert_eq!(
        owner
            .witnessed_policy_renewal_progress()
            .expect("closed progress"),
        Some(Progress::Terminal {
            proposal: p,
            target: a.target.checkpoint(),
            disposition: Disposition::Closed,
            retired: true
        })
    );
    owner.close();
    assert_eq!(journal(&f), (before.0, None));
    let mut owner = open(&f.c);
    let client = owner
        .anchor_client(
            &f.c.policy,
            150,
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("original P0 client");
    owner
        .activate(&f.c.policy, 150, Some(client))
        .expect("still-live original P0 remains usable after close")
        .close();
}
#[test]
fn lost_commit_and_ack_replies_recover_original_terminal_after_expiry() {
    for (opcode, after) in [(11, false), (11, true), (14, false), (14, true)] {
        let f = fixture();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        let original = journal(&f);
        approve_witness(&f, &a, p);
        let mut owner = open(&f.c);
        let mut carrier = policy_client(&f, &mut owner);
        *f.carrier.cut.lock().expect("cut") = Some((opcode, after));
        assert!(owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                150,
                &mut carrier
            )
            .is_err());
        assert!(owner.active.is_none());
        if opcode == 14 {
            assert_eq!(
                open(&f.c)
                    .witnessed_policy_renewal_progress()
                    .expect("terminal persisted before ACK"),
                Some(Progress::Terminal {
                    proposal: p,
                    target: a.target.checkpoint(),
                    disposition: Disposition::Applied,
                    retired: false
                })
            );
        }
        assert_eq!(
            journal(&f).1,
            original.1,
            "unknown ACK cannot erase pending"
        );
        f.carrier.clock.store(401, Ordering::SeqCst);
        a.target.close();
        f.c.policy.close();
        let mut owner = open(&f.c);
        let mut carrier = policy_client(&f, &mut owner);
        let expected = if opcode == 11 && !after {
            assert_eq!(
                owner
                    .reconcile_witnessed_policy_renewal(
                        p.operation(),
                        p.statement(),
                        f.c.policy.historical(),
                        &mut carrier
                    )
                    .expect("Prepared remains honest"),
                State::Prepared
            );
            assert_eq!(
                owner
                    .close_witnessed_policy_renewal(
                        p.operation(),
                        p.statement(),
                        f.c.policy.historical(),
                        &mut carrier
                    )
                    .expect("historical close"),
                State::Closed
            );
            (State::Closed, Disposition::Closed, original.0.clone())
        } else {
            assert_eq!(
                owner
                    .reconcile_witnessed_policy_renewal(
                        p.operation(),
                        p.statement(),
                        f.c.policy.historical(),
                        &mut carrier
                    )
                    .expect("historical original outcome"),
                State::Applied
            );
            (State::Applied, Disposition::Applied, target(&original))
        };
        assert_eq!(
            owner.witnessed_policy_renewal_progress().expect("retired"),
            Some(Progress::Terminal {
                proposal: p,
                target: a.target.checkpoint(),
                disposition: expected.1,
                retired: true
            })
        );
        owner.close();
        assert_eq!(journal(&f), (expected.2, None));
        let mut owner = open(&f.c);
        let mut carrier = policy_client(&f, &mut owner);
        assert_eq!(
            owner
                .reconcile_witnessed_policy_renewal(
                    p.operation(),
                    p.statement(),
                    f.c.policy.historical(),
                    &mut carrier
                )
                .expect("exact history"),
            expected.0
        );
    }
}
#[test]
fn changed_expected_policy_proposal_never_dispatches_commit_or_retires_pending() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    approve_witness(&f, &a, p);
    let before = journal(&f);
    let calls = f.carrier.requests.lock().expect("requests").len();
    let mut wire = p.to_bytes();
    *wire.last_mut().expect("target digest") ^= 1;
    let wrong = PolicyProposal::from_trusted_state(&wire).expect("different valid descriptor");
    let mut owner = open(&f.c);
    let mut carrier = policy_client(&f, &mut owner);
    assert!(owner
        .commit_witnessed_policy_renewal(
            &wrong,
            f.c.policy.historical(),
            &a.target,
            150,
            &mut carrier
        )
        .is_err());
    assert_eq!(journal(&f), before);
    assert_eq!(f.carrier.requests.lock().expect("requests").len(), calls);
    let mut owner = open(&f.c);
    let mut carrier = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                150,
                &mut carrier
            )
            .expect("finish original"),
        State::Applied
    );
    owner.close();
    let calls = f.carrier.requests.lock().expect("requests").len();
    let after = journal(&f);
    let mut owner = open(&f.c);
    let mut carrier = policy_client(&f, &mut owner);
    assert!(
        owner
            .commit_witnessed_policy_renewal(
                &wrong,
                f.c.policy.historical(),
                &a.target,
                150,
                &mut carrier
            )
            .is_err(),
        "completed history must still reject another expected target head"
    );
    assert_eq!(journal(&f), after);
    assert_eq!(f.carrier.requests.lock().expect("requests").len(), calls);
    let other_target = super::super::policy_continuation::policy(&f.c, 3, 350, 150);
    let mut owner = open(&f.c);
    let mut carrier = policy_client(&f, &mut owner);
    assert!(
        owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &other_target,
                150,
                &mut carrier
            )
            .is_err(),
        "completed history must still reject a different authentic target policy"
    );
    assert_eq!(journal(&f), after);
    assert_eq!(f.carrier.requests.lock().expect("requests").len(), calls);
}

fn run_terminal(
    f: &Fixture,
    a: &Approval,
    p: PolicyProposal,
    owner: &mut DeviceEnrollment,
    carrier: &mut AnchorClient,
    closed: bool,
) -> Result<State, DurableError> {
    if closed {
        owner.close_witnessed_policy_renewal(
            p.operation(),
            p.statement(),
            f.c.policy.historical(),
            carrier,
        )
    } else {
        owner.commit_witnessed_policy_renewal(&p, f.c.policy.historical(), &a.target, 150, carrier)
    }
}
#[test]
fn enrollment_sync_failures_never_ack_before_original_terminal_is_durable() {
    let mut faults = 0;
    for closed in [false, true] {
        let f = fixture();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        approve_witness(&f, &a, p);
        let (mut owner, _, count) = faulty(&f.c, false);
        let mut carrier = policy_client(&f, &mut owner);
        let terminal_count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&terminal_count);
        let counter = Arc::clone(&count);
        *f.carrier.after_reply.lock().expect("hook") = Some((
            14,
            Box::new(move || {
                seen.store(counter.load(Ordering::SeqCst), Ordering::SeqCst);
            }),
        ));
        let state = if closed {
            State::Closed
        } else {
            State::Applied
        };
        assert_eq!(
            run_terminal(&f, &a, p, &mut owner, &mut carrier, closed).expect("calibration"),
            state
        );
        let barriers = count.load(Ordering::SeqCst);
        let terminal_barriers = terminal_count.load(Ordering::SeqCst);
        assert!(terminal_barriers > 0 && barriers > terminal_barriers && barriers <= 16);
        owner.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                let f = fixture();
                let a = approval(&f);
                stage(&f, &a);
                let p = prepare(&f, &a);
                let before = journal(&f);
                approve_witness(&f, &a, p);
                let (mut owner, remaining, _) = faulty(&f.c, after);
                let mut carrier = policy_client(&f, &mut owner);
                let start = f.carrier.requests.lock().expect("calls").len();
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    run_terminal(&f, &a, p, &mut owner, &mut carrier, closed),
                    after,
                );
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                assert!(owner.active.is_none());
                let ack = f
                    .carrier
                    .requests
                    .lock()
                    .expect("calls")
                    .get(start..)
                    .expect("attempt calls")
                    .contains(&14);
                if cut <= terminal_barriers {
                    assert!(
                        !ack,
                        "ACK escaped before terminal acknowledgement at cut {cut}"
                    );
                }
                let mut reopened = open(&f.c);
                let progress = reopened
                    .witnessed_policy_renewal_progress()
                    .expect("original durable image");
                if ack {
                    assert!(
                        matches!(progress, Some(Progress::Terminal { .. })),
                        "ACK without a retained original terminal"
                    );
                }
                reopened.close();
                f.carrier.clock.store(401, Ordering::SeqCst);
                a.target.close();
                f.c.policy.close();
                let mut reopened = open(&f.c);
                let mut carrier = policy_client(&f, &mut reopened);
                assert_eq!(
                    reopened
                        .reconcile_witnessed_policy_renewal(
                            p.operation(),
                            p.statement(),
                            f.c.policy.historical(),
                            &mut carrier
                        )
                        .expect("same historical operation resumes"),
                    state
                );
                assert_eq!(
                    reopened
                        .witnessed_policy_renewal_progress()
                        .expect("exact retired terminal"),
                    Some(Progress::Terminal {
                        proposal: p,
                        target: a.target.checkpoint(),
                        disposition: if closed {
                            Disposition::Closed
                        } else {
                            Disposition::Applied
                        },
                        retired: true
                    })
                );
                reopened.close();
                assert_eq!(
                    journal(&f),
                    (
                        if closed {
                            before.0.clone()
                        } else {
                            target(&before)
                        },
                        None
                    )
                );
                faults += 1;
            }
        }
    }
    eprintln!("INDEPENDENT_POLICY_ENROLLMENT_SYNC terminal_and_retired_faults={faults} no_ack_before_durable_terminal=true original_pending_cleanup=true historical_retry=true");
}

fn terminal_before_ack(
    f: &Fixture,
    a: &Approval,
    p: PolicyProposal,
    closed: bool,
) -> DeviceEnrollment {
    let mut owner = open(&f.c);
    let mut carrier = policy_client(f, &mut owner);
    *f.carrier.cut.lock().expect("cut") = Some((14, false));
    assert!(run_terminal(f, a, p, &mut owner, &mut carrier, closed).is_err());
    assert!(owner.active.is_none());
    let mut original = open(&f.c);
    assert_eq!(
        original
            .witnessed_policy_renewal_progress()
            .expect("durable original terminal"),
        Some(Progress::Terminal {
            proposal: p,
            target: a.target.checkpoint(),
            disposition: if closed {
                Disposition::Closed
            } else {
                Disposition::Applied
            },
            retired: false
        })
    );
    original
}
#[test]
fn pending_cleanup_sync_failures_retry_only_with_the_original_persisted_terminal() {
    let mut faults = 0;
    for closed in [false, true] {
        let f = fixture();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        let _before = journal(&f); // Match the fault cases' actual open/close history.
        approve_witness(&f, &a, p);
        let mut owner = terminal_before_ack(&f, &a, p, closed);
        let terminal = owner
            .persisted_policy_terminal(f.c.policy.historical())
            .expect("actual durable capability");
        let mut carrier = policy_client(&f, &mut owner);
        let lease = owner
            .witness_lease(&f.original, f.c.policy.historical(), f.id)
            .expect("original service lease");
        let (db, _, count, _) = fault_database_path(f.c.paths.installation.files()[1], false);
        let key = JournalKey::open(&f.c.paths.wrapping).expect("same key");
        DeviceJournal::retire_policy_renewal_in_database(
            &db,
            &key,
            &f.original,
            f.c.policy.historical(),
            f.id,
            &terminal,
            &mut carrier,
        )
        .expect("calibrate original cleanup");
        let barriers = count.load(Ordering::SeqCst);
        assert!((1..=8).contains(&barriers));
        drop(db);
        drop(lease);
        owner.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                let f = fixture();
                let a = approval(&f);
                stage(&f, &a);
                let p = prepare(&f, &a);
                let before = journal(&f);
                approve_witness(&f, &a, p);
                let mut owner = terminal_before_ack(&f, &a, p, closed);
                let terminal = owner
                    .persisted_policy_terminal(f.c.policy.historical())
                    .expect("only persisted terminal grants ACK");
                let mut carrier = policy_client(&f, &mut owner);
                let lease = owner
                    .witness_lease(&f.original, f.c.policy.historical(), f.id)
                    .expect("original lease");
                let (db, remaining, attempted_syncs, _) =
                    fault_database_path(f.c.paths.installation.files()[1], after);
                let key = JournalKey::open(&f.c.paths.wrapping).expect("original key");
                remaining.store(cut, Ordering::SeqCst);
                let result = DeviceJournal::retire_policy_renewal_in_database(
                    &db,
                    &key,
                    &f.original,
                    f.c.policy.historical(),
                    f.id,
                    &terminal,
                    &mut carrier,
                );
                eprintln!("P_CLEANUP_SYNC_DIAGNOSTIC closed={closed} after={after} cut={cut} calibrated={barriers} actual={} remaining={} outcome={result:?}",attempted_syncs.load(Ordering::SeqCst),remaining.load(Ordering::SeqCst));
                assert_sync_failure(result, after);
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                drop(db);
                drop(lease);
                owner.close();
                let expected = if closed {
                    before.0.clone()
                } else {
                    target(&before)
                };
                let observed = journal(&f);
                assert_eq!(observed.0, expected);
                assert!(
                    observed.1.is_none() || observed.1 == before.1,
                    "cleanup must keep exact original or remove it atomically"
                );
                f.carrier.clock.store(401, Ordering::SeqCst);
                a.target.close();
                f.c.policy.close();
                let mut owner = open(&f.c);
                let mut carrier = policy_client(&f, &mut owner);
                assert_eq!(
                    owner
                        .reconcile_witnessed_policy_renewal(
                            p.operation(),
                            p.statement(),
                            f.c.policy.historical(),
                            &mut carrier
                        )
                        .expect("resume exact terminal after ACK and I/O uncertainty"),
                    if closed {
                        State::Closed
                    } else {
                        State::Applied
                    }
                );
                owner.close();
                assert_eq!(journal(&f), (expected, None));
                faults += 1;
            }
        }
    }
    eprintln!("INDEPENDENT_POLICY_CLEANUP_SYNC faults={faults} exact_persisted_terminal=true uncertain_ack_or_cleanup_idempotent=true unchanged_image=true");
}

#[path = "witness_independent_policy_operational_tests.rs"]
mod operational;

#[path = "managed_policy_tests.rs"]
mod managed;
