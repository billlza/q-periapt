// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AnchorCredentialRenewalProposal, AnchorCredentialRenewalState as State};

fn proposal(
    c: &Case,
    grant: &crate::VerifiedCredentialRenewal,
    target: u8,
) -> AnchorCredentialRenewalProposal {
    // Store-only expectation. End-to-end journal tests supply its actual sealed image.
    AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(c),
        AnchorHead::from_trusted_state(1, 2, [target; 32]).expect("target"),
    )
    .expect("proposal")
}
fn exchange(
    c: &mut Case,
    proposal: &AnchorCredentialRenewalProposal,
    operation: AnchorOperation,
    now: u64,
) -> State {
    let rq = request(c, operation);
    let wire = c
        .store
        .handle(rq.as_bytes(), now)
        .expect("real witness response");
    let reply = c
        .pin
        .verify_reply(&rq, &wire)
        .expect("fresh dual-signed response");
    assert!(
        reply.applied_head().is_err(),
        "generic advance evidence cannot authorize joint apply"
    );
    reply
        .credential_renewal_state(proposal)
        .expect("exact original proposal")
}
fn prepare(
    c: &mut Case,
    p: AnchorCredentialRenewalProposal,
    g: &crate::VerifiedCredentialRenewal,
    now: u64,
) -> State {
    c.store
        .prepare_credential_renewal(p, g, c.peer.responder.policy(), now)
        .expect("independent root approval")
}
fn status(c: &mut Case, p: &AnchorCredentialRenewalProposal, now: u64) -> State {
    exchange(c, p, AnchorOperation::credential_renewal_status(p), now)
}
fn ack(c: &mut Case, p: &AnchorCredentialRenewalProposal, now: u64) -> State {
    exchange(
        c,
        p,
        AnchorOperation::acknowledge_credential_renewal(p),
        now,
    )
}
#[test]
fn target_commits_after_original_credential_expiry_and_exact_history_survives_target_expiry() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 211);
    assert_eq!(prepare(&mut c, p, &g, 170), State::Prepared);
    assert_eq!(status(&mut c, &p, 170), State::Prepared);
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            170
        ),
        State::Applied
    );
    let image = c.store.image().expect("joint durable image");
    let entry = image
        .entries
        .get(&p.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(entry.head, p.target_head());
    assert_eq!(entry.credential_owner, storage_owner(g.successor_device()));
    assert_eq!(entry.authority, g.successor_device().authority_binding());
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(status(&mut c, &p, 181), State::Applied);
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            181
        ),
        State::Applied
    );
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::close_credential_renewal(&p),
            181
        ),
        State::Applied
    );
    let admission = request(
        &c,
        AnchorOperation::admit_authority(g.successor_device().authority_binding())
            .expect("admission"),
    );
    let wire = c
        .store
        .handle(admission.as_bytes(), 181)
        .expect("expired denial");
    assert_eq!(
        c.pin
            .verify_reply(&admission, &wire)
            .expect("denial")
            .outcome(),
        AnchorOutcome::AuthorityDenied
    );
    assert_eq!(ack(&mut c, &p, 181), State::Acknowledged);
    assert_eq!(ack(&mut c, &p, 181), State::Acknowledged);
    assert_eq!(status(&mut c, &p, 181), State::Unavailable);
}
#[test]
fn closed_before_prepare_never_revives_through_pruning_or_legacy_control_plane() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 212);
    assert_eq!(status(&mut c, &p, 150), State::Unavailable);
    assert_eq!(
        c.store
            .close_credential_renewal(p, &g, c.peer.responder.policy())
            .expect("explicit close before prepare"),
        State::Closed
    );
    assert_eq!(prepare(&mut c, p, &g, 150), State::Closed);
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            150
        ),
        State::Closed
    );
    assert_eq!(ack(&mut c, &p, 150), State::Acknowledged);
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(status(&mut c, &p, 150), State::Unavailable);
    assert!(matches!(
        c.store
            .prepare_credential_renewal(p, &g, c.peer.responder.policy(), 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        c.store
            .close_credential_renewal(p, &g, c.peer.responder.policy()),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        c.store.renew_credential_authority(
            p.subject(),
            &g,
            g.operation(),
            c.peer.responder.policy(),
            150
        ),
        Err(DurableError::Suspended)
    ));
    let image = c.store.image().expect("no resurrection");
    let entry = image
        .entries
        .get(&p.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(entry.head, p.expected_head());
    assert_eq!(entry.credential_owner, storage_owner(g.previous_device()));
    assert_eq!(entry.renewal_floor, 2);
    assert!(entry.renewal.is_none());
    c.store
        .enroll(
            &c.genesis,
            c.peer.responder.inventory_inputs().1,
            c.peer.responder.policy(),
            150,
        )
        .expect("exact enrollment readback");
    assert!(matches!(
        c.store
            .prepare_credential_renewal(p, &g, c.peer.responder.policy(), 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
}
#[test]
fn prepared_and_unacknowledged_terminal_exclude_ordinary_advance_fence_and_roster_refresh() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 213);
    prepare(&mut c, p, &g, 150);
    for closed in [false, true] {
        if closed {
            assert_eq!(
                exchange(
                    &mut c,
                    &p,
                    AnchorOperation::close_credential_renewal(&p),
                    150
                ),
                State::Closed
            );
        }
        for operation in [
            AnchorOperation::advance(p.expected_head(), [214; 32]).expect("ordinary"),
            AnchorOperation::fence_writer(p.expected_head()).expect("fence"),
        ] {
            let rq = request(&c, operation);
            assert!(matches!(
                c.store.handle(rq.as_bytes(), 150),
                Err(AnchorError::Rejected(Error::State))
            ));
        }
        assert!(matches!(
            c.store.renew_credential_authority(
                p.subject(),
                &g,
                g.operation(),
                c.peer.responder.policy(),
                150
            ),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            c.store.update_roster_authority(
                p.subject(),
                g.previous_device().roster().checkpoint(),
                g.successor_device(),
                c.peer.responder.policy(),
                150
            ),
            Err(DurableError::Suspended)
        ));
    }
}

#[test]
fn same_version_is_not_operation_identity_and_old_ack_cannot_erase_a_new_slot() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 215);
    let root = crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("root");
    let original = c.peer.responder.inventory_inputs().1;
    let certificate = root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("origin");
    let other = crate::durable::tests::grant(
        &root,
        &certificate,
        original,
        180,
        2,
        [216; 32],
        c.peer.responder.policy().checkpoint().digest(),
    );
    assert_eq!(
        g.successor_device().roster().checkpoint(),
        other.successor_device().roster().checkpoint()
    );
    assert_ne!(g.statement_digest(), other.statement_digest());
    let alias = proposal(&c, &other, 215);
    prepare(&mut c, p, &g, 150);
    assert_eq!(status(&mut c, &alias, 150), State::Unavailable);
    assert!(matches!(
        c.store
            .prepare_credential_renewal(alias, &other, c.peer.responder.policy(), 150),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store
            .close_credential_renewal(alias, &other, c.peer.responder.policy()),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::close_credential_renewal(&p),
            150
        ),
        State::Closed
    );
    assert_eq!(ack(&mut c, &p, 150), State::Acknowledged);
    assert!(matches!(
        c.store
            .prepare_credential_renewal(alias, &other, c.peer.responder.policy(), 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(status(&mut c, &alias, 150), State::Unavailable);
    let next = credential_grant(&c, c.peer.responder.inventory_inputs().1, 3, 190);
    let next_p = proposal(&c, &next, 217);
    assert_eq!(prepare(&mut c, next_p, &next, 170), State::Prepared);
    assert_eq!(ack(&mut c, &p, 170), State::Acknowledged);
    assert_eq!(status(&mut c, &next_p, 170), State::Prepared);
    assert_eq!(
        exchange(
            &mut c,
            &next_p,
            AnchorOperation::commit_credential_renewal(&next_p),
            170
        ),
        State::Applied
    );
    assert_eq!(ack(&mut c, &next_p, 170), State::Acknowledged);
    assert_eq!(
        ack(&mut c, &p, 170),
        State::Unavailable,
        "retired acknowledgement history is bounded"
    );
    let updated = renewed_device(
        next.successor_device(),
        4,
        Validity::new(100, 195).expect("roster interval"),
    );
    c.store
        .update_roster_authority(
            next_p.subject(),
            next.successor_device().roster().checkpoint(),
            &updated,
            c.peer.responder.policy(),
            175,
        )
        .expect("later root roster refresh");
    assert!(matches!(
        c.store
            .close_credential_renewal(p, &g, c.peer.responder.policy()),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(status(&mut c, &p, 175), State::Unavailable);
    assert!(matches!(
        c.store.renew_credential_authority(
            p.subject(),
            &g,
            g.operation(),
            c.peer.responder.policy(),
            175
        ),
        Err(DurableError::Suspended)
    ));
    let image = c.store.image().expect("retained floor");
    let e = image
        .entries
        .get(&p.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(e.renewal_floor, 3);
    assert_eq!(e.authority, updated.authority_binding());
}

#[test]
fn expiry_and_policy_closure_allow_only_historical_classification_and_close() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 218);
    assert!(matches!(
        c.store
            .prepare_credential_renewal(p, &g, c.peer.responder.policy(), 180),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert_eq!(status(&mut c, &p, 180), State::Unavailable);
    c.peer.responder.policy().close();
    assert_eq!(
        c.store
            .close_credential_renewal(p, &g, c.peer.responder.policy())
            .expect("retained close after expiry"),
        State::Closed
    );
    assert_eq!(status(&mut c, &p, 181), State::Closed);
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            181
        ),
        State::Closed
    );
    assert_eq!(ack(&mut c, &p, 181), State::Acknowledged);
    assert_eq!(status(&mut c, &p, 181), State::Unavailable);
}

#[test]
fn signed_status_requires_exact_scope_freshness_and_consistent_joint_head() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 219);
    prepare(&mut c, p, &g, 150);
    let mut changed = p.to_bytes();
    changed.get_mut(168..200).expect("statement").fill(220);
    let other =
        AnchorCredentialRenewalProposal::from_trusted_state(&changed).expect("different metadata");
    assert_eq!(status(&mut c, &other, 150), State::Unavailable);
    let rq = request(&c, AnchorOperation::credential_renewal_status(&p));
    let wire = c
        .store
        .handle(rq.as_bytes(), 150)
        .expect("prepared response");
    let next = request(&c, AnchorOperation::credential_renewal_status(&p));
    assert!(matches!(
        c.pin.verify_reply(&next, &wire),
        Err(Error::Scope)
    ));
    let verified = c
        .pin
        .verify_reply(&rq, &wire)
        .expect("original fresh reply");
    assert!(verified.credential_renewal_state(&other).is_err());
    assert_eq!(
        verified.credential_renewal_state(&p).expect("exact"),
        State::Prepared
    );
    assert!(matches!(c.pin.verify_reply(&rq, &wire), Err(Error::Closed)));
    // Even an authentically signed malformed provider response cannot become a
    // local apply receipt for the retained target or a generic journal advance.
    for outcome in [
        AnchorOutcome::CredentialApplied,
        AnchorOutcome::CredentialAcknowledged,
    ] {
        let rq = request(&c, AnchorOperation::credential_renewal_status(&p));
        let parsed = incoming(&c.pin, rq.as_bytes()).expect("request");
        let signer = &c.store.active.as_ref().expect("active").signer;
        let wire = reply(&c.pin, signer, &parsed, outcome, p.expected_head(), None)
            .expect("authentic malformed fixture");
        match c.pin.verify_reply(&rq, &wire) {
            Ok(response) => assert!(response.credential_renewal_state(&p).is_err()),
            Err(error) => assert_eq!(error, Error::State),
        }
    }
    for operation in [
        AnchorOperation::credential_renewal_status(&p),
        AnchorOperation::commit_credential_renewal(&p),
        AnchorOperation::close_credential_renewal(&p),
        AnchorOperation::acknowledge_credential_renewal(&p),
    ] {
        let wire = operation.to_bytes();
        assert_eq!(wire.len(), 97);
        assert_eq!(
            AnchorOperation::from_trusted_state(&wire).expect("canonical operation"),
            operation
        );
        for index in [0, 33, 96] {
            let mut bad = wire.clone();
            *bad.get_mut(index).expect("field") = 255;
            assert!(AnchorOperation::from_trusted_state(&bad).is_err());
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Transition {
    Prepare,
    Apply,
    ClosePrepared,
    CloseMissing,
    Acknowledge,
}
fn transition(
    c: &mut Case,
    p: AnchorCredentialRenewalProposal,
    g: &crate::VerifiedCredentialRenewal,
    action: Transition,
) -> Result<State, DurableError> {
    match action {
        Transition::Prepare => {
            c.store
                .prepare_credential_renewal(p, g, c.peer.responder.policy(), 170)
        }
        Transition::CloseMissing => {
            c.store
                .close_credential_renewal(p, g, c.peer.responder.policy())
        }
        _ => {
            let operation = match action {
                Transition::Apply => AnchorOperation::commit_credential_renewal(&p),
                Transition::ClosePrepared => AnchorOperation::close_credential_renewal(&p),
                Transition::Acknowledge => AnchorOperation::acknowledge_credential_renewal(&p),
                _ => return Err(Error::State.into()),
            };
            let rq = request(c, operation);
            let wire = c.store.handle(rq.as_bytes(), 170).map_err(|e| match e {
                AnchorError::Storage(e) => e,
                AnchorError::Rejected(e) | AnchorError::ReplyUnavailable(e) => e.into(),
            })?;
            Ok(c.pin
                .verify_reply(&rq, &wire)?
                .credential_renewal_state(&p)?)
        }
    }
}
fn setup_transition(
    c: &mut Case,
    p: AnchorCredentialRenewalProposal,
    g: &crate::VerifiedCredentialRenewal,
    action: Transition,
) {
    if matches!(
        action,
        Transition::Apply | Transition::ClosePrepared | Transition::Acknowledge
    ) {
        prepare(c, p, g, 170);
    }
    if matches!(action, Transition::Acknowledge) {
        assert_eq!(
            exchange(c, &p, AnchorOperation::commit_credential_renewal(&p), 170),
            State::Applied
        );
    }
}
#[test]
fn every_joint_transaction_sync_cut_recovers_one_exact_transition_and_preserves_the_floor() {
    let mut faults = 0;
    let mut expected_faults = 0;
    for action in [
        Transition::Prepare,
        Transition::Apply,
        Transition::ClosePrepared,
        Transition::CloseMissing,
        Transition::Acknowledge,
    ] {
        let mut baseline = credential_case();
        let g = credential_grant_first(&baseline);
        let p = proposal(&baseline, &g, 221);
        setup_transition(&mut baseline, p, &g, action);
        let (_, count) = with_fault_database(&mut baseline, false);
        count.store(0, Ordering::SeqCst);
        let target = transition(&mut baseline, p, &g, action).expect("measured transition");
        let barriers = count.load(Ordering::SeqCst);
        assert!(
            (2..=8).contains(&barriers),
            "bounded measured {action:?} barriers"
        );
        expected_faults += 2 * barriers;
        eprintln!("JOINT_RENEWAL_MEASURED action={action:?} barriers={barriers}");
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut c = credential_case();
                let g = credential_grant_first(&c);
                let p = proposal(&c, &g, 221);
                setup_transition(&mut c, p, &g, action);
                let revision = c.store.image().expect("before").revision;
                let (remaining, _) = with_fault_database(&mut c, after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    transition(&mut c, p, &g, action),
                    after,
                );
                assert!(c.store.active.is_none());
                c.store = reopen(&c.server);
                assert_eq!(
                    transition(&mut c, p, &g, action).expect("exact retry"),
                    target
                );
                assert_eq!(c.store.image().expect("once only").revision, revision + 1);
                faults += 1;
            }
        }
    }
    assert_eq!(faults, expected_faults);
    assert!(faults >= 20);
    eprintln!("JOINT_RENEWAL_SYNC_FAULTS={faults}");
}

#[test]
fn joint_transition_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_JOINT_RENEWAL_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let p = AnchorCredentialRenewalProposal::from_trusted_state(
        &fs::read(path.join("joint-proposal")).expect("original proposal"),
    )
    .expect("proposal");
    let peer = crate::bootstrap::tests::fixture_with_public_and_credential_validity(
        PrekeyQuality::OneTimeBoth,
        Validity::new(100, 200).expect("roster"),
        Validity::new(100, 155).expect("prekey"),
        Validity::new(100, 160).expect("credential"),
    );
    let (policy, original, _) = peer.responder.inventory_inputs();
    let target = fs::read(path.join("joint-target-pin")).expect("independent target");
    let mut d = Decoder::new(&target);
    let checkpoint = crate::RosterCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("checkpoint");
    d.finish().expect("exact encoding");
    let pin = crate::AccountPin::new(
        original.account_id(),
        original.authority_key.clone(),
        checkpoint,
        original.description.family,
    )
    .expect("independent pin");
    let grant = crate::VerifiedCredentialRenewal::verify(
        &fs::read(path.join("joint-grant")).expect("original grant"),
        &pin,
        policy.checkpoint().digest(),
        170,
    )
    .expect("verified original grant");
    let mut store = reopen(path);
    match fs::read_to_string(path.join("joint-action"))
        .expect("retained action")
        .as_str()
    {
        "Prepare" => {
            store
                .prepare_credential_renewal(p, &grant, policy, 170)
                .expect("prepare");
        }
        "CloseMissing" => {
            store
                .close_credential_renewal(p, &grant, policy)
                .expect("close missing");
        }
        action => {
            let operation = match action {
                "Apply" => AnchorOperation::commit_credential_renewal(&p),
                "ClosePrepared" => AnchorOperation::close_credential_renewal(&p),
                "Acknowledge" => AnchorOperation::acknowledge_credential_renewal(&p),
                _ => {
                    assert_eq!(action, "known action");
                    return;
                }
            };
            let rq = AnchorRequest::new(
                &store.pin().expect("pin"),
                p.subject(),
                operation,
                &peer.signer_r,
            )
            .expect("signed original operation");
            store.handle(rq.as_bytes(), 170).expect("original request");
        }
    }
    fs::write(path.join("joint-returned"), b"returned").expect("return marker");
}

#[test]
fn killed_prepare_apply_close_and_ack_keep_original_state_without_early_reply() {
    for action in [
        Transition::Prepare,
        Transition::Apply,
        Transition::ClosePrepared,
        Transition::CloseMissing,
        Transition::Acknowledge,
    ] {
        let mut c = credential_case();
        let g = credential_grant_first(&c);
        let p = proposal(&c, &g, 222);
        setup_transition(&mut c, p, &g, action);
        let target = g.successor_device().roster().checkpoint();
        let mut pin = target.version().to_be_bytes().to_vec();
        pin.extend_from_slice(&target.digest());
        fs::write(c.server.join("joint-target-pin"), pin).expect("independent target pin");
        fs::write(c.server.join("joint-grant"), g.as_bytes()).expect("original grant");
        fs::write(c.server.join("joint-proposal"), p.to_bytes()).expect("exact proposal");
        fs::write(c.server.join("joint-action"), format!("{action:?}")).expect("action");
        let revision = c.store.image().expect("before").revision;
        c.store.close();
        let log = fs::File::create_new(c.server.join("joint-child.log")).expect("child log");
        let mut child = ChildGuard(
            Process::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "anchor::store::tests::joint::joint_transition_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_JOINT_RENEWAL_DIR", &c.server)
                .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
                .env("QPERIAPT_ANCHOR_CRASH_REVISION", (revision + 1).to_string())
                .stdout(Stdio::from(log.try_clone().expect("clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !c.server.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "missing {action:?} commit: {}",
                fs::read_to_string(c.server.join("joint-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!c.server.join("joint-returned").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        c.store = reopen(&c.server);
        let expected = match action {
            Transition::Prepare => State::Prepared,
            Transition::Apply => State::Applied,
            Transition::ClosePrepared | Transition::CloseMissing => State::Closed,
            Transition::Acknowledge => State::Unavailable,
        };
        assert_eq!(
            status(&mut c, &p, 181),
            expected,
            "historical {action:?} after target expiry"
        );
        assert_eq!(
            c.store.image().expect("no second commit").revision,
            revision + 1
        );
        if matches!(action, Transition::Acknowledge) {
            assert_eq!(ack(&mut c, &p, 181), State::Acknowledged);
        } else if matches!(action, Transition::Prepare) {
            let rq = request(&c, AnchorOperation::commit_credential_renewal(&p));
            assert!(matches!(
                c.store.handle(rq.as_bytes(), 181),
                Err(AnchorError::Rejected(Error::Validity))
            ));
            assert_eq!(
                exchange(
                    &mut c,
                    &p,
                    AnchorOperation::close_credential_renewal(&p),
                    181
                ),
                State::Closed
            );
        }
    }
}

#[test]
fn joint_storage_upgrade_is_explicit_and_authenticated_inconsistent_floors_are_refused() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 223);
    let old = c.store.image().expect("old image");
    let active = c.store.active.as_ref().expect("active");
    assert_eq!(
        encode(&active.wrapping, &active.pin, &old)
            .expect("legacy")
            .get(..8),
        Some(b"QPANC002".as_slice())
    );
    prepare(&mut c, p, &g, 170);
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(status(&mut c, &p, 170), State::Prepared);
    let active = c.store.active.as_ref().expect("active");
    let image = load(&active.db, &active.wrapping, &active.pin).expect("current");
    let wire = encode(&active.wrapping, &active.pin, &image).expect("joint encoding");
    assert_eq!(wire.get(..8), Some(b"QPANC003".as_slice()));
    // Full MAC recomputation models an authenticated but semantically inconsistent
    // stored image; it must fail even though its outer storage tag verifies.
    let mut body = wire
        .get(..wire.len() - 32)
        .expect("authenticated body")
        .to_vec();
    let floor_offset = 50 + 32 + 96 + PUBLIC_KEY_BYTES + 32 + 32 + 16 + 32 + 48 + 33;
    body.get_mut(floor_offset..floor_offset + 8)
        .expect("floor field")
        .copy_from_slice(&2u64.to_be_bytes());
    let mut auth = authenticator(&active.wrapping).expect("state authenticator");
    auth.update(&body);
    body.extend_from_slice(&auth.finalize().into_bytes());
    assert!(matches!(
        decode(&active.wrapping, &active.pin, &body),
        Err(DurableError::Corrupt)
    ));
    let mut malformed = image;
    malformed
        .entries
        .get_mut(&p.subject().id(&c.pin.binding()))
        .expect("entry")
        .renewal_floor = 2;
    assert!(matches!(
        encode(&active.wrapping, &active.pin, &malformed),
        Err(DurableError::Corrupt)
    ));
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::close_credential_renewal(&p),
            181
        ),
        State::Closed
    );
    ack(&mut c, &p, 181);
    c.store.close();
    c.store = reopen(&c.server);
    let active = c.store.active.as_ref().expect("active");
    let mut image = load(&active.db, &active.wrapping, &active.pin).expect("retired");
    assert_eq!(
        encode(&active.wrapping, &active.pin, &image)
            .expect("floor retained")
            .get(..8),
        Some(b"QPANC003".as_slice())
    );
    image
        .entries
        .get_mut(&p.subject().id(&c.pin.binding()))
        .expect("entry")
        .renewal_floor = 0;
    assert!(matches!(
        encode(&active.wrapping, &active.pin, &image),
        Err(DurableError::Corrupt)
    ));
}

#[test]
fn independent_preparation_rejects_wrong_proposal_scope_and_noncurrent_predecessor() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 224);
    let original = c.store.image().expect("original").digest;
    for range in [
        8..40,
        40..72,
        72..104,
        104..136,
        136..168,
        168..200,
        216..248,
    ] {
        let mut bytes = p.to_bytes();
        bytes.get_mut(range).expect("bound metadata").fill(225);
        let changed = AnchorCredentialRenewalProposal::from_trusted_state(&bytes)
            .expect("well-formed different proposal");
        assert!(c
            .store
            .prepare_credential_renewal(changed, &g, c.peer.responder.policy(), 170)
            .is_err());
        assert!(c
            .store
            .close_credential_renewal(changed, &g, c.peer.responder.policy())
            .is_err());
        assert_eq!(c.store.image().expect("no mutation").digest, original);
    }
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            170
        ),
        State::Unavailable
    );
    c.store
        .renew_credential_authority(
            p.subject(),
            &g,
            g.operation(),
            c.peer.responder.policy(),
            170,
        )
        .expect("separate legacy lineage setup");
    assert!(matches!(
        c.store
            .prepare_credential_renewal(p, &g, c.peer.responder.policy(), 170),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store
            .close_credential_renewal(p, &g, c.peer.responder.policy()),
        Err(DurableError::Conflict)
    ));
}

#[test]
fn independently_reconstructed_expired_grant_and_policy_only_close_original_proposal() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let p = proposal(&c, &g, 217);
    let pin = g
        .successor_device()
        .roster()
        .historical_pin(g.successor_device().roster().checkpoint())
        .expect("independently retained exact target pin");
    let wire = g.as_bytes().to_vec();
    let policy = c.peer.responder.policy().historical().clone();
    assert!(matches!(
        crate::VerifiedCredentialRenewal::verify(&wire, &pin, policy.checkpoint().digest(), 250),
        Err(Error::Validity)
    ));
    let historical =
        crate::HistoricalCredentialRenewal::verify(&wire, &pin, policy.checkpoint().digest())
            .expect("expired grant metadata");
    c.peer.responder.policy().close();
    let before = c
        .store
        .image()
        .expect("before")
        .entries
        .remove(&p.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(
        c.store
            .close_credential_renewal(p, &historical, &policy)
            .expect("independent historical close"),
        State::Closed
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(status(&mut c, &p, 250), State::Closed);
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            250
        ),
        State::Closed
    );
    let after = c
        .store
        .image()
        .expect("after")
        .entries
        .remove(&p.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(
        (
            after.head,
            after.credential_owner,
            after.authority,
            after.validity,
            after.last
        ),
        (
            before.head,
            before.credential_owner,
            before.authority,
            before.validity,
            before.last
        )
    );
    assert_eq!(after.renewal_floor, 2);
    assert_eq!(ack(&mut c, &p, 250), State::Acknowledged);
    assert!(matches!(
        c.store.close_credential_renewal(p, &historical, &policy),
        Err(DurableError::Protocol(Error::Retired))
    ));
}

fn cancellation(
    c: &Case,
    grant: &crate::VerifiedCredentialRenewal,
) -> crate::AnchorCredentialRenewalCancellation {
    let mut bytes = b"QPCRNC01".to_vec();
    bytes.extend_from_slice(&c.pin.binding());
    bytes.extend_from_slice(&c.genesis.subject().to_bytes());
    bytes.extend_from_slice(grant.operation().as_bytes());
    bytes.extend_from_slice(&grant.statement_digest());
    initial(c).encode(&mut bytes);
    assert_eq!(bytes.len(), 248);
    crate::AnchorCredentialRenewalCancellation::from_trusted_state(&bytes)
        .expect("original grant closure expectation")
}
fn cancellation_exchange(
    c: &mut Case,
    cancel: &crate::AnchorCredentialRenewalCancellation,
    acknowledge: bool,
    now: u64,
) -> crate::AnchorCredentialCancellationState {
    let op = if acknowledge {
        AnchorOperation::acknowledge_credential_cancellation(cancel)
    } else {
        AnchorOperation::credential_cancellation_status(cancel)
    };
    let rq = request(c, op);
    let wire = c
        .store
        .handle(rq.as_bytes(), now)
        .expect("signed cancellation response");
    let reply = c
        .pin
        .verify_reply(&rq, &wire)
        .expect("fresh authenticated response");
    assert!(reply.applied_head().is_err());
    reply
        .credential_cancellation_state(cancel)
        .expect("exact independent cancellation")
}

#[test]
fn grant_only_close_never_creates_target_or_current_authority_and_floor_survives_pruning() {
    use crate::AnchorCredentialCancellationState as Cancel;
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let cancel = cancellation(&c, &g);
    let p = proposal(&c, &g, 218);
    let pin = g
        .successor_device()
        .roster()
        .historical_pin(g.successor_device().roster().checkpoint())
        .expect("retained target pin");
    let historical =
        crate::HistoricalCredentialRenewal::verify(g.as_bytes(), &pin, g.policy_digest())
            .expect("historical grant");
    let policy = c.peer.responder.policy().historical().clone();
    c.peer.responder.policy().close();
    assert_eq!(
        cancellation_exchange(&mut c, &cancel, false, 250),
        Cancel::Unavailable
    );
    let before = c
        .store
        .image()
        .expect("before")
        .entries
        .remove(&cancel.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(cancel, &historical, &policy)
            .expect("close grant"),
        Cancel::Closed
    );
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(cancel, &historical, &policy)
            .expect("exact retry"),
        Cancel::Closed
    );
    let image = c.store.image().expect("image");
    let active = c.store.active.as_ref().expect("active");
    assert_eq!(
        encode(&active.wrapping, &active.pin, &image)
            .expect("new encoding")
            .get(..8)
            .expect("version tag"),
        b"QPANC004"
    );
    let after = image
        .entries
        .get(&cancel.subject().id(&c.pin.binding()))
        .expect("entry");
    assert_eq!(
        (
            after.head,
            after.credential_owner,
            after.authority,
            after.validity,
            after.last
        ),
        (
            before.head,
            before.credential_owner,
            before.authority,
            before.validity,
            before.last
        )
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        cancellation_exchange(&mut c, &cancel, false, 250),
        Cancel::Closed
    );
    assert_eq!(status(&mut c, &p, 250), State::Unavailable);
    for kind in [5, 7] {
        let mut op = vec![kind];
        op.extend_from_slice(&cancel.binding());
        op.extend_from_slice(&[0; 64]);
        let rq = request(
            &c,
            AnchorOperation::from_trusted_state(&op).expect("canonical command"),
        );
        assert!(matches!(
            c.store.handle(rq.as_bytes(), 250),
            Err(AnchorError::Rejected(Error::State))
        ));
    }
    assert_eq!(
        cancellation_exchange(&mut c, &cancel, true, 250),
        Cancel::Acknowledged
    );
    assert_eq!(
        cancellation_exchange(&mut c, &cancel, true, 250),
        Cancel::Acknowledged
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        cancellation_exchange(&mut c, &cancel, false, 250),
        Cancel::Unavailable
    );
    assert!(matches!(
        c.store
            .close_unprepared_credential_renewal(cancel, &historical, &policy),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        c.store
            .prepare_credential_renewal(p, &g, c.peer.responder.policy(), 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
}

#[test]
fn grant_only_close_preserves_every_hidden_original_proposal_and_never_relabels_applied() {
    for desired in [State::Prepared, State::Applied, State::Closed] {
        let mut c = credential_case();
        let g = credential_grant_first(&c);
        let p = proposal(&c, &g, 219);
        let cancel = cancellation(&c, &g);
        assert_eq!(prepare(&mut c, p, &g, 150), State::Prepared);
        if desired != State::Prepared {
            let operation = if desired == State::Applied {
                AnchorOperation::commit_credential_renewal(&p)
            } else {
                AnchorOperation::close_credential_renewal(&p)
            };
            assert_eq!(exchange(&mut c, &p, operation, 150), desired);
        }
        let before = c.store.image().expect("before").digest;
        assert!(matches!(
            c.store
                .close_unprepared_credential_renewal(cancel, &g, c.peer.responder.policy()),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.store.image().expect("unchanged").digest, before);
        c.store.close();
        c.store = reopen(&c.server);
        assert_eq!(status(&mut c, &p, 250), desired);
        assert_eq!(
            cancellation_exchange(&mut c, &cancel, false, 250),
            crate::AnchorCredentialCancellationState::Unavailable
        );
        if desired != State::Prepared {
            assert_eq!(ack(&mut c, &p, 250), State::Acknowledged);
            assert!(matches!(
                c.store
                    .close_unprepared_credential_renewal(cancel, &g, c.peer.responder.policy()),
                Err(DurableError::Protocol(Error::Retired))
            ));
        }
    }
}

#[test]
fn grant_only_close_and_ordinary_transition_obey_exact_head_and_unacknowledged_slot_exclusion() {
    use crate::AnchorCredentialCancellationState as Cancel;
    for closure_first in [false, true] {
        let mut c = credential_case();
        let g = credential_grant_first(&c);
        let cancel = cancellation(&c, &g);
        let advance = request(
            &c,
            AnchorOperation::advance(initial(&c), [220; 32]).expect("advance"),
        );
        let fence = request(
            &c,
            AnchorOperation::fence_writer(initial(&c)).expect("fence"),
        );
        if closure_first {
            assert_eq!(
                c.store
                    .close_unprepared_credential_renewal(cancel, &g, c.peer.responder.policy())
                    .expect("close first"),
                Cancel::Closed
            );
            for rq in [&advance, &fence] {
                assert!(matches!(
                    c.store.handle(rq.as_bytes(), 150),
                    Err(AnchorError::Rejected(Error::State))
                ));
            }
            assert_eq!(
                cancellation_exchange(&mut c, &cancel, false, 150),
                Cancel::Closed
            );
            assert_eq!(
                cancellation_exchange(&mut c, &cancel, true, 150),
                Cancel::Acknowledged
            );
            let wire = c
                .store
                .handle(advance.as_bytes(), 150)
                .expect("ordinary current authorization after ACK");
            c.pin
                .verify_reply(&advance, &wire)
                .expect("advance")
                .applied_head()
                .expect("applied");
        } else {
            let wire = c
                .store
                .handle(advance.as_bytes(), 150)
                .expect("advance first");
            c.pin
                .verify_reply(&advance, &wire)
                .expect("advance")
                .applied_head()
                .expect("applied");
            let before = c.store.image().expect("before").digest;
            assert!(matches!(
                c.store
                    .close_unprepared_credential_renewal(cancel, &g, c.peer.responder.policy()),
                Err(DurableError::Conflict)
            ));
            assert_eq!(c.store.image().expect("after").digest, before);
        }
    }
}

#[test]
fn cancellation_statement_identity_and_domain_survive_same_operation_alias_and_old_ack() {
    use crate::AnchorCredentialCancellationState as Cancel;
    let mut c = credential_case();
    let first = credential_grant_first(&c);
    let alias = credential_grant(&c, c.peer.responder.inventory_inputs().1, 2, 181);
    assert_eq!(first.operation(), alias.operation());
    assert_ne!(first.statement_digest(), alias.statement_digest());
    let one = cancellation(&c, &first);
    let other = cancellation(&c, &alias);
    let p = proposal(&c, &first, 221);
    assert_ne!(one.binding(), other.binding());
    assert_ne!(one.binding(), p.binding());
    assert!(matches!(
        c.store
            .close_unprepared_credential_renewal(other, &first, c.peer.responder.policy()),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(one, &first, c.peer.responder.policy())
            .expect("first close"),
        Cancel::Closed
    );
    assert!(matches!(
        c.store
            .close_unprepared_credential_renewal(other, &alias, c.peer.responder.policy()),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        cancellation_exchange(&mut c, &one, true, 150),
        Cancel::Acknowledged
    );
    assert!(matches!(
        c.store
            .close_unprepared_credential_renewal(other, &alias, c.peer.responder.policy()),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let next = credential_grant(&c, c.peer.responder.inventory_inputs().1, 3, 190);
    let next_cancel = cancellation(&c, &next);
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(next_cancel, &next, c.peer.responder.policy())
            .expect("new root grant"),
        Cancel::Closed
    );
    assert_eq!(
        cancellation_exchange(&mut c, &one, true, 150),
        Cancel::Acknowledged
    );
    assert_eq!(
        cancellation_exchange(&mut c, &next_cancel, false, 150),
        Cancel::Closed
    );
}

#[test]
fn cancellation_scope_fresh_reply_and_authenticated_storage_shape_are_exact() {
    use crate::{
        AnchorCredentialCancellationState as Cancel,
        AnchorCredentialRenewalCancellation as Cancellation,
    };
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let cancel = cancellation(&c, &g);
    let before = c.store.image().expect("before").digest;
    for range in [
        8..40,
        40..72,
        72..104,
        104..136,
        136..168,
        168..200,
        200..208,
        208..216,
        216..248,
    ] {
        let mut bytes = cancel.to_bytes();
        bytes.get_mut(range).expect("descriptor field").fill(226);
        let changed =
            Cancellation::from_trusted_state(&bytes).expect("well formed substituted expectation");
        assert!(c
            .store
            .close_unprepared_credential_renewal(changed, &g, c.peer.responder.policy())
            .is_err());
        assert_eq!(c.store.image().expect("unchanged").digest, before);
    }
    for bytes in [
        cancel
            .to_bytes()
            .get(..247)
            .expect("truncated descriptor")
            .to_vec(),
        [cancel.to_bytes(), vec![0]].concat(),
        proposal(&c, &g, 227).to_bytes(),
    ] {
        assert!(Cancellation::from_trusted_state(&bytes).is_err());
    }
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(cancel, &g, c.peer.responder.policy())
            .expect("close"),
        Cancel::Closed
    );
    let request1 = request(&c, AnchorOperation::credential_cancellation_status(&cancel));
    let request2 = request(&c, AnchorOperation::credential_cancellation_status(&cancel));
    let wire = c.store.handle(request1.as_bytes(), 250).expect("reply");
    assert!(c.pin.verify_reply(&request2, &wire).is_err());
    let reply = c
        .pin
        .verify_reply(&request1, &wire)
        .expect("original attempt");
    let mut changed = cancel.to_bytes();
    *changed.get_mut(168).expect("statement byte") ^= 1;
    let changed = Cancellation::from_trusted_state(&changed).expect("other statement");
    assert!(reply.credential_cancellation_state(&changed).is_err());
    let query = request(&c, AnchorOperation::query());
    let wire = c.store.handle(query.as_bytes(), 250).expect("query");
    assert!(c
        .pin
        .verify_reply(&query, &wire)
        .expect("signed query")
        .credential_cancellation_state(&cancel)
        .is_err());
    let active = c.store.active.as_ref().expect("active");
    let mut image = load(&active.db, &active.wrapping, &active.pin).expect("valid image");
    let valid = encode(&active.wrapping, &active.pin, &image).expect("004 encoding");
    for floor in [0, 1, 3, u64::MAX] {
        image
            .entries
            .get_mut(&cancel.subject().id(&c.pin.binding()))
            .expect("entry")
            .renewal_floor = floor;
        assert!(encode(&active.wrapping, &active.pin, &image).is_err());
    }
    let mut downgraded = valid
        .get(..valid.len() - 32)
        .expect("authenticated body")
        .to_vec();
    downgraded
        .get_mut(..8)
        .expect("version tag")
        .copy_from_slice(b"QPANC003");
    let mut auth = authenticator(&active.wrapping).expect("test authenticator");
    auth.update(&downgraded);
    downgraded.extend_from_slice(&auth.finalize().into_bytes());
    assert!(matches!(
        decode(&active.wrapping, &active.pin, &downgraded),
        Err(DurableError::Corrupt)
    ));
}

fn cancellation_transition(
    c: &mut Case,
    cancel: crate::AnchorCredentialRenewalCancellation,
    grant: &crate::VerifiedCredentialRenewal,
    acknowledge: bool,
) -> Result<crate::AnchorCredentialCancellationState, DurableError> {
    if !acknowledge {
        return c.store.close_unprepared_credential_renewal(
            cancel,
            grant,
            c.peer.responder.policy(),
        );
    }
    let rq = request(
        c,
        AnchorOperation::acknowledge_credential_cancellation(&cancel),
    );
    let wire = c
        .store
        .handle(rq.as_bytes(), 250)
        .map_err(|error| match error {
            AnchorError::Storage(error) => error,
            AnchorError::Rejected(error) | AnchorError::ReplyUnavailable(error) => error.into(),
        })?;
    Ok(c.pin
        .verify_reply(&rq, &wire)?
        .credential_cancellation_state(&cancel)?)
}
#[test]
fn every_grant_cancellation_and_ack_sync_cut_preserves_original_head_and_exact_retirement() {
    use crate::AnchorCredentialCancellationState as Cancel;
    let mut faults = 0;
    let mut expected_faults = 0;
    for acknowledge in [false, true] {
        let mut baseline = credential_case();
        let g = credential_grant_first(&baseline);
        let cancel = cancellation(&baseline, &g);
        if acknowledge {
            cancellation_transition(&mut baseline, cancel, &g, false).expect("setup close");
        }
        let (_, count) = with_fault_database(&mut baseline, false);
        count.store(0, Ordering::SeqCst);
        let target =
            cancellation_transition(&mut baseline, cancel, &g, acknowledge).expect("baseline");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        expected_faults += 2 * barriers;
        eprintln!("GRANT_CANCELLATION_MEASURED ack={acknowledge} barriers={barriers}");
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut c = credential_case();
                let g = credential_grant_first(&c);
                let cancel = cancellation(&c, &g);
                if acknowledge {
                    cancellation_transition(&mut c, cancel, &g, false).expect("setup close");
                }
                let revision = c.store.image().expect("original revision").revision;
                let (remaining, _) = with_fault_database(&mut c, after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    cancellation_transition(&mut c, cancel, &g, acknowledge),
                    after,
                );
                assert!(c.store.active.is_none());
                c.store = reopen(&c.server);
                assert_eq!(
                    cancellation_transition(&mut c, cancel, &g, acknowledge).expect("exact retry"),
                    target
                );
                let image = c.store.image().expect("recovered once");
                assert_eq!(image.revision, revision + 1);
                let entry = image
                    .entries
                    .get(&cancel.subject().id(&c.pin.binding()))
                    .expect("entry");
                assert_eq!(entry.head, cancel.expected_head());
                assert_eq!(entry.renewal_floor, 2);
                assert_eq!(entry.credential_owner, storage_owner(g.previous_device()));
                assert_eq!(
                    cancellation_exchange(&mut c, &cancel, false, 250),
                    if acknowledge {
                        Cancel::Unavailable
                    } else {
                        Cancel::Closed
                    }
                );
                faults += 1;
            }
        }
    }
    assert_eq!(faults, expected_faults);
    assert!(faults >= 8);
    eprintln!("GRANT_CANCELLATION_SYNC_FAULTS={faults}");
}
