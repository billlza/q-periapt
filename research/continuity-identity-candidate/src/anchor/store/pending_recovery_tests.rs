// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Store-only guard/protocol fixtures; enrollment tests use actual sealed images.
use super::*;
use crate::{anchor::PendingWriteRecoveryScope, AnchorPendingWriteRecoveryProposal};

fn prepared(c: &Case) -> (AnchorPendingWriteRecoveryProposal, Vec<u8>, Vec<u8>) {
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original credential");
    let scope = PendingWriteRecoveryScope {
        witness: c.pin.binding(),
        subject: c.genesis.subject(),
        expected: initial(c),
        target: AnchorHead::from_trusted_state(1, 2, [91; 32]).expect("test target"),
        authority: device.authority_binding(),
        policy: policy.checkpoint().digest(),
        policy_authorization: None,
        intent: [92; 32],
    };
    // Only controller binding/serialization is under test here. These are not
    // claims about real journal records, host accounting, or device acceptance.
    let mut metadata = scope.metadata_prefix().expect("scope");
    for _ in 0..2 {
        metadata.extend_from_slice(&96u64.to_be_bytes());
        metadata.extend_from_slice(&[0; 96]);
    }
    let p = scope.proposal(&metadata).expect("expectation");
    let signature = c
        .peer
        .signer_r
        .sign(Purpose::PendingWriteRecovery, &p.to_bytes())
        .expect("historical origin");
    let wire = crate::crypto::envelope(&p.to_bytes(), &signature).expect("request");
    (p, metadata, wire)
}

#[derive(Clone, Copy, Debug)]
enum Guard {
    Live,
    Head,
    Authority,
    Renewal,
    Frozen,
}

#[test]
fn pending_write_recovery_control_requires_exact_live_subject_expired_authority_and_free_slot() {
    for guard in [
        Guard::Live,
        Guard::Head,
        Guard::Authority,
        Guard::Renewal,
        Guard::Frozen,
    ] {
        let mut c = credential_case();
        let (p, metadata, wire) = prepared(&c);
        match guard {
            Guard::Live => {}
            Guard::Head => {
                let rq = request(
                    &c,
                    AnchorOperation::advance(initial(&c), [34; 32]).expect("different command"),
                );
                apply_request(&mut c, &rq);
            }
            Guard::Authority => {
                let g = credential_grant_first(&c);
                let policy = c.peer.responder.current_policy().expect("P0");
                c.store
                    .renew_credential_authority(c.genesis.subject(), &g, g.operation(), policy, 170)
                    .expect("real changed authority at same head");
            }
            Guard::Renewal => {
                let g = credential_grant_first(&c);
                let proposal = crate::AnchorCredentialRenewalProposal::from_journal(
                    c.pin.binding(),
                    c.genesis.subject(),
                    g.operation(),
                    g.statement_digest(),
                    initial(&c),
                    AnchorHead::from_trusted_state(1, 2, [31; 32]).expect("G target"),
                )
                .expect("independent G proposal");
                c.store
                    .prepare_credential_renewal(
                        proposal,
                        &g,
                        c.peer.responder.current_policy().expect("P0"),
                        170,
                    )
                    .expect("real unacknowledged G slot");
            }
            Guard::Frozen => {
                let root = c
                    .peer
                    .responder
                    .inventory_inputs()
                    .expect("original root")
                    .1
                    .authority_key
                    .clone();
                let freeze = crate::AnchorAccountFreezeRequest::from_trusted_state(
                    crate::AnchorAccountFreezeId::generate().expect("freeze ID"),
                    root,
                    &c.pin,
                )
                .expect("independent freeze scope");
                c.store
                    .freeze_account(&freeze)
                    .expect("actual account frozen");
            }
        }
        let before = c.store.image().expect("original witness state");
        assert!(
            c.store
                .complete_pending_write_recovery(
                    &p,
                    &wire,
                    &metadata,
                    if matches!(guard, Guard::Live) {
                        160
                    } else {
                        190
                    }
                )
                .is_err(),
            "guard {guard:?}"
        );
        let after = c.store.image().expect("unchanged witness state");
        assert_eq!(
            (after.revision, after.digest),
            (before.revision, before.digest),
            "guard {guard:?} mutated state"
        );
        if matches!(guard, Guard::Live) {
            assert_eq!(
                c.store
                    .complete_pending_write_recovery(&p, &wire, &metadata, 170)
                    .expect("expired independent completion"),
                p.target_head()
            );
        }
        eprintln!("PENDING_RECOVERY_GUARD {guard:?} refused_without_mutation=true");
    }
}

#[test]
fn pending_write_recovery_proposal_rejects_truncated_extended_and_noncanonical_inputs() {
    let c = credential_case();
    let (p, metadata, _) = prepared(&c);
    for range in [361..369, 465..473] {
        let mut changed = metadata.clone();
        changed.get_mut(range).expect("frame length").fill(255);
        assert!(p.scope.clone().proposal(&changed).is_err());
    }
    let mut extra_metadata = metadata;
    extra_metadata.push(0);
    assert!(p.scope.clone().proposal(&extra_metadata).is_err());
    let wire = p.to_bytes();
    assert_eq!(
        AnchorPendingWriteRecoveryProposal::from_trusted_state(&wire).expect("canonical"),
        p
    );
    for n in 0..wire.len() {
        assert!(AnchorPendingWriteRecoveryProposal::from_trusted_state(
            wire.get(..n).expect("prefix")
        )
        .is_err());
    }
    let mut extended = wire.clone();
    extended.push(0);
    assert!(AnchorPendingWriteRecoveryProposal::from_trusted_state(&extended).is_err());
    for (range, byte) in [
        (0..8, 0),
        (8..40, 0),
        (184..200, 0),
        (296..297, 2),
        (297..329, 1),
        (329..361, 0),
        (361..393, 0),
    ] {
        let mut changed = wire.clone();
        changed.get_mut(range).expect("field").fill(byte);
        assert!(AnchorPendingWriteRecoveryProposal::from_trusted_state(&changed).is_err());
    }
}

#[test]
fn pending_write_recovery_control_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_PENDING_RECOVERY_SERVER") else {
        return;
    };
    let path = Path::new(&path);
    let mut store = reopen(path);
    let p = AnchorPendingWriteRecoveryProposal::from_trusted_state(
        &fs::read(path.join("approved.bin")).expect("approved"),
    )
    .expect("original approval");
    let metadata = fs::read(path.join("metadata.bin")).expect("retained metadata");
    let signed = fs::read(path.join("request.bin")).expect("original signed request");
    store
        .complete_pending_write_recovery(&p, &signed, &metadata, 170)
        .expect("original completion");
    fs::write(path.join("returned-result"), b"returned").expect("only after actual method return");
}

#[test]
fn pending_write_recovery_control_survives_process_loss_after_commit_before_return() {
    let mut c = credential_case();
    let (p, metadata, wire) = prepared(&c);
    fs::write(c.server.join("approved.bin"), p.to_bytes()).expect("approved public proposal");
    fs::write(c.server.join("metadata.bin"), &metadata).expect("full controller metadata");
    fs::write(c.server.join("request.bin"), &wire).expect("signed request");
    let revision = c.store.image().expect("before").revision;
    c.store.close();
    let log = fs::File::create(c.server.join("child.log")).expect("log");
    let mut child = ChildGuard(Process::new(std::env::current_exe().expect("binary"))
        .args(["--exact", "anchor::store::tests::pending_recovery::pending_write_recovery_control_crash_child", "--nocapture"])
        .env("QPERIAPT_PENDING_RECOVERY_SERVER", &c.server)
        .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
        .env("QPERIAPT_ANCHOR_CRASH_REVISION", (revision+1).to_string())
        .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log))
        .spawn().expect("owned controller process"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "controller commit deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-result").exists());
    child.0.kill().expect("kill owned controller");
    assert!(!child.0.wait().expect("reap owned controller").success());
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .complete_pending_write_recovery(&p, &wire, &metadata, 170)
            .expect("exact original retry"),
        p.target_head()
    );
    assert_eq!(
        c.store.image().expect("one durable mutation").revision,
        revision + 1
    );
    let rq = request(&c, AnchorOperation::query());
    let reply = c
        .store
        .handle(rq.as_bytes(), 170)
        .expect("fresh signed query");
    p.confirm_reply(&c.pin.verify_reply(&rq, &reply).expect("verified reply"))
        .expect("exact target and last command");
    eprintln!("PENDING_RECOVERY_PROCESS_LOSS actual_child_killed=true after_commit_before_return=true exact_retry=true one_mutation=true");
}
