// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    fs,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
#[path = "tests/support.rs"]
mod support;
use support::*;
#[path = "tests/account_authority.rs"]
mod account_authority;
#[path = "tests/peer_retirement.rs"]
mod peer_retirement;

fn fault_recovery(
    owner: &mut AccountRootJournalRecovery,
    path: &Path,
    after: bool,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let old = *owner.active.take().expect("restricted original owner");
    drop(old.db);
    let (db, remaining, count, _) = crate::durable::tests::fault_database_path(path, after);
    owner.active = Some(Box::new(Owners { db, ..old }));
    (remaining, count)
}

pub(super) fn at_boundary(stage: &str, after: bool) {
    let Some(path) = std::env::var_os("QPERIAPT_ROOT_FENCE_DIR") else {
        return;
    };
    let Ok(selected) = std::env::var("QPERIAPT_ROOT_FENCE_CUT") else {
        return;
    };
    if selected != format!("{stage}-{}", if after { "after" } else { "before" }) {
        return;
    }
    fs::write(Path::new(&path).join("ready"), selected).expect("owned child checkpoint");
    loop {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn account_root_local_fence_blocks_old_context_and_reopen_without_advancing_the_witness() {
    let mut c = case();
    let (mut peer, session) = c.connected_peer();
    let id = c
        .journal
        .next_message_id(&c.f.responder, session, 150)
        .expect("original message identity");
    let wire = c
        .journal
        .send_message(
            &c.f.responder,
            session,
            id,
            b"original unacknowledged data",
            b"root-cutover",
            150,
        )
        .expect("real committed ciphertext");
    assert_eq!(
        peer.receive_message(&c.f.initiator, session, &wire, b"root-cutover", 150)
            .expect("real peer receive")
            .as_bytes(),
        b"original unacknowledged data"
    );
    let original = rows(&c.journal.active.as_ref().expect("live journal").db);
    let p = c.proposal(201);
    let mut recovery = c
        .journal
        .begin_account_root_replacement(c.pin.clone(), p.clone())
        .expect("durable local fence");
    assert_eq!(
        recovery.status().expect("local observation"),
        AccountRootJournalState::LocalFenced
    );
    assert!(matches!(
        c.journal.resume_message(&c.f.responder, session, id, 150),
        Err(DurableError::Closed)
    ));
    assert_eq!(
        rows(&recovery.active.as_ref().expect("restricted owner").db),
        original
    );
    let request = crate::AnchorRequest::new(
        &c.pin,
        c.genesis.subject(),
        crate::AnchorOperation::query(),
        &c.f.signer_r,
    )
    .expect("signed fresh witness query");
    let answer = c
        .witness
        .lock()
        .expect("witness lock")
        .handle(request.as_bytes(), 150)
        .expect("witness still live before commit");
    assert_eq!(
        c.pin
            .verify_reply(&request, &answer)
            .expect("fresh witness answer")
            .outcome(),
        crate::AnchorOutcome::Current
    );
    recovery.close();
    c.assert_ordinary_refused();
    let mut recovery = c.resume(&p);
    assert_eq!(recovery.proposal().expect("original proposal"), p);
    let receipt = c.receipt(&p);
    assert_eq!(
        recovery
            .retain_witness_retirement(&receipt)
            .expect("retain exact decision"),
        AccountRootJournalState::WitnessCommitted
    );
    assert_eq!(
        recovery
            .retirement()
            .expect("signed historical decision")
            .proposal(),
        &p
    );
    assert_eq!(
        rows(&recovery.active.as_ref().expect("restricted owner").db),
        original
    );
    assert!(!wire.is_empty());
    recovery.close();
    c.assert_ordinary_refused();
}

#[test]
fn account_root_local_fence_does_not_enroll_or_activate_the_target() {
    let mut c = case();
    let p = c.proposal(202);
    let mut r = c
        .journal
        .begin_account_root_replacement(c.pin.clone(), p.clone())
        .expect("local fence");
    let open = || {
        DeviceJournal::open_anchored(
            &c.next_path.join("state.redb"),
            JournalKey::open(&c.next_path.join("key")).expect("target key"),
            &c.next,
            c.f.responder.current_policy().expect("policy"),
            c.next_identity,
            c.client(true),
        )
    };
    assert!(open().is_err());
    let receipt = c.receipt(&p);
    r.retain_witness_retirement(&receipt)
        .expect("retained original witness decision");
    let mut target = open().expect("fresh authenticated target after witness commit");
    assert_eq!(
        target.identity().expect("new journal identity"),
        c.next_identity
    );
    target.close();
    r.close();
    c.assert_ordinary_refused();
}

#[test]
fn account_root_local_fence_conflicting_proposal_or_receipt_never_overwrites_the_original() {
    let mut c = case();
    let p = c.proposal(203);
    let competing = c.proposal(204);
    let mut r = c
        .journal
        .begin_account_root_replacement(c.pin.clone(), p.clone())
        .expect("local fence");
    r.close();
    assert!(matches!(
        AccountRootJournalRecovery::resume_original(
            &c.path.join("state.redb"),
            c.key(),
            c.f.local_device(),
            c.identity,
            c.pin.clone(),
            competing
        ),
        Err(DurableError::Conflict)
    ));
    let mut r = c.resume(&p);
    let mut receipt = c.receipt(&p);
    *receipt.last_mut().expect("signature byte") ^= 1;
    assert!(matches!(
        r.retain_witness_retirement(&receipt),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert!(r.active.is_none());
    let mut r = c.resume(&p);
    assert_eq!(
        r.status().expect("original local fence"),
        AccountRootJournalState::LocalFenced
    );
    r.close();
    c.assert_ordinary_refused();
}

#[test]
fn account_root_local_fence_retains_original_pending_write_without_applying_it() {
    let mut c = case();
    let mut image = c.journal.image().expect("actual original image");
    image.revision += 1;
    let active = c.journal.active.as_ref().expect("live journal");
    let next = seal(&active.key, &image).expect("actual sealed next image");
    let pending = PendingWrite::new(active, &image, &next).expect("original pending write");
    reserve(active, &pending).expect("durable write intent");
    let original = rows(&active.db);
    assert!(original.1.is_some());
    let p = c.proposal(205);
    let mut r = c
        .journal
        .begin_account_root_replacement(c.pin.clone(), p.clone())
        .expect("fence original pending intent");
    assert_eq!(
        rows(&r.active.as_ref().expect("restricted owner").db),
        original
    );
    let receipt = c.receipt(&p);
    r.retain_witness_retirement(&receipt)
        .expect("exact witness decision");
    assert_eq!(
        rows(&r.active.as_ref().expect("restricted owner").db),
        original
    );
    r.close();
    c.assert_ordinary_refused();
    let mut r = c.resume(&p);
    assert_eq!(
        rows(&r.active.as_ref().expect("restricted owner").db),
        original
    );
    r.close();
}

#[test]
fn account_root_local_fence_each_sync_failure_preserves_exact_image_and_reconciles_original() {
    let mut calibration = case();
    let p = calibration.proposal(206);
    let (_, count) = crate::durable::tests::fault_existing_journal(
        &mut calibration.journal,
        &calibration.path.join("state.redb"),
        false,
    );
    count.store(0, Ordering::SeqCst);
    let mut r = calibration
        .journal
        .begin_account_root_replacement(calibration.pin.clone(), p)
        .expect("calibrated fence");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    r.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = case();
            let p = c.proposal(207);
            let original = rows(&c.journal.active.as_ref().expect("live").db);
            let (remaining, _) = crate::durable::tests::fault_existing_journal(
                &mut c.journal,
                &c.path.join("state.redb"),
                after,
            );
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                c.journal
                    .begin_account_root_replacement(c.pin.clone(), p.clone()),
                after,
            );
            assert!(c.journal.active.is_none());
            let mut r = c.resume(&p);
            assert_eq!(
                rows(&r.active.as_ref().expect("recovered owner").db),
                original
            );
            assert_eq!(
                r.status().expect("local fence"),
                AccountRootJournalState::LocalFenced
            );
            r.close();
            c.assert_ordinary_refused();
        }
    }
    eprintln!(
        "ACCOUNT_ROOT_LOCAL_FENCE_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn account_root_local_receipt_each_sync_failure_reconciles_the_original_historical_decision() {
    let mut calibration = case();
    let p = calibration.proposal(208);
    let mut r = calibration
        .journal
        .begin_account_root_replacement(calibration.pin.clone(), p.clone())
        .expect("original fence");
    let receipt = calibration.receipt(&p);
    let (_, count) = fault_recovery(&mut r, &calibration.path.join("state.redb"), false);
    count.store(0, Ordering::SeqCst);
    r.retain_witness_retirement(&receipt)
        .expect("calibrated receipt retention");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    r.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = case();
            let p = c.proposal(209);
            let mut r = c
                .journal
                .begin_account_root_replacement(c.pin.clone(), p.clone())
                .expect("original fence");
            let original = rows(&r.active.as_ref().expect("restricted owner").db);
            let receipt = c.receipt(&p);
            let (remaining, _) = fault_recovery(&mut r, &c.path.join("state.redb"), after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                r.retain_witness_retirement(&receipt),
                after,
            );
            assert!(r.active.is_none());
            let mut r = c.resume(&p);
            r.retain_witness_retirement(&receipt)
                .expect("reconcile original signed decision");
            assert_eq!(
                r.status().expect("retained decision"),
                AccountRootJournalState::WitnessCommitted
            );
            assert_eq!(
                rows(&r.active.as_ref().expect("restricted owner").db),
                original
            );
            let first = r
                .active
                .as_ref()
                .expect("restricted owner")
                .read()
                .expect("retained marker");
            let repeated = c.receipt(&p);
            r.retain_witness_retirement(&repeated)
                .expect("same statement re-signing");
            assert_eq!(
                r.active
                    .as_ref()
                    .expect("restricted owner")
                    .read()
                    .expect("unchanged marker")
                    .receipt,
                first.receipt
            );
            r.close();
            c.assert_ordinary_refused();
        }
    }
    eprintln!(
        "ACCOUNT_ROOT_LOCAL_RECEIPT_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn account_root_local_fence_authentication_scope_schema_and_exact_original_bytes_are_required() {
    for damage in ["mac", "image", "extra", "proposal"] {
        let mut c = case();
        let p = c.proposal(210);
        let mut r = c
            .journal
            .begin_account_root_replacement(c.pin.clone(), p.clone())
            .expect("original fence");
        let owners = r.active.as_ref().expect("restricted owner");
        let original = owners.read().expect("authenticated fence");
        let mut changed = original.clone();
        if damage == "image" {
            changed.image = [211; 32];
        }
        if damage == "proposal" {
            changed.proposal = c.proposal(211);
        }
        let mut bytes = changed
            .encode(&owners.key)
            .expect("canonical fixture marker");
        if damage == "mac" {
            *bytes.last_mut().expect("MAC byte") ^= 1;
        }
        let tx = transaction(&owners.db).expect("fixture transaction");
        {
            let mut table = tx.open_table(TABLE).expect("original table");
            table.insert(ROW, bytes.as_slice()).expect("fixture marker");
            if damage == "extra" {
                table
                    .insert("unrecognized", b"extra".as_slice())
                    .expect("adversarial extra row");
            }
        }
        tx.commit().expect("fixture commit");
        assert!(r.status().is_err());
        assert!(r.active.is_none());
        assert!(AccountRootJournalRecovery::resume_original(
            &c.path.join("state.redb"),
            c.key(),
            c.f.local_device(),
            c.identity,
            c.pin.clone(),
            p
        )
        .is_err());
        assert!(DeviceJournal::open(
            &c.path.join("state.redb"),
            c.key(),
            c.f.local_device(),
            c.identity
        )
        .is_err());
    }
}

#[test]
fn account_root_local_recovery_remains_historical_after_runtime_closure() {
    let mut c = case();
    let p = c.proposal(213);
    let mut r = c
        .journal
        .begin_account_root_replacement(c.pin.clone(), p.clone())
        .expect("original fence");
    let receipt = c.receipt(&p);
    c.f.responder
        .current_policy()
        .expect("fixture runtime")
        .close();
    assert_eq!(
        r.retain_witness_retirement(&receipt)
            .expect("historical witness fact"),
        AccountRootJournalState::WitnessCommitted
    );
    r.close();
    let mut r = c.resume(&p);
    assert_eq!(
        r.retirement().expect("permanent signed fact").proposal(),
        &p
    );
    r.close();
    c.assert_ordinary_refused();
}

#[test]
fn account_root_local_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ROOT_FENCE_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let identity = crate::AnchorIdentity::from_trusted_state(
        fs::read(path.join("witness-id"))
            .expect("retained public identity")
            .try_into()
            .expect("identity width"),
    )
    .expect("witness identity");
    let public = crate::PublicKey::decode(
        &fs::read(path.join("witness-public")).expect("retained witness key"),
    )
    .expect("public key");
    let pin = AnchorPin::new(identity, public);
    let f = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        crate::PrekeyQuality::OneTimeBoth,
        crate::AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    let journal = JournalIdentity::from_trusted_state(
        fs::read(path.join("store-id"))
            .expect("original identity")
            .try_into()
            .expect("identity width"),
    )
    .expect("journal identity");
    let p = Proposal::from_trusted_state(
        &fs::read(path.join("original-proposal")).expect("original proposal bytes"),
    )
    .expect("retained proposal");
    let mut r = AccountRootJournalRecovery::resume_original(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("original key"),
        f.local_device(),
        journal,
        pin,
        p,
    )
    .expect("original child recovery");
    if std::env::var("QPERIAPT_ROOT_FENCE_CUT")
        .expect("selected cut")
        .starts_with("receipt-")
    {
        r.retain_witness_retirement(
            &fs::read(path.join("receipt")).expect("original signed reply"),
        )
        .expect("child receipt retention");
    }
    fs::write(path.join("returned"), b"returned").expect("child API return marker");
}

#[test]
fn account_root_local_process_loss_at_both_commits_keeps_one_fence_and_original_inventory() {
    use std::process::{Command, Stdio};
    for stage in ["fence", "receipt"] {
        for after in [false, true] {
            let mut c = case();
            let p = c.proposal(214);
            let original = rows(&c.journal.active.as_ref().expect("live original").db);
            fs::write(c.path.join("witness-id"), c.pin.identity().as_bytes())
                .expect("retain independent public identity");
            fs::write(c.path.join("witness-public"), c.pin.public_key().encode())
                .expect("retain independent public key");
            fs::write(
                c.path.join("original-proposal"),
                p.to_bytes().expect("original proposal bytes"),
            )
            .expect("retain approved operation");
            if stage == "receipt" {
                let mut r = c
                    .journal
                    .begin_account_root_replacement(c.pin.clone(), p.clone())
                    .expect("first fence commit");
                r.close();
                fs::write(c.path.join("receipt"), c.receipt(&p)).expect("retain signed reply");
            } else {
                c.journal.close();
            }
            let log = fs::File::create_new(c.path.join("child.log")).expect("owned child log");
            let mut child=crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact","durable::write_intent::account_root::tests::account_root_local_process_child","--nocapture"])
            .env("QPERIAPT_ROOT_FENCE_DIR",&c.path).env("QPERIAPT_ROOT_FENCE_CUT",format!("{stage}-{}",if after {"after"}else{"before"}))
            .stdout(Stdio::from(log.try_clone().expect("owned stdout"))).stderr(Stdio::from(log)).spawn().expect("owned child"));
            let deadline = Instant::now() + Duration::from_secs(20);
            while !c.path.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("observe owned child").is_none()
                        && Instant::now() < deadline,
                    "root fence child checkpoint deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!c.path.join("returned").exists());
            child.0.kill().expect("kill at exact boundary");
            assert!(!child.0.wait().expect("reap child").success());
            let mut r = c.resume(&p);
            assert_eq!(
                r.status().expect("recovered local state"),
                if stage == "receipt" && after {
                    AccountRootJournalState::WitnessCommitted
                } else {
                    AccountRootJournalState::LocalFenced
                }
            );
            assert_eq!(
                rows(&r.active.as_ref().expect("recovered owner").db),
                original
            );
            r.retain_witness_retirement(&c.receipt(&p))
                .expect("same original witness decision");
            r.close();
            c.assert_ordinary_refused();
        }
    }
    eprintln!("ACCOUNT_ROOT_LOCAL_PROCESS cuts=4 original_inventory=true no_early_return=true same_proposal=true");
}
