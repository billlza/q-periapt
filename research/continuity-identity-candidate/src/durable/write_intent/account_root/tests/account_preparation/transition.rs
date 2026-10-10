// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AccountRootJournalTransition, AnchorAccountReplacementState as WitnessState};
#[path = "transition/support.rs"]
mod support;
use support::Transition;

#[test]
fn account_closure_handoff_authenticated_history_rejects_broken_links_duplicates_and_wrong_retry() {
    let mut t = Transition::new_exact();
    t.owner
        .transition_after_noncommit(&t.transition)
        .expect("original handoff");
    let owners = t.owner.active.as_ref().expect("restricted owner");
    let original = owners.read().expect("exact fence");
    let wire = original.encode(&owners.key).expect("authenticated history");
    assert_eq!(wire.get(..8).expect("complete format tag"), b"QPARJF02");
    let body_length = wire.len() - 32;
    let record = body_length - transfer::TRANSFER_BYTES;
    // Preserve a valid MAC to exercise structural validation, not only authentication.
    for field in [32, 64, 96, 97] {
        let mut damaged = wire
            .get(..body_length)
            .expect("complete authenticated body")
            .to_vec();
        *damaged
            .get_mut(record + field)
            .expect("exact history field") ^= 0x80;
        let mut auth = mac(&owners.key).expect("owned fixture key");
        auth.update(&damaged);
        damaged.extend_from_slice(&auth.finalize().into_bytes());
        assert!(
            Fence::decode(&owners.key, &damaged).is_err(),
            "invalid history field {field}"
        );
    }
    let mut repeated = original.clone();
    repeated.history.push(
        original
            .history
            .first()
            .expect("original transition")
            .clone(),
    );
    assert!(repeated.encode(&owners.key).is_err());
    let proof =
        t.p.c
            .witness
            .lock()
            .expect("witness")
            .closed_account_replacement(&t.old)
            .expect("original exact fact");
    let mut changed = t.next.to_bytes().expect("approved bytes");
    *changed.last_mut().expect("preparation binding") ^= 1;
    let wrong = AccountRootJournalTransition::from_closed_replacement(
        proof,
        Proposal::from_trusted_state(&changed).expect("different parseable expectation"),
    )
    .expect("same account scope");
    assert!(matches!(
        t.owner.transition_after_noncommit(&wrong),
        Err(DurableError::Conflict)
    ));
    assert!(t.owner.active.is_none());
    t.resume();
    assert_eq!(
        t.owner
            .active
            .as_ref()
            .expect("original owner")
            .read()
            .expect("original history")
            .encode(&t.p.c.key())
            .expect("unchanged original bytes"),
        wire
    );
    t.assert_preserved();
}

#[test]
fn account_closure_exact_proposal_handoff_requires_the_original_noncommit_and_current_target() {
    let mut t = Transition::new_exact();
    t.owner
        .transition_after_noncommit(&t.transition)
        .expect("exact non-commit handoff");
    t.assert_preserved();
    t.commit();
    t.owner.close();
    t.resume();
    assert_eq!(
        t.owner.status().expect("exact retained retirement"),
        AccountRootJournalState::WitnessCommitted
    );
    t.assert_preserved();
}

#[test]
fn account_closure_handoff_process_loss_on_both_sides_of_commit_preserves_original_inventory() {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
    };
    for after in [false, true] {
        let mut t = Transition::new();
        let path = &t.p.c.path;
        for (name, bytes) in [
            ("witness-id", t.p.c.pin.identity().as_bytes().to_vec()),
            ("witness-public", t.p.c.pin.public_key().encode()),
            (
                "original-proposal",
                t.old.to_bytes().expect("original proposal"),
            ),
            ("original-plan", t.p.plan.to_bytes().expect("original plan")),
            (
                "approved-next",
                t.next.to_bytes().expect("separate original approval"),
            ),
            (
                "original-noncommit",
                t.p.c
                    .witness
                    .lock()
                    .expect("witness")
                    .closed_account_preparation_receipt(&t.p.plan)
                    .expect("original proof"),
            ),
        ] {
            fs::write(path.join(name), bytes).expect("retain independent inputs before child");
        }
        t.owner.close();
        let log = fs::File::create_new(path.join("handoff-child.log")).expect("owned log");
        let selected = format!("handoff-{}", if after { "after" } else { "before" });
        let mut child = crate::durable::tests::ChildGuard(
            Command::new(std::env::current_exe().expect("actual same binary"))
                .args([
                    "--exact",
                    "durable::write_intent::account_root::tests::account_root_local_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_ROOT_FENCE_DIR", path)
                .env("QPERIAPT_ROOT_FENCE_CUT", &selected)
                .stdout(Stdio::from(log.try_clone().expect("stdout")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(25);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "handoff did not reach original commit boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(path.join("ready")).expect("exact checkpoint"),
            selected.as_bytes()
        );
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill owned child at boundary");
        assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
        let mut observed = t.p.c.resume(if after { &t.next } else { &t.old });
        assert_eq!(
            observed
                .active
                .as_ref()
                .expect("owner")
                .read()
                .expect("original committed marker")
                .history
                .len(),
            usize::from(after)
        );
        observed.close();
        t.resume();
        t.assert_preserved();
        t.commit();
    }
    eprintln!("ACCOUNT_CLOSURE_HANDOFF_PROCESS cuts=2 no_api_return=true original_inventory_preserved=true");
}

#[test]
fn account_closure_expired_target_handoff_preserves_ciphertext_pending_intent_and_denial() {
    let mut t = Transition::new();
    assert_eq!(t.transition.next_proposal(), &t.next);
    assert_eq!(
        t.owner
            .transition_after_noncommit(&t.transition)
            .expect("authorized transition"),
        AccountRootJournalState::LocalFenced
    );
    t.assert_preserved();
    let first = t
        .owner
        .active
        .as_ref()
        .expect("owner")
        .read()
        .expect("fence");
    assert_eq!(first.history.len(), 1);
    t.owner.close();
    t.p.c.assert_ordinary_refused();
    assert!(matches!(
        AccountRootJournalRecovery::resume_original(
            &t.p.c.path.join("state.redb"),
            t.p.c.key(),
            t.p.c.f.local_device(),
            t.p.c.identity,
            t.p.c.pin.clone(),
            t.old.clone()
        ),
        Err(DurableError::Conflict)
    ));
    t.resume();
    assert_eq!(
        t.owner
            .active
            .as_ref()
            .expect("owner")
            .read()
            .expect("same fence")
            .history,
        first.history
    );
    t.commit();
    t.owner.close();
    t.resume(); // Retry after the new retirement was retained must not discard it.
    assert_eq!(
        t.owner.status().expect("retained decision"),
        AccountRootJournalState::WitnessCommitted
    );
    t.assert_preserved();
    t.p.reopen();
    assert_eq!(
        t.p.registry
            .preparation(t.p.plan.operation())
            .expect("original plan")
            .1,
        State::Closed
    );
    let current =
        t.p.registry
            .access()
            .expect("access")
            .current(t.p.expected.application())
            .expect("new mapping");
    assert_eq!(current.revision(), 2);
    assert_eq!(current.account(), t.device.account_id());
    eprintln!("ACCOUNT_CLOSURE_TRANSITION original_expired_at=160 transition_time=170 image_unchanged=true pending_unchanged=true unacknowledged_ciphertext_preserved=true history_entries=1");
}

#[test]
fn account_closure_handoff_every_sync_failure_recovers_only_the_same_transition() {
    let mut calibration = Transition::new();
    let (_, count) = fault_recovery(
        &mut calibration.owner,
        &calibration.p.c.path.join("state.redb"),
        false,
    );
    count.store(0, Ordering::SeqCst);
    calibration
        .owner
        .transition_after_noncommit(&calibration.transition)
        .expect("calibrate real barriers");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    calibration.owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut t = Transition::new();
            let (remaining, _) =
                fault_recovery(&mut t.owner, &t.p.c.path.join("state.redb"), after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                t.owner.transition_after_noncommit(&t.transition),
                after,
            );
            assert!(t.owner.active.is_none());
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            t.resume();
            t.assert_preserved();
            assert_eq!(
                t.owner
                    .active
                    .as_ref()
                    .expect("owner")
                    .read()
                    .expect("fence")
                    .history
                    .len(),
                1
            );
            t.commit();
        }
    }
    eprintln!(
        "ACCOUNT_CLOSURE_HANDOFF_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}
