// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
fn original_inputs(t: &Transition) {
    let path =
        t.f.original
            .paths
            .wrapping
            .parent()
            .expect("original directory");
    let mut public = t.f.original.intent.root.encode();
    t.f.original.intent.encode(&mut public);
    public.extend_from_slice(t.f.pin.identity().as_bytes());
    public.extend_from_slice(&t.f.pin.public_key().encode());
    let plan = t
        .registry
        .preparation(t.old.operation())
        .expect("independently retained original plan")
        .2;
    let wire =
        t.f.witness
            .lock()
            .expect("witness")
            .closed_account_preparation_receipt(plan)
            .expect("actual original non-commit");
    for (name, bytes) in [
        ("independent-inputs", public),
        ("proposal", t.old.to_bytes().expect("old proposal")),
        ("original-plan", plan.to_bytes().expect("original intent")),
        ("noncommit", wire),
        (
            "approved-next",
            t.next.to_bytes().expect("separate exact approval"),
        ),
    ] {
        fs::write(path.join(name), bytes).expect("retain original approval before child");
    }
}
fn observe_commits(t: &Transition, parent_committed: bool, child_committed: bool) {
    let key = JournalKey::open(&t.f.original.paths.wrapping).expect("original key");
    let binding =
        t.f.original
            .paths
            .binding(&key, &t.f.original.intent)
            .expect("original parent scope");
    let db = open_private_database(&t.f.original.paths.configuration).expect("same parent");
    let snapshot = read_snapshot(&db, &key, binding).expect("actual authenticated commit result");
    let state = snapshot
        .root_replacement
        .expect("original fence never disappears");
    assert_eq!(
        state.proposal,
        if parent_committed {
            t.next.clone()
        } else {
            t.old.clone()
        }
    );
    assert_eq!(state.history.len(), usize::from(parent_committed));
    drop(db);
    let expected = if child_committed { &t.next } else { &t.old };
    let mut child = AccountRootJournalRecovery::resume_original(
        t.f.original.paths.installation.files()[1],
        key,
        &t.f.original.device,
        state.journal,
        t.f.pin.clone(),
        expected.clone(),
    )
    .expect("exact observed child commit");
    assert_eq!(
        child.proposal().expect("actual child expectation"),
        *expected
    );
    child.close();
}
#[test]
fn account_root_parent_transition_process_loss_at_parent_and_child_commits_preserves_order() {
    for child_cut in [false, true] {
        for after in [false, true] {
            let mut t = Transition::new();
            original_inputs(&t);
            t.owner.close();
            let path =
                t.f.original
                    .paths
                    .wrapping
                    .parent()
                    .expect("original directory")
                    .to_path_buf();
            let suffix = if after { "after" } else { "before" };
            let selected = format!(
                "{}-{suffix}",
                if child_cut {
                    "child-handoff"
                } else {
                    "handoff"
                }
            );
            let expected_marker = format!(
                "{}-{suffix}",
                if child_cut {
                    "parent-handoff"
                } else {
                    "handoff"
                }
            );
            let log = fs::File::create_new(path.join("handoff-child.log")).expect("owned log");
            let mut command =
                Command::new(std::env::current_exe().expect("same actual test binary"));
            command.args(["--exact","enrollment::account_root::tests::process::account_root_enrollment_process_child","--nocapture"])
            .env("QPERIAPT_ROOT_PARENT_DIR",&path).env("QPERIAPT_ROOT_PARENT_CUT",&selected)
            .stdout(Stdio::from(log.try_clone().expect("stdout"))).stderr(Stdio::from(log));
            if child_cut {
                command
                    .env("QPERIAPT_ROOT_FENCE_DIR", &path)
                    .env("QPERIAPT_ROOT_FENCE_CUT", &expected_marker);
            }
            let mut child =
                crate::durable::tests::ChildGuard(command.spawn().expect("owned child"));
            let deadline = Instant::now() + Duration::from_secs(25);
            while !path.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("child status").is_none()
                        && Instant::now() < deadline,
                    "transition child did not reach {selected}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                fs::read(path.join("ready")).expect("exact boundary"),
                expected_marker.as_bytes()
            );
            assert!(!path.join("returned").exists());
            child
                .0
                .kill()
                .expect("kill owned process before API return");
            assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
            observe_commits(&t, child_cut || after, child_cut && after);
            t.resume();
            t.assert_parent_preserved();
            t.commit();
            t.owner.close();
            t.assert_child_preserved();
            t.f.assert_fenced();
        }
    }
    eprintln!("ACCOUNT_ROOT_PARENT_HANDOFF_PROCESS cuts=4 parent_first=true child_second=true no_api_return=true exact_resume=true");
}
