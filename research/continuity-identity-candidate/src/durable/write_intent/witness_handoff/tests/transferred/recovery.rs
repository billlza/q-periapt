// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::network::{adopt, attach, pending_write, server, Delivery};
use super::*;
use std::{
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};
fn faulted(
    owner: &mut WitnessJournalAdoption,
    path: &Path,
    after: bool,
) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let old = owner.active.take().expect("adopted owner");
    drop(old.db);
    let (db, remaining, count, _) = crate::durable::tests::fault_database_path(path, after);
    owner.active = Some(Owners { db, ..old });
    (remaining, count)
}
#[test]
fn transferred_witness_recovery_sync_faults_keep_image_control_and_original_intent_atomic() {
    let mut c = Case::new(Some(1));
    let mut owner = adopt(&mut c);
    let (_, count) = faulted(&mut owner, &c.path(), false);
    count.store(0, Ordering::SeqCst);
    let ((), target) = server(
        c.target.take().expect("target"),
        1,
        Delivery::Exact,
        |address| {
            attach(&mut owner, address);
            owner.recover_original_pending().expect("calibration");
        },
    );
    c.target = Some(target);
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = Case::new(Some(1));
            let before = c.original_rows();
            let mut owner = adopt(&mut c);
            let pending = pending_write(&owner).expect("real P");
            let (remaining, _) = faulted(&mut owner, &c.path(), after);
            remaining.store(cut, Ordering::SeqCst);
            let (result, target) = server(
                c.target.take().expect("target"),
                1,
                Delivery::Exact,
                |address| {
                    attach(&mut owner, address);
                    owner.recover_original_pending()
                },
            );
            c.target = Some(target);
            crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
            assert!(matches!(owner.status(), Err(DurableError::Closed)));
            let mut owner = c.resume();
            let recovered = rows(&owner.active.as_ref().expect("owner").db);
            assert!(recovered.1 == before.1, "intent unchanged");
            assert!(
                recovered.0 == before.0 || recovered.0 == pending.target,
                "atomic image/control reconciliation"
            );
            let ((), target) = server(
                c.target.take().expect("target"),
                1,
                Delivery::Exact,
                |address| {
                    attach(&mut owner, address);
                    owner
                        .recover_original_pending()
                        .expect("exact original retry");
                },
            );
            c.target = Some(target);
            let final_rows = rows(&owner.active.as_ref().expect("owner").db);
            assert!(
                final_rows.0 == pending.target && final_rows.1 == before.1,
                "exact sealed target and original intent"
            );
        }
    }
    eprintln!(
        "TRANSFERRED_WITNESS_RECOVERY_SYNC barriers={barriers} faults={}",
        2 * barriers
    );
}

#[test]
fn transferred_witness_recovery_sigkill_before_and_after_local_install_reuses_original_target() {
    use std::os::unix::process::ExitStatusExt;
    for cut in ["reconcile-before", "reconcile-after"] {
        let mut c = Case::new(Some(1));
        let before = c.original_rows();
        let mut owner = adopt(&mut c);
        let pending = pending_write(&owner).expect("real P");
        owner.close();
        c.publish_child_inputs();
        let ((), target) = server(
            c.target.take().expect("target"),
            1,
            Delivery::Exact,
            |address| {
                fs::write(c.root.join("current-peer"), address.to_string())
                    .expect("owned endpoint");
                let log = fs::File::create(c.root.join("recovery-child.log")).expect("log");
                let mut child=crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact","durable::write_intent::witness_handoff::tests::recovery::witness_journal_adoption_crash_child","--nocapture"])
                .env("QPERIAPT_WITNESS_ADOPTION_DIR",&c.root).env("QPERIAPT_WITNESS_ADOPTION_CUT",cut)
                .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log)).spawn().expect("owned child"));
                let deadline = Instant::now() + Duration::from_secs(20);
                while !c.root.join("ready").exists() {
                    assert!(
                        child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                        "child did not reach {cut}: {}",
                        fs::read_to_string(c.root.join("recovery-child.log")).expect("child log")
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(!c.root.join("returned").exists());
                let pid = child.0.id();
                child.0.kill().expect("kill owned child");
                assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
                eprintln!(
                    "TRANSFERRED_WITNESS_RECOVERY_KILLED cut={cut} pid={pid} parent={}",
                    std::process::id()
                );
            },
        );
        c.target = Some(target);
        let mut owner = c.resume();
        let recovered = rows(&owner.active.as_ref().expect("owner").db);
        assert!(recovered.1 == before.1);
        assert!(
            recovered.0
                == if cut.ends_with("before") {
                    before.0
                } else {
                    pending.target.clone()
                }
        );
        let ((), target) = server(
            c.target.take().expect("target"),
            1,
            Delivery::Exact,
            |address| {
                attach(&mut owner, address);
                owner
                    .recover_original_pending()
                    .expect("same original result after process loss");
            },
        );
        c.target = Some(target);
        let final_rows = rows(&owner.active.as_ref().expect("owner").db);
        assert!(final_rows.0 == pending.target && final_rows.1 == before.1);
    }
}
