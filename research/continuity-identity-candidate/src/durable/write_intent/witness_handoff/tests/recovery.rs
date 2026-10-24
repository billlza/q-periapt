// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

fn fault_owner(c: &Case, after: bool) -> (Owners, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (db, remaining, count, _) = crate::durable::tests::fault_database_path(&c.path(), after);
    (
        Owners {
            client: None,
            db,
            key: c.key(),
            plan: c.plan.clone(),
        },
        remaining,
        count,
    )
}
#[test]
fn witness_journal_adoption_sync_faults_reconcile_each_phase_without_changing_pending_bytes() {
    for adopting in [false, true] {
        let c = Case::new(Some(2));
        if adopting {
            WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || {
                Ok(180)
            })
            .expect("prepared")
            .close();
        }
        let (owner, _, count) = fault_owner(&c, false);
        count.store(0, Ordering::SeqCst);
        let mut calibration = if adopting {
            let mut calibration = WitnessJournalAdoption {
                active: Some(owner),
            };
            calibration
                .adopt_authorization(&c.receipt)
                .expect("calibration");
            calibration
        } else {
            owner.prepare(|| Ok(180)).expect("calibration")
        };
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        calibration.close();
        eprintln!(
            "WITNESS_JOURNAL_CALIBRATION phase={} commit_syncs={barriers} owner_close_syncs={}",
            if adopting { "adopt" } else { "prepare" },
            count.load(Ordering::SeqCst) - barriers
        );
        for after in [false, true] {
            for cut in 1..=barriers {
                let c = Case::new(Some(2));
                let before = c.original_rows();
                if adopting {
                    WitnessJournalAdoption::prepare_original(
                        &c.path(),
                        c.key(),
                        c.plan.clone(),
                        || Ok(180),
                    )
                    .expect("prepared")
                    .close();
                }
                let (owner, remaining, _) = fault_owner(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                let result = if adopting {
                    let mut recovery = WitnessJournalAdoption {
                        active: Some(owner),
                    };
                    let result = recovery.adopt_authorization(&c.receipt).map(|_| ());
                    assert!(matches!(recovery.status(), Err(DurableError::Closed)));
                    result
                } else {
                    owner.prepare(|| Ok(180)).map(|_| ())
                };
                crate::durable::tests::assert_sync_failure(result, after);
                let recovered =
                    WitnessJournalAdoption::resume_original(&c.path(), c.key(), c.plan.clone());
                let mut recovery = match recovered {
                    Ok(owner) => owner,
                    Err(error) => {
                        assert!(
                            !adopting && matches!(error, DurableError::Absent),
                            "unexpected recovery error: {error}"
                        );
                        WitnessJournalAdoption::prepare_original(
                            &c.path(),
                            c.key(),
                            c.plan.clone(),
                            || Ok(180),
                        )
                        .expect("retry same uncommitted preparation")
                    }
                };
                recovery
                    .adopt_authorization(&c.receipt)
                    .expect("exact original selection");
                assert_eq!(rows(&recovery.active.as_ref().expect("owner").db), before);
                assert_eq!(
                    recovery
                        .authorization_receipt()
                        .expect("receipt")
                        .as_bytes(),
                    c.receipt
                );
            }
        }
        eprintln!(
            "WITNESS_JOURNAL_SYNC phase={} barriers={barriers} faults={}",
            if adopting { "adopt" } else { "prepare" },
            2 * barriers
        );
    }
}

#[test]
fn witness_journal_adoption_crash_child() {
    let Some(root) = std::env::var_os("QPERIAPT_WITNESS_ADOPTION_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let stage = std::env::var("QPERIAPT_WITNESS_ADOPTION_CUT").expect("cut");
    let path = root.join("client/state.redb");
    let key = JournalKey::open(&root.join("client/key")).expect("original wrapping key");
    let plan = restore_child_plan(&root);
    let mut owner = if stage.starts_with("prepare-") {
        WitnessJournalAdoption::prepare_original(&path, key, plan, || Ok(180)).expect("prepare")
    } else {
        WitnessJournalAdoption::resume_original(&path, key, plan).expect("prepared original")
    };
    if stage.starts_with("adopt-") {
        owner
            .adopt_authorization(&fs::read(root.join("receipt")).expect("original receipt"))
            .expect("adopt");
    }
    if stage.starts_with("reconcile-") {
        let address = fs::read_to_string(root.join("current-peer"))
            .expect("owned endpoint")
            .parse()
            .expect("address");
        owner
            .attach_current_witness(
                crate::DeviceSigningKey::deterministic([111; 32], [112; 32])
                    .expect("original device signer"),
                Box::new(crate::AnchorTcpTransport::new(address)),
                Duration::from_secs(3),
            )
            .expect("attach adopted current witness");
        owner
            .recover_original_pending()
            .expect("original pending recovery");
    }
    fs::write(root.join("returned"), b"returned").expect("return marker");
}

#[test]
fn witness_journal_adoption_process_loss_preserves_before_and_after_commit_decisions() {
    use std::os::unix::process::ExitStatusExt;
    for cut in [
        "prepare-before",
        "prepare-after",
        "adopt-before",
        "adopt-after",
    ] {
        let c = Case::new(Some(2));
        let before = c.original_rows();
        if cut.starts_with("adopt-") {
            WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || {
                Ok(180)
            })
            .expect("prepared")
            .close();
        }
        c.publish_child_inputs();
        let root = c.root.as_path();
        let log = fs::File::create(root.join("child.log")).expect("log");
        let mut child=crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact","durable::write_intent::witness_handoff::tests::recovery::witness_journal_adoption_crash_child","--nocapture"])
            .env("QPERIAPT_WITNESS_ADOPTION_DIR",root).env("QPERIAPT_WITNESS_ADOPTION_CUT",cut)
            .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log)).spawn().expect("owned child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "child stopped before cut: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned").exists());
        let pid = child.0.id();
        child.0.kill().expect("kill owned child");
        assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
        let recovered = WitnessJournalAdoption::resume_original(&c.path(), c.key(), c.plan.clone());
        let mut owner = if cut == "prepare-before" {
            assert!(matches!(recovered, Err(DurableError::Absent)));
            WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || Ok(180))
                .expect("original preparation retry")
        } else {
            recovered.expect("retained original control")
        };
        assert_eq!(
            owner.status().expect("state"),
            if cut == "adopt-after" {
                WitnessJournalAdoptionState::Adopted
            } else {
                WitnessJournalAdoptionState::Prepared
            }
        );
        owner
            .adopt_authorization(&c.receipt)
            .expect("exact original completion");
        assert_eq!(
            owner
                .authorization_receipt()
                .expect("same receipt")
                .as_bytes(),
            c.receipt
        );
        assert_eq!(rows(&owner.active.as_ref().expect("owner").db), before);
        eprintln!(
            "WITNESS_JOURNAL_KILLED cut={cut} pid={pid} parent={}",
            std::process::id()
        );
    }
}
