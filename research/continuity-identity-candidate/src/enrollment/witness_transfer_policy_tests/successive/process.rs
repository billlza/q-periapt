// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::tests::witness_handoff::process::{publish_case, restore, restore_plan};
use crate::WitnessJournalAdoptionPlan;
use std::{
    os::unix::{fs::DirBuilderExt, process::ExitStatusExt},
    process::{Command, Stdio},
    time::Instant,
};

fn selected(
    root: &Path,
) -> (
    DeviceEnrollment,
    VerifiedSessionPolicy,
    WitnessJournalAdoptionPlan,
) {
    let (mut owner, policy, plan) = restore(root);
    let image = owner.image().expect("same original enrollment");
    let original = owner
        .original_device_metadata(&image)
        .expect("original device");
    let (previous, receipt) = restore_plan(&root.join("previous-selection"), &original, &policy);
    let plan = plan
        .continue_from(&previous, &receipt)
        .expect("restore full independent predecessor chain, not infer it from journal rows");
    (owner, policy, plan)
}
#[test]
fn enrollment_witness_successor_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_SUCCESSOR_CLIENT_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let action = std::env::var("QPERIAPT_SUCCESSOR_CLIENT_ACTION").expect("explicit action");
    let (mut owner, policy, plan) = selected(&root);
    if action == "recover" || action.contains("prepare") {
        owner
            .prepare_witness_handoff(policy.historical(), plan.clone(), || Ok(155))
            .expect("same new selection preparation/reconciliation");
    }
    if action == "recover" || action.contains("adopt") {
        owner
            .adopt_witness_handoff(
                policy.historical(),
                plan.clone(),
                &fs::read(root.join("receipt")).expect("receipt"),
            )
            .expect("same exact new target receipt");
    }
    if action == "recover" {
        assert_eq!(
            owner
                .witness_handoff_status(policy.historical(), plan)
                .expect("fresh process recovered both original stores"),
            WitnessJournalAdoptionState::Adopted
        );
        owner.close();
    }
    fs::write(root.join("returned"), std::process::id().to_be_bytes()).expect("terminal marker");
}
fn command(root: &Path, action: &str, log: &str) -> Command {
    let log = fs::File::create(root.join(log)).expect("child log");
    let mut cmd = Command::new(std::env::current_exe().expect("current test binary"));
    let module = module_path!().split_once("::").expect("crate and module").1;
    let test = format!("{module}::enrollment_witness_successor_process_child");
    cmd.args(["--exact", &test, "--nocapture"])
        .env("QPERIAPT_SUCCESSOR_CLIENT_ROOT", root)
        .env("QPERIAPT_SUCCESSOR_CLIENT_ACTION", action)
        .stdout(Stdio::from(log.try_clone().expect("child stdout")))
        .stderr(Stdio::from(log));
    cmd
}

#[test]
fn enrollment_witness_successor_sigkill_reopens_both_selections_in_new_process() {
    for cut in [
        "child-prepare-before",
        "child-prepare-after",
        "parent-prepare-before",
        "parent-prepare-after",
        "child-adopt-before",
        "child-adopt-after",
        "parent-adopt-before",
        "parent-adopt-after",
    ] {
        let (f, a, p) = pending_case();
        let before = journal(&f);
        let signer = fs::read(&f.c.paths.signer).expect("original signer");
        let wrapping = fs::read(&f.c.paths.wrapping).expect("original key");
        let first = first_transfer(&f);
        let mut second = next_transfer(&f, &first, 154, 78);
        second.plan = second
            .plan
            .clone()
            .continue_from(&first.plan, &first.control)
            .expect("exact trusted predecessor");
        second.set_time(156);
        let root =
            f.c.paths
                .configuration
                .parent()
                .expect("same original directory");
        let previous = root.join("previous-selection");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&previous)
            .expect("owned independent checkpoint directory");
        publish_case(&f.c, &first, &previous);
        publish_case(&f.c, &second, root);
        if cut.contains("adopt") {
            open(&f.c)
                .prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || Ok(155))
                .expect("second Prepared before adoption interruption");
        }
        let mut cmd = command(root, cut, "successor-crash.log");
        cmd.env("QPERIAPT_ENROLLMENT_WITNESS_DIR", root)
            .env("QPERIAPT_ENROLLMENT_WITNESS_CUT", cut)
            .env("QPERIAPT_WITNESS_ADOPTION_DIR", root)
            .env(
                "QPERIAPT_WITNESS_ADOPTION_CUT",
                cut.strip_prefix("child-").unwrap_or(""),
            );
        let mut child = crate::durable::tests::ChildGuard(cmd.spawn().expect("owned crash child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "missing second-selection cut {cut}: {}",
                fs::read_to_string(root.join("successor-crash.log")).expect("crash log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned").exists());
        let killed = child.0.id();
        child.0.kill().expect("kill owned test process");
        assert_eq!(child.0.wait().expect("reaped").signal(), Some(9));
        assert_eq!(
            journal(&f),
            before,
            "selection crash cannot rewrite original sealed P"
        );
        let mut recovered = crate::durable::tests::ChildGuard(
            command(root, "recover", "successor-recover.log")
                .spawn()
                .expect("fresh recovery process"),
        );
        let recovery_pid = recovered.0.id();
        assert_ne!(recovery_pid, killed);
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = recovered.0.try_wait().expect("recovery status") {
                break status;
            }
            assert!(Instant::now() < deadline, "bounded fresh recovery");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "recovery {cut}: {}",
            fs::read_to_string(root.join("successor-recover.log")).expect("recovery log")
        );
        assert_eq!(
            fs::read(root.join("returned")).expect("recovery terminal"),
            recovery_pid.to_be_bytes()
        );
        assert_eq!(journal(&f), before);
        complete_original(&f, &a, p, &before, &second, 156);
        assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
        assert_eq!(fs::read(&f.c.paths.wrapping).expect("same key"), wrapping);
        eprintln!("SUCCESSOR_CLIENT_SIGKILL cut={cut} killed={killed} recovery={recovery_pid} original_p_completed=true");
    }
}
