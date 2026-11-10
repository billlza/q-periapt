// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{io::Write, os::unix::fs::OpenOptionsExt, time::Instant};

pub(super) fn after_commit(bytes: &[u8]) {
    let Some(root) = std::env::var_os("QPERIAPT_PREINSTALLATION_CUT_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("extension-committed.pending"))
        .expect("commit barrier");
    file.write_all(bytes)
        .expect("exact committed public record");
    file.sync_all().expect("barrier sync");
    fs::rename(
        root.join("extension-committed.pending"),
        root.join("extension-committed"),
    )
    .expect("publish barrier");
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        assert!(
            Instant::now() < deadline,
            "parent did not interrupt committed extension"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn preinstallation_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::var_os("QPERIAPT_PREINSTALLATION_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    // Deterministic policy fixture only; the child's device identity and wrapping
    // key are opened from the exact files created by the parent.
    let (issuer, _, _, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let issued = issuer
        .issue_session_policy(
            &runtime,
            crate::SessionPolicyParameters::new(
                2,
                Validity::new(100, 400).expect("policy interval"),
                crate::AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                crate::AnchorRequirement::local_only(),
                crate::ApplicationSendBudget::new(1024).expect("budget"),
            )
            .expect("policy parameters"),
        )
        .expect("signed fixture policy");
    let policy = crate::PolicyPin::new(
        issuer.policy_family().expect("family"),
        issuer.public_key().expect("policy key"),
        issued.checkpoint(),
    )
    .expect("policy pin")
    .verify(issued.as_bytes(), runtime, 210)
    .expect("current fixture policy");
    let public =
        PublicKey::decode(&fs::read(root.join("extension-root")).expect("independent root"))
            .expect("root encoding");
    let intent = EnrollmentIntent::new(
        public.clone(),
        DeviceDescription::new(
            [7; 16],
            1,
            policy.family(),
            Validity::new(100, 160).expect("original interval"),
        )
        .expect("original description"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    match std::env::var("QPERIAPT_PREINSTALLATION_CUT_STAGE")
        .expect("stage")
        .as_str()
    {
        "adopt" => {
            let read_checkpoint = |name, version| {
                RosterCheckpoint::from_trusted_state(
                    version,
                    fs::read(root.join(name))
                        .expect("checkpoint")
                        .try_into()
                        .expect("digest width"),
                )
                .expect("checkpoint")
            };
            let predecessor = read_checkpoint("extension-predecessor", 1);
            let checkpoint = read_checkpoint("extension-checkpoint", 2);
            let approval =
                EnrollmentExtensionApproval::from_trusted_state([45; 32], None, predecessor, 300)
                    .expect("retained exact approval");
            let certificate = fs::read(root.join("extension-certificate")).expect("certificate");
            let roster = fs::read(root.join("extension-roster")).expect("roster");
            let pin = AccountPin::new(
                crate::identity::account_id(&public),
                public,
                checkpoint,
                policy.family(),
            )
            .expect("independent target pin");
            owner
                .adopt_credential_extension(
                    EnrollmentExtensionInputs {
                        approval: &approval,
                        certificate: &certificate,
                        issued_roster: &roster,
                        issued_checkpoint: checkpoint,
                        current_roster: &roster,
                    },
                    &pin,
                    &policy,
                    210,
                )
                .expect("interrupted adoption");
        }
        "select" => {
            owner.prepare(&policy, 210).expect("interrupted selection");
        }
        _ => return Err("unknown cut".into()),
    }
    Err("commit barrier was not reached".into())
}

#[test]
fn actual_process_kills_preserve_extension_and_prechild_selection() {
    use crate::durable::tests::ChildGuard;
    use std::process::{Command, Stdio};
    for stage in ["adopt", "select"] {
        let (c, proof, journal, original) = setup();
        let next = target(&c, &original, 45, None, 300, 210);
        let p2 = policy_continuation::policy(&c, 2, 400, 210);
        let root = c.paths.configuration.parent().expect("test root");
        let signer = fs::read(&c.paths.signer).expect("original protected signer");
        if stage == "select" {
            open(&c)
                .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
                .expect("committed extension before cut");
        }
        fs::write(root.join("extension-root"), c.intent.root.encode()).expect("independent root");
        fs::write(
            root.join("extension-predecessor"),
            next.approval.predecessor().digest(),
        )
        .expect("approved predecessor");
        fs::write(
            root.join("extension-checkpoint"),
            next.roster.checkpoint().digest(),
        )
        .expect("independent checkpoint");
        fs::write(root.join("extension-certificate"), &next.certificate)
            .expect("signed certificate");
        fs::write(root.join("extension-roster"), next.roster.as_bytes()).expect("signed roster");
        let log = fs::File::create_new(root.join("extension-child.log")).expect("child log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "enrollment::tests::preinstallation::process::preinstallation_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_PREINSTALLATION_CUT_ROOT", root)
                .env("QPERIAPT_PREINSTALLATION_CUT_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("original process"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("extension-committed").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "missing extension cut {stage}: {}",
                fs::read_to_string(root.join("extension-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().expect("SIGKILL at exact durable boundary");
        assert!(!child.0.wait().expect("reap").success());
        let mut owner = open(&c);
        assert_eq!(
            row(&mut owner),
            fs::read(root.join("extension-committed")).expect("exact committed image")
        );
        assert!(
            matches!(owner.image().expect("image").phase,Phase::Accepted{request,..} if request==proof)
        );
        assert_eq!(fs::read(&c.paths.signer).expect("signer"), signer);
        for path in c.paths.installation.files() {
            assert!(!path.exists(), "cut precedes every child");
        }
        if stage == "adopt" {
            assert_eq!(
                owner.preparation_status().expect("state"),
                EnrollmentPreparationStatus::Unprepared
            );
            assert_eq!(
                owner
                    .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
                    .expect("exact retry"),
                journal
            );
        } else {
            assert_eq!(
                owner.preparation_status().expect("state"),
                EnrollmentPreparationStatus::Selected
            );
            assert!(owner
                .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
                .is_err());
            owner = open(&c);
        }
        owner
            .prepare(&p2, 210)
            .expect("resume same selected context");
        let mut active = owner
            .activate(&p2, 210, None)
            .expect("original active installation");
        assert_eq!(
            active
                .parts()
                .expect("owners")
                .0
                .stores()
                .expect("journal")
                .0
                .test_snapshot()
                .id,
            *journal.as_bytes()
        );
        active.close();
        eprintln!("PREINSTALLATION_PROCESS_CUT stage={stage} exact_target=true original_signer=true original_journal=true children_absent_at_cut=true");
    }
}
