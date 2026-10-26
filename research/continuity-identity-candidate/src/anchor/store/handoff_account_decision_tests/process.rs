// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::process::ExitStatusExt;

fn read(root: &Path, name: &str) -> Vec<u8> {
    fs::read(root.join(name)).expect("original independently retained public input")
}
fn pin(root: &Path, name: &str) -> AnchorPin {
    let raw = read(root, name);
    let mut d = Decoder::new(&raw);
    let pin = AnchorPin::new(
        AnchorIdentity::from_trusted_state(d.array().expect("identity")).expect("identity"),
        PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("public bytes")).expect("key"),
    );
    d.finish().expect("exact pin");
    pin
}
fn retain(c: &RetirementCase, n: &Next, a: &Approval) {
    let p = n.policy.checkpoint();
    let roster = n.device.roster().checkpoint();
    for (name, bytes) in [
        ("decision-history", c.history.to_bytes().expect("history")),
        ("decision-checkpoint", c.history.checkpoint().to_vec()),
        (
            "decision-approval",
            a.to_bytes().expect("original approval"),
        ),
        ("decision-retired", c.retired.clone()),
        ("previous-root", c.root.encode()),
        ("successor-root", n.device.authority_key.encode()),
        ("successor-certificate", n.certificate.clone()),
        ("successor-roster", n.device.roster().as_bytes().to_vec()),
        (
            "successor-roster-checkpoint",
            [roster.version().to_be_bytes().as_slice(), &roster.digest()].concat(),
        ),
        ("successor-policy", n.policy_wire.clone()),
        (
            "successor-policy-root",
            c.c.issuer.public_key().expect("policy key").encode(),
        ),
        ("successor-family", n.policy.family().to_vec()),
        (
            "successor-policy-checkpoint",
            [p.version().to_be_bytes().as_slice(), &p.digest()].concat(),
        ),
        ("successor-subject", n.genesis.subject().to_bytes()),
        ("successor-image", n.genesis.image_digest().to_vec()),
    ] {
        fs::write(c.f.directory.join(name), bytes).expect("retain exact public material");
    }
}

#[test]
fn transferred_account_decision_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_ACCOUNT_DECISION_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let origin = pin(root, "source-pin");
    let current = pin(root, "target-pin");
    let target = AnchorHandoffTargetApproval::restore_trusted_state(
        &read(root, "approval"),
        &origin,
        &current,
    )
    .expect("original transfer approval");
    let history = AnchorHandoffHistory::restore_trusted_state(
        &read(root, "decision-history"),
        &origin,
        &current,
        read(root, "decision-checkpoint")
            .try_into()
            .expect("checkpoint size"),
    )
    .expect("independent complete history");
    let raw = read(root, "successor-policy-checkpoint");
    let mut d = Decoder::new(&raw);
    let expected = crate::PolicyCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("policy checkpoint");
    d.finish().expect("complete policy checkpoint");
    let policy = crate::PolicyPin::new(
        read(root, "successor-family").try_into().expect("family"),
        PublicKey::decode(&read(root, "successor-policy-root")).expect("policy root"),
        expected,
    )
    .expect("independent policy pin")
    .verify(
        &read(root, "successor-policy"),
        crate::tests::sdk_runtime(),
        185,
    )
    .expect("original signed target policy, no re-signing");
    let raw = read(root, "successor-roster-checkpoint");
    let mut d = Decoder::new(&raw);
    let expected = crate::RosterCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("roster checkpoint");
    d.finish().expect("complete roster checkpoint");
    let successor = PublicKey::decode(&read(root, "successor-root")).expect("independent new root");
    let device = crate::AccountPin::new(
        crate::identity::account_id(&successor),
        successor,
        expected,
        policy.family(),
    )
    .expect("independent account pin")
    .verify_device(
        &read(root, "successor-certificate"),
        &read(root, "successor-roster"),
        185,
    )
    .expect("original target credential and roster");
    let genesis = AnchorGenesis::from_trusted_state(
        AnchorSubject::from_trusted_state(&read(root, "successor-subject"))
            .expect("original subject"),
        read(root, "successor-image")
            .try_into()
            .expect("original journal digest"),
    )
    .expect("same actual original target journal");
    let previous_root =
        PublicKey::decode(&read(root, "previous-root")).expect("independent original root");
    let m = Materials {
        previous_root: &previous_root,
        genesis: &genesis,
        device: &device,
        policy: &policy,
        history: &history,
    };
    let a = Approval::restore_trusted_state(&read(root, "decision-approval"), &m)
        .expect("same original account decision");
    let wrapping = JournalKey::open(&root.join("wrapping")).expect("original wrapping key");
    let signer = AnchorSigningKey::open(&root.join("signer"), &wrapping, target_key_id())
        .expect("original Witness signer");
    let (mut active, _) = AnchorHandoffTarget::open(&root.join("import.redb"), wrapping, target)
        .expect("original imported store")
        .activate(&read(root, "decision-retired"), signer)
        .expect("original activation");
    let close = std::env::var("QPERIAPT_ACCOUNT_DECISION_ACTION").expect("action") == "close";
    let decision = if close {
        active.close_transferred_account_replacement(&a)
    } else {
        active.replace_transferred_account_root(&a, &m, || Ok(185))
    }
    .expect("exact original action");
    fs::write(root.join("returned-decision"), decision.as_bytes()).expect("returned exact proof");
    fs::write(
        root.join("decision-recovery-pid"),
        std::process::id().to_string(),
    )
    .expect("actual recovery PID");
}

#[test]
fn transferred_account_decision_process_loss_recovers_both_outcomes_in_new_pid() {
    const CHILD: &str = "anchor::store::tests::handoff_import::account_decision::process::transferred_account_decision_process_child";
    for close in [false, true] {
        for committed in [false, true] {
            let mut c = RetirementCase::new(Some((if close { "G" } else { "P" }, !close)), false);
            let n = next(&c, 220);
            let a = approve(&mut c, &n, 223);
            let old = c.old_entry();
            let revision = c.active.image().expect("original revision").revision;
            retain(&c, &n, &a);
            c.active.close();
            let root = &c.f.directory;
            let command = || {
                let mut cmd = Process::new(std::env::current_exe().expect("test binary"));
                cmd.args(["--exact", CHILD, "--nocapture"])
                    .env("QPERIAPT_ACCOUNT_DECISION_DIR", root)
                    .env(
                        "QPERIAPT_ACCOUNT_DECISION_ACTION",
                        if close { "close" } else { "commit" },
                    );
                cmd
            };
            let log = fs::File::create(root.join("decision-crash.log")).expect("owned log");
            let mut child = ChildGuard(
                command()
                    .env("QPERIAPT_ANCHOR_SERVER_DIR", root)
                    .env(
                        if committed {
                            "QPERIAPT_ANCHOR_CRASH_REVISION"
                        } else {
                            "QPERIAPT_ANCHOR_BEFORE_COMMIT_REVISION"
                        },
                        (revision + 1).to_string(),
                    )
                    .stdout(Stdio::from(log.try_clone().expect("log")))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .expect("fresh process"),
            );
            let killed = child.0.id();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !root.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                    "bounded exact commit boundary"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                read(root, "ready"),
                if committed {
                    b"committed".as_slice()
                } else {
                    b"before-commit".as_slice()
                }
            );
            assert!(!root.join("returned-decision").exists());
            child.0.kill().expect("kill owned child");
            assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
            let observed = c.f.open().transferred_account_decision(&a);
            let before = if committed {
                Some(
                    observed
                        .expect("persisted proof before return")
                        .as_bytes()
                        .to_vec(),
                )
            } else {
                assert!(matches!(observed, Err(DurableError::Absent)));
                None
            };
            let log =
                fs::File::create(root.join("decision-recover.log")).expect("owned recovery log");
            let mut recovery = ChildGuard(
                command()
                    .stdout(Stdio::from(log.try_clone().expect("log")))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .expect("new recovery process"),
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = recovery.0.try_wait().expect("recovery status") {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "bounded recovery");
                std::thread::sleep(Duration::from_millis(10));
            }
            let pid: u32 = fs::read_to_string(root.join("decision-recovery-pid"))
                .expect("PID")
                .parse()
                .expect("numeric PID");
            assert_ne!(pid, killed);
            assert_ne!(pid, std::process::id());
            let wire = read(root, "returned-decision");
            if let Some(before) = before {
                assert_eq!(wire, before);
            }
            assert_eq!(
                a.verify_decision(&c.history, &wire)
                    .expect("same approved signed result")
                    .state(),
                if close {
                    State::Closed
                } else {
                    State::Committed
                }
            );
            c.reopen();
            assert_eq!(c.old_entry(), old);
            assert_eq!(
                c.active
                    .transferred_account_decision(&a)
                    .expect("same recovered outcome")
                    .as_bytes(),
                wire
            );
            assert_eq!(
                c.active
                    .image()
                    .expect("target enrollment is atomic with decision")
                    .entries
                    .len(),
                if close { 1 } else { 2 }
            );
            eprintln!("TRANSFERRED_ACCOUNT_DECISION_PROCESS close={close} committed={committed} killed_pid={killed} recovery_pid={pid}");
        }
    }
}
