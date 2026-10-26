// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reconstruct both independently approved closed attempts in each new process.
use super::super::super::super::process::inputs as old_inputs;
use super::super::super::process::inputs as next_inputs;
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
const CHILD: &str = "enrollment::account_root::tests::transferred::next_attempt::managed::successive::process::transferred_successive_cleanup_child";

fn publish(c: &CleanupCase, root: &Path) {
    old_inputs::publish(&c.flow.t, &c.first_closed);
    c.recovery.publish(root);
    for (name, next) in [("second", &c.second), ("third", &c.third)] {
        let dir = root.join(name);
        fs::create_dir(&dir).expect("owned independent target inputs");
        next_inputs::publish_next(next, &dir);
        for leaf in [
            "policy-family",
            "policy-root",
            "successor-policy",
            "successor-policy-checkpoint",
        ] {
            fs::copy(root.join(leaf), dir.join(leaf)).expect("same independent policy inputs");
        }
    }
    fs::write(root.join("second-closed"), &c.closed).expect("exact second closure");
    fs::write(root.join("final-committed"), &c.committed).expect("exact final decision");
}
fn accounting(c: &CleanupCase, root: &Path) {
    let history = c.flow.context.history();
    let pin = history.current_pin();
    let mut wire = pin.identity().as_bytes().to_vec();
    wire.extend_from_slice(&pin.public_key().encode());
    fs::write(root.join("accounting-pin"), wire).expect("independent accounting pin");
    fs::write(
        root.join("accounting-history"),
        history.to_bytes().expect("complete history"),
    )
    .expect("same accounting history");
    fs::write(root.join("accounting-checkpoint"), history.checkpoint())
        .expect("independent checkpoint");
}

#[test]
fn transferred_successive_cleanup_child() {
    let Some(root) = std::env::var_os("QPERIAPT_SUCCESSIVE_CLEANUP_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let read = |name| fs::read(root.join(name)).expect("original independent public input");
    let old = old_inputs::restore_registry(&root);
    let mut plan = TransferredAccountRootPreparation::new(
        old.preparation.clone(),
        old.logical.clone(),
        old.history.clone(),
        Some(old.selected.clone()),
    )
    .expect("original first preparation");
    let mut approval = old.approval.clone();
    let mut closed = read("root-decision");
    let mut proofs = vec![(old.preparation.operation(), closed.clone())];
    for (name, now) in [("second", 186), ("third", 187)] {
        let (target, next) =
            next_inputs::restore_at(&root.join(name), &old.intent.root, &old.history, now);
        plan = TransferredAccountRootPreparation::new(
            target.clone(),
            old.logical.clone(),
            old.history.clone(),
            Some(old.selected.clone()),
        )
        .expect("independent target")
        .after_closed(&plan, approval, next.clone(), &old.frozen, &closed)
        .expect("complete original signed attempt prefix");
        approval = next;
        closed = read(if name == "second" {
            "second-closed"
        } else {
            "final-committed"
        });
        proofs.push((target.operation(), closed.clone()));
    }
    let wire = read("accounting-pin");
    let mut decoder = Decoder::new(&wire);
    let current = AnchorPin::new(
        AnchorIdentity::from_trusted_state(decoder.array().expect("identity")).expect("identity"),
        PublicKey::decode(decoder.take(PUBLIC_KEY_BYTES).expect("public key")).expect("public key"),
    );
    decoder.finish().expect("complete independent pin");
    let history = AnchorHandoffHistory::restore_trusted_state(
        &read("accounting-history"),
        &old.logical,
        &current,
        read("accounting-checkpoint")
            .try_into()
            .expect("checkpoint"),
    )
    .expect("original independently selected accounting history");
    let recovery = RegistryRecovery::restore(&root);
    let family = read("policy-family").try_into().expect("family");
    let mut owner = ManagedAccountRootReplacement::resume_transferred_cleanup_original(
        recovery.open_with(family, old.logical.clone()),
        recovery.expected,
        plan,
        paths(&root),
        old.intent,
        history.clone(),
    )
    .expect("same final controller without a recreated signer or journal");
    let action = fs::read_to_string(root.join("cleanup-action")).expect("fixed action");
    owner
        .with_retired_cleanup(|parent| {
            match action.as_str() {
                "inventory" => {
                    parent.installation()?.proposal()?;
                }
                "journal" => parent
                    .installation()?
                    .erase_journal(history.current_pin(), &read("cleanup-ack"))?,
                "signer-plan" => parent.prepare_signer_erasure(&read("cleanup-ack"))?,
                "signer" => parent.erase_signer()?,
                _ => return Err(DurableError::Corrupt),
            }
            Ok(())
        })
        .expect("exact original cleanup action");
    owner
        .successor_authority()
        .expect("same final target mapping");
    owner.close();
    let mut registry = recovery.open_with(family, old.logical);
    for (operation, wire) in proofs {
        assert_eq!(
            registry
                .transferred_account_decision(operation)
                .expect("retained proof")
                .as_bytes(),
            wire
        );
    }
    registry.close();
    fs::write(root.join("cleanup-returned"), action).expect("returned marker");
    fs::write(root.join("cleanup-pid"), std::process::id().to_string()).expect("new PID");
}

fn command(root: &Path, log: &str) -> Command {
    let file = fs::File::create_new(root.join(log)).expect("owned child log");
    let mut command = Command::new(std::env::current_exe().expect("same source executable"));
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_SUCCESSIVE_CLEANUP_DIR", root)
        .stdout(Stdio::from(file.try_clone().expect("stdout")))
        .stderr(Stdio::from(file));
    command
}
fn cut(root: &Path, action: &str, stage: &str, after: bool) -> (u32, u32) {
    let mut command = command(root, "cut.log");
    let side = if after { "after" } else { "before" };
    let (ready, expected) = if action == "journal" {
        let expected = format!("{side}-commit");
        command
            .env("QPERIAPT_RETIRED_ERASURE_CHILD", root)
            .env("QPERIAPT_RETIRED_ERASURE_STAGE", &expected);
        (root.join("erasure-ready"), expected)
    } else if action == "signer" {
        let expected = format!("{stage}-{side}");
        command
            .env("QPERIAPT_SIGNER_CUT_ROOT", root)
            .env("QPERIAPT_SIGNER_CUT_STAGE", &expected);
        (root.join("signer-ready"), expected)
    } else {
        let expected = format!("{stage}-{side}");
        command
            .env("QPERIAPT_ROOT_PARENT_DIR", root)
            .env("QPERIAPT_ROOT_PARENT_CUT", &expected);
        (root.join("ready"), expected)
    };
    let mut child = crate::durable::tests::ChildGuard(command.spawn().expect("actual cut process"));
    let killed = child.0.id();
    let until = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < until,
            "cut not reached: {}",
            fs::read_to_string(root.join("cut.log")).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(ready).expect("actual boundary"),
        expected
    );
    assert!(!root.join("cleanup-returned").exists());
    child.0.kill().expect("real SIGKILL");
    assert_eq!(child.0.wait().expect("reaped process").signal(), Some(9));
    let mut recovered = crate::durable::tests::ChildGuard(
        command_for_recovery(root)
            .spawn()
            .expect("new recovery process"),
    );
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = recovered.0.try_wait().expect("recovery status") {
            assert!(
                status.success(),
                "recovery failed: {}",
                fs::read_to_string(root.join("recovered.log")).expect("log")
            );
            break;
        }
        assert!(Instant::now() < until, "bounded recovery");
        std::thread::sleep(Duration::from_millis(10));
    }
    let pid: u32 = fs::read_to_string(root.join("cleanup-pid"))
        .expect("new PID")
        .parse()
        .expect("PID");
    assert_ne!(pid, killed);
    assert_ne!(pid, std::process::id());
    assert_eq!(
        fs::read_to_string(root.join("cleanup-returned")).expect("actual return"),
        action
    );
    (killed, pid)
}
fn command_for_recovery(root: &Path) -> Command {
    command(root, "recovered.log")
}

fn exercise(work: Work) {
    for later in [false, true] {
        for (action, stage) in [
            ("inventory", "cleanup-parent"),
            ("journal", "commit"),
            ("signer-plan", "cleanup-parent"),
            ("signer", "HeaderWrite"),
            ("signer", "HeaderSync"),
            ("signer", "Truncate"),
            ("signer", "TerminalSync"),
            ("signer", "DirectorySync"),
        ] {
            for after in [false, true] {
                let mut c = prepare_cleanup(work);
                let root = c
                    .flow
                    .t
                    .f
                    .original
                    .paths
                    .configuration
                    .parent()
                    .expect("owned root")
                    .to_path_buf();
                publish(&c, &root);
                if later {
                    later_accounting(&mut c.flow);
                }
                accounting(&c, &root);
                let resume = |c: &CleanupCase| {
                    ManagedAccountRootReplacement::resume_transferred_cleanup_original(
                        c.recovery.open(&c.flow.t.f),
                        c.recovery.expected,
                        c.plan.as_ref().clone(),
                        c.flow.t.f.original.paths.clone(),
                        c.flow.t.f.original.intent.clone(),
                        c.flow.context.history().clone(),
                    )
                };
                if action != "inventory" {
                    let mut owner = resume(&c).expect("same final controller");
                    let ack = owner
                        .with_retired_cleanup(|parent| {
                            let child = parent.installation()?;
                            let (report, verified, previous) = c.flow.report(child);
                            let ack = c
                                .flow
                                .account(child, &report, &verified, &previous)
                                .as_bytes()
                                .to_vec();
                            if action != "journal" {
                                child.erase_journal(c.flow.context.accounting_pin(), &ack)?;
                            }
                            if action == "signer" {
                                parent.prepare_signer_erasure(&ack)?;
                            }
                            Ok(ack)
                        })
                        .expect("complete original host accounting");
                    owner.close();
                    fs::write(root.join("cleanup-ack"), ack).expect("exact original ACK");
                }
                fs::write(root.join("cleanup-action"), action).expect("fixed action");
                let (killed, recovered) = cut(&root, action, stage, after);
                let mut owner =
                    resume(&c).expect("same final controller after strong process boundary");
                owner
                    .with_retired_cleanup(|parent| {
                        let child = parent.installation()?;
                        let ack = if action == "inventory" {
                            let (report, verified, previous) = c.flow.report(child);
                            c.flow
                                .account(child, &report, &verified, &previous)
                                .as_bytes()
                                .to_vec()
                        } else {
                            fs::read(root.join("cleanup-ack")).expect("retained ACK")
                        };
                        if child.journal_erasure_status(c.flow.context.accounting_pin())?
                            == JournalErasureState::Retained
                        {
                            child.erase_journal(c.flow.context.accounting_pin(), &ack)?;
                        }
                        parent.prepare_signer_erasure(&ack)?;
                        parent.erase_signer()
                    })
                    .expect("finish original authorized erasure");
                owner.close();
                resume(&c)
                    .expect("cold exact original context without signer or journal")
                    .close();
                assert_eq!(
                    fs::read(&c.flow.t.f.original.paths.signer).expect("terminal signer"),
                    b"QPSRET01"
                );
                assert!(
                    fs::read(&c.flow.t.f.original.paths.wrapping).expect("original wrapping key")
                        == c.original_bytes.2[0]
                );
                assert!(original_parent(&c.flow.t) == c.original_bytes.1);
                eprintln!("SUCCESSIVE_CLEANUP_SIGKILL work={work:?} later={later} action={action} stage={stage} after={after} killed={killed} recovered={recovered} exact_two_closures=true");
            }
        }
    }
}
#[test]
fn transferred_successive_cleanup_process_policy() {
    exercise(Work::Policy(2));
}
#[test]
fn transferred_successive_cleanup_process_credential() {
    exercise(Work::Credential(1));
}
#[test]
fn transferred_successive_cleanup_process_roster() {
    exercise(Work::Roster(1));
}
#[test]
fn transferred_successive_cleanup_process_cancellation() {
    exercise(Work::Cancellation(true));
}
