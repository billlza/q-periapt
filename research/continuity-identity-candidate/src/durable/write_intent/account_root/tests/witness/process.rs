// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};

fn read(root: &Path, name: &str) -> Vec<u8> {
    fs::read(root.join(name)).expect("retained original public input")
}
fn pin(root: &Path, name: &str) -> crate::AnchorPin {
    let raw = read(root, name);
    let mut d = Decoder::new(&raw);
    let value = crate::AnchorPin::new(
        crate::AnchorIdentity::from_trusted_state(d.array().expect("identity")).expect("identity"),
        crate::PublicKey::decode(d.take(crate::PUBLIC_KEY_BYTES).expect("key bytes"))
            .expect("public key"),
    );
    d.finish().expect("complete independent pin");
    value
}
fn device(root: &Path, prefix: &str) -> crate::VerifiedDevice {
    let key = crate::PublicKey::decode(&read(root, &format!("{prefix}-root")))
        .expect("independent account root");
    let raw = read(root, &format!("{prefix}-checkpoint"));
    let mut d = Decoder::new(&raw);
    let checkpoint = crate::RosterCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("checkpoint");
    d.finish().expect("complete checkpoint");
    crate::AccountPin::new(
        crate::identity::account_id(&key),
        key,
        checkpoint,
        read(root, &format!("{prefix}-family"))
            .try_into()
            .expect("family"),
    )
    .expect("independent account pin")
    .verify_device(
        &read(root, &format!("{prefix}-certificate")),
        &read(root, &format!("{prefix}-roster")),
        185,
    )
    .expect("same original signed credential and roster")
}
fn publish(f: &Ready) {
    f.c.publish_child_inputs();
    let next = &f.next;
    let roster = next.device.roster().checkpoint();
    let policy = next.policy.checkpoint();
    for (name, wire) in [
        ("target-certificate", next.certificate.clone()),
        ("target-root", next.device.authority_key.encode()),
        ("target-roster", next.device.roster().as_bytes().to_vec()),
        ("target-family", next.policy.family().to_vec()),
        (
            "target-checkpoint",
            [roster.version().to_be_bytes().as_slice(), &roster.digest()].concat(),
        ),
        ("target-policy", next.policy_wire.clone()),
        ("target-policy-root", next.policy_root.encode()),
        (
            "target-policy-checkpoint",
            [policy.version().to_be_bytes().as_slice(), &policy.digest()].concat(),
        ),
        ("target-subject", next.genesis.subject().to_bytes()),
        ("target-image", next.genesis.image_digest().to_vec()),
        ("original-journal", f.c.identity.as_bytes().to_vec()),
        (
            "root-approval",
            f.approval
                .to_bytes()
                .expect("original independent root approval"),
        ),
    ] {
        fs::write(f.c.root.join(name), wire).expect("retain original public inputs");
    }
}

#[test]
fn transferred_root_journal_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_ROOT_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let logical = pin(root, "origin-pin");
    let current = pin(root, "current-pin");
    let history = crate::AnchorHandoffHistory::restore_trusted_state(
        &read(root, "history"),
        &logical,
        &current,
        read(root, "checkpoint")
            .try_into()
            .expect("history checkpoint"),
    )
    .expect("original independently verified history");
    let selection = witness_handoff::tests::support::restore_child_plan(root);
    let original = device(root, "original");
    let target = device(root, "target");
    let raw = read(root, "target-policy-checkpoint");
    let mut d = Decoder::new(&raw);
    let checkpoint = crate::PolicyCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("policy checkpoint");
    d.finish().expect("complete checkpoint");
    let policy = crate::PolicyPin::new(
        read(root, "target-family").try_into().expect("family"),
        crate::PublicKey::decode(&read(root, "target-policy-root")).expect("policy authority"),
        checkpoint,
    )
    .expect("independent policy pin")
    .verify(
        &read(root, "target-policy"),
        crate::tests::sdk_runtime(),
        185,
    )
    .expect("original policy, no new signature");
    let genesis = crate::AnchorGenesis::from_trusted_state(
        crate::AnchorSubject::from_trusted_state(&read(root, "target-subject"))
            .expect("original subject"),
        read(root, "target-image")
            .try_into()
            .expect("original image digest"),
    )
    .expect("actual original target genesis");
    let m = Materials {
        previous_root: &original.authority_key,
        genesis: &genesis,
        device: &target,
        policy: &policy,
        history: &history,
    };
    let approval = Approval::restore_trusted_state(&read(root, "root-approval"), &m)
        .expect("same complete account decision");
    let plan = TransferredAccountRootJournalPlan::new(logical, approval, history, Some(selection))
        .expect("same root and Witness expectations");
    let mut owner = AccountRootJournalRecovery::resume_transferred_original(
        &root.join("client/state.redb"),
        JournalKey::open(&root.join("client/key")).expect("original wrapping key"),
        &original,
        JournalIdentity::from_trusted_state(
            read(root, "original-journal")
                .try_into()
                .expect("identity width"),
        )
        .expect("original identity"),
        plan,
    )
    .expect("same restricted original owner");
    let decision = read(root, "root-decision");
    owner
        .retain_account_decision(&decision)
        .expect("original signed outcome");
    assert_eq!(
        owner
            .account_decision()
            .expect("exact retained outcome")
            .as_bytes(),
        decision
    );
    fs::write(root.join("returned-root-decision"), decision).expect("released result");
    fs::write(
        root.join("root-recovery-pid"),
        std::process::id().to_string(),
    )
    .expect("new recovery process ID");
}

fn observed(c: &WitnessCase) -> Option<Fence> {
    let db = open_private_database(&c.path()).expect("same database");
    let tx = db.begin_read().expect("read");
    let table = image_table(&tx).expect("table");
    table
        .get(ROW)
        .expect("row")
        .map(|v| Fence::decode(&c.key(), v.value()).expect("authenticated retained fence"))
}
#[test]
fn transferred_root_journal_process_loss_at_both_commits_recovers_original_in_new_pid() {
    const CHILD: &str = "durable::write_intent::account_root::tests::witness::process::transferred_root_journal_process_child";
    for phase in ["fence", "receipt"] {
        for after in [false, true] {
            for closed in [false, true] {
                let mut f = Ready::new();
                let original = f.c.original_rows();
                let selected = control(&f.c);
                publish(&f);
                if phase == "receipt" {
                    let mut owner = f.open().expect("first local fence committed");
                    owner.close();
                }
                let decision = f.decide(closed);
                fs::write(f.c.root.join("root-decision"), decision.as_bytes())
                    .expect("same independent server proof");
                let root = &f.c.root;
                let command = || {
                    let mut cmd = Command::new(std::env::current_exe().expect("test binary"));
                    cmd.args(["--exact", CHILD, "--nocapture"])
                        .env("QPERIAPT_TRANSFERRED_ROOT_DIR", root);
                    cmd
                };
                let log = fs::File::create(root.join("root-crash.log")).expect("owned log");
                let mut child = crate::durable::tests::ChildGuard(
                    command()
                        .env("QPERIAPT_ROOT_FENCE_DIR", root)
                        .env(
                            "QPERIAPT_ROOT_FENCE_CUT",
                            format!("{phase}-{}", if after { "after" } else { "before" }),
                        )
                        .stdout(Stdio::from(log.try_clone().expect("log")))
                        .stderr(Stdio::from(log))
                        .spawn()
                        .expect("new crash process"),
                );
                let killed = child.0.id();
                let deadline = Instant::now() + Duration::from_secs(30);
                while !root.join("ready").exists() {
                    let status = child.0.try_wait().expect("status");
                    assert!(
                        status.is_none() && Instant::now() < deadline,
                        "bounded exact boundary: status={status:?}, log={}",
                        String::from_utf8_lossy(&read(root, "root-crash.log"))
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    read(root, "ready"),
                    format!("{phase}-{}", if after { "after" } else { "before" }).as_bytes()
                );
                assert!(!root.join("returned-root-decision").exists());
                child.0.kill().expect("kill owned child");
                assert_eq!(child.0.wait().expect("reap owned child").signal(), Some(9));
                let before = observed(&f.c);
                if phase == "fence" {
                    assert_eq!(before.is_some(), after);
                } else {
                    assert_eq!(
                        before.as_ref().expect("original fence").receipt.is_some(),
                        after
                    );
                }
                if let Some(wire) = before.as_ref().and_then(|v| v.receipt.as_deref()) {
                    assert_eq!(wire, decision.as_bytes());
                }
                let log = fs::File::create(root.join("root-recover.log")).expect("recovery log");
                let mut recovery = crate::durable::tests::ChildGuard(
                    command()
                        .stdout(Stdio::from(log.try_clone().expect("log")))
                        .stderr(Stdio::from(log))
                        .spawn()
                        .expect("new recovery process"),
                );
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    if let Some(status) = recovery.0.try_wait().expect("recovery status") {
                        assert!(
                            status.success(),
                            "recovery log={}",
                            String::from_utf8_lossy(&read(root, "root-recover.log"))
                        );
                        break;
                    }
                    assert!(Instant::now() < deadline, "bounded recovery");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let recovered: u32 = fs::read_to_string(root.join("root-recovery-pid"))
                    .expect("PID")
                    .parse()
                    .expect("numeric PID");
                assert_ne!(recovered, killed);
                assert_ne!(recovered, std::process::id());
                assert_eq!(read(root, "returned-root-decision"), decision.as_bytes());
                assert_eq!(f.c.original_rows(), original);
                assert_eq!(control(&f.c), selected);
                let mut owner = f.open().expect("same cold context");
                assert_eq!(
                    owner.status().expect("same terminal"),
                    if closed {
                        AccountRootJournalState::WitnessClosed
                    } else {
                        AccountRootJournalState::WitnessCommitted
                    }
                );
                owner.close();
                eprintln!("TRANSFERRED_ROOT_PROCESS phase={phase} after={after} closed={closed} killed={killed} recovered={recovered}");
            }
        }
    }
}
