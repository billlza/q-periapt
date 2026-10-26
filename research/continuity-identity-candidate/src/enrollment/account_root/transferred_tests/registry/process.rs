// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::process::inputs;
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, Stdio},
};
const CHILD:&str="enrollment::account_root::tests::transferred::registry::process::transferred_registry_process_child";

#[test]
fn transferred_registry_process_child() -> Result<(), DurableError> {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_REGISTRY_DIR") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let inputs = inputs::restore_registry(&root);
    let base = root.parent().expect("original fixture directory");
    let bytes = fs::read(root.join("registry-inputs"))
        .expect("independently retained registry identity/checkpoint");
    let mut d = Decoder::new(&bytes);
    let identity =
        AccountAuthorityIdentity::from_trusted_state(d.array().expect("registry identity"))
            .expect("identity");
    let app = ApplicationAccountId::from_trusted_state(d.array().expect("application"))
        .expect("application");
    let expected = AccountAuthorityCheckpoint::from_trusted_state(
        app,
        d.u64().expect("revision"),
        d.array().expect("account"),
    )
    .expect("original checkpoint");
    d.finish().expect("complete independent registry inputs");
    let family = fs::read(root.join("policy-family"))
        .expect("original family")
        .try_into()
        .expect("family width");
    let mut registry = AccountAuthorityStore::open(
        &base.join("original-registry"),
        JournalKey::open(&base.join("original-registry-key")).expect("same original key"),
        identity,
        family,
        inputs.logical,
    )
    .expect("same original registry");
    let phase = std::env::var("QPERIAPT_TRANSFERRED_REGISTRY_PHASE")
        .expect("owned test phase")
        .parse::<u8>()
        .expect("phase");
    let wire = fs::read(root.join("root-decision")).expect("original signed result");
    match phase {
        0 => assert_eq!(
            registry
                .begin_transferred_preparation(
                    expected,
                    inputs.preparation.clone(),
                    &inputs.history
                )
                .expect("reconcile original preparation"),
            State::Preparing
        ),
        1 => assert_eq!(
            registry
                .bind_transferred_preparation(
                    inputs.preparation.operation(),
                    &inputs.frozen,
                    inputs.approval
                )
                .expect("reconcile original freeze binding"),
            State::Pending
        ),
        2 => {
            registry
                .retain_transferred_account_decision(inputs.preparation.operation(), &wire)
                .expect("reconcile exact original outcome");
            assert_eq!(
                registry
                    .transferred_account_decision(inputs.preparation.operation())
                    .expect("exact retained wire")
                    .as_bytes(),
                wire
            );
        }
        _ => return Err(DurableError::Corrupt),
    }
    assert_eq!(
        registry
            .transferred_preparation(inputs.preparation.operation())
            .expect("retained original intent")
            .2,
        &inputs.preparation
    );
    registry.close();
    fs::write(
        root.join("registry-returned"),
        if phase == 2 {
            wire
        } else {
            inputs.preparation.to_bytes().expect("exact original plan")
        },
    )
    .expect("owned original result");
    fs::write(
        root.join("registry-recovery-pid"),
        std::process::id().to_string(),
    )
    .expect("actual new process");
    Ok(())
}
fn command(root: &Path, phase: u8, label: &str) -> Command {
    let log = fs::File::create_new(root.join(label)).expect("owned child log");
    let mut cmd = Command::new(std::env::current_exe().expect("same source executable"));
    cmd.args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_TRANSFERRED_REGISTRY_DIR", root)
        .env("QPERIAPT_TRANSFERRED_REGISTRY_PHASE", phase.to_string())
        .stdout(Stdio::from(log.try_clone().expect("stdout")))
        .stderr(Stdio::from(log));
    cmd
}
#[test]
fn transferred_registry_sigkill_reopens_original_intent_and_exact_outcomes_in_new_process() {
    for closed in [false, true] {
        for phase in 0..=2 {
            for after in [false, true] {
                let (t, mut registry, wire) = recovery::setup(phase, closed);
                let rows = journal_rows(&t);
                let parent = original_parent(&t);
                let keys = [
                    &registry.key,
                    &t.f.original.paths.wrapping,
                    &t.f.original.paths.signer,
                ]
                .map(|p| fs::read(p).expect("same original sealed key file"));
                inputs::publish(&t, &wire);
                let root =
                    t.f.original
                        .paths
                        .configuration
                        .parent()
                        .expect("original parent directory");
                let mut trusted = registry.identity.as_bytes().to_vec();
                trusted.extend_from_slice(registry.expected.application().as_bytes());
                trusted.extend_from_slice(&registry.expected.revision().to_be_bytes());
                trusted.extend_from_slice(&registry.expected.account());
                fs::write(root.join("registry-inputs"), trusted)
                    .expect("original independent checkpoint");
                registry.owner.close();
                let cut = format!("{phase}-{}", if after { "after" } else { "before" });
                let mut child = crate::durable::tests::ChildGuard(
                    command(root, phase, "registry-cut.log")
                        .env("QPERIAPT_TRANSFERRED_REGISTRY_CUT", &cut)
                        .spawn()
                        .expect("cut process"),
                );
                let killed = child.0.id();
                let until = Instant::now() + Duration::from_secs(30);
                while !root.join("ready").exists() {
                    assert!(
                        child.0.try_wait().expect("status").is_none() && Instant::now() < until,
                        "cut not reached: {}",
                        fs::read_to_string(root.join("registry-cut.log")).expect("log")
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(!root.join("registry-returned").exists());
                child.0.kill().expect("actual SIGKILL");
                assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
                let mut recovered = crate::durable::tests::ChildGuard(
                    command(root, phase, "registry-recover.log")
                        .spawn()
                        .expect("new recovery process"),
                );
                let until = Instant::now() + Duration::from_secs(30);
                loop {
                    if let Some(status) = recovered.0.try_wait().expect("recovery status") {
                        assert!(
                            status.success(),
                            "recovery failed: {}",
                            fs::read_to_string(root.join("registry-recover.log")).expect("log")
                        );
                        break;
                    }
                    assert!(Instant::now() < until, "bounded new-process recovery");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let pid = fs::read_to_string(root.join("registry-recovery-pid"))
                    .expect("returned PID")
                    .parse::<u32>()
                    .expect("PID");
                assert_ne!(pid, killed);
                assert_ne!(pid, std::process::id());
                assert_eq!(
                    fs::read(root.join("registry-returned")).expect("original result"),
                    if phase == 2 {
                        wire
                    } else {
                        t.preparation.to_bytes().expect("original plan")
                    }
                );
                assert!(
                    journal_rows(&t) == rows && original_parent(&t) == parent,
                    "registry-only recovery changed original parent/pending/selection"
                );
                for (path, before) in [
                    &registry.key,
                    &t.f.original.paths.wrapping,
                    &t.f.original.paths.signer,
                ]
                .into_iter()
                .zip(keys)
                {
                    assert!(fs::read(path).expect("retained keys") == before);
                }
                registry.reopen(&t.f);
                assert_eq!(
                    registry
                        .owner
                        .transferred_preparation(t.preparation.operation())
                        .expect("same original recovered intent")
                        .2,
                    &t.preparation
                );
                eprintln!("TRANSFERRED_REGISTRY_SIGKILL phase={phase} closed={closed} after={after} killed={killed} recovered={pid} original_pending=true same_registry=true");
            }
        }
    }
}
