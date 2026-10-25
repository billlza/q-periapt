// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn pin(path: &Path) -> AnchorPin {
    let bytes = fs::read(path).expect("independently retained public pin");
    let mut d = Decoder::new(&bytes);
    let pin = AnchorPin::new(
        AnchorIdentity::from_trusted_state(d.array().expect("identity")).expect("identity"),
        PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("public key")).expect("public key"),
    );
    d.finish().expect("exact public pin");
    pin
}
#[test]
fn successive_source_control_crash_child() {
    let Some(root) = std::env::var_os("QPERIAPT_SOURCE_CONTROL_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let source = pin(&root.join("source-pin"));
    let target = pin(&root.join("target-pin"));
    let approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &fs::read(root.join("approval")).expect("original target approval"),
        &source,
        &target,
    )
    .expect("same independent pins");
    let key = JournalKey::open(&root.join("wrapping")).expect("original target storage key");
    let signer = AnchorSigningKey::open(&root.join("signer"), &key, target_key_id())
        .expect("original B signer");
    let (mut current, _) = AnchorHandoffTarget::open(&root.join("import.redb"), key, approval)
        .expect("original target database")
        .activate(
            &fs::read(root.join("retirement")).expect("retained A retirement"),
            signer,
        )
        .expect("same activation");
    let plan = AnchorHandoffPlan::restore_trusted_state(
        &fs::read(root.join("source-plan")).expect("exact B plan"),
    )
    .expect("independently retained control input");
    let stage = std::env::var("QPERIAPT_SOURCE_CONTROL_CUT").expect("selected cut");
    let receipt = if stage.starts_with("source-freeze-") {
        current.freeze_handoff(&plan, 180)
    } else {
        current.cancel_handoff(&plan)
    }
    .expect("durable source decision");
    fs::write(root.join("returned-source-receipt"), receipt.as_bytes())
        .expect("release returned receipt");
}

#[test]
fn successive_source_control_process_loss_preserves_exact_original_transaction(
) -> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "anchor::store::tests::handoff_import::adoption::authorization::successive_freeze::process::successive_source_control_crash_child";
    for kind in ["freeze", "cancel"] {
        for committed in [false, true] {
            let mut f = Prepared::new(Some(("R", false)));
            f.active
                .authorize_handoff_client(&f.request, || Ok(180))
                .expect("actual client authorization");
            let original = f.original_entry();
            let (snapshot, plan) = next_plan(&mut f.active, 244);
            if kind == "cancel" {
                f.active
                    .freeze_handoff(&plan, 180)
                    .expect("already committed freeze");
            }
            f.active.close();
            fs::write(f.f.directory.join("retirement"), &f.retired).expect("retained A decision");
            fs::write(f.f.directory.join("source-plan"), plan.to_bytes())
                .expect("retained exact B plan");
            let stage = format!(
                "source-{kind}-{}",
                if committed { "after" } else { "before" }
            );
            let mut child = Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", CHILD, "--nocapture"])
                .env("QPERIAPT_SOURCE_CONTROL_DIR", &f.f.directory)
                .env("QPERIAPT_SOURCE_CONTROL_CUT", &stage)
                .stdout(Stdio::from(
                    fs::File::create(f.f.directory.join("child.stdout")).expect("child stream"),
                ))
                .stderr(Stdio::from(
                    fs::File::create(f.f.directory.join("child.stderr")).expect("child stream"),
                ))
                .spawn()
                .expect("real independent source process");
            let pid = child.id();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !f.f.directory.join("ready").exists() {
                if let Some(status) = child.try_wait().expect("child status") {
                    return Err(format!("child ended before {stage}: {status}").into());
                }
                if Instant::now() >= deadline {
                    child.kill().expect("stop bounded test child");
                    child.wait().expect("reap child");
                    return Err(format!("child did not reach {stage}").into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                fs::read(f.f.directory.join("ready")).expect("boundary marker"),
                if committed {
                    b"committed".as_slice()
                } else {
                    b"before-commit".as_slice()
                }
            );
            assert!(!f.f.directory.join("returned-source-receipt").exists());
            child.kill().expect("actual SIGKILL");
            assert_eq!(child.wait().expect("reap killed source").signal(), Some(9));
            f.reopen();
            let observed = f.active.observe_handoff(&plan);
            if committed || kind == "cancel" {
                assert!(observed.is_ok());
            } else {
                assert!(matches!(&observed, Err(DurableError::Absent)));
            }
            let receipt = if kind == "freeze" {
                let receipt = f
                    .active
                    .freeze_handoff(&plan, 180)
                    .expect("same original freeze retry");
                assert_eq!(
                    f.active
                        .frozen_handoff_state(&plan)
                        .expect("all original source bytes")
                        .as_bytes(),
                    snapshot.as_bytes()
                );
                f.active
                    .cancel_handoff(&plan)
                    .expect("finish exact reversible source decision");
                receipt
            } else {
                f.active
                    .cancel_handoff(&plan)
                    .expect("same original cancellation retry")
            };
            if let Ok(old) = observed {
                if old.state() == receipt.state() {
                    assert_eq!(old.as_bytes(), receipt.as_bytes());
                }
            }
            assert_eq!(f.original_entry(), original);
            assert_ne!(pid, std::process::id());
            eprintln!("SUCCESSIVE_SOURCE_PROCESS stage={stage} killed_pid={pid} recovery_pid={} exact_original=true", std::process::id());
        }
    }
    Ok(())
}
