// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn account_root_enrollment_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ROOT_PARENT_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let public = fs::read(path.join("independent-inputs")).expect("retained public inputs");
    let mut d = Decoder::new(&public);
    let root = PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("root bytes")).expect("root");
    assert_eq!(
        d.array::<32>().expect("account"),
        crate::identity::account_id(&root)
    );
    let id = d.array().expect("device id");
    let generation = u64::from_be_bytes(d.array().expect("generation"));
    let from = u64::from_be_bytes(d.array().expect("from"));
    let until = u64::from_be_bytes(d.array().expect("until"));
    let family = d.array().expect("family");
    let intent = EnrollmentIntent::new(
        root,
        DeviceDescription::new(
            id,
            generation,
            family,
            Validity::new(from, until).expect("validity"),
        )
        .expect("description"),
    );
    let identity =
        AnchorIdentity::from_trusted_state(d.array().expect("witness identity")).expect("identity");
    let public =
        PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("witness key")).expect("witness public");
    d.finish().expect("exact independent inputs");
    let p =
        Proposal::from_trusted_state(&fs::read(path.join("proposal")).expect("original proposal"))
            .expect("proposal");
    let pin = AnchorPin::new(identity, public);
    let mut recovery =
        AccountRootEnrollmentRecovery::resume_original(paths(&path), intent, pin.clone(), p)
            .expect("original recovery");
    let cut = std::env::var("QPERIAPT_ROOT_PARENT_CUT").expect("cut");
    if cut.starts_with("receipt-") {
        recovery
            .retain_witness_retirement(
                &fs::read(path.join("receipt")).expect("signed original receipt"),
            )
            .expect("retain decision");
    } else if cut.starts_with("handoff-") || cut.starts_with("child-handoff-") {
        let plan = crate::AnchorAccountReplacementPlan::from_trusted_state(
            &fs::read(path.join("original-plan")).expect("original approved plan"),
        )
        .expect("exact original plan");
        let closed = pin
            .verify_closed_account_preparation(
                &plan,
                &fs::read(path.join("noncommit")).expect("original witness proof"),
            )
            .expect("authenticated original non-commit");
        let next = Proposal::from_trusted_state(
            &fs::read(path.join("approved-next")).expect("independent next approval"),
        )
        .expect("exact next proposal");
        let transition = crate::AccountRootJournalTransition::from_closed_preparation(closed, next)
            .expect("scoped original transition");
        recovery
            .transition_after_noncommit(&transition)
            .expect("parent then child transition");
    }
    fs::write(path.join("returned"), b"returned").expect("API return marker");
}

#[test]
fn account_root_enrollment_process_loss_before_and_after_parent_commits() {
    for stage in ["intent", "receipt"] {
        for after in [false, true] {
            let f = fixture();
            let p = f.proposal(228);
            let path = f
                .original
                .paths
                .wrapping
                .parent()
                .expect("original directory");
            let mut public = f.original.intent.root.encode();
            f.original.intent.encode(&mut public);
            public.extend_from_slice(f.pin.identity().as_bytes());
            public.extend_from_slice(&f.pin.public_key().encode());
            fs::write(path.join("independent-inputs"), public)
                .expect("retained public expectations");
            fs::write(path.join("proposal"), p.to_bytes().expect("proposal bytes"))
                .expect("original approved intent");
            if stage == "receipt" {
                f.resume(&p).close();
                fs::write(path.join("receipt"), f.receipt(&p)).expect("original signed receipt");
            }
            let log = fs::File::create_new(path.join("child.log")).expect("owned log");
            let mut child = crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", "enrollment::account_root::tests::process::account_root_enrollment_process_child", "--nocapture"])
            .env("QPERIAPT_ROOT_PARENT_DIR", path)
            .env("QPERIAPT_ROOT_PARENT_CUT", format!("{stage}-{}", if after { "after" } else { "before" }))
            .stdout(Stdio::from(log.try_clone().expect("stdout"))).stderr(Stdio::from(log))
            .spawn().expect("owned child"));
            let deadline = Instant::now() + Duration::from_secs(20);
            while !path.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("child status").is_none()
                        && Instant::now() < deadline,
                    "parent checkpoint not reached: {}",
                    fs::read_to_string(path.join("child.log")).expect("child log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!path.join("returned").exists());
            child.0.kill().expect("kill at parent boundary");
            assert!(!child.0.wait().expect("reap child").success());
            let mut recovery = f.resume(&p);
            assert_eq!(recovery.proposal().expect("original intent"), p);
            assert_eq!(
                recovery.status().expect("original parent observation"),
                if stage == "receipt" && after {
                    AccountRootEnrollmentState::WitnessCommitted
                } else {
                    AccountRootEnrollmentState::IntentRetained
                }
            );
            recovery
                .retain_witness_retirement(&f.receipt(&p))
                .expect("same original decision");
            recovery.close();
            f.assert_fenced();
        }
    }
}
