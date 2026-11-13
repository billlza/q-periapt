// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn transferred_witness_operating_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_OPERATING_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let plan = restore_child_plan(&root);
    let path = root.join("client/state.redb");
    let mut owner = WitnessJournalAdoption::resume_original(
        &path,
        JournalKey::open(&root.join("client/key")).expect("key"),
        plan,
    )
    .expect("original selection");
    let address: SocketAddr = fs::read_to_string(root.join("current-endpoint"))
        .expect("endpoint")
        .parse()
        .expect("address");
    owner
        .attach_current_witness(
            DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("original signer"),
            Box::new(AnchorTcpTransport::new(address)),
            Duration::from_secs(3),
        )
        .expect("current witness");
    let selected = owner.active.take().expect("selected lease");
    let (image, pending) = selected.snapshot().expect("authenticated state");
    assert!(pending.is_none());
    let Owners {
        db,
        key,
        mut client,
        ..
    } = selected;
    let mut active = Active {
        db,
        key,
        owner: image.owner,
        id: image.id,
        protection: image.protection,
        anchor: None,
        account_authority: None,
        enrollment_completion: None,
    };
    active
        .attach_retained_cleanup_subject(client.take().expect("current client"))
        .expect("exact original subject");
    let mut journal = DeviceJournal {
        active: Some(active),
    };
    let (image, sealed) = super::storage::target(&mut journal);
    fs::write(root.join("operating-original-target"), &sealed)
        .expect("retain exact encrypted target");
    commit(journal.active.as_mut().expect("active"), &image, &sealed)
        .expect("original transaction");
    fs::write(root.join("returned"), b"returned").expect("unexpected returned marker");
}

#[test]
fn transferred_witness_operating_sigkill_preserves_each_original_transaction_boundary() {
    use std::os::unix::process::ExitStatusExt;
    for cut in [
        "ordinary-reserve-before",
        "ordinary-reserve-after",
        "ordinary-apply-before",
        "ordinary-apply-after",
    ] {
        let mut c = Case::new(None);
        let mut owner = super::super::transferred::network::adopt(&mut c);
        let before = rows(&owner.active.as_ref().expect("owner").db);
        owner.close();
        c.publish_child_inputs();
        let ((), target, frames) = serve(c.target.take().expect("target"), |address| {
            fs::write(c.root.join("current-endpoint"), address.to_string()).expect("endpoint");
            let log = fs::File::create(c.root.join("operating-child.log")).expect("log");
            let mut child=crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("binary"))
                .args(["--exact","durable::write_intent::witness_handoff::tests::operating::process::transferred_witness_operating_process_child","--nocapture"])
                .env("QPERIAPT_TRANSFERRED_OPERATING_CHILD",&c.root)
                .env("QPERIAPT_WITNESS_ADOPTION_DIR",&c.root).env("QPERIAPT_WITNESS_ADOPTION_CUT",cut)
                .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log)).spawn().expect("owned child"));
            let deadline = Instant::now() + Duration::from_secs(20);
            while !c.root.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                    "missing cut {cut}: {}",
                    fs::read_to_string(c.root.join("operating-child.log")).expect("log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!c.root.join("returned").exists());
            let pid = child.0.id();
            child.0.kill().expect("kill only owned child");
            assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
            let sealed =
                fs::read(c.root.join("operating-original-target")).expect("original target");
            let mut journal = open(&c, client(c.resume(), address));
            let after = rows(&journal.active.as_ref().expect("reopened").db);
            assert!(
                after.0
                    == if cut == "ordinary-reserve-before" {
                        before.0.clone()
                    } else {
                        sealed
                    }
            );
            assert!(after.1.is_none());
            journal.close();
            eprintln!(
                "TRANSFERRED_OPERATING_KILLED cut={cut} child={pid} parent={}",
                std::process::id()
            );
        });
        assert!(frames >= 2);
        c.target = Some(target);
    }
}
