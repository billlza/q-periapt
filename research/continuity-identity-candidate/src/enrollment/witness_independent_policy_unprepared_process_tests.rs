// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real process termination around the sole local-abandonment durable save.
use super::*;
use crate::durable::tests::ChildGuard;
use crate::PolicyCheckpoint;
use std::process::{Command, Stdio};

#[test]
fn unprepared_policy_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_UNPREPARED_POLICY_CHILD") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    fs::write(
        root.join("enrollment-path"),
        f.c.paths
            .configuration
            .parent()
            .expect("parent")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .expect("path");
    fs::write(root.join("trusted-root"), f.c.intent.root.encode()).expect("root");
    fs::write(root.join("operation"), a.proof.scope().operation.as_bytes()).expect("operation");
    fs::write(root.join("statement"), a.proof.statement_digest()).expect("statement");
    fs::write(root.join("old-image"), journal(&f).0).expect("ciphertext");
    let (authority, issued, _, _) = crate::tests::session_policy_fixture_with_anchor(
        &[PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&f.pin),
    );
    assert_eq!(issued.checkpoint(), f.c.policy.checkpoint());
    fs::write(
        root.join("policy-root"),
        authority.public_key().expect("policy root").encode(),
    )
    .expect("root");
    fs::write(root.join("policy-wire"), issued.as_bytes()).expect("policy");
    fs::write(root.join("family"), f.c.policy.family()).expect("family");
    for (name, checkpoint) in [
        ("original", issued.checkpoint()),
        ("target", a.target.checkpoint()),
    ] {
        let mut bytes = checkpoint.version().to_be_bytes().to_vec();
        bytes.extend_from_slice(&checkpoint.digest());
        fs::write(root.join(name), bytes).expect("checkpoint");
    }
    open(&f.c)
        .abandon_unprepared_policy_renewal(
            a.proof.scope().operation,
            a.proof.statement_digest(),
            f.c.policy.historical(),
        )
        .expect("requested process cut");
    Err("process cut was not reached")
}
fn checkpoint(path: &Path) -> PolicyCheckpoint {
    let bytes = fs::read(path).expect("checkpoint");
    let mut d = Decoder::new(&bytes);
    let result =
        PolicyCheckpoint::from_trusted_state(d.u64().expect("version"), d.array().expect("digest"))
            .expect("pin");
    d.finish().expect("exact checkpoint");
    result
}

#[test]
fn actual_process_kills_recover_unprepared_policy_abandonment_without_network_or_signer() {
    for stage in [
        "independent-policy-unprepared-before-save",
        "independent-policy-unprepared-after-save",
    ] {
        let root = directory().keep().canonicalize().expect("owned directory");
        eprintln!("Unprepared policy cut retained: {}", root.display());
        let log = fs::File::create(root.join("child.log")).expect("log");
        let mut child=ChildGuard(Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact","enrollment::tests::witness_renewal::independent_policy::unprepared::process::unprepared_policy_process_child","--nocapture"])
            .env("TMPDIR",&root).env("QPERIAPT_UNPREPARED_POLICY_CHILD",&root)
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT",&root).env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE",stage)
            .stdout(Stdio::from(log.try_clone().expect("log"))).stderr(Stdio::from(log)).spawn().expect("child"));
        let deadline = Instant::now() + Duration::from_secs(40);
        while !root.join("renewal-ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "missing cut {stage}: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().expect("actual process termination");
        assert!(!child.0.wait().expect("reap").success());
        let folder = PathBuf::from(fs::read_to_string(root.join("enrollment-path")).expect("path"));
        assert!(folder.starts_with(&root));
        let policy = crate::PolicyPin::new(
            fs::read(root.join("family"))
                .expect("family")
                .try_into()
                .expect("width"),
            PublicKey::decode(&fs::read(root.join("policy-root")).expect("root")).expect("root"),
            checkpoint(&root.join("original")),
        )
        .expect("independent pin")
        .verify_historical(&fs::read(root.join("policy-wire")).expect("policy"))
        .expect("history");
        let intent = EnrollmentIntent::new(
            PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root")).expect("root"),
            DeviceDescription::new(
                [7; 16],
                1,
                policy.family(),
                Validity::new(100, 160).expect("original validity"),
            )
            .expect("intent"),
        );
        let paths = paths(&folder);
        fs::rename(&paths.signer, paths.signer.with_extension("retained"))
            .expect("keep original signer offline");
        let operation = PolicyRenewalId::from_trusted_state(
            fs::read(root.join("operation"))
                .expect("operation")
                .try_into()
                .expect("width"),
        )
        .expect("id");
        let statement = fs::read(root.join("statement"))
            .expect("statement")
            .try_into()
            .expect("width");
        let expected = Progress::AbandonedBeforePreparation {
            operation,
            statement,
            target: checkpoint(&root.join("target")),
        };
        let mut owner = DeviceEnrollment::open(paths.clone(), intent.clone()).expect("same owner");
        assert_eq!(
            owner.witnessed_policy_renewal_progress().expect("history"),
            if stage.ends_with("after-save") {
                Some(expected)
            } else {
                None
            }
        );
        assert_eq!(
            owner
                .abandon_unprepared_policy_renewal(operation, statement, &policy)
                .expect("original recovery"),
            expected
        );
        owner.close();
        let mut owner = DeviceEnrollment::open(paths.clone(), intent).expect("readback");
        assert_eq!(
            owner
                .witnessed_policy_renewal_progress()
                .expect("durable history"),
            Some(expected)
        );
        owner.close();
        let db = open_private_database(paths.installation.files()[1]).expect("original journal");
        let tx = db.begin_read().expect("read");
        let table = tx.open_table(JOURNAL).expect("table");
        assert_eq!(
            table
                .get("image")
                .expect("image")
                .expect("retained")
                .value(),
            fs::read(root.join("old-image")).expect("ciphertext")
        );
        assert!(table.get("pending").expect("pending").is_none());
    }
}
