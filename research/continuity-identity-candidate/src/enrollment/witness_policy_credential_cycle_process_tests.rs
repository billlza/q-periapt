// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kill all three original stores between G terminal persistence and cleanup.
use super::*;
use crate::durable::tests::ChildGuard;
use std::{
    process::{Command, Stdio},
    time::Instant,
};

#[test]
fn required_policy_credential_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_CREDENTIAL_CHILD") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let roster_first = std::env::var("QPERIAPT_POLICY_CREDENTIAL_ROSTER").as_deref() == Ok("1");
    let (f, a) = if roster_first {
        roster::with_existing_prekey()
    } else {
        adopted()
    };
    let previous = if roster_first {
        let target = roster::roster_target(&f, &f.original, 2, 155);
        roster::refresh(&f, &a.target, &f.original, &target, 155).expect("original R before G");
        let mut owner = open(&f.c);
        let Some(crate::WitnessedRosterRefreshProgress::Terminal {
            proposal,
            retired: true,
            ..
        }) = owner
            .witnessed_roster_refresh_progress()
            .expect("R terminal")
        else {
            return Err("original R must have retired");
        };
        fs::write(root.join("original-roster-proposal"), proposal.to_bytes()).expect("original R");
        target
    } else {
        f.original.clone()
    };
    let g = credential::grant(&f, &previous, if roster_first { 3 } else { 2 }, 280);
    let p = prepared_g(&f, &a, &g);
    let saved = journal(&f);
    for (name, path) in [
        (
            "enrollment-path",
            f.c.paths.configuration.parent().expect("parent"),
        ),
        ("witness-path", f._witness_dir.path()),
    ] {
        fs::write(
            root.join(name),
            path.canonicalize()
                .expect("canonical private path")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .expect("retain path");
    }
    fs::write(root.join("witness-id"), f.pin.identity().as_bytes()).expect("instance");
    fs::write(root.join("trusted-root"), f.c.intent.root.encode()).expect("public root");
    fs::write(root.join("proposal"), p.to_bytes()).expect("proposal");
    fs::write(root.join("old-image"), &saved.0).expect("original encrypted image");
    fs::write(root.join("target-image"), credential_target(&saved)).expect("exact sealed target");
    let (issuer, issued, _, _) = crate::tests::session_policy_fixture_with_anchor(
        &[PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&f.pin),
    );
    assert_eq!(issued.checkpoint(), f.c.policy.checkpoint());
    fs::write(root.join("policy-wire"), issued.as_bytes()).expect("historical wire");
    fs::write(
        root.join("policy-root"),
        issuer.public_key().expect("public issuer").encode(),
    )
    .expect("issuer pin");
    fs::write(root.join("family"), f.c.policy.family()).expect("family");
    let mut checkpoint = issued.checkpoint().version().to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&issued.checkpoint().digest());
    fs::write(root.join("policy-checkpoint"), checkpoint).expect("historical pin");
    let mut owner = open(&f.c);
    let mut client = credential::client(&f, &mut owner, 180);
    if std::env::var("QPERIAPT_POLICY_CREDENTIAL_CLOSE").as_deref() == Ok("1") {
        owner
            .close_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                180,
                &mut client,
            )
            .expect("close original G");
    } else {
        owner
            .commit_witnessed_policy_continuation(
                &p,
                f.c.policy.historical(),
                &a.target,
                180,
                &mut client,
            )
            .expect("commit original G");
    }
    Err("expected process cut was not reached")
}

#[test]
fn required_policy_credential_cycle_process_kills_recover_original_terminal_at_each_store_boundary()
{
    process_kills(false);
}

#[test]
fn original_credential_roster_g_process_kills_preserve_prior_r_at_each_store_boundary() {
    process_kills(true);
}

fn process_kills(roster_first: bool) {
    for closed in [false, true] {
        for stage in [
            "witness-observed",
            "witness-terminal",
            "witness-retired",
            "witness-complete",
        ] {
            let folder = directory();
            let root = folder.path().canonicalize().expect("private directory");
            let log = fs::File::create(root.join("child.log")).expect("log");
            let mut child=ChildGuard(Command::new(std::env::current_exe().expect("frozen executable"))
                .args(["--exact","enrollment::tests::witness_renewal::independent_policy::operational::credential_composition::cycle::process::required_policy_credential_process_child","--nocapture"])
                .env("TMPDIR",&root).env("QPERIAPT_POLICY_CREDENTIAL_CHILD",&root)
                .env("QPERIAPT_POLICY_CREDENTIAL_CLOSE",if closed {"1"} else {"0"})
                .env("QPERIAPT_POLICY_CREDENTIAL_ROSTER",if roster_first {"1"} else {"0"})
                .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT",&root).env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE",stage)
                .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log)).spawn().expect("owned child"));
            let deadline = Instant::now() + Duration::from_secs(40);
            while !root.join("renewal-ready").exists() {
                assert!(
                    child.0.try_wait().expect("child status").is_none()
                        && Instant::now() < deadline,
                    "cut {stage} missing: {}",
                    fs::read_to_string(root.join("child.log")).expect("log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().expect("SIGKILL owned enrollment process");
            assert!(!child.0.wait().expect("reap").success());
            let enrollment =
                PathBuf::from(fs::read_to_string(root.join("enrollment-path")).expect("path"));
            let witness =
                PathBuf::from(fs::read_to_string(root.join("witness-path")).expect("path"));
            assert!(enrollment.starts_with(&root) && witness.starts_with(&root));
            let identity = crate::AnchorIdentity::from_trusted_state(
                fs::read(root.join("witness-id"))
                    .expect("identity")
                    .try_into()
                    .expect("width"),
            )
            .expect("identity");
            let store = AnchorStore::open(
                &witness.join("witness.redb"),
                JournalKey::open(&witness.join("witness.key")).expect("original wrapping"),
                crate::AnchorSigningKey::deterministic([226; 32], [227; 32])
                    .expect("original test signer"),
                identity,
            )
            .expect("original witness reopens");
            let pin = store.pin().expect("pin");
            let carrier = credential::Carrier {
                store: Arc::new(Mutex::new(store)),
                clock: Arc::new(AtomicU64::new(500)),
                cut: Arc::new(Mutex::new(None)),
                requests: Arc::new(Mutex::new(Vec::new())),
                after_reply: Arc::new(Mutex::new(None)),
            };
            let raw = fs::read(root.join("policy-checkpoint")).expect("checkpoint");
            let mut d = Decoder::new(&raw);
            let checkpoint = crate::PolicyCheckpoint::from_trusted_state(
                d.u64().expect("version"),
                d.array().expect("digest"),
            )
            .expect("checkpoint");
            d.finish().expect("exact pin");
            let policy = crate::PolicyPin::new(
                fs::read(root.join("family"))
                    .expect("family")
                    .try_into()
                    .expect("width"),
                PublicKey::decode(&fs::read(root.join("policy-root")).expect("root"))
                    .expect("public root"),
                checkpoint,
            )
            .expect("independent pin")
            .verify_historical(&fs::read(root.join("policy-wire")).expect("wire"))
            .expect("historical P without runtime");
            let intent = EnrollmentIntent::new(
                PublicKey::decode(&fs::read(root.join("trusted-root")).expect("account root"))
                    .expect("public root"),
                DeviceDescription::new(
                    [7; 16],
                    1,
                    policy.family(),
                    Validity::new(100, 160).expect("original C interval"),
                )
                .expect("original intent"),
            );
            let paths = paths(&enrollment);
            let mut owner =
                DeviceEnrollment::open(paths.clone(), intent).expect("original enrollment");
            let mut client = owner
                .credential_renewal_anchor_client(
                    &policy,
                    500,
                    pin,
                    Box::new(carrier),
                    Duration::from_secs(3),
                )
                .expect("original historical signer");
            let p =
                GProposal::from_trusted_state(&fs::read(root.join("proposal")).expect("proposal"))
                    .expect("exact proposal");
            let outcome = owner
                .reconcile_witnessed_credential_renewal(
                    p.operation(),
                    p.statement(),
                    &policy,
                    500,
                    &mut client,
                )
                .expect("recover original G after C/P expiry");
            assert!(match outcome {
                GStatus::Closed {
                    operation,
                    statement,
                    ..
                } if closed => operation == p.operation() && statement == p.statement(),
                GStatus::Committed {
                    operation,
                    statement,
                    ..
                } if !closed => operation == p.operation() && statement == p.statement(),
                _ => false,
            });
            if roster_first {
                let proposal = crate::AnchorRosterRefreshProposal::from_trusted_state(
                    &fs::read(root.join("original-roster-proposal")).expect("original R"),
                )
                .expect("exact R proposal");
                assert_eq!(
                    owner
                        .witnessed_roster_refresh_progress()
                        .expect("retained R"),
                    Some(crate::WitnessedRosterRefreshProgress::Terminal {
                        proposal,
                        disposition: crate::WitnessedRosterRefreshDisposition::Applied,
                        retired: true,
                    })
                );
            }
            owner.close();
            let db = open_private_database(paths.installation.files()[1]).expect("journal");
            let tx = db.begin_read().expect("read");
            let table = tx.open_table(JOURNAL).expect("table");
            assert!(table.get("pending").expect("pending").is_none());
            assert_eq!(
                table.get("image").expect("image").expect("present").value(),
                fs::read(root.join(if closed { "old-image" } else { "target-image" }))
                    .expect("exact original ciphertext")
            );
        }
    }
    eprintln!("CREDENTIAL_OWNER_PROCESS prior_roster={roster_first} kills=8 original_three_stores=true expired_recovery=true");
}
