// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kill and reopen actual P enrollment, journal and witness databases together.
use super::*;
use crate::durable::tests::ChildGuard;
use std::process::{Command, Stdio};

#[test]
fn independent_policy_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_INDEPENDENT_POLICY_CHILD") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    let original = journal(&f);
    approve_witness(&f, &a, p);
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
    fs::write(
        root.join("witness-path"),
        f._witness_dir
            .path()
            .canonicalize()
            .expect("path")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .expect("path");
    fs::write(root.join("witness-id"), f.pin.identity().as_bytes()).expect("identity");
    fs::write(root.join("trusted-root"), f.c.intent.root.encode()).expect("account root");
    fs::write(root.join("proposal"), p.to_bytes()).expect("original proposal");
    fs::write(root.join("old-image"), &original.0).expect("original ciphertext");
    fs::write(root.join("target-image"), target(&original)).expect("original sealed target");
    let (authority, issued, _, _) = crate::tests::session_policy_fixture_with_anchor(
        &[PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&f.pin),
    );
    assert_eq!(issued.checkpoint(), f.c.policy.checkpoint());
    fs::write(
        root.join("trusted-policy-root"),
        authority.public_key().expect("policy root").encode(),
    )
    .expect("root");
    fs::write(root.join("policy-wire"), issued.as_bytes()).expect("public policy");
    fs::write(root.join("trusted-family"), f.c.policy.family()).expect("family");
    for (name, checkpoint) in [
        ("trusted-policy", issued.checkpoint()),
        ("target-policy", a.target.checkpoint()),
    ] {
        let mut bytes = checkpoint.version().to_be_bytes().to_vec();
        bytes.extend_from_slice(&checkpoint.digest());
        fs::write(root.join(name), bytes).expect("public pin");
    }
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    let closed = std::env::var("QPERIAPT_INDEPENDENT_POLICY_CLOSED").expect("mode") == "1";
    run_terminal(&f, &a, p, &mut owner, &mut client, closed).expect("requested terminal flow");
    Err("requested process cut was not reached")
}
fn checkpoint(path: &Path) -> crate::PolicyCheckpoint {
    let bytes = fs::read(path).expect("trusted checkpoint");
    let mut d = Decoder::new(&bytes);
    let result = crate::PolicyCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("checkpoint");
    d.finish().expect("exact pin");
    result
}
#[test]
fn actual_process_kills_recover_original_independent_policy_at_four_cross_store_boundaries() {
    let mut cuts = 0;
    for closed in [false, true] {
        for stage in [
            "independent-policy-observed",
            "independent-policy-terminal",
            "independent-policy-retired",
            "independent-policy-complete",
        ] {
            let folder = directory();
            let root = folder.path().canonicalize().expect("owned directory");
            let log = fs::File::create(root.join("child.log")).expect("log");
            let mut child=ChildGuard(Command::new(std::env::current_exe().expect("test binary")).args(["--exact","enrollment::tests::witness_renewal::independent_policy::operational::process::independent_policy_process_child","--nocapture"])
                .env("TMPDIR",&root).env("QPERIAPT_INDEPENDENT_POLICY_CHILD",&root).env("QPERIAPT_INDEPENDENT_POLICY_CLOSED",if closed {"1"} else {"0"}).env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT",&root).env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE",stage).stdout(Stdio::from(log.try_clone().expect("log"))).stderr(Stdio::from(log)).spawn().expect("child"));
            let deadline = Instant::now() + Duration::from_secs(40);
            while !root.join("renewal-ready").exists() {
                assert!(
                    child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                    "cut {stage} missing: {}",
                    fs::read_to_string(root.join("child.log")).expect("log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().expect("actual process termination");
            assert!(!child.0.wait().expect("reap").success());
            let client_path =
                PathBuf::from(fs::read_to_string(root.join("enrollment-path")).expect("path"));
            let witness_path =
                PathBuf::from(fs::read_to_string(root.join("witness-path")).expect("path"));
            assert!(client_path.starts_with(&root) && witness_path.starts_with(&root));
            let identity = crate::AnchorIdentity::from_trusted_state(
                fs::read(root.join("witness-id"))
                    .expect("identity")
                    .try_into()
                    .expect("width"),
            )
            .expect("identity");
            let store = AnchorStore::open(
                &witness_path.join("witness.redb"),
                JournalKey::open(&witness_path.join("witness.key")).expect("key"),
                crate::AnchorSigningKey::deterministic([226; 32], [227; 32])
                    .expect("same test signer"),
                identity,
            )
            .expect("original witness reopens");
            let pin = store.pin().expect("pin");
            let policy = crate::PolicyPin::new(
                fs::read(root.join("trusted-family"))
                    .expect("family")
                    .try_into()
                    .expect("width"),
                PublicKey::decode(&fs::read(root.join("trusted-policy-root")).expect("root"))
                    .expect("public root"),
                checkpoint(&root.join("trusted-policy")),
            )
            .expect("independent pin")
            .verify_historical(&fs::read(root.join("policy-wire")).expect("wire"))
            .expect("historical policy without runtime");
            let intent = EnrollmentIntent::new(
                PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root"))
                    .expect("root"),
                DeviceDescription::new(
                    [7; 16],
                    1,
                    policy.family(),
                    Validity::new(100, 160).expect("credential interval"),
                )
                .expect("original intent"),
            );
            let carrier = Carrier {
                store: Arc::new(Mutex::new(store)),
                clock: Arc::new(AtomicU64::new(401)),
                cut: Arc::new(Mutex::new(None)),
                requests: Arc::new(Mutex::new(Vec::new())),
                after_reply: Arc::new(Mutex::new(None)),
            };
            let paths = paths(&client_path);
            let mut owner =
                DeviceEnrollment::open(paths.clone(), intent).expect("original enrollment reopens");
            let mut client = owner
                .policy_renewal_anchor_client(
                    &policy,
                    pin,
                    Box::new(carrier.clone()),
                    Duration::from_secs(3),
                )
                .expect("original historical signer");
            let proposal = PolicyProposal::from_trusted_state(
                &fs::read(root.join("proposal")).expect("original proposal"),
            )
            .expect("proposal");
            assert_eq!(
                owner
                    .reconcile_witnessed_policy_renewal(
                        proposal.operation(),
                        proposal.statement(),
                        &policy,
                        &mut client
                    )
                    .expect("same original expired operation"),
                if closed {
                    State::Closed
                } else {
                    State::Applied
                }
            );
            assert_eq!(
                owner
                    .witnessed_policy_renewal_progress()
                    .expect("durable exact completion"),
                Some(Progress::Terminal {
                    proposal,
                    target: checkpoint(&root.join("target-policy")),
                    disposition: if closed {
                        Disposition::Closed
                    } else {
                        Disposition::Applied
                    },
                    retired: true
                })
            );
            owner.close();
            let db =
                open_private_database(paths.installation.files()[1]).expect("original journal");
            let tx = db.begin_read().expect("read");
            let table = tx.open_table(JOURNAL).expect("table");
            assert!(table.get("pending").expect("pending lookup").is_none());
            assert_eq!(
                table
                    .get("image")
                    .expect("image lookup")
                    .expect("image")
                    .value(),
                fs::read(root.join(if closed { "old-image" } else { "target-image" }))
                    .expect("exact expected ciphertext")
            );
            cuts += 1;
        }
    }
    assert_eq!(cuts, 8);
    eprintln!("INDEPENDENT_POLICY_PROCESS_CUTS cuts={cuts} actual_kills=true expired_recovery_without_runtime=true exact_image=true");
}
