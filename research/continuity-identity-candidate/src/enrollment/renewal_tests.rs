// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{CredentialRenewalId, CredentialRenewalStatus, Validity, VerifiedCredentialRenewal};

fn local() -> (Case, Vec<u8>, VerifiedDevice, JournalIdentity) {
    let mut c = case();
    c.intent.description.validity = Validity::new(100, 160).expect("short original identity");
    let (mut owner, request, id) = accepted(&c);
    let image = owner.image().expect("image");
    let original = owner.admitted(&image, &c.policy, 150).expect("original");
    owner.prepare(&c.policy, 150).expect("prepare");
    owner
        .activate(&c.policy, 150, None)
        .expect("original active owner")
        .close();
    (c, request, original, id)
}
fn grant(
    c: &Case,
    original: &VerifiedDevice,
    previous: &VerifiedDevice,
    version: u64,
    until: u64,
) -> VerifiedCredentialRenewal {
    let certificate = c
        .root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original body");
    crate::durable::tests::grant(
        &c.root,
        &certificate,
        previous,
        until,
        version,
        [u8::try_from(100 + version).expect("fixture operation"); 32],
        c.policy.checkpoint().digest(),
    )
}
fn pending(proof: &VerifiedCredentialRenewal) -> CredentialRenewalStatus {
    CredentialRenewalStatus::Pending {
        operation: proof.operation(),
        statement: proof.statement_digest(),
    }
}
fn committed(proof: &VerifiedCredentialRenewal) -> CredentialRenewalStatus {
    CredentialRenewalStatus::Committed {
        operation: proof.operation(),
        statement: proof.statement_digest(),
        target: proof.successor_device().roster().checkpoint(),
    }
}

#[test]
fn expired_local_credential_renewal_preserves_original_enrollment_signer_and_storage() {
    let (c, request, original, id) = local();
    let signer_file = fs::read(&c.paths.signer).expect("protected original signer");
    assert!(matches!(
        open(&c).activate(&c.policy, 170, None),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let first = grant(&c, &original, &original, 2, 180);
    let mut owner = open(&c);
    let signer_id = owner.identity().expect("original signing ID");
    assert_eq!(
        owner
            .stage_credential_renewal(&first, first.operation(), &c.policy, 170)
            .expect("durable intent"),
        pending(&first)
    );
    assert_eq!(
        owner
            .stage_credential_renewal(&first, first.operation(), &c.policy, 170)
            .expect("same pending intent"),
        pending(&first)
    );
    let image = owner.image().expect("version two state");
    let bytes = encode(
        &JournalKey::open(&c.paths.wrapping).expect("key"),
        owner.binding,
        &image,
    )
    .expect("bounded renewal state");
    assert_eq!(bytes.get(..8), Some(b"QPENST02".as_slice()));
    assert!(bytes.len() > MAX_IMAGE && bytes.len() <= MAX_RENEWAL_IMAGE);
    owner.close();
    let mut active = open(&c)
        .activate(&c.policy, 170, None)
        .expect("same original installation");
    let (service, signer, current) = active.parts().expect("controlled owners");
    signer
        .check_device(current)
        .expect("original complete signing key");
    assert_eq!(
        current.credential_digest(),
        first.successor_device().credential_digest()
    );
    let snapshot = service.stores().expect("stores").0.test_snapshot();
    assert_eq!(snapshot.id, *id.as_bytes());
    assert_eq!(snapshot.owner, crate::bootstrap::storage_owner(&original));
    active.close();
    let mut owner = open(&c);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("historical progress"),
        committed(&first)
    );
    assert_eq!(owner.identity().expect("original signer ID"), signer_id);
    let saved = match owner.image().expect("image").phase {
        Phase::Accepted { request, .. } => Ok(request),
        _ => Err("expected original accepted enrollment"),
    }
    .expect("accepted");
    assert_eq!(saved, request);
    assert_eq!(
        fs::read(&c.paths.signer).expect("unchanged key file"),
        signer_file
    );
    assert_eq!(
        owner
            .stage_credential_renewal(&first, first.operation(), &c.policy, 170)
            .expect("exact completed readback"),
        committed(&first)
    );
    let second = grant(&c, &original, first.successor_device(), 3, 190);
    assert_eq!(
        owner
            .stage_credential_renewal(&second, second.operation(), &c.policy, 175)
            .expect("second exact operation"),
        pending(&second)
    );
    owner
        .activate(&c.policy, 175, None)
        .expect("second same-key continuation")
        .close();
    let mut owner = open(&c);
    assert_eq!(
        owner.credential_renewal_status().expect("second commit"),
        committed(&second)
    );
    assert_eq!(
        owner.status().expect("original lifecycle"),
        EnrollmentStatus::Active(id)
    );
    owner.close();
    open(&c)
        .activate(&c.policy, 175, None)
        .expect("reopen completed owner")
        .close();
}

#[test]
fn renewal_scope_and_original_operation_cannot_be_replaced_before_activation() {
    let (c, _, original, _) = local();
    let proof = grant(&c, &original, &original, 2, 190);
    let mut owner = open(&c);
    let wrong = CredentialRenewalId::from_trusted_state([199; 32]).expect("different operation");
    assert!(owner
        .stage_credential_renewal(&proof, wrong, &c.policy, 170)
        .is_err());
    let mut owner = open(&c);
    assert_eq!(
        owner.credential_renewal_status().expect("no intent"),
        CredentialRenewalStatus::Absent
    );
    owner
        .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
        .expect("original intent");
    let other = grant(&c, &original, &original, 3, 190);
    assert!(owner
        .stage_credential_renewal(&other, other.operation(), &c.policy, 170)
        .is_err());
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("preserved pending"),
        pending(&proof)
    );
}

#[test]
fn current_roster_refresh_after_credential_renewal_keeps_original_scope_and_completion() {
    let (c, _, original, _) = local();
    let proof = grant(&c, &original, &original, 2, 190);
    let mut owner = open(&c);
    owner
        .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
        .expect("intent");
    owner
        .activate(&c.policy, 170, None)
        .expect("new credential")
        .close();
    let certificate = c
        .root
        .issue_device(
            proof.successor_device().description.clone(),
            proof.successor_device().key.clone(),
        )
        .expect("same C1");
    let next = c
        .root
        .issue_roster(
            3,
            interval(),
            &[c.root.roster_entry(&certificate).expect("member")],
        )
        .expect("new authority");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        next.checkpoint(),
        c.policy.family(),
    )
    .expect("current independent pin");
    let mut owner = open(&c);
    owner
        .refresh_roster(
            proof.successor_device().roster().checkpoint(),
            next.as_bytes(),
            &pin,
            &c.policy,
            175,
        )
        .expect("C1 roster intent");
    let mut active = owner
        .activate(&c.policy, 175, None)
        .expect("refreshed original owner");
    let (service, _, current) = active.parts().expect("parts");
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .roster_checkpoint(current.account_id())
            .expect("head"),
        next.checkpoint()
    );
    assert_eq!(
        current.credential_digest(),
        proof.successor_device().credential_digest()
    );
    active.close();
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("historical original renewal"),
        committed(&proof)
    );
}

pub(in crate::enrollment) fn boundary(stage: &str) {
    let Some(root) = std::env::var_os("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT") else {
        return;
    };
    if std::env::var("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE").expect("cut stage") != stage {
        return;
    }
    let root = Path::new(&root);
    fs::write(root.join("renewal-ready.pending"), stage).expect("cut marker");
    fs::rename(
        root.join("renewal-ready.pending"),
        root.join("renewal-ready"),
    )
    .expect("published marker");
    loop {
        std::thread::park();
    }
}

#[test]
fn local_renewal_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let (_, issued, pin, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let policy = pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("original policy");
    let account_root =
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent root"))
            .expect("root");
    let intent = EnrollmentIntent::new(
        account_root.clone(),
        DeviceDescription::new(
            [7; 16],
            1,
            policy.family(),
            Validity::new(100, 160).expect("original interval"),
        )
        .expect("original intent"),
    );
    let target = fs::read(root.join("trusted-target")).expect("independent target checkpoint");
    let mut d = Decoder::new(&target);
    let checkpoint =
        RosterCheckpoint::from_trusted_state(d.u64().expect("version"), d.array().expect("digest"))
            .expect("checkpoint");
    d.finish().expect("complete checkpoint");
    let current_pin = AccountPin::new(
        crate::identity::account_id(&account_root),
        account_root,
        checkpoint,
        policy.family(),
    )
    .expect("current independent pin");
    let wire = fs::read(root.join("public-renewal")).expect("signed grant");
    let proof =
        VerifiedCredentialRenewal::verify(&wire, &current_pin, policy.checkpoint().digest(), 170)
            .expect("verified grant");
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    owner
        .stage_credential_renewal(&proof, proof.operation(), &policy, 170)
        .expect("retain exact intent");
    owner
        .activate(&policy, 170, None)
        .expect("activate")
        .close();
    Err("requested durable boundary did not suspend the child")
}

#[test]
fn process_cuts_distinguish_committed_then_superseded_from_never_committed_without_rollback() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut cuts = 0;
    let mut historical_commits = 0;
    let mut unresolved = 0;
    for stage in ["intent", "journal", "completion", "acknowledgement"] {
        for later in ["retained", "revoked", "generation"] {
            let (c, _, original, id) = local();
            let proof = grant(&c, &original, &original, 2, 190);
            let root = c.paths.configuration.parent().expect("root");
            fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("root");
            let target = proof.successor_device().roster().checkpoint();
            let mut checkpoint = target.version().to_be_bytes().to_vec();
            checkpoint.extend_from_slice(&target.digest());
            fs::write(root.join("trusted-target"), checkpoint).expect("trusted checkpoint");
            fs::write(root.join("public-renewal"), proof.as_bytes()).expect("public grant");
            let mut child = ChildGuard(
                Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "enrollment::tests::renewal::local_renewal_process_child",
                        "--nocapture",
                    ])
                    .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root)
                    .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", stage)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("child"),
            );
            let deadline = Instant::now() + Duration::from_secs(20);
            while !root.join("renewal-ready").exists() {
                assert!(
                    child.0.try_wait().expect("child status").is_none()
                        && Instant::now() < deadline,
                    "child did not reach {stage}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().expect("process cut");
            assert!(!child.0.wait().expect("reap child").success());
            cuts += 1;
            let mut journal = crate::DeviceJournal::open(
                c.paths
                    .installation
                    .files()
                    .get(1)
                    .copied()
                    .expect("original journal path"),
                JournalKey::open(&c.paths.wrapping).expect("original key"),
                &original,
                id,
            )
            .expect("recover original journal");
            let before = journal.test_snapshot();
            let baseline = if stage == "intent" {
                &original
            } else {
                proof.successor_device()
            };
            let certificate = if later == "generation" {
                let mut description = baseline.description.clone();
                description.generation += 1;
                c.root
                    .issue_device(description, baseline.key.clone())
                    .expect("independent replacement generation")
            } else {
                c.root
                    .issue_device(baseline.description.clone(), baseline.key.clone())
                    .expect("same current body")
            };
            let entries = if later == "revoked" {
                Vec::new()
            } else {
                vec![c.root.roster_entry(&certificate).expect("member")]
            };
            let next = c
                .root
                .issue_roster(3, interval(), &entries)
                .expect("later signed head");
            let pin = AccountPin::new(
                original.account_id(),
                c.intent.root.clone(),
                next.checkpoint(),
                c.policy.family(),
            )
            .expect("later independent pin");
            let verified = pin
                .verify_roster(next.as_bytes(), 175)
                .expect("current roster");
            journal
                .install_roster(&verified, 175)
                .expect("authority may advance while enrollment awaits completion");
            journal.close();
            let outcome = open(&c).activate(&c.policy, 175, None);
            if stage != "intent" && later == "retained" {
                outcome.expect("same current C1 still authorized").close();
            } else {
                assert!(
                    outcome.is_err(),
                    "no owner from historical or absent commit"
                );
            }
            let mut owner = open(&c);
            if stage == "intent" {
                assert_eq!(
                    owner.credential_renewal_status().expect("unresolved"),
                    pending(&proof)
                );
                unresolved += 1;
            } else {
                assert_eq!(
                    owner
                        .credential_renewal_status()
                        .expect("actual historical completion"),
                    committed(&proof)
                );
                historical_commits += 1;
            }
            owner.close();
            let mut journal = crate::DeviceJournal::open(
                c.paths
                    .installation
                    .files()
                    .get(1)
                    .copied()
                    .expect("original journal path"),
                JournalKey::open(&c.paths.wrapping).expect("same key"),
                &original,
                id,
            )
            .expect("original storage");
            assert_eq!(
                journal
                    .roster_checkpoint(original.account_id())
                    .expect("later head preserved"),
                next.checkpoint()
            );
            let after = journal.test_snapshot();
            assert_eq!((after.id, after.owner), (before.id, before.owner));
        }
    }
    assert_eq!((cuts, historical_commits, unresolved), (12, 9, 3));
    eprintln!("LOCAL_RENEWAL_PROCESS cuts={cuts} historical_commits={historical_commits} unresolved={unresolved}");
}

#[test]
fn enrollment_intent_and_completion_io_errors_reconcile_original_operation_after_revocation() {
    let mut injected = 0;
    let mut pending_after_error = 0;
    let mut completed_after_error = 0;
    for completing in [false, true] {
        let (c, _, original, _) = local();
        let proof = grant(&c, &original, &original, 2, 190);
        if completing {
            let mut owner = open(&c);
            owner
                .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
                .expect("pending");
            owner.close();
        }
        let (mut owner, _, count) = faulty(&c, false);
        count.store(0, Ordering::SeqCst);
        let syncs = if completing {
            let mut active = owner
                .activate(&c.policy, 170, None)
                .expect("calibrate completion");
            let syncs = count.load(Ordering::SeqCst);
            active.close();
            syncs
        } else {
            owner
                .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
                .expect("calibrate intent");
            let syncs = count.load(Ordering::SeqCst);
            owner.close();
            syncs
        };
        eprintln!(
            "LOCAL_RENEWAL_CONFIG_BARRIERS completing={completing} operation={syncs} with_close={}",
            count.load(Ordering::SeqCst)
        );
        assert!((1..=16).contains(&syncs));
        for cut in 1..=syncs {
            for after in [false, true] {
                let (c, _, original, id) = local();
                let proof = grant(&c, &original, &original, 2, 190);
                if completing {
                    let mut owner = open(&c);
                    owner
                        .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
                        .expect("pending");
                    owner.close();
                }
                let (mut owner, remaining, _) = faulty(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(owner.activate(&c.policy, 170, None), after);
                } else {
                    assert_sync_failure(
                        owner.stage_credential_renewal(&proof, proof.operation(), &c.policy, 170),
                        after,
                    );
                    assert!(owner.active.is_none());
                }
                injected += 1;
                let mut owner = open(&c);
                if completing {
                    let counter = match owner
                        .credential_renewal_status()
                        .expect("ambiguous returned write")
                    {
                        CredentialRenewalStatus::Pending { .. } => Ok(&mut pending_after_error),
                        CredentialRenewalStatus::Committed { .. } => Ok(&mut completed_after_error),
                        CredentialRenewalStatus::Absent => {
                            Err("completion error cannot remove durable intent")
                        }
                        CredentialRenewalStatus::ExpiredUncommitted { .. } => {
                            Err("activation never abandons a renewal implicitly")
                        }
                    }
                    .expect("durable intent survives completion I/O failure");
                    *counter += 1;
                    let mut journal = crate::DeviceJournal::open(
                        c.paths
                            .installation
                            .files()
                            .get(1)
                            .copied()
                            .expect("journal"),
                        JournalKey::open(&c.paths.wrapping).expect("key"),
                        &original,
                        id,
                    )
                    .expect("same journal");
                    let revoked = c.root.issue_roster(3, interval(), &[]).expect("revocation");
                    let pin = AccountPin::new(
                        original.account_id(),
                        c.intent.root.clone(),
                        revoked.checkpoint(),
                        c.policy.family(),
                    )
                    .expect("current pin");
                    journal
                        .install_roster(
                            &pin.verify_roster(revoked.as_bytes(), 175)
                                .expect("verified revocation"),
                            175,
                        )
                        .expect("revoke before config recovery");
                    journal.close();
                    assert!(owner.activate(&c.policy, 175, None).is_err());
                    assert_eq!(
                        open(&c)
                            .credential_renewal_status()
                            .expect("actual committed fact survives revocation"),
                        committed(&proof)
                    );
                } else {
                    owner
                        .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
                        .expect("original exact intent retry");
                    owner
                        .activate(&c.policy, 170, None)
                        .expect("complete original target")
                        .close();
                    assert_eq!(
                        open(&c).credential_renewal_status().expect("commit"),
                        committed(&proof)
                    );
                }
            }
        }
    }
    assert!(pending_after_error > 0 && completed_after_error > 0);
    eprintln!("LOCAL_RENEWAL_ENROLLMENT_IO injected={injected} pending_after_error={pending_after_error} completed_after_error={completed_after_error}");
}

#[test]
fn policy_close_after_renewal_completion_keeps_commit_fact_but_releases_no_owner() {
    let (c, _, original, _) = local();
    let proof = grant(&c, &original, &original, 2, 190);
    let mut owner = open(&c);
    owner
        .stage_credential_renewal(&proof, proof.operation(), &c.policy, 170)
        .expect("original intent");
    owner.close();
    let Case {
        paths,
        intent,
        policy,
        ..
    } = c;
    let policy = Arc::new(policy);
    assert!(policy.check_mode(PrekeyQuality::OneTimeBoth, 170).is_ok());
    CLOSE_POLICY_AFTER_ACTIVE.with(|pending| *pending.borrow_mut() = Some(Arc::clone(&policy)));
    assert!(DeviceEnrollment::open(paths.clone(), intent.clone())
        .expect("original owner")
        .activate(&policy, 170, None)
        .is_err());
    assert!(policy.check_mode(PrekeyQuality::OneTimeBoth, 170).is_err());
    assert_eq!(
        DeviceEnrollment::open(paths, intent)
            .expect("metadata owner")
            .credential_renewal_status()
            .expect("completed operation remains observable"),
        committed(&proof)
    );
}

fn cut_renewal(c: &Case, proof: &VerifiedCredentialRenewal, stage: &str) {
    cut_renewal_entry(
        c,
        proof,
        stage,
        "enrollment::tests::renewal::local_renewal_process_child",
    );
}
fn cut_renewal_entry(c: &Case, proof: &VerifiedCredentialRenewal, stage: &str, entry: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("root");
    let ready = root.join("renewal-ready");
    if ready.try_exists().expect("marker lookup") {
        fs::remove_file(&ready).expect("retire previous test marker");
    }
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("root");
    let target = proof.successor_device().roster().checkpoint();
    let mut checkpoint = target.version().to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&target.digest());
    fs::write(root.join("trusted-target"), checkpoint).expect("independent checkpoint");
    fs::write(root.join("public-renewal"), proof.as_bytes()).expect("public grant");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", entry, "--nocapture"])
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root)
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "child did not reach {stage}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("process cut");
    assert!(!child.0.wait().expect("reap").success());
}

#[test]
fn next_renewal_reconciles_completed_predecessor_receipt_without_deleting_pending_target_receipt() {
    for interrupt_second_commit in [false, true] {
        let (c, _, original, id) = local();
        let first = grant(&c, &original, &original, 2, 180);
        cut_renewal(&c, &first, "completion");
        let mut owner = open(&c);
        assert_eq!(
            owner
                .credential_renewal_status()
                .expect("T1 completion persisted"),
            committed(&first)
        );
        let second = grant(&c, &original, first.successor_device(), 3, 190);
        assert_eq!(
            owner
                .stage_credential_renewal(&second, second.operation(), &c.policy, 170)
                .expect("T2 pending"),
            pending(&second)
        );
        owner.close();
        if interrupt_second_commit {
            cut_renewal(&c, &second, "journal");
        }
        let mut active = open(&c)
            .activate(&c.policy, 175, None)
            .expect("T1 receipt must not strand T2, and T2 receipt must survive exact retry");
        let (service, _, current) = active.parts().expect("T2 owner");
        assert_eq!(
            current.credential_digest(),
            second.successor_device().credential_digest()
        );
        assert_eq!(
            service
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("original journal"),
            id
        );
        active.close();
        assert_eq!(
            open(&c).credential_renewal_status().expect("T2 completed"),
            committed(&second)
        );
    }
}

#[path = "renewal_connection_tests.rs"]
mod connection;

#[path = "renewed_operations_tests.rs"]
mod renewed_operations;

#[path = "expired_renewal_tests.rs"]
mod expired_renewal;
