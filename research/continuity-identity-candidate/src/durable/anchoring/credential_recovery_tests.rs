// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::credential_preparation::{disk, grant, inspect, prepare, request_operation};
use super::*;
use crate::{AnchorCredentialRenewalProposal as Proposal, AnchorCredentialRenewalState as State};
use std::sync::atomic::Ordering;

fn target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let intent = saved.1.as_ref().expect("original pending");
    assert_eq!(intent.get(..8), Some(b"QPWINT02".as_slice()));
    // QPWINT02 adds operation/statement64 to the156-byte ordinary header.
    intent
        .get(220..intent.len().checked_sub(32).expect("MAC"))
        .expect("sealed target")
        .to_vec()
}
fn recover(c: &Case, p: Proposal) -> Result<State, DurableError> {
    DeviceJournal::recover_credential_renewal(
        &c.path.join("state.redb"),
        JournalKey::open(&c.path.join("key")).expect("key"),
        c.peer.initiator_device(),
        c.peer
            .initiator
            .current_policy()
            .expect("fixture policy owner"),
        c.identity,
        p,
        &mut client(&c.pin, &c.server, true),
    )
}
fn prepared(c: &mut Case) -> Proposal {
    let grant = grant(c);
    let p = prepare(c, &grant).expect("sealed preparation");
    assert_eq!(
        c.server
            .lock()
            .expect("server")
            .store
            .prepare_credential_renewal(
                p,
                &grant,
                c.peer
                    .initiator
                    .current_policy()
                    .expect("fixture policy owner"),
                150
            )
            .expect("root-approved target"),
        State::Prepared
    );
    p
}
fn terminal(c: &Case, p: Proposal, applied: bool) {
    let operation = if applied {
        AnchorOperation::commit_credential_renewal(&p)
    } else {
        AnchorOperation::close_credential_renewal(&p)
    };
    let reply = client(&c.pin, &c.server, true)
        .exchange(c.subject, operation)
        .expect("real witness terminal");
    assert_eq!(
        reply.credential_renewal_state(&p).expect("typed"),
        if applied {
            State::Applied
        } else {
            State::Closed
        }
    );
}
fn only_status(c: &Case, p: Proposal, start: usize) {
    let server = c.server.lock().expect("server");
    assert!(server
        .requests
        .get(start..)
        .expect("requests")
        .iter()
        .all(|wire| request_operation(wire) == AnchorOperation::credential_renewal_status(&p)));
}

#[test]
fn exact_applied_target_recovers_after_expiry_and_policy_close_without_retiring_intent() {
    let mut c = case();
    let p = prepared(&mut c);
    let original = disk(&c);
    assert_eq!(
        recover(&c, p).expect("read-only preparation"),
        State::Prepared
    );
    assert_eq!(disk(&c), original);
    terminal(&c, p, true);
    c.server.lock().expect("server").now = 301;
    c.peer
        .initiator
        .current_policy()
        .expect("fixture policy owner")
        .close();
    let start = c.server.lock().expect("server").requests.len();
    assert_eq!(
        recover(&c, p).expect("historical exact apply"),
        State::Applied
    );
    let applied = disk(&c);
    assert_eq!(applied.0, target(&original));
    assert_eq!(applied.1, original.1);
    assert_eq!(image_hash(&applied.0), p.target_head().digest());
    assert_eq!(inspect(&c).expect("same intent after apply"), Some(p));
    assert_eq!(recover(&c, p).expect("fresh exact retry"), State::Applied);
    assert_eq!(disk(&c), applied);
    only_status(&c, p, start);
    let start = c.server.lock().expect("server").requests.len();
    assert!(
        reopen(&c).is_err(),
        "generic operational reopen admitted retained intent"
    );
    assert_eq!(c.server.lock().expect("server").requests.len(), start);
    assert_eq!(disk(&c), applied);
}

#[test]
fn closed_and_unavailable_never_erase_intent_or_infer_local_commit() {
    for closed in [false, true] {
        let mut c = case();
        let proof = grant(&c);
        let p = prepare(&mut c, &proof).expect("local preparation");
        if closed {
            assert_eq!(
                c.server
                    .lock()
                    .expect("server")
                    .store
                    .close_credential_renewal(
                        p,
                        &proof,
                        c.peer
                            .initiator
                            .current_policy()
                            .expect("fixture policy owner")
                    )
                    .expect("independent exact close"),
                State::Closed
            );
        }
        let original = disk(&c);
        c.server.lock().expect("server").now = 301;
        c.peer
            .initiator
            .current_policy()
            .expect("fixture policy owner")
            .close();
        let start = c.server.lock().expect("server").requests.len();
        assert_eq!(
            recover(&c, p).expect("historical observation"),
            if closed {
                State::Closed
            } else {
                State::Unavailable
            }
        );
        assert_eq!(disk(&c), original);
        only_status(&c, p, start);
    }
    let mut c = case();
    let p = prepared(&mut c);
    terminal(&c, p, true);
    assert_eq!(recover(&c, p).expect("apply"), State::Applied);
    let applied = disk(&c);
    // Simulate a separate host incorrectly acknowledging early. Missing witness
    // terminal cannot undo the already applied target or prove NoCommit.
    let reply = client(&c.pin, &c.server, true)
        .exchange(
            c.subject,
            AnchorOperation::acknowledge_credential_renewal(&p),
        )
        .expect("external ACK");
    assert_eq!(
        reply.credential_renewal_state(&p).expect("exact"),
        State::Acknowledged
    );
    assert_eq!(
        recover(&c, p).expect("unavailable stays unknown"),
        State::Unavailable
    );
    assert_eq!(disk(&c), applied);
}

#[test]
fn retained_proposal_original_identity_key_and_client_are_checked_before_network_dispatch() {
    let mut c = case();
    let p = prepared(&mut c);
    terminal(&c, p, true);
    let original = disk(&c);
    let start = c.server.lock().expect("server").requests.len();
    for index in [8usize, 40, 72, 104, 136, 168, 216, 264] {
        let mut wire = p.to_bytes();
        *wire.get_mut(index).expect("scope field") ^= 1;
        let other =
            Proposal::from_trusted_state(&wire).expect("well-formed alternative expectation");
        assert!(recover(&c, other).is_err(), "foreign proposal field{index}");
    }
    for (device, id, signer) in [
        (
            c.peer.initiator_device(),
            JournalIdentity::generate().expect("foreign ID"),
            true,
        ),
        (
            c.peer
                .responder
                .inventory_inputs()
                .expect("fixture inventory owner")
                .1,
            c.identity,
            true,
        ),
        (c.peer.initiator_device(), c.identity, false),
    ] {
        assert!(DeviceJournal::recover_credential_renewal(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            device,
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            id,
            p,
            &mut client(&c.pin, &c.server, signer),
        )
        .is_err());
    }
    assert!(DeviceJournal::recover_credential_renewal(
        &c.path.join("state.redb"),
        JournalKey::provision(&c.path.join("wrong-key")).expect("foreign key"),
        c.peer.initiator_device(),
        c.peer
            .initiator
            .current_policy()
            .expect("fixture policy owner"),
        c.identity,
        p,
        &mut client(&c.pin, &c.server, true),
    )
    .is_err());
    assert_eq!(c.server.lock().expect("server").requests.len(), start);
    assert_eq!(disk(&c), original);
}

#[test]
fn lost_or_stale_authentic_status_replies_never_authorize_a_local_write() {
    for after in [false, true] {
        let mut c = case();
        let p = prepared(&mut c);
        terminal(&c, p, true);
        let original = disk(&c);
        {
            let mut server = c.server.lock().expect("server");
            server.fail = Some((server.requests.len() + 1, after));
        }
        assert!(matches!(recover(&c, p), Err(DurableError::Anchor(_))));
        assert_eq!(disk(&c), original);
        c.server.lock().expect("server").fail = None;
        client(&c.pin, &c.server, true)
            .exchange(c.subject, AnchorOperation::credential_renewal_status(&p))
            .expect("authentic old status");
        {
            let mut server = c.server.lock().expect("server");
            server.substitute = Some(server.replies.last().expect("signed reply").clone());
        }
        assert!(recover(&c, p).is_err());
        assert_eq!(disk(&c), original);
        c.server.lock().expect("server").substitute = None;
        assert_eq!(recover(&c, p).expect("new status attempt"), State::Applied);
        assert_eq!(disk(&c).0, target(&original));
    }
}

#[test]
fn target_image_with_prepared_or_closed_witness_is_an_explicit_conflict() {
    for closed in [false, true] {
        let mut c = case();
        let p = prepared(&mut c);
        if closed {
            terminal(&c, p, false);
        }
        let original = disk(&c);
        {
            let db = open_private_database(&c.path.join("state.redb")).expect("db");
            let tx = transaction(&db).expect("transaction");
            tx.open_table(TABLE)
                .expect("table")
                .insert("image", target(&original).as_slice())
                .expect("inconsistent fixture");
            tx.commit().expect("fixture durable");
        }
        let inconsistent = disk(&c);
        assert_eq!(inspect(&c).expect("exact target metadata"), Some(p));
        assert!(matches!(recover(&c, p), Err(DurableError::Conflict)));
        assert_eq!(disk(&c), inconsistent);
    }
}

#[test]
fn every_local_apply_sync_cut_preserves_exact_intent_and_allows_historical_retry() {
    let mut c = case();
    let p = prepared(&mut c);
    terminal(&c, p, true);
    let (db, _, count, _) = crate::durable::tests::fault_database(&c.path, false);
    let key = JournalKey::open(&c.path.join("key")).expect("key");
    let run = |db: &Database, key: &JournalKey, c: &Case, p| {
        write_intent::recover_credential_renewal(
            db,
            key,
            c.peer.initiator_device(),
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            c.identity,
            p,
            &mut client(&c.pin, &c.server, true),
        )
    };
    assert_eq!(run(&db, &key, &c, p).expect("calibration"), State::Applied);
    let syncs = count.load(Ordering::SeqCst);
    assert!(
        (1..=8).contains(&syncs),
        "bounded measured commit syncs={syncs}"
    );
    count.store(0, Ordering::SeqCst);
    assert_eq!(
        run(&db, &key, &c, p).expect("idempotent retry"),
        State::Applied
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "exact retry must not commit again"
    );
    drop(db);
    let mut injected = 0;
    for after in [false, true] {
        for cut in 1..=syncs {
            let mut c = case();
            let p = prepared(&mut c);
            terminal(&c, p, true);
            let original = disk(&c);
            let (db, remaining, _, _) = crate::durable::tests::fault_database(&c.path, after);
            let key = JournalKey::open(&c.path.join("key")).expect("key");
            remaining.store(cut, Ordering::SeqCst);
            assert!(run(&db, &key, &c, p).is_err(), "cut{cut},after{after}");
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            drop(db);
            let observed = disk(&c);
            assert!(observed.0 == original.0 || observed.0 == target(&original));
            assert_eq!(observed.1, original.1);
            c.server.lock().expect("server").now = 301;
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner")
                .close();
            assert_eq!(
                recover(&c, p).expect("exact historical retry"),
                State::Applied
            );
            assert_eq!(disk(&c), (target(&original), original.1));
            injected += 1;
        }
    }
    assert_eq!(injected, 2 * syncs);
    eprintln!("joint local apply measured syncs={syncs}, injected cuts={injected}");
}

#[test]
fn recovery_crash_child() {
    let Some(root) = std::env::var_os("QPERIAPT_CREDENTIAL_RECOVERY_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let mut c = case_with_witness_signer(
        1024,
        AnchorSigningKey::deterministic([222; 32], [223; 32]).expect("retained test signer"),
    );
    assert!(c.path.starts_with(&root));
    let p = prepared(&mut c);
    terminal(&c, p, true);
    let saved = disk(&c);
    fs::write(
        root.join("state-path"),
        c.path.as_os_str().as_encoded_bytes(),
    )
    .expect("path");
    fs::write(root.join("witness-id"), c.pin.identity().as_bytes()).expect("witness identity");
    fs::write(root.join("proposal"), p.to_bytes()).expect("public proposal");
    fs::write(
        root.join("original-intent"),
        saved.1.as_ref().expect("intent"),
    )
    .expect("exact intent");
    fs::write(root.join("original-target"), target(&saved)).expect("exact target");
    c.server.lock().expect("server").now = 301;
    c.peer
        .initiator
        .current_policy()
        .expect("fixture policy owner")
        .close();
    assert_eq!(
        recover(&c, p).expect("must be killed before return"),
        State::Applied
    );
    fs::write(root.join("returned"), b"unexpected").expect("marker");
    assert!(
        !root.join("returned").exists(),
        "recovery hook did not stop after commit"
    );
}

#[test]
fn process_kill_after_exact_target_commit_reopens_with_original_pending_and_fresh_expired_status() {
    use crate::durable::tests::ChildGuard;
    use std::process::{Command, Stdio};
    let folder = directory();
    let root = folder.path().canonicalize().expect("owned root");
    let log = fs::File::create(root.join("child.log")).expect("log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::anchoring::tests::credential_recovery::recovery_crash_child",
                "--nocapture",
            ])
            .env("TMPDIR", &root)
            .env("QPERIAPT_CREDENTIAL_RECOVERY_CHILD", &root)
            .env("QPERIAPT_CREDENTIAL_RECOVERY_CRASH_DIR", &root)
            .stdout(Stdio::from(log.try_clone().expect("clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("recovery-ready").exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "child failed before commit: {}",
            fs::read_to_string(root.join("child.log")).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!root.join("returned").exists());
    child.0.kill().expect("kill after commit");
    assert!(!child.0.wait().expect("reap").success());
    let path = PathBuf::from(fs::read_to_string(root.join("state-path")).expect("path"));
    assert!(path.starts_with(&root));
    let witness = AnchorIdentity::from_trusted_state(
        fs::read(root.join("witness-id"))
            .expect("witness identity")
            .try_into()
            .expect("width"),
    )
    .expect("identity");
    let store = AnchorStore::open(
        &path.join("witness.redb"),
        JournalKey::open(&path.join("witness-key")).expect("witness wrapping key"),
        AnchorSigningKey::deterministic([222; 32], [223; 32]).expect("same test signer"),
        witness,
    )
    .expect("original durable witness");
    let pin = store.pin().expect("same pin");
    let peer = fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    peer.initiator
        .current_policy()
        .expect("fixture policy owner")
        .close();
    let p = Proposal::from_trusted_state(&fs::read(root.join("proposal")).expect("proposal"))
        .expect("original expectation");
    let identity = crate::durable::tests::identity(&path);
    let server = Arc::new(Mutex::new(Server {
        now: 301,
        store,
        requests: Vec::new(),
        replies: Vec::new(),
        fail: None,
        substitute: None,
    }));
    let c = Case {
        peer,
        server,
        pin,
        journal: DeviceJournal { active: None },
        identity,
        subject: p.subject(),
        path,
        _folder: folder,
    };
    let saved = disk(&c);
    assert_eq!(
        saved.0,
        fs::read(root.join("original-target")).expect("target")
    );
    assert_eq!(
        saved.1.as_ref().expect("pending"),
        &fs::read(root.join("original-intent")).expect("intent")
    );
    assert_eq!(
        inspect(&c).expect("reopen exact target with pending"),
        Some(p)
    );
    assert_eq!(
        recover(&c, p).expect("fresh historical retry after process kill"),
        State::Applied
    );
    assert_eq!(disk(&c), saved);
    only_status(&c, p, 0);
    assert!(reopen(&c).is_err());
}
