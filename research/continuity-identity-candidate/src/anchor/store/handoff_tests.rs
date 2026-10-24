// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) fn plan(c: &mut Case, operation: u8) -> AnchorHandoffPlan {
    let state = c
        .store
        .handoff_source_state()
        .expect("authenticated complete source");
    let target = AnchorPin::new(
        AnchorIdentity::generate().expect("target instance"),
        AnchorSigningKey::generate()
            .expect("different target key")
            .public_key()
            .expect("target public key"),
    );
    AnchorHandoffPlan::from_trusted_state(
        [operation; 32],
        &state,
        target,
        Validity::new(140, 160).expect("finite approval"),
        [231; 32],
    )
    .expect("trusted exact source approval")
}

#[test]
fn freeze_blocks_queries_exact_retries_and_enrollment_without_resetting_original_state() {
    let mut c = case();
    let advance = request(
        &c,
        AnchorOperation::advance(initial(&c), [232; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &advance)
        .applied_head()
        .expect("original head");
    let state = c.store.handoff_source_state().expect("capture");
    let p = plan(&mut c, 233);
    let frozen = c.store.freeze_handoff(&p, 150).expect("atomic freeze");
    assert_eq!(
        p.verify_receipt(frozen.as_bytes())
            .expect("independent verification")
            .state(),
        AnchorHandoffState::Frozen
    );
    assert_eq!(
        c.store
            .frozen_handoff_state(&p)
            .expect("exact frozen snapshot")
            .as_bytes(),
        state.as_bytes()
    );
    for q in [request(&c, AnchorOperation::query()), advance] {
        assert!(matches!(
            c.store.handle(q.as_bytes(), 150),
            Err(AnchorError::Storage(DurableError::Suspended))
        ));
    }
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("enrollment inputs");
    assert!(matches!(
        c.store.enroll(&c.genesis, device, policy, 150),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        c.store.handoff_source_state(),
        Err(DurableError::Suspended)
    ));
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .freeze_handoff(&p, 190)
            .expect("historical exact repeat after expiry")
            .as_bytes(),
        frozen.as_bytes()
    );
    let cancelled = c
        .store
        .cancel_handoff(&p)
        .expect("trusted cancellation after expiry");
    assert_eq!(cancelled.state(), AnchorHandoffState::Cancelled);
    assert_eq!(
        c.store
            .cancel_handoff(&p)
            .expect("same terminal bytes")
            .as_bytes(),
        cancelled.as_bytes()
    );
    assert!(matches!(
        c.store.freeze_handoff(&p, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        c.store.frozen_handoff_state(&p),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let query = request(&c, AnchorOperation::query());
    assert_eq!(apply_request(&mut c, &query).observed_head(), head);
    assert_ne!(
        c.store
            .handoff_source_state()
            .expect("retained cancellation")
            .commitment(),
        state.commitment()
    );
    assert_eq!(
        c.store
            .image()
            .expect("content revision unchanged")
            .revision,
        state.revision()
    );
}

#[test]
fn stale_changed_competing_and_expired_plans_never_freeze_a_different_state() {
    let mut c = case();
    let p = plan(&mut c, 234);
    assert!(matches!(
        c.store.freeze_handoff(&p, 160),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let rq = request(
        &c,
        AnchorOperation::advance(initial(&c), [235; 32]).expect("update before freeze"),
    );
    apply_request(&mut c, &rq)
        .applied_head()
        .expect("winning update");
    assert!(matches!(
        c.store.freeze_handoff(&p, 150),
        Err(DurableError::Conflict)
    ));
    let fresh = plan(&mut c, 236);
    let other = plan(&mut c, 237);
    let wire = c
        .store
        .freeze_handoff(&fresh, 150)
        .expect("winning exact target");
    assert!(matches!(
        c.store.freeze_handoff(&other, 150),
        Err(DurableError::Conflict)
    ));
    let mut changed = fresh.to_bytes();
    // The approval remains in the common v1/v2 prefix; v2 appends history.
    let approval_offset = 8 + 32 + 2 * (32 + PUBLIC_KEY_BYTES) + 8 + 32 + 16;
    *changed.get_mut(approval_offset).expect("approval byte") ^= 1;
    let changed =
        AnchorHandoffPlan::restore_trusted_state(&changed).expect("different shaped descriptor");
    assert!(matches!(
        c.store.cancel_handoff(&changed),
        Err(DurableError::Conflict)
    ));
    assert!(changed.verify_receipt(wire.as_bytes()).is_err());
    assert_eq!(
        c.store
            .observe_handoff(&fresh)
            .expect("original unchanged")
            .as_bytes(),
        wire.as_bytes()
    );
    assert!(fresh.verify_receipt(&[0; 64]).is_err());
    let mut changed_wire = wire.as_bytes().to_vec();
    *changed_wire.last_mut().expect("signature") ^= 1;
    assert!(fresh.verify_receipt(&changed_wire).is_err());
    for length in [0, 7, 8, 39, fresh.to_bytes().len() - 1] {
        assert!(AnchorHandoffPlan::restore_trusted_state(
            fresh.to_bytes().get(..length).expect("prefix")
        )
        .is_err());
    }
    c.store
        .cancel_handoff(&fresh)
        .expect("cancel winning target");
    assert!(matches!(c.store.freeze_handoff(&other, 150), Err(DurableError::Conflict)),
        "retained cancellation changes the exact commitment even though content revision is unchanged");
    let state = c.store.handoff_source_state().expect("new current capture");
    let reused_key = AnchorPin::new(
        AnchorIdentity::generate().expect("different instance"),
        c.pin.public_key().clone(),
    );
    assert!(matches!(
        AnchorHandoffPlan::from_trusted_state(
            [254; 32],
            &state,
            reused_key,
            Validity::new(140, 160).expect("interval"),
            [255; 32]
        ),
        Err(Error::Scope)
    ));
}

#[test]
fn capture_freeze_and_cancel_keep_pending_credential_operation_and_original_namespace() {
    let mut c = credential_case();
    let g = credential_grant_first(&c);
    let proposal = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        g.operation(),
        g.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [238; 32]).expect("target"),
    )
    .expect("original G");
    let policy = c.peer.responder.current_policy().expect("policy");
    c.store
        .prepare_credential_renewal(proposal, &g, policy, 170)
        .expect("pending original G");
    let before = c
        .store
        .handoff_source_state()
        .expect("all pending metadata");
    let p = plan(&mut c, 239);
    c.store
        .freeze_handoff(&p, 150)
        .expect("nonquiescent freeze");
    assert_eq!(
        c.store
            .frozen_handoff_state(&p)
            .expect("complete pending export")
            .as_bytes(),
        before.as_bytes()
    );
    let policy = c.peer.responder.current_policy().expect("policy");
    assert!(matches!(
        c.store.close_credential_renewal(proposal, &g, policy),
        Err(DurableError::Suspended)
    ));
    c.store.close();
    c.store = reopen(&c.server);
    c.store.cancel_handoff(&p).expect("resume original state");
    assert_eq!(
        c.store
            .close_credential_renewal(proposal, &g, policy)
            .expect("close same G"),
        crate::AnchorCredentialRenewalState::Closed
    );
}

#[test]
fn terminal_observer_needs_no_old_private_signing_key() {
    let mut c = case();
    let p = plan(&mut c, 240);
    c.store.freeze_handoff(&p, 150).expect("freeze");
    let wire = c
        .store
        .cancel_handoff(&p)
        .expect("committed retained cancellation");
    c.store.close();
    fs::remove_file(c.server.join("signer")).expect("remove test-owned private signer");
    let observer = AnchorHandoffObserver::open(
        &c.server.join("anchor.redb"),
        JournalKey::open(&c.server.join("wrapping")).expect("storage authentication"),
        c.pin.clone(),
    )
    .expect("no signer input");
    assert_eq!(
        observer
            .observe(&p)
            .expect("original retained bytes")
            .as_bytes(),
        wire.as_bytes()
    );
}

#[test]
fn stale_writer_cannot_commit_over_a_freeze_and_signing_failure_cannot_thaw_it() {
    let mut c = case();
    let mut stale = c
        .store
        .image()
        .expect("writer's pre-freeze authenticated image");
    let p = plan(&mut c, 244);
    let before = c
        .store
        .handoff_source_state()
        .expect("before failed preparation");
    c.store
        .active
        .as_mut()
        .expect("owned signer")
        .signer
        .close();
    assert!(matches!(
        c.store.freeze_handoff(&p, 150),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(
        c.store
            .handoff_source_state()
            .expect("not frozen on signing failure")
            .as_bytes(),
        before.as_bytes()
    );
    c.store.close();
    c.store = reopen(&c.server);
    let receipt = c.store.freeze_handoff(&p, 150).expect("committed freeze");
    assert!(matches!(
        c.store.persist(&mut stale),
        Err(DurableError::Conflict)
    ));
    assert!(c.store.active.is_none());
    c.store = reopen(&c.server);
    c.store
        .active
        .as_mut()
        .expect("source signer")
        .signer
        .close();
    assert!(matches!(
        c.store.cancel_handoff(&p),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(
        c.store
            .observe_handoff(&p)
            .expect("failed signing did not thaw")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert!(matches!(c.store.image(), Err(DurableError::Suspended)));
}

#[test]
fn bounded_cancellation_history_reserves_completion_and_refuses_new_work_without_losing_history() {
    let mut c = case();
    let mut first = None;
    for index in 1..=super::super::handoff::MAX_CANCELLED {
        let p = plan(&mut c, u8::try_from(index).expect("bounded operation"));
        if first.is_none() {
            first = Some(p.clone());
        }
        let before = c
            .store
            .handoff_source_state()
            .expect("complete retained history");
        c.store
            .freeze_handoff(&p, 150)
            .expect("admitted freeze reserves cancellation space");
        assert_eq!(
            c.store
                .frozen_handoff_state(&p)
                .expect("all prior history in frozen export")
                .as_bytes(),
            before.as_bytes()
        );
        c.store
            .cancel_handoff(&p)
            .expect("completion never loses reserved capacity");
        c.store.close();
        c.store = reopen(&c.server);
    }
    let p = plan(&mut c, 250);
    let before = c.store.handoff_source_state().expect("full history");
    assert!(matches!(
        c.store.freeze_handoff(&p, 150),
        Err(DurableError::Capacity)
    ));
    assert_eq!(
        c.store
            .handoff_source_state()
            .expect("rejection leaves source usable")
            .as_bytes(),
        before.as_bytes()
    );
    let first = first.expect("first terminal operation");
    assert_eq!(
        c.store
            .observe_handoff(&first)
            .expect("earliest terminal receipt retained")
            .state(),
        AnchorHandoffState::Cancelled
    );
    assert!(matches!(
        c.store.freeze_handoff(&first, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let q = request(&c, AnchorOperation::query());
    assert_eq!(apply_request(&mut c, &q).observed_head(), initial(&c));
}

#[test]
fn changed_frozen_content_is_rejected_even_with_a_valid_storage_mac() {
    let mut c = case();
    let p = plan(&mut c, 251);
    c.store.freeze_handoff(&p, 150).expect("freeze");
    let owner = c.store.active.as_ref().expect("owned test store");
    let image = load(&owner.db, &owner.wrapping, &owner.pin).expect("frozen image");
    let mut bytes =
        encode(&owner.wrapping, &owner.pin, &image).expect("authenticated outer format");
    // Outer tag + sized inner image; then inner tag + pin binding + revision.
    let revision_offset = 8 + 4 + 8 + 32;
    bytes
        .get_mut(revision_offset..revision_offset + 8)
        .expect("inner content revision")
        .copy_from_slice(&(image.revision + 1).to_be_bytes());
    let body_len = bytes.len().checked_sub(32).expect("storage authenticator");
    let mut mac = authenticator(&owner.wrapping).expect("test storage key");
    mac.update(bytes.get(..body_len).expect("body"));
    bytes
        .get_mut(body_len..)
        .expect("tag")
        .copy_from_slice(&mac.finalize().into_bytes());
    let tx = transaction(&owner.db).expect("test corruption");
    tx.open_table(TABLE)
        .expect("table")
        .insert("image", bytes.as_slice())
        .expect("replace test state");
    tx.commit().expect("corruption committed");
    assert!(matches!(
        c.store.observe_handoff(&p),
        Err(DurableError::Corrupt)
    ));
    assert!(c.store.active.is_none());
}

#[test]
fn every_freeze_and_cancellation_sync_error_preserves_exact_recovery() {
    for cancelling in [false, true] {
        let mut calibration = case();
        let p = plan(&mut calibration, 241);
        if cancelling {
            calibration
                .store
                .freeze_handoff(&p, 150)
                .expect("freeze first");
        }
        let (_, count) = with_fault_database(&mut calibration, false);
        count.store(0, Ordering::SeqCst);
        if cancelling {
            calibration.store.cancel_handoff(&p).expect("calibration");
        } else {
            calibration
                .store
                .freeze_handoff(&p, 150)
                .expect("calibration");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut c = case();
                let p = plan(&mut c, 242);
                let original = c.store.handoff_source_state().expect("original");
                if cancelling {
                    c.store.freeze_handoff(&p, 150).expect("initial freeze");
                }
                let (remaining, _) = with_fault_database(&mut c, after);
                remaining.store(cut, Ordering::SeqCst);
                let result = if cancelling {
                    c.store.cancel_handoff(&p)
                } else {
                    c.store.freeze_handoff(&p, 150)
                };
                crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
                assert!(c.store.active.is_none());
                c.store = reopen(&c.server);
                let receipt = if cancelling {
                    c.store.cancel_handoff(&p).expect("same cancel retry")
                } else {
                    c.store.freeze_handoff(&p, 150).expect("same freeze retry")
                };
                assert_eq!(
                    c.store
                        .observe_handoff(&p)
                        .expect("retained exact decision")
                        .as_bytes(),
                    receipt.as_bytes()
                );
                if !cancelling {
                    assert_eq!(
                        c.store
                            .frozen_handoff_state(&p)
                            .expect("original complete content")
                            .as_bytes(),
                        original.as_bytes()
                    );
                    c.store
                        .cancel_handoff(&p)
                        .expect("cancel for original query");
                }
                let q = request(&c, AnchorOperation::query());
                assert_eq!(apply_request(&mut c, &q).observed_head(), initial(&c));
            }
        }
        eprintln!(
            "HANDOFF_SYNC cancelling={cancelling} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}

#[test]
fn handoff_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_HANDOFF_CHILD") else {
        return;
    };
    let path = Path::new(&path);
    let mut store = reopen(path);
    let p = AnchorHandoffPlan::restore_trusted_state(
        &fs::read(path.join("plan")).expect("retained intent"),
    )
    .expect("plan");
    let receipt = if std::env::var_os("QPERIAPT_HANDOFF_CANCEL").is_some() {
        store.cancel_handoff(&p)
    } else {
        store.freeze_handoff(&p, 150)
    }
    .expect("commit before release");
    fs::write(path.join("returned-reply"), receipt.as_bytes()).expect("released bytes");
}

#[test]
fn freeze_and_cancel_survive_sigkill_after_commit_before_receipt_release() {
    for cancelling in [false, true] {
        let mut c = case();
        let p = plan(&mut c, 243);
        let original = c.store.handoff_source_state().expect("original");
        if cancelling {
            c.store.freeze_handoff(&p, 150).expect("initial freeze");
        }
        fs::write(c.server.join("plan"), p.to_bytes()).expect("retained exact intent");
        c.store.close();
        let log = fs::File::create(c.server.join("child.log")).expect("test log");
        let mut command = Process::new(std::env::current_exe().expect("binary"));
        command
            .args([
                "--exact",
                "anchor::store::tests::handoff::handoff_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_HANDOFF_CHILD", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env(
                "QPERIAPT_ANCHOR_CRASH_REVISION",
                original.revision().to_string(),
            )
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log));
        if cancelling {
            command.env("QPERIAPT_HANDOFF_CANCEL", "1");
        }
        let mut child = ChildGuard(command.spawn().expect("test-owned process"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !c.server.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "child commit deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!c.server.join("returned-reply").exists());
        let pid = child.0.id();
        child.0.kill().expect("SIGKILL test process");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
        c.store = reopen(&c.server);
        let r = c
            .store
            .observe_handoff(&p)
            .expect("committed decision after real process loss");
        assert_eq!(
            r.state(),
            if cancelling {
                AnchorHandoffState::Cancelled
            } else {
                AnchorHandoffState::Frozen
            }
        );
        if !cancelling {
            assert_eq!(
                c.store
                    .frozen_handoff_state(&p)
                    .expect("original complete state")
                    .as_bytes(),
                original.as_bytes()
            );
        }
        eprintln!(
            "HANDOFF_SIGKILL cancelling={cancelling} pid={pid} retained_bytes={}",
            r.as_bytes().len()
        );
    }
}
