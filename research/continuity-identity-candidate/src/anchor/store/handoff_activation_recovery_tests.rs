// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn each_activation_sync_failure_recovers_the_same_original_transaction() {
    let mut c = case();
    let (f, mut target, retirement) = retired(&mut c, 150);
    target.close();
    let (db, _, count, _) = fault_database_path(&f.db_path(), false);
    let mut target = AnchorHandoffTarget::from_database(db, f.key(), f.approval.clone())
        .expect("calibration owner");
    count.store(0, Ordering::SeqCst);
    let (mut active, _) = target
        .activate(&retirement, f.signer())
        .expect("calibration activation");
    let barriers = count.load(Ordering::SeqCst);
    active.close();
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = case();
            let (f, mut target, retirement) = retired(&mut c, 150);
            target.close();
            let (db, remaining, _, _) = fault_database_path(&f.db_path(), after);
            let mut target = AnchorHandoffTarget::from_database(db, f.key(), f.approval.clone())
                .expect("fault owner");
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                target.activate(&retirement, f.signer()).map(|_| ()),
                after,
            );
            assert!(matches!(target.status(), Err(DurableError::Closed)));
            let mut target = f.open();
            let state = target.status().expect("reconciled state");
            let prior = if state == AnchorHandoffTargetState::Activated {
                Some(
                    target
                        .activation_receipt()
                        .expect("committed certificate")
                        .as_bytes()
                        .to_vec(),
                )
            } else {
                assert_eq!(
                    state,
                    AnchorHandoffTargetState::ImportedInactive,
                    "retirement cannot cancel target"
                );
                None
            };
            assert_eq!(
                target
                    .retained_source_state()
                    .expect("original whole state"),
                f.source
            );
            let (mut active, receipt) = target
                .activate(&retirement, f.signer())
                .expect("same original retry");
            if let Some(prior) = prior {
                assert_eq!(prior, receipt.as_bytes());
            }
            assert_eq!(
                active.namespace().expect("original namespace"),
                c.pin.binding()
            );
            active.close();
            let mut target = f.open();
            assert_eq!(
                target.status().expect("durable activation"),
                AnchorHandoffTargetState::Activated
            );
            assert_eq!(
                target
                    .activation_receipt()
                    .expect("exact receipt")
                    .as_bytes(),
                receipt.as_bytes()
            );
        }
    }
    eprintln!(
        "HANDOFF_ACTIVATION_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}

#[test]
fn activation_process_loss_after_commit_recovers_before_any_result_escaped() {
    use std::os::unix::process::ExitStatusExt;
    let mut c = case();
    let (f, mut target, retirement) = retired(&mut c, 150);
    target.close();
    c.store.close();
    fs::remove_file(c.server.join("signer")).expect("remove owned old source key");
    fs::write(f.directory.join("retirement"), &retirement).expect("original committed certificate");
    let log = fs::File::create(f.directory.join("activation-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "anchor::store::tests::handoff_import::recovery::target_import_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_HANDOFF_TARGET_DIR", &f.directory)
            .env("QPERIAPT_HANDOFF_TARGET_STAGE", "activate")
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f.directory.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "activation commit deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!f.directory.join("returned").exists());
    let pid = child.0.id();
    child.0.kill().expect("kill only owned test child");
    assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
    let mut target = f.open();
    assert_eq!(
        target.status().expect("committed despite lost result"),
        AnchorHandoffTargetState::Activated
    );
    let receipt = target
        .activation_receipt()
        .expect("without either signing key");
    assert_eq!(
        target
            .retained_source_state()
            .expect("same whole original state"),
        f.source
    );
    let (mut active, replay) = target
        .activate(&retirement, f.signer())
        .expect("new owner for original activation");
    assert_eq!(receipt.as_bytes(), replay.as_bytes());
    assert_eq!(
        active.namespace().expect("namespace unchanged"),
        c.pin.binding()
    );
    let q = AnchorRequest::new(
        &f.pin,
        c.genesis.subject(),
        AnchorOperation::query(),
        &c.peer.signer_r,
    )
    .expect("original device proof");
    assert!(matches!(
        active.handle(q.as_bytes(), 150),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    eprintln!(
        "HANDOFF_ACTIVATION_SIGKILL pid={pid} committed=true returned=false original_state=true"
    );
}

#[test]
fn valid_target_mac_cannot_change_an_inherited_entry_or_select_another_activation() {
    const IMPORT: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_import_v1");
    let mut c = case();
    let (f, mut target, retirement) = retired(&mut c, 150);
    let history = target
        .verify_source_retirement(&retirement)
        .expect("exact trusted history");
    let (mut active, _) = target.activate(&retirement, f.signer()).expect("activated");
    let mut image = active.image().expect("complete current state");
    let entry = image
        .entries
        .get_mut(&c.genesis.subject().id(&c.pin.binding()))
        .expect("inherited entry");
    let op = AnchorOperation::advance(entry.head, [225; 32]).expect("otherwise valid operation");
    entry.head = AnchorHead::from_trusted_state(1, 2, [225; 32]).expect("head");
    entry.last = Some(command_id(&f.pin.binding(), entry.subject, op));
    let changed =
        image_codec::encode_content(&history, &image).expect("core-shaped but unadopted mutation");
    active.close();
    let db = open_private_database(&f.db_path()).expect("owned corruption fixture lease");
    let tx = transaction(&db).expect("fixture transaction");
    {
        let mut table = tx.open_table(IMPORT).expect("table");
        let raw = table
            .get("image")
            .expect("lookup")
            .expect("row")
            .value()
            .to_vec();
        let end = raw.len() - 32;
        let mut d = Decoder::new(raw.get(..end).expect("body"));
        assert_eq!(d.array::<8>().expect("tag"), *b"QPAHI002");
        for _ in 0..4 {
            let size = u32::from_be_bytes(d.array().expect("size")) as usize;
            d.take(size).expect("immutable field");
        }
        assert_eq!(d.array::<1>().expect("cancel flag"), [0]);
        for _ in 0..2 {
            let size = u32::from_be_bytes(d.array().expect("size")) as usize;
            d.take(size).expect("retirement/certificate");
        }
        let size = u32::from_be_bytes(d.array().expect("content size")) as usize;
        assert_eq!(size, changed.len());
        let offset = end - d.remaining();
        d.take(size).expect("complete content");
        d.finish().expect("exact fields");
        let mut altered = raw;
        altered
            .get_mut(offset..end)
            .expect("current content only")
            .copy_from_slice(&changed);
        let mut mac = authenticator(&f.key()).expect("valid fixture storage key");
        mac.update(altered.get(..end).expect("body"));
        altered
            .get_mut(end..)
            .expect("tag")
            .copy_from_slice(&mac.finalize().into_bytes());
        table
            .insert("image", altered.as_slice())
            .expect("write shaped unauthorized state");
    }
    tx.commit().expect("fixture commit");
    drop(db);
    assert!(matches!(
        AnchorHandoffTarget::open(&f.db_path(), f.key(), f.approval.clone()),
        Err(DurableError::Corrupt)
    ));
    assert!(
        AnchorStore::open(&f.db_path(), f.key(), f.signer(), f.pin.identity()).is_err(),
        "no original-store fallback"
    );
}
