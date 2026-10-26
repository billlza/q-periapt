// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "process.rs"]
mod process;

#[test]
fn transferred_account_freeze_cold_open_requires_signature_even_with_valid_storage_mac() {
    const PRIMARY: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_import_v1");
    fn replace(f: &Prepared, bytes: &[u8]) {
        let db = open_private_database(&f.f.db_path()).expect("test-owned lease");
        let tx = transaction(&db).expect("test transaction");
        {
            tx.open_table(PRIMARY)
                .expect("primary")
                .insert("image", bytes)
                .expect("replace");
        }
        tx.commit().expect("committed test mutation");
    }
    let mut f = Prepared::new(Some(("R", false)));
    let approved = approval(&mut f, 217);
    let wire = f
        .active
        .freeze_transferred_account(&approved, || Ok(180))
        .expect("actual freeze");
    f.active.close();
    let original = {
        let db = open_private_database(&f.f.db_path()).expect("test-owned read");
        let tx = db.begin_read().expect("read");
        tx.open_table(PRIMARY)
            .expect("primary")
            .get("image")
            .expect("lookup")
            .expect("image")
            .value()
            .to_vec()
    };
    let positions = original
        .windows(wire.len())
        .enumerate()
        .filter_map(|(i, b)| (b == wire).then_some(i))
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let start = *positions.first().expect("one embedded exact receipt");
    for offset in [8 + 32, wire.len() - 1] {
        let mut changed = original.clone();
        *changed
            .get_mut(start + offset)
            .expect("bounded proof field") ^= 1;
        let end = changed.len() - 32;
        let mut mac = authenticator(&f.f.key()).expect("test-owned MAC key");
        mac.update(changed.get(..end).expect("authenticated body"));
        changed
            .get_mut(end..)
            .expect("fixed MAC")
            .copy_from_slice(&mac.finalize().into_bytes());
        replace(&f, &changed);
        assert!(
            AnchorHandoffTarget::open(&f.f.db_path(), f.f.key(), f.f.approval.clone()).is_err()
        );
        replace(&f, &original);
        let signer = f.f.directory.join("signer");
        let withheld = f.f.directory.join("signer.withheld");
        fs::rename(&signer, &withheld).expect("withhold only test-owned signer");
        let mut observer = f.f.open();
        assert_eq!(
            observer
                .transferred_account_freeze_receipt(&approved)
                .expect("no private signer needed"),
            wire
        );
        observer.close();
        fs::rename(&withheld, &signer).expect("restore test-owned signer");
    }
}

#[test]
fn transferred_account_freeze_remains_verifiable_after_successive_witness_retirement() {
    let mut f = Prepared::new(Some(("G", false)));
    let approved = approval(&mut f, 219);
    let old_entry = f.original_entry();
    let wire = f
        .active
        .freeze_transferred_account(&approved, || Ok(180))
        .expect("approved B account freeze");
    let root = f.c.server.join("successor-root");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("private C parent");
    let next = TargetFixture::from_store_operation(&mut f.active, &root, &f.f.pin, 191, false, 221);
    let mut target = next.provision();
    let ack = target.import_receipt().expect("C exact full import");
    let retired = f
        .active
        .retire_handoff(&next.approval, ack.as_bytes(), || Ok(191))
        .expect("B irreversibly retired");
    let history = target
        .verify_source_retirement(retired.as_bytes())
        .expect("complete A-B-C history");
    let (mut current, _) = target
        .activate(retired.as_bytes(), next.signer())
        .expect("C activated");
    assert_eq!(history.sequence(), 2);
    assert_eq!(
        current
            .transferred_account_freeze_receipt(&approved)
            .expect("historical B proof under current C history"),
        wire
    );
    let mut time_calls = 0;
    assert_eq!(
        current
            .freeze_transferred_account(&approved, || {
                time_calls += 1;
                Err(DurableError::Conflict)
            })
            .expect("historical exact retry"),
        wire
    );
    assert_eq!(
        time_calls, 0,
        "historical B approval cannot require fresh time"
    );
    approved
        .verify_receipt(&history, &wire)
        .expect("independent original approval and extended history");
    let image = current.image().expect("C full state");
    let mut bytes = Vec::new();
    encode_entry(
        image
            .entries
            .get(&f.c.subject.id(&image.namespace))
            .expect("original G"),
        &history,
        EntryFormat::COMPLETE,
        &mut bytes,
    )
    .expect("unchanged original entry");
    assert_eq!(bytes, old_entry);
    current.close();
    assert_eq!(
        next.open()
            .transferred_account_freeze_receipt(&approved)
            .expect("cold public-key-only observation"),
        wire
    );
}

#[test]
fn transferred_account_freeze_sync_faults_recover_only_exact_original_approval() {
    let mut f = Prepared::new(Some(("P", false)));
    let approved = approval(&mut f, 215);
    f.active.close();
    let (db, _, count, _) = fault_database_path(&f.f.db_path(), false);
    f.active = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
        .expect("same target")
        .activate(&f.retired, f.f.signer())
        .expect("activation")
        .0;
    count.store(0, Ordering::SeqCst);
    f.active
        .freeze_transferred_account(&approved, || Ok(180))
        .expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    f.active.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut f = Prepared::new(Some(("P", false)));
            let old = f.original_entry();
            let approved = approval(&mut f, 215);
            f.active.close();
            let (db, remaining, _, _) = fault_database_path(&f.f.db_path(), after);
            f.active = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
                .expect("fault-backed target")
                .activate(&f.retired, f.f.signer())
                .expect("same activation")
                .0;
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                f.active.freeze_transferred_account(&approved, || Ok(180)),
                after,
            );
            assert!(matches!(f.active.pin(), Err(DurableError::Closed)));
            f.reopen();
            assert_eq!(f.original_entry(), old);
            let observed = match f.active.transferred_account_freeze_receipt(&approved) {
                Err(DurableError::Absent) => None,
                result => {
                    Some(result.expect("only authenticated committed receipt or exact absence"))
                }
            };
            let wire = f
                .active
                .freeze_transferred_account(&approved, || Ok(180))
                .expect("exact replay");
            if let Some(committed) = observed {
                assert_eq!(committed, wire);
            }
            f.reopen();
            assert_eq!(
                f.active
                    .transferred_account_freeze_receipt(&approved)
                    .expect("exact original result"),
                wire
            );
        }
    }
    eprintln!(
        "TRANSFERRED_ACCOUNT_FREEZE_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}
