// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_account_decision_sync_failures_preserve_original_targets_and_exact_outcomes() {
    for close in [false, true] {
        let mut c = RetirementCase::new(Some(("R", false)), false);
        let n = next(&c, 210);
        let a = approve(&mut c, &n, 213);
        c.active.close();
        let (db, _, count, _) = fault_database_path(&c.f.db_path(), false);
        c.active = AnchorHandoffTarget::from_database(db, c.f.key(), c.f.approval.clone())
            .expect("same original target")
            .activate(&c.retired, c.f.signer())
            .expect("original activation")
            .0;
        count.store(0, Ordering::SeqCst);
        if close {
            c.active.close_transferred_account_replacement(&a)
        } else {
            c.active.replace_transferred_account_root(
                &a,
                &materials(&c.root, &n, &c.history),
                || Ok(185),
            )
        }
        .expect("calibration");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        c.active.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut c = RetirementCase::new(Some(("R", false)), false);
                let n = next(&c, 210);
                let a = approve(&mut c, &n, 213);
                let old = c.old_entry();
                c.active.close();
                let (db, remaining, _, _) = fault_database_path(&c.f.db_path(), after);
                c.active = AnchorHandoffTarget::from_database(db, c.f.key(), c.f.approval.clone())
                    .expect("fault-backed original import")
                    .activate(&c.retired, c.f.signer())
                    .expect("same activation")
                    .0;
                remaining.store(cut, Ordering::SeqCst);
                let result = if close {
                    c.active.close_transferred_account_replacement(&a)
                } else {
                    c.active.replace_transferred_account_root(
                        &a,
                        &materials(&c.root, &n, &c.history),
                        || Ok(185),
                    )
                };
                crate::durable::tests::assert_sync_failure(result, after);
                assert!(matches!(c.active.pin(), Err(DurableError::Closed)));
                c.reopen();
                assert_eq!(c.old_entry(), old);
                let observed = match c.active.transferred_account_decision(&a) {
                    Err(DurableError::Absent) => None,
                    result => Some(
                        result
                            .expect("only exact outcome or authenticated absence")
                            .as_bytes()
                            .to_vec(),
                    ),
                };
                let outcome = if close {
                    c.active.close_transferred_account_replacement(&a)
                } else {
                    c.active.replace_transferred_account_root(
                        &a,
                        &materials(&c.root, &n, &c.history),
                        || Ok(185),
                    )
                }
                .expect("exact original retry");
                if let Some(wire) = observed {
                    assert_eq!(wire, outcome.as_bytes());
                }
                c.reopen();
                assert_eq!(
                    c.active
                        .transferred_account_decision(&a)
                        .expect("same durable proof")
                        .as_bytes(),
                    outcome.as_bytes()
                );
            }
        }
        eprintln!(
            "TRANSFERRED_ACCOUNT_DECISION_SYNC close={close} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}

#[test]
fn transferred_account_decision_survives_further_witness_retirement_and_key_free_reopen() {
    let mut c = RetirementCase::new(Some(("G", false)), false);
    let n = next(&c, 215);
    let losing = approve(&mut c, &n, 217);
    let winner = approve(&mut c, &n, 219);
    let closed = c
        .active
        .close_transferred_account_replacement(&losing)
        .expect("original noncommit");
    let committed = c
        .active
        .replace_transferred_account_root(&winner, &materials(&c.root, &n, &c.history), || Ok(185))
        .expect("original winner");
    let original = c.old_entry();
    let dir = c.c.server.join("next-witness-parent");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("owned C parent");
    let next = TargetFixture::from_store_operation(&mut c.active, &dir, &c.f.pin, 201, false, 221);
    let mut target = next.provision();
    let ack = target.import_receipt().expect("full C import");
    let retirement = c
        .active
        .retire_handoff(&next.approval, ack.as_bytes(), || Ok(201))
        .expect("B retired");
    let history = target
        .verify_source_retirement(retirement.as_bytes())
        .expect("full A-B-C");
    let (mut current, _) = target
        .activate(retirement.as_bytes(), next.signer())
        .expect("C committed");
    for (approval, outcome) in [(&losing, &closed), (&winner, &committed)] {
        assert_eq!(
            current
                .transferred_account_decision(approval)
                .expect("same exact retained proof")
                .as_bytes(),
            outcome.as_bytes()
        );
        approval
            .verify_decision(&history, outcome.as_bytes())
            .expect("old B signature through independent history");
    }
    assert_eq!(
        current
            .replace_transferred_account_root(&winner, &materials(&c.root, &n, &history), || Err(
                DurableError::Conflict
            ))
            .expect("historical committed retry after approval expiry")
            .as_bytes(),
        committed.as_bytes()
    );
    let image = current.image().expect("complete original G");
    let mut bytes = Vec::new();
    encode_entry(
        image
            .entries
            .get(&c.c.subject.id(&image.namespace))
            .expect("old G"),
        &history,
        EntryFormat::COMPLETE,
        &mut bytes,
    )
    .expect("exact old record");
    assert_eq!(bytes, original);
    current.close();
    let signer = next.directory.join("signer");
    let withheld = next.directory.join("signer.withheld");
    fs::rename(&signer, &withheld).expect("withhold only fixture private key");
    assert_eq!(
        next.open()
            .transferred_account_decision(&winner)
            .expect("public observer needs no signer")
            .as_bytes(),
        committed.as_bytes()
    );
    fs::rename(withheld, signer).expect("restore owned fixture key");
}
