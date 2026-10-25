// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const PRIMARY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_import_v1");
const ARCHIVE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_source_archive_v1");

#[test]
fn successive_activation_receipt_requires_exact_complete_history_and_tail() {
    for archived in [false, true] {
        let mut f = RecoveryCase::new(archived);
        let retirement = f.retire();
        let mut target = f.next.open();
        let history = target
            .verify_source_retirement(retirement.as_bytes())
            .expect("full history");
        let (mut current, receipt) = target
            .activate(retirement.as_bytes(), f.next.signer())
            .expect("active target");
        f.next
            .approval
            .verify_activation_receipt(
                &history,
                &f.next.freeze,
                &f.acknowledgement,
                retirement.as_bytes(),
                receipt.as_bytes(),
            )
            .expect("exact independently verified history");
        assert!(
            f.next
                .approval
                .verify_activation_receipt(
                    &f.history,
                    &f.next.freeze,
                    &f.acknowledgement,
                    retirement.as_bytes(),
                    receipt.as_bytes()
                )
                .is_err(),
            "prior history must not be extended implicitly"
        );
        let reset = AnchorHandoffHistory::from_trusted_origin(f.next.pin.clone());
        assert!(
            f.next
                .approval
                .verify_activation_receipt(
                    &reset,
                    &f.next.freeze,
                    &f.acknowledgement,
                    retirement.as_bytes(),
                    receipt.as_bytes()
                )
                .is_err(),
            "current pin is not the original namespace"
        );
        assert!(
            f.next
                .approval
                .verify_activation_receipt(
                    &history,
                    &f.next.freeze,
                    &f.acknowledgement,
                    &f.prior_retirement,
                    receipt.as_bytes()
                )
                .is_err(),
            "valid earlier retirement is not this transition"
        );
        let mut changed = receipt.as_bytes().to_vec();
        *changed.last_mut().expect("signed receipt") ^= 1;
        assert!(f
            .next
            .approval
            .verify_activation_receipt(
                &history,
                &f.next.freeze,
                &f.acknowledgement,
                retirement.as_bytes(),
                &changed
            )
            .is_err());
        current.close();
        f.finish(&retirement, Some(receipt.as_bytes()));
    }
}

fn activation_fields(body: &[u8]) -> [std::ops::Range<usize>; 3] {
    let mut d = Decoder::new(body);
    assert_eq!(d.array::<8>().expect("current tag"), *b"QPAHI006");
    let len = u32::from_be_bytes(d.array().expect("approval length")) as usize;
    d.take(len).expect("approval");
    d.take(32).expect("archive commitment");
    for _ in 0..2 {
        let len = u32::from_be_bytes(d.array().expect("length")) as usize;
        d.take(len).expect("freeze/import");
    }
    assert_eq!(d.array::<1>().expect("not cancelled"), [0]);
    let ranges = std::array::from_fn(|_| {
        let len = u32::from_be_bytes(d.array().expect("activation field length")) as usize;
        let start = body.len() - d.remaining();
        d.take(len).expect("complete activation field");
        start..start + len
    });
    assert_eq!(d.u16().expect("no current grants yet"), 0);
    assert_eq!(d.array::<1>().expect("no next handoff yet"), [0]);
    d.finish().expect("exact primary schema");
    ranges
}
fn replace_row(f: &RecoveryCase, table: TableDefinition<&str, &[u8]>, name: &str, bytes: &[u8]) {
    let db = open_private_database(&f.next.db_path()).expect("owned corruption fixture");
    let tx = transaction(&db).expect("fixture transaction");
    tx.open_table(table)
        .expect("fixture table")
        .insert(name, bytes)
        .expect("replace one row");
    tx.commit().expect("commit test mutation");
}

#[test]
fn successive_activated_archive_and_mac_valid_semantic_corruption_are_rejected() {
    for archived in [false, true] {
        for kind in ["archive", "retirement", "activation", "content"] {
            let mut f = RecoveryCase::new(archived);
            let retirement = f.retire();
            let mut target = f.next.open();
            let history = target
                .verify_source_retirement(retirement.as_bytes())
                .expect("full history");
            let (mut current, receipt) = target
                .activate(retirement.as_bytes(), f.next.signer())
                .expect("active target");
            let mut image = current.handoff_image().expect("original current image");
            let entry = image
                .entries
                .get_mut(&f.c.subject.id(&f.c.pin.binding()))
                .expect("original subject");
            // Dropping a pending record has a well-formed standalone encoding,
            // but this target has no client grant permitting that state change.
            assert!(entry.independent_policy.take().is_some());
            let altered_content =
                image_codec::encode_content(&history, &image).expect("public encoding");
            image_codec::decode_content(&history, &altered_content)
                .expect("standalone image is valid");
            current.close();
            let (table, name) = if kind == "archive" {
                (ARCHIVE, "source")
            } else {
                (PRIMARY, "image")
            };
            let original = {
                let db = open_private_database(&f.next.db_path()).expect("owned fixture");
                let tx = db.begin_read().expect("read original");
                let table = tx.open_table(table).expect("table");
                let row = table.get(name).expect("row").expect("present");
                row.value().to_vec()
            };
            let mut changed = original.clone();
            if kind == "archive" {
                let middle = changed.len() / 2;
                *changed.get_mut(middle).expect("middle of complete archive") ^= 1;
            } else {
                changed.truncate(changed.len().checked_sub(32).expect("stored MAC"));
                let fields = activation_fields(&changed);
                match kind {
                    "retirement" => {
                        assert_eq!(fields[0].len(), f.prior_retirement.len());
                        changed
                            .get_mut(fields[0].clone())
                            .expect("retirement field")
                            .copy_from_slice(&f.prior_retirement);
                    }
                    "activation" => {
                        *changed
                            .get_mut(fields[1].end - 1)
                            .expect("activation signature byte") ^= 1
                    }
                    "content" => {
                        let mut field = u32::try_from(altered_content.len())
                            .expect("bounded content")
                            .to_be_bytes()
                            .to_vec();
                        field.extend_from_slice(&altered_content);
                        changed.splice(fields[2].start - 4..fields[2].end, field);
                    }
                    _ => unreachable!("closed test case set"),
                }
                let key = f.next.key();
                let mut mac = authenticator(&key).expect("owned fixture target key");
                mac.update(&changed);
                changed.extend_from_slice(&mac.finalize().into_bytes());
            }
            replace_row(&f, table, name, &changed);
            assert!(
                AnchorHandoffTarget::open(&f.next.db_path(), f.next.key(), f.next.approval.clone())
                    .is_err(),
                "archived={archived} {kind} must not be admitted even with a valid target MAC"
            );
            replace_row(&f, table, name, &original);
            f.finish(&retirement, Some(receipt.as_bytes()));
        }
    }
}
