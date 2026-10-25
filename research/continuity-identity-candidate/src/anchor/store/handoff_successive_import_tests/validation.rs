// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const ARCHIVE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_source_archive_v1");
const PRIMARY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_import_v1");

#[test]
fn successive_import_archive_is_complete_and_missing_or_modified_rows_fail(
) -> Result<(), Box<dyn std::error::Error>> {
    for case in [
        "missing-table",
        "missing-row",
        "extra-row",
        "modified",
        "inline-with-valid-mac",
    ] {
        let (_f, next) = setup("G", false, true);
        let mut target = next.provision();
        let ack = target
            .import_receipt()
            .expect("committed exact acknowledgement");
        target.close();
        let before = fs::read(next.db_path()).expect("owned original fixture");
        let db = open_private_database(&next.db_path()).expect("owned corruption fixture");
        let tx = transaction(&db).expect("fixture write");
        {
            let table = tx.open_table(PRIMARY).expect("primary");
            let row = table.get("image").expect("read").expect("primary row");
            assert!(row.value().starts_with(b"QPAHI005"));
            assert!(row.value().len() < next.source.len());
        }
        match case {
            "missing-table" => {
                tx.delete_table(ARCHIVE).expect("remove fixture table");
            }
            "missing-row" => {
                tx.open_table(ARCHIVE)
                    .expect("archive")
                    .remove("source")
                    .expect("remove fixture row");
            }
            "extra-row" => {
                tx.open_table(ARCHIVE)
                    .expect("archive")
                    .insert("other", b"x".as_slice())
                    .expect("extra fixture row");
            }
            "modified" => {
                let mut bytes = next.source.clone();
                *bytes.last_mut().expect("nonempty source") ^= 1;
                tx.open_table(ARCHIVE)
                    .expect("archive")
                    .insert("source", bytes.as_slice())
                    .expect("corrupt original source");
            }
            "inline-with-valid-mac" => {
                let mut body = b"QPAHI001".to_vec();
                for field in [
                    next.approval.to_bytes().as_slice(),
                    &next.source,
                    &next.freeze,
                    ack.as_bytes(),
                ] {
                    body.extend_from_slice(
                        &u32::try_from(field.len())
                            .expect("bounded fixture")
                            .to_be_bytes(),
                    );
                    body.extend_from_slice(field);
                }
                body.push(0);
                let mut mac = authenticator(&next.key()).expect("owned target MAC");
                mac.update(&body);
                body.extend_from_slice(&mac.finalize().into_bytes());
                assert!(
                    body.len() < MAX_IMAGE,
                    "fixture fits old inline limit; rejection must be canonical-format validation"
                );
                tx.open_table(PRIMARY)
                    .expect("primary")
                    .insert("image", body.as_slice())
                    .expect("MAC-valid inline forgery");
                tx.delete_table(ARCHIVE).expect("missing detached archive");
            }
            _ => return Err("unknown corruption case".into()),
        }
        tx.commit().expect("commit fixture corruption");
        drop(db);
        assert!(matches!(
            AnchorHandoffTarget::open(&next.db_path(), next.key(), next.approval.clone()),
            Err(DurableError::Corrupt)
        ));
        fs::write(next.db_path(), before).expect("restore only owned original fixture");
        let mut restored = next.open();
        assert_eq!(
            restored
                .import_receipt()
                .expect("exact original receipt")
                .as_bytes(),
            ack.as_bytes()
        );
        assert_eq!(
            restored
                .retained_source_state()
                .expect("all original state"),
            next.source
        );
    }
    Ok(())
}

#[test]
fn successive_import_rechecks_old_history_and_records_under_valid_current_source_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    for case in [
        "origin",
        "history-signature",
        "public-index",
        "missing-records",
    ] {
        let (mut f, next) = setup("R", true, false);
        let revision = f
            .active
            .handoff_image()
            .expect("exact frozen image")
            .revision;
        let mut bytes = next.source.clone();
        let mut d = Decoder::new(&bytes);
        d.take(8).expect("capture tag");
        let history_len = usize::try_from(u32::from_be_bytes(d.array().expect("history length")))
            .expect("bounded length");
        d.take(history_len).expect("history");
        let body_len = usize::try_from(u32::from_be_bytes(d.array().expect("body length")))
            .expect("bounded body");
        d.take(body_len).expect("body");
        let history_end = 12 + history_len;
        let body_end = history_end + 4 + body_len;
        match case {
            "origin" => *bytes.get_mut(12 + 8).expect("historical origin") ^= 1,
            "history-signature" => {
                *bytes
                    .get_mut(history_end - 1)
                    .expect("old signed transition") ^= 1
            }
            "public-index" => {
                *bytes
                    .get_mut(body_end - 1)
                    .expect("old client proof commitment") ^= 1
            }
            "missing-records" => {
                bytes.truncate(body_end);
                bytes.extend_from_slice(&0u16.to_be_bytes());
            }
            "reset-context" | "wrong-revision" | "reused-origin-key" => {}
            _ => return Err("unknown corruption case".into()),
        }
        let context = if case == "reset-context" {
            AnchorHandoffHistory::from_trusted_origin(f.f.pin.clone()).context()
        } else {
            f.history.context()
        };
        let target_pin = if case == "reused-origin-key" {
            AnchorPin::new(
                AnchorIdentity::generate().expect("new identity"),
                f.c.pin.public_key().clone(),
            )
        } else {
            next.pin.clone()
        };
        let observed = AnchorHandoffSourceState::captured(
            &f.f.pin,
            if case == "wrong-revision" {
                increment(revision).expect("wrong revision")
            } else {
                revision
            },
            bytes.clone(),
            context,
        );
        let plan = AnchorHandoffPlan::from_trusted_state(
            [248; 32],
            &observed,
            target_pin.clone(),
            Validity::new(180, 200).expect("window"),
            [249; 32],
        )
        .expect("independently fixed original history context");
        let approval = AnchorHandoffTargetApproval::from_trusted_state(
            &plan,
            &f.f.pin,
            &target_pin,
            Validity::new(180, 200).expect("window"),
            [250; 32],
        )
        .expect("target approval");
        let mut body = b"QPAHFR01".to_vec();
        body.extend_from_slice(&plan.to_bytes());
        let wire = envelope(
            &body,
            &f.f.signer()
                .sign(Purpose::AnchorHandoffFreeze, &body)
                .expect("actual B signature"),
        )
        .expect("signed counterfeit source claim");
        plan.verify_receipt(&wire)
            .expect("source signature is valid, so it cannot substitute for prior validation");
        let signer = next.signer();
        let selected_signer = if case == "reused-origin-key" {
            &f.c.store
                .active
                .as_ref()
                .expect("retained original signer")
                .signer
        } else {
            &signer
        };
        let result = AnchorHandoffTarget::provision_import(
            &next.db_path(),
            next.key(),
            selected_signer,
            approval,
            &bytes,
            &wire,
            185,
        );
        assert!(
            result.is_err(),
            "valid B signature must not authenticate changed history or omit original records"
        );
        assert!(!next.db_path().exists());
    }
    Ok(())
}
