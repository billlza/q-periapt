// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_account_decision_rechecks_target_expiry_and_clock_before_commit() {
    for times in [[179, 185], [185, 200], [186, 185], [259, 260]] {
        let mut c = RetirementCase::new(None, false);
        let n = next(&c, 235);
        let original = c.old_entry();
        let mut a = approve(&mut c, &n, 237);
        if times[0] == 259 {
            a = Approval::from_trusted_state(
                a.proposal().clone(),
                &materials(&c.root, &n, &c.history),
                [238; 32],
                Validity::new(180, 300).expect("operator outlives target"),
            )
            .expect("independent long operator decision");
        }
        let mut clock = times.into_iter();
        let m = materials(&c.root, &n, &c.history);
        assert!(c
            .active
            .replace_transferred_account_root(&a, &m, || Ok(clock.next().expect("two decisions")))
            .is_err());
        c.reopen();
        assert_eq!(c.old_entry(), original);
        assert!(matches!(
            c.active.transferred_account_decision(&a),
            Err(DurableError::Absent)
        ));
        let image = c.active.image().expect("exact noncommit");
        assert_eq!(image.entries.len(), 1);
        assert!(image.account_replacements.is_empty());
        let closed = c
            .active
            .close_transferred_account_replacement(&a)
            .expect("historical permanent close");
        assert_eq!(closed.state(), State::Closed);
    }
}

#[test]
fn transferred_account_decision_refuses_substituted_target_history_and_operation() {
    let mut c = RetirementCase::new(None, false);
    let n = next(&c, 240);
    let other = next(&c, 241);
    let a = approve(&mut c, &n, 243);
    let other_approval = approve(&mut c, &other, 245);
    let before = c.active.handoff_source_state().expect("before");
    assert!(c
        .active
        .replace_transferred_account_root(&a, &materials(&c.root, &other, &c.history), || Ok(185))
        .is_err());
    let mut bytes = a.to_bytes().expect("retained approval");
    *bytes.get_mut(8 + 32).expect("history checkpoint") ^= 1;
    assert!(Approval::restore_trusted_state(&bytes, &materials(&c.root, &n, &c.history)).is_err());
    assert_eq!(
        c.active
            .handoff_source_state()
            .expect("unchanged")
            .as_bytes(),
        before.as_bytes()
    );
    let decision = c
        .active
        .replace_transferred_account_root(&a, &materials(&c.root, &n, &c.history), || Ok(185))
        .expect("exact target");
    assert!(other_approval
        .verify_decision(&c.history, decision.as_bytes())
        .is_err());
    assert!(c
        .active
        .replace_transferred_account_root(
            &other_approval,
            &materials(&c.root, &other, &c.history),
            || Ok(185)
        )
        .is_err());
    assert_eq!(
        c.active
            .transferred_account_decision(&a)
            .expect("original winner")
            .as_bytes(),
        decision.as_bytes()
    );
}

#[test]
fn transferred_account_decision_missing_or_forged_proof_refuses_even_with_valid_storage_mac() {
    const PRIMARY: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_import_v1");
    fn write(c: &RetirementCase, bytes: &[u8]) {
        let db = open_private_database(&c.f.db_path()).expect("owned lease");
        let tx = transaction(&db).expect("mutation");
        {
            tx.open_table(PRIMARY)
                .expect("primary")
                .insert("image", bytes)
                .expect("insert");
        }
        tx.commit().expect("commit mutation");
    }
    fn mac(c: &RetirementCase, bytes: &mut [u8]) {
        let end = bytes.len() - 32;
        let mut a = authenticator(&c.f.key()).expect("owned key");
        a.update(bytes.get(..end).expect("body"));
        bytes
            .get_mut(end..)
            .expect("MAC")
            .copy_from_slice(&a.finalize().into_bytes());
    }
    for legacy in [false, true] {
        let mut c = RetirementCase::new(Some(("P", false)), legacy);
        let n = next(&c, 247);
        let a = approve(&mut c, &n, 249);
        let decision = c
            .active
            .replace_transferred_account_root(&a, &materials(&c.root, &n, &c.history), || Ok(185))
            .expect("real commit");
        let wire = decision.as_bytes();
        let image = c.active.image().expect("canonical state");
        let body = image_codec::encode_content(&c.history, &image).expect("full body");
        assert_eq!(body.get(..8), Some(b"QPANC021".as_slice()));
        c.active.close();
        let original = {
            let db = open_private_database(&c.f.db_path()).expect("read original");
            let tx = db.begin_read().expect("snapshot");
            tx.open_table(PRIMARY)
                .expect("primary")
                .get("image")
                .expect("get")
                .expect("original")
                .value()
                .to_vec()
        };
        let positions = original
            .windows(body.len())
            .enumerate()
            .filter_map(|(i, b)| (b == body).then_some(i))
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1);
        let start = *positions.first().expect("unique current content");
        let length_start = start.checked_sub(4).expect("bounded length prefix");
        assert_eq!(
            original.get(length_start..start),
            Some(
                u32::try_from(body.len())
                    .expect("bounded body")
                    .to_be_bytes()
                    .as_slice()
            )
        );
        let mut forged = original.clone();
        let end_of_body = start + body.len();
        *forged.get_mut(end_of_body - 1).expect("signature tail") ^= 1;
        mac(&c, &mut forged);
        write(&c, &forged);
        assert!(
            AnchorHandoffTarget::open(&c.f.db_path(), c.f.key(), c.f.approval.clone()).is_err()
        );
        // Remove the full decision map and empty legacy closure count, retaining
        // the real new target and complete account retirement under old layout16.
        let cut = body
            .len()
            .checked_sub(2 + 32 + wire.len() + 2)
            .expect("one fixed decision plus empty closure map");
        assert_eq!(body.get(cut..cut + 4), Some([0, 0, 0, 1].as_slice()));
        let mut downgrade = body.get(..cut).expect("old records").to_vec();
        downgrade
            .get_mut(..8)
            .expect("tag")
            .copy_from_slice(b"QPANC016");
        assert!(
            matches!(
                image_codec::decode_content(&c.history, &downgrade),
                Err(DurableError::Suspended)
            ),
            "missing decision proof must be the refusing boundary"
        );
        let mut forged = original.get(..length_start).expect("prefix").to_vec();
        forged.extend_from_slice(
            &u32::try_from(downgrade.len())
                .expect("bounded length")
                .to_be_bytes(),
        );
        forged.extend_from_slice(&downgrade);
        forged.extend_from_slice(original.get(end_of_body..).expect("suffix"));
        mac(&c, &mut forged);
        write(&c, &forged);
        assert!(
            AnchorHandoffTarget::open(&c.f.db_path(), c.f.key(), c.f.approval.clone()).is_err()
        );
        write(&c, &original);
        assert_eq!(
            c.f.open()
                .transferred_account_decision(&a)
                .expect("exact public proof restored")
                .as_bytes(),
            wire
        );
    }
}
