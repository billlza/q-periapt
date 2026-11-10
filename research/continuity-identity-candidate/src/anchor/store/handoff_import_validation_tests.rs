// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn source_signature_and_matching_digest_do_not_excuse_malformed_complete_image() {
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    let mut bad = f.source.clone();
    // This source fixture has no handoff wrapper yet. Alter its canonical
    // entry count to exceed the original complete-image capacity, then sign
    // an exactly matching plan with the owned test source key.
    bad.get_mut(48..50)
        .expect("legacy complete-image count")
        .copy_from_slice(&257_u16.to_be_bytes());
    let mut plan = f.plan.to_bytes();
    // Source commitment is in the common prefix, before validity, approval and
    // the optional v2 namespace/history suffix. Keep that history unchanged.
    let commitment_offset = 8 + 32 + 2 * (32 + PUBLIC_KEY_BYTES) + 8;
    plan.get_mut(commitment_offset..commitment_offset + 32)
        .expect("source commitment field")
        .copy_from_slice(&digest(
            b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-SOURCE/v1",
            &bad,
        ));
    let plan =
        AnchorHandoffPlan::restore_trusted_state(&plan).expect("shaped but corrupt state plan");
    let mut body = b"QPAHFR01".to_vec();
    body.extend_from_slice(&plan.to_bytes());
    let signer = &c.store.active.as_ref().expect("owned source signer").signer;
    let freeze = envelope(
        &body,
        &signer
            .sign(Purpose::AnchorHandoffFreeze, &body)
            .expect("negative-control source signature"),
    )
    .expect("signed envelope");
    plan.verify_receipt(&freeze)
        .expect("source signature alone is valid");
    let approval = AnchorHandoffTargetApproval::from_trusted_state(
        &plan,
        &c.pin,
        &f.pin,
        Validity::new(145, 155).expect("target interval"),
        [220; 32],
    )
    .expect("independent test approval");
    assert!(matches!(
        AnchorHandoffTarget::provision_import(
            &f.db_path(),
            f.key(),
            &f.signer(),
            approval,
            &bad,
            &freeze,
            150
        ),
        Err(DurableError::Capacity)
    ));
    assert!(!f.db_path().exists());
    assert!(matches!(
        AnchorHandoffTarget::provision_import(
            &f.db_path(),
            f.key(),
            &f.signer(),
            f.approval.clone(),
            &vec![0; MAX_IMAGE],
            &f.freeze,
            150
        ),
        Err(DurableError::Capacity)
    ));
    assert!(!f.db_path().exists());
}

#[test]
fn complete_import_preserves_legacy_identity_classification() {
    let mut c = case();
    legacy_without_original_identity(&mut c);
    let f = TargetFixture::new(&mut c);
    let mut target = f.provision();
    let body = target
        .retained_source_state()
        .expect("legacy complete body");
    assert_eq!(body, f.source);
    let key = f.key();
    let mut sealed = body.clone();
    let mut mac = authenticator(&key).expect("target key");
    mac.update(&body);
    sealed.extend_from_slice(&mac.finalize().into_bytes());
    let image = decode(&key, &c.pin, &sealed).expect("full original schema under new storage key");
    assert!(image
        .entries
        .values()
        .all(|entry| entry.original_identity.is_none()));
    target.close();
    assert_eq!(
        f.open().retained_source_state().expect("same legacy state"),
        body
    );
}

#[test]
fn valid_storage_mac_cannot_hide_changed_original_content_or_receipt() {
    const IMPORT: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_import_v1");
    for alter_receipt in [false, true] {
        let mut c = case();
        let f = TargetFixture::new(&mut c);
        f.provision().close();
        let db = open_private_database(&f.db_path()).expect("owned corruption lease");
        let tx = transaction(&db).expect("corruption transaction");
        {
            let mut table = tx.open_table(IMPORT).expect("table");
            let mut raw = table
                .get("image")
                .expect("lookup")
                .expect("image")
                .value()
                .to_vec();
            let index = if alter_receipt {
                raw.len() - 34
            } else {
                8 + 4 + f.approval.to_bytes().len() + 4 + f.source.len() - 1
            };
            *raw.get_mut(index).expect("bounded corruption byte") ^= 1;
            let end = raw.len() - 32;
            let mut mac = authenticator(&f.key()).expect("test storage key");
            mac.update(raw.get(..end).expect("body"));
            raw.get_mut(end..)
                .expect("MAC")
                .copy_from_slice(&mac.finalize().into_bytes());
            table
                .insert("image", raw.as_slice())
                .expect("MAC-valid corrupt record");
        }
        tx.commit().expect("commit corruption");
        drop(db);
        assert!(AnchorHandoffTarget::open(&f.db_path(), f.key(), f.approval.clone()).is_err());
    }
}
