// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

const PRIMARY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_import_v1");
const CLIENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_clients_v1");

fn snapshot(f: &Prepared) -> (Vec<u8>, Vec<u8>) {
    let db = open_private_database(&f.f.db_path()).expect("owned database");
    let tx = db.begin_read().expect("snapshot");
    let primary = tx.open_table(PRIMARY).expect("primary");
    let clients = tx.open_table(CLIENTS).expect("clients");
    let image = primary.get("image").expect("lookup").expect("image");
    let id = f.c.subject.id(&f.c.pin.binding());
    let row = clients.get(id.as_slice()).expect("lookup").expect("row");
    (image.value().to_vec(), row.value().to_vec())
}
fn replace(f: &Prepared, image: &[u8], row: Option<&[u8]>, extra: bool) {
    let db = open_private_database(&f.f.db_path()).expect("owned mutation lease");
    let tx = transaction(&db).expect("test transaction");
    {
        tx.open_table(PRIMARY)
            .expect("primary")
            .insert("image", image)
            .expect("image");
        let mut clients = tx.open_table(CLIENTS).expect("clients");
        let id = f.c.subject.id(&f.c.pin.binding());
        clients.remove(id.as_slice()).expect("replace known row");
        clients
            .remove([77; 32].as_slice())
            .expect("remove test row");
        if let Some(row) = row {
            clients.insert(id.as_slice(), row).expect("proof row");
            if extra {
                assert_ne!(id, [77; 32]);
                clients.insert([77; 32].as_slice(), row).expect("extra row");
            }
        }
    }
    tx.commit().expect("test mutation committed");
}
fn authenticate(f: &Prepared, image: &mut [u8]) {
    let end = image.len().checked_sub(32).expect("MAC body");
    let mut mac = authenticator(&f.f.key()).expect("owned storage key");
    mac.update(image.get(..end).expect("body"));
    image
        .get_mut(end..)
        .expect("MAC")
        .copy_from_slice(&mac.finalize().into_bytes());
}
fn rejected_then_restore(f: &Prepared, image: &[u8], row: &[u8], receipt: &[u8]) {
    assert!(AnchorHandoffTarget::open(&f.f.db_path(), f.f.key(), f.f.approval.clone()).is_err());
    replace(f, image, Some(row), false);
    assert_eq!(
        f.f.open()
            .client_authorization_receipt(f.c.subject)
            .expect("same original authenticated authorization after exact restoration")
            .as_bytes(),
        receipt
    );
}

#[test]
fn client_authorization_cold_open_rejects_missing_extra_and_detached_rows() {
    let mut f = Prepared::new(None);
    let receipt = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("commit");
    f.active.close();
    let (image, row) = snapshot(&f);
    assert_eq!(image.get(..8), Some(b"QPAHI003".as_slice()));
    assert!(
        row.len() < 16 * 1024,
        "complete public proof stays in its fixed row budget"
    );
    replace(&f, &image, None, false);
    rejected_then_restore(&f, &image, &row, receipt.as_bytes());
    replace(&f, &image, Some(&row), true);
    rejected_then_restore(&f, &image, &row, receipt.as_bytes());
    // Retain the proof table but strip its primary index, with a valid storage
    // MAC. The old activated schema must not silently discard authorization.
    let mut detached = image.clone();
    detached.truncate(detached.len() - 2 - 64 - 32);
    detached
        .get_mut(..8)
        .expect("tag")
        .copy_from_slice(b"QPAHI002");
    detached.extend_from_slice(&[0; 32]);
    authenticate(&f, &mut detached);
    replace(&f, &detached, Some(&row), false);
    rejected_then_restore(&f, &image, &row, receipt.as_bytes());
}

#[test]
fn client_authorization_valid_storage_mac_and_index_do_not_replace_public_proofs() {
    let mut f = Prepared::new(Some(("P", false)));
    let receipt = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("commit");
    f.active.close();
    let (image, row) = snapshot(&f);
    let request_start = 8 + 4;
    let descriptions = request_start + 8 + 2 * PUBLIC_KEY_BYTES;
    let roster = descriptions + 2 * 72;
    let original_policy = roster + 40;
    for offset in [
        request_start + 8,
        request_start + 8 + PUBLIC_KEY_BYTES,
        descriptions + 16 + 7,
        roster + 8,
        original_policy + 96,
        row.len() - 1,
    ] {
        let mut changed = row.clone();
        *changed
            .get_mut(offset)
            .expect("bounded semantic corruption") ^= 1;
        let mut primary = image.clone();
        let end = primary.len() - 32;
        primary
            .get_mut(end - 32..end)
            .expect("single index digest")
            .copy_from_slice(&digest(
                b"Q-PERIAPT-WITNESS-CLIENT-AUTHORIZATION-ROW/v1",
                &changed,
            ));
        authenticate(&f, &mut primary);
        replace(&f, &primary, Some(&changed), false);
        rejected_then_restore(&f, &image, &row, receipt.as_bytes());
    }
}

#[test]
fn client_authorization_rejects_self_signed_replacement_roots() {
    let mut f = Prepared::new(None);
    let account = RootSigningKey::generate().expect("untrusted account root");
    let policy = PolicySigningKey::generate().expect("untrusted policy root");
    let body = f.approved.scope().to_bytes();
    let pair_start = f.request.len() - crate::MAX_ANCHOR_HANDOFF_ADOPTION_BYTES;
    let approval_length = 4 + body.len() + crate::crypto::SIGNATURE_BYTES;
    let before = fs::read(f.f.db_path()).expect("original target");
    for (which, key, signature) in [
        (
            0,
            account.public_key().expect("public"),
            account
                .sign(Purpose::AnchorHandoffAdoption, &body)
                .expect("self signature"),
        ),
        (
            1,
            policy.public_key().expect("public"),
            policy
                .sign(Purpose::AnchorHandoffAdoption, &body)
                .expect("self signature"),
        ),
    ] {
        let mut changed = f.request.clone();
        let key_start = 8 + which * PUBLIC_KEY_BYTES;
        changed
            .get_mut(key_start..key_start + PUBLIC_KEY_BYTES)
            .expect("key field")
            .copy_from_slice(&key.encode());
        let approval_start = pair_start + 8 + which * (2 + approval_length) + 2;
        let signed = envelope(&body, &signature).expect("well formed self-signed approval");
        changed
            .get_mut(approval_start..approval_start + approval_length)
            .expect("signed proof")
            .copy_from_slice(&signed);
        assert!(f
            .active
            .authorize_handoff_client(&changed, || Ok(180))
            .is_err());
    }
    assert_eq!(
        fs::read(f.f.db_path()).expect("no substituted authorization"),
        before
    );
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("original independent roots");
}
