// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Successive capture must include the activated owner, not an empty new store.
use super::*;
use crate::anchor::store::handoff::validate_capture;

fn local_key(f: &Prepared) -> JournalKey {
    JournalKey::provision(&f.c.server.join("independent-capture-key"))
        .expect("separate owned validation key, not the source storage key")
}

struct CaptureParts {
    history: Vec<u8>,
    body: Vec<u8>,
    rows: Vec<([u8; 32], Vec<u8>)>,
}
impl CaptureParts {
    fn decode(bytes: &[u8]) -> Self {
        let mut d = Decoder::new(bytes);
        assert_eq!(d.array::<8>().expect("capture tag"), *b"QPAHSS01");
        fn field(d: &mut Decoder<'_>) -> Vec<u8> {
            let length = usize::try_from(u32::from_be_bytes(d.array().expect("field size")))
                .expect("bounded fixture size");
            d.take(length).expect("exact field").to_vec()
        }
        let history = field(&mut d);
        let body = field(&mut d);
        let count = d.u16().expect("row count");
        let rows = (0..count)
            .map(|_| (d.array().expect("subject"), field(&mut d)))
            .collect();
        d.finish().expect("complete fixture");
        Self {
            history,
            body,
            rows,
        }
    }
    fn encode(&self) -> Vec<u8> {
        fn put(bytes: &[u8], out: &mut Vec<u8>) {
            out.extend_from_slice(
                &u32::try_from(bytes.len())
                    .expect("bounded fixture")
                    .to_be_bytes(),
            );
            out.extend_from_slice(bytes);
        }
        let mut bytes = b"QPAHSS01".to_vec();
        put(&self.history, &mut bytes);
        put(&self.body, &mut bytes);
        bytes.extend_from_slice(
            &u16::try_from(self.rows.len())
                .expect("bounded row count")
                .to_be_bytes(),
        );
        for (id, row) in &self.rows {
            bytes.extend_from_slice(id);
            put(row, &mut bytes);
        }
        bytes
    }
}

#[test]
fn successive_source_capture_retains_unresolved_work_and_original_authorization() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let mut f = Prepared::new(Some((kind, applied)));
            let old_entry = f.original_entry();
            let receipt = f
                .active
                .authorize_handoff_client(&f.request, || Ok(180))
                .expect("committed current-target authorization");
            let before = fs::read(f.f.db_path()).expect("current durable state");
            let captured = f
                .active
                .handoff_source_state()
                .expect("complete successor source with unresolved original work");
            assert_eq!(captured.pin().binding(), f.f.pin.binding());
            assert!(captured.as_bytes().starts_with(b"QPAHSS01"));
            let checked = validate_capture(
                captured.as_bytes(),
                &local_key(&f),
                &f.f.approval,
                &f.history,
            )
            .expect("all records under a different local key");
            assert_eq!(checked.namespace, f.c.pin.binding());
            let entry = checked
                .entries
                .get(&f.c.subject.id(&checked.namespace))
                .expect("same namespace and subject");
            let mut bytes = Vec::new();
            encode_entry(entry, &f.history, EntryFormat::COMPLETE, &mut bytes)
                .expect("all pending and retained fields");
            assert_eq!(bytes, old_entry);
            assert_eq!(f.original_entry(), old_entry);
            assert_eq!(fs::read(f.f.db_path()).expect("read-only capture"), before);
            assert_eq!(
                f.active
                    .handoff_client_authorization(f.c.subject)
                    .expect("same exact authorization")
                    .as_bytes(),
                receipt.as_bytes()
            );
            f.reopen();
            assert_eq!(
                f.active
                    .handoff_source_state()
                    .expect("exact reopened capture")
                    .as_bytes(),
                captured.as_bytes()
            );
        }
    }
}

#[test]
fn successive_source_capture_keeps_old_pending_g_and_new_authority_pending_p_together() {
    let mut f = Prepared::new(Some(("G", false)));
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("old client authorization");
    let old = f.original_entry();
    let key = local_key(&f);
    let mut next = super::super::super::activation::new_client(f.active, &f.f.pin);
    let approval = next.approval(&next.original, None, &next.target);
    let proposal = next.proposal(&approval, next.initial, 228);
    next.prepare(proposal, &approval)
        .expect("actual second-root P preparation");
    let image = next.store.image().expect("actual mixed state");
    assert_eq!(image.entries.len(), 2);
    let captured = next
        .store
        .handoff_source_state()
        .expect("complete mixed-authority capture");
    let restored = validate_capture(captured.as_bytes(), &key, &f.f.approval, &f.history)
        .expect("both original logical authorities resolved through verified history");
    assert_eq!(
        image_codec::encode_content(&f.history, &restored).expect("restored complete image"),
        image_codec::encode_content(&f.history, &image).expect("original complete image")
    );
    let mut retained = Vec::new();
    encode_entry(
        restored
            .entries
            .get(&f.c.subject.id(&f.c.pin.binding()))
            .expect("old G"),
        &f.history,
        EntryFormat::COMPLETE,
        &mut retained,
    )
    .expect("retained G bytes");
    assert_eq!(retained, old);
    next.store.close();
    next.store =
        f.f.open()
            .activate(&f.retired, f.f.signer())
            .expect("cold original owner")
            .0;
    assert_eq!(
        next.store
            .handoff_source_state()
            .expect("cold full capture")
            .as_bytes(),
        captured.as_bytes()
    );
}

#[test]
fn successive_source_capture_rejects_missing_rows_wrong_history_and_modified_public_state() {
    let mut f = Prepared::new(Some(("P", true)));
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("current authorization");
    let captured = f.active.handoff_source_state().expect("complete capture");
    let key = local_key(&f);
    let check = |bytes: &[u8]| validate_capture(bytes, &key, &f.f.approval, &f.history);
    assert!(check(captured.as_bytes()).is_ok());
    let mut parts = CaptureParts::decode(captured.as_bytes());
    assert_eq!(parts.rows.len(), 1);
    assert_eq!(
        parts.history,
        f.history.to_bytes().expect("same verified history")
    );
    let active = f.active.active.as_ref().expect("actual owned database");
    let read = active.db.begin_read().expect("read-only actual store");
    let table = read
        .open_table(TableDefinition::<&str, &[u8]>::new(
            "continuity_anchor_handoff_import_v1",
        ))
        .expect("original import row");
    let stored = table
        .get("image")
        .expect("row read")
        .expect("complete stored image");
    assert_eq!(
        parts.body,
        stored
            .value()
            .get(..stored.value().len().checked_sub(32).expect("stored MAC"))
            .expect("complete public stored image"),
        "capture keeps the complete public image and excludes its keyed MAC"
    );
    drop(stored);
    drop(table);
    drop(read);
    parts.rows.clear();
    assert!(matches!(check(&parts.encode()), Err(DurableError::Corrupt)));
    let mut parts = CaptureParts::decode(captured.as_bytes());
    *parts
        .rows
        .first_mut()
        .expect("one row")
        .0
        .first_mut()
        .expect("subject byte") ^= 1;
    assert!(matches!(check(&parts.encode()), Err(DurableError::Corrupt)));
    let mut parts = CaptureParts::decode(captured.as_bytes());
    let (id, row) = parts.rows.first_mut().expect("one row");
    *row.last_mut().expect("exact target signature") ^= 1;
    let commitment = digest(b"Q-PERIAPT-WITNESS-CLIENT-AUTHORIZATION-ROW/v1", row);
    let end = parts.body.len();
    assert_eq!(
        parts
            .body
            .get(
                end.checked_sub(64).expect("index ID")
                    ..end.checked_sub(32).expect("index commitment")
            )
            .expect("index subject"),
        id
    );
    parts
        .body
        .get_mut(end - 32..)
        .expect("one retained index entry")
        .copy_from_slice(&commitment);
    assert!(
        matches!(
            check(&parts.encode()),
            Err(DurableError::Protocol(Error::Authentication))
        ),
        "a repaired public row hash cannot replace the original target signature"
    );
    assert!(validate_capture(
        captured.as_bytes(),
        &key,
        &f.f.approval,
        &AnchorHandoffHistory::from_trusted_origin(f.c.pin.clone())
    )
    .is_err());
    let mut changed = captured.as_bytes().to_vec();
    *changed.last_mut().expect("authorization signature") ^= 1;
    assert!(check(&changed).is_err());
    assert!(check(
        captured
            .as_bytes()
            .get(
                ..captured
                    .as_bytes()
                    .len()
                    .checked_sub(1)
                    .expect("nonempty capture")
            )
            .expect("truncated fixture")
    )
    .is_err());
    let mut trailing = captured.as_bytes().to_vec();
    trailing.push(0);
    assert!(check(&trailing).is_err());
    for offset in [8usize, 12] {
        let mut changed = captured.as_bytes().to_vec();
        *changed.get_mut(offset).expect("history length/body") ^= 0x80;
        assert!(check(&changed).is_err());
    }
    let before = f.original_entry();
    assert_eq!(
        f.active
            .handoff_source_state()
            .expect("original owner remains unchanged")
            .as_bytes(),
        captured.as_bytes()
    );
    assert_eq!(f.original_entry(), before);
}

#[test]
fn successive_source_capture_binds_authorization_revision_without_rewriting_the_subject() {
    let mut f = Prepared::new(Some(("R", false)));
    let before = f
        .active
        .handoff_source_state()
        .expect("complete unadopted capture");
    let entry = f.original_entry();
    let receipt = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("actual durable authorization");
    let after = f
        .active
        .handoff_source_state()
        .expect("capture includes its exact row");
    assert_eq!(
        after.revision(),
        before
            .revision()
            .checked_add(1)
            .expect("store metadata commit")
    );
    assert_ne!(before.commitment(), after.commitment());
    assert_eq!(f.original_entry(), entry);
    let parts = CaptureParts::decode(after.as_bytes());
    assert!(parts
        .rows
        .first()
        .expect("one authorized row")
        .1
        .ends_with(receipt.as_bytes()));
    let signer = AnchorSigningKey::generate().expect("new distinct root");
    let pin = AnchorPin::new(
        AnchorIdentity::generate().expect("new root identity"),
        signer.public_key().expect("new root public key"),
    );
    let plan = AnchorHandoffPlan::from_trusted_state(
        [240; 32],
        &after,
        pin,
        Validity::new(180, 200).expect("prospective admission"),
        [241; 32],
    )
    .expect("prospective exact successor plan");
    let mut context = f.history.namespace_binding().to_vec();
    context.extend_from_slice(&f.history.sequence().to_be_bytes());
    context.extend_from_slice(&f.history.checkpoint());
    assert_eq!(context.len(), 72);
    assert!(plan.to_bytes().ends_with(&context));
    assert!(
        matches!(
            f.active.freeze_handoff(&plan, 180),
            Err(DurableError::Suspended)
        ),
        "capture does not substitute for the successive durable transaction"
    );
    assert_eq!(
        f.active
            .handoff_source_state()
            .expect("unchanged current owner")
            .as_bytes(),
        after.as_bytes()
    );
}
