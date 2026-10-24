// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete codec tests; mixed fixtures are not activated-store acceptance.
use super::*;

fn history_between(
    store: &mut AnchorStore,
    path: &Path,
    target: &AnchorPin,
    signer: &AnchorSigningKey,
) -> (Image, AnchorHandoffHistory) {
    let original = store.image().expect("original complete image");
    let source = store.handoff_source_state().expect("full capture");
    let plan = AnchorHandoffPlan::from_trusted_state(
        [201; 32],
        &source,
        target.clone(),
        Validity::new(990, 1010).expect("independent interval"),
        [202; 32],
    )
    .expect("source approval");
    let approval = AnchorHandoffTargetApproval::from_trusted_state(
        &plan,
        source.pin(),
        target,
        Validity::new(995, 1005).expect("target interval"),
        [203; 32],
    )
    .expect("target approval");
    let freeze = store.freeze_handoff(&plan, 1000).expect("committed freeze");
    let mut imported = AnchorHandoffTarget::provision_import(
        &path.join("history-codec-import.redb"),
        JournalKey::provision(&path.join("history-codec-key")).expect("target wrapping"),
        signer,
        approval.clone(),
        source.as_bytes(),
        freeze.as_bytes(),
        1000,
    )
    .expect("actual complete inactive import");
    let ack = imported
        .import_receipt()
        .expect("committed acknowledgement");
    let retirement = store
        .retire_handoff(&approval, ack.as_bytes(), || Ok(1000))
        .expect("actual source retirement");
    let history = imported
        .verify_source_retirement(retirement.as_bytes())
        .expect("complete source validated with historical resolver");
    assert_eq!(
        imported.status().expect("inactive"),
        AnchorHandoffTargetState::ImportedInactive
    );
    assert_eq!(
        imported
            .retained_source_state()
            .expect("unchanged whole source"),
        source.as_bytes()
    );
    assert!(matches!(
        history.require_current(source.pin().binding()),
        Err(Error::Retired)
    ));
    (original, history)
}

fn content_roundtrip(image: &Image, history: &AnchorHandoffHistory) {
    let bytes = image_codec::encode_content(history, image).expect("complete historical content");
    let restored =
        image_codec::decode_content(history, &bytes).expect("complete cross-record validation");
    assert_eq!(
        image_codec::encode_content(history, &restored).expect("canonical"),
        bytes
    );
    assert_eq!(
        restored.entries.keys().collect::<Vec<_>>(),
        image.entries.keys().collect::<Vec<_>>()
    );
    assert!(image_codec::decode_content(history.current_pin(), &bytes).is_err());
    let mut wrong_namespace = bytes;
    wrong_namespace
        .get_mut(8..40)
        .expect("namespace")
        .copy_from_slice(&history.current_pin().binding());
    assert!(image_codec::decode_content(history, &wrong_namespace).is_err());
}

pub(in crate::anchor::store) fn retained_image_roundtrip(store: &mut AnchorStore, path: &Path) {
    let signer = AnchorSigningKey::generate().expect("independent target key");
    let target = AnchorPin::new(
        AnchorIdentity::generate().expect("target ID"),
        signer.public_key().expect("key"),
    );
    let source = store.pin().expect("original pin");
    let (image, history) = history_between(store, path, &target, &signer);
    let before = image_codec::encode_content(&source, &image).expect("original encoding");
    assert_eq!(
        image_codec::encode_content(&history, &image).expect("same bytes"),
        before
    );
    content_roundtrip(&image, &history);
}

fn pending_credential(c: &mut Case, applied: bool) {
    let grant = credential_grant_first(c);
    let p = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(c),
        AnchorHead::from_trusted_state(1, 2, [204; 32]).expect("target"),
    )
    .expect("original G");
    c.store
        .prepare_credential_renewal(
            p,
            &grant,
            c.peer.responder.current_policy().expect("policy"),
            170,
        )
        .expect("prepared G");
    if applied {
        let request = request(c, AnchorOperation::commit_credential_renewal(&p));
        let reply = c
            .store
            .handle(request.as_bytes(), 175)
            .expect("actual G commit");
        c.pin
            .verify_reply(&request, &reply)
            .expect("signed G reply");
    }
}

// B is a separate original fixture used to produce genuine B-bound records.
// Combining its entries into A's namespace is deliberately a codec fixture,
// not a claim that an inherited client has already adopted B in production.
fn combine_entries(original: &mut Image, next: Image, namespace: [u8; 32]) {
    for entry in next.entries.into_values() {
        assert!(original
            .entries
            .insert(entry.subject.id(&namespace), entry)
            .is_none());
    }
}

#[test]
fn mixed_history_keeps_credential_proposals_and_applied_command_ids_exact() {
    for applied in [false, true] {
        let mut a = credential_case();
        let mut b = crate::anchor::store::policy_renewal::tests::Case::new();
        pending_credential(&mut a, applied);
        let approval = b.approval(&b.original, None, &b.target);
        let proposal = b.proposal(&approval, b.initial, 211);
        b.prepare(proposal, &approval)
            .expect("B retained independent P");
        if applied {
            b.exchange(
                &proposal,
                AnchorOperation::commit_policy_renewal(&proposal),
                170,
            );
        }
        let next = b.store.image().expect("B original records");
        let (_, signer, _) = owners(&b.server);
        let (mut image, history) = history_between(&mut a.store, &a.server, &b.pin, &signer);
        combine_entries(&mut image, next, history.namespace_binding());
        assert!(
            image_codec::encode_content(&a.pin, &image).is_err(),
            "A alone cannot validate B's P"
        );
        content_roundtrip(&image, &history);
        if applied {
            let entry = image
                .entries
                .values_mut()
                .find(|e| e.subject == a.genesis.subject())
                .expect("old subject");
            entry.last = Some([205; 32]);
            assert!(
                image_codec::encode_content(&history, &image).is_err(),
                "unknown last command rejected"
            );
        }
        let mut foreign = credential_case();
        pending_credential(&mut foreign, false);
        let unknown = foreign.store.image().expect("unknown authority");
        assert!(unknown
            .entries
            .values()
            .next()
            .expect("unknown G")
            .check_renewal_state(&history)
            .is_err());
    }
}

#[test]
fn mixed_history_keeps_policy_proposals_and_applied_command_ids_exact() {
    use crate::anchor::store::policy_renewal::tests::Case as PolicyCase;
    for applied in [false, true] {
        let mut a = PolicyCase::new();
        let mut b = PolicyCase::new();
        for c in [&mut a, &mut b] {
            let approval = c.approval(&c.original, None, &c.target);
            let proposal = c.proposal(&approval, c.initial, 206);
            c.prepare(proposal, &approval)
                .expect("real dual-root P approval");
            if applied {
                c.exchange(
                    &proposal,
                    AnchorOperation::commit_policy_renewal(&proposal),
                    170,
                );
            }
        }
        let next = b.store.image().expect("B retained P");
        let (_, signer, _) = owners(&b.server);
        let (mut image, history) = history_between(&mut a.store, &a.server, &b.pin, &signer);
        combine_entries(&mut image, next, history.namespace_binding());
        assert!(image_codec::encode_content(&a.pin, &image).is_err());
        content_roundtrip(&image, &history);
        if applied {
            image.entries.values_mut().next().expect("entry").last = Some([207; 32]);
            assert!(image_codec::encode_content(&history, &image).is_err());
        }
    }
}

#[test]
fn import_refuses_target_key_shared_with_inherited_device_before_acknowledgement() {
    for (pq, classic) in [(96, 97), (96, 98), (98, 97)] {
        let mut c = case();
        let source = c.store.handoff_source_state().expect("original snapshot");
        let device = c.peer.responder.inventory_inputs().expect("device").1;
        let signer =
            AnchorSigningKey::deterministic([pq; 32], [classic; 32]).expect("explicit test key");
        let target = AnchorPin::new(
            AnchorIdentity::generate().expect("new instance"),
            signer.public_key().expect("target key"),
        );
        assert!(device.key.shares_component(target.public_key()));
        let plan = AnchorHandoffPlan::from_trusted_state(
            [208; 32],
            &source,
            target.clone(),
            Validity::new(140, 160).expect("interval"),
            [209; 32],
        )
        .expect("distinct from source signer");
        let approval = AnchorHandoffTargetApproval::from_trusted_state(
            &plan,
            &c.pin,
            &target,
            Validity::new(145, 155).expect("interval"),
            [210; 32],
        )
        .expect("approval");
        let freeze = c.store.freeze_handoff(&plan, 150).expect("source frozen");
        let path = c.server.join("shared-target.redb");
        let result = AnchorHandoffTarget::provision_import(
            &path,
            JournalKey::provision(&c.server.join("shared-target-key")).expect("wrapping"),
            &signer,
            approval.clone(),
            source.as_bytes(),
            freeze.as_bytes(),
            150,
        );
        assert!(
            matches!(result, Err(DurableError::Protocol(Error::Scope))),
            "shared witness/device component was admitted: {:?}",
            result.as_ref().map(|_| "imported")
        );
        assert!(!path.exists(), "no target publication or acknowledgement");
        // A foreign implementation can sign bytes even though the official
        // target rejected import. The source must independently enforce this
        // known key-separation condition before irreversible retirement.
        let mut body = b"QPAHIA01".to_vec();
        body.extend_from_slice(&approval.to_bytes());
        body.extend_from_slice(&digest(
            b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-FREEZE/v1",
            freeze.as_bytes(),
        ));
        let foreign_ack = envelope(
            &body,
            &signer
                .sign(Purpose::AnchorHandoffImport, &body)
                .expect("valid foreign target signature"),
        )
        .expect("foreign acknowledgement");
        approval
            .verify_import_receipt(freeze.as_bytes(), &foreign_ack)
            .expect("signature and all bindings valid");
        let mut clock_called = false;
        let result = c.store.retire_handoff(&approval, &foreign_ack, || {
            clock_called = true;
            Ok(150)
        });
        assert!(
            matches!(result, Err(DurableError::Protocol(Error::Scope))),
            "source trusted inadmissible target: {:?}",
            result.as_ref().map(|r| r.state())
        );
        assert!(
            !clock_called,
            "known key collision must fail before signing/admission"
        );
        assert_eq!(
            c.store
                .observe_handoff(&plan)
                .expect("cancellable source")
                .state(),
            AnchorHandoffState::Frozen
        );
        // Original QPAHI001 writer fixture: a previous version could retain
        // this validly authenticated but inadmissible inactive target. Its
        // observation/cancellation must not be mistaken for fresh admission.
        let legacy_path = c.server.join("legacy-shared-target.redb");
        let key_path = c.server.join("shared-target-key");
        let key = JournalKey::open(&key_path).expect("same target wrapping");
        let mut bytes = b"QPAHI001".to_vec();
        for value in [
            approval.to_bytes().as_slice(),
            source.as_bytes(),
            freeze.as_bytes(),
            foreign_ack.as_slice(),
        ] {
            bytes.extend_from_slice(
                &u32::try_from(value.len())
                    .expect("bounded field")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(value);
        }
        bytes.push(0);
        let mut mac = authenticator(&key).expect("old writer authenticator");
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        let db = provision_private_database(&legacy_path, |db| {
            let tx = transaction(db)?;
            tx.open_table(TableDefinition::<&str, &[u8]>::new(
                "continuity_anchor_handoff_import_v1",
            ))
            .map_err(storage)?
            .insert("image", bytes.as_slice())
            .map_err(storage)?;
            tx.commit().map_err(DurableError::CommitUncertain)?;
            Ok::<_, DurableError>(())
        })
        .expect("actual old-format durable image");
        drop(db);
        let mut legacy = AnchorHandoffTarget::open(&legacy_path, key, approval.clone())
            .expect("old inactive import remains observable");
        assert_eq!(
            legacy.status().expect("inactive"),
            AnchorHandoffTargetState::ImportedInactive
        );
        assert_eq!(
            legacy
                .import_receipt()
                .expect("exact retained acknowledgement")
                .as_bytes(),
            foreign_ack
        );
        assert_eq!(
            legacy.retained_source_state().expect("exact source"),
            source.as_bytes()
        );
        let cancelled = c
            .store
            .cancel_handoff(&plan)
            .expect("no irreversible source retirement");
        legacy
            .close_cancelled(cancelled.as_bytes())
            .expect("original source can close old import");
        legacy.close();
        let mut legacy = AnchorHandoffTarget::open(
            &legacy_path,
            JournalKey::open(&key_path).expect("original wrapping"),
            approval,
        )
        .expect("closed old import reopens");
        assert_eq!(
            legacy.status().expect("durable cancellation"),
            AnchorHandoffTargetState::Cancelled
        );
        assert_eq!(
            legacy
                .cancellation_receipt()
                .expect("original cancellation"),
            cancelled.as_bytes()
        );
        assert_eq!(
            legacy
                .retained_source_state()
                .expect("source retained after cancellation"),
            source.as_bytes()
        );
    }
}
