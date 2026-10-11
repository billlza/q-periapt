// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual original traffic plus sealed journal intents, independently retired by the witness.
use super::*;
use crate::retired_device::{Intent, RecordMetadata, SessionState, ViewRole};

#[test]
fn account_root_cleanup_reports_real_unconfirmed_traffic_and_exact_pending_views() {
    for stage in 0..3 {
        let mut c = case();
        let (mut peer, session) = c.connected_peer();
        let message = c
            .journal
            .next_message_id(&c.f.responder, session, 150)
            .expect("original ID");
        let wire = c
            .journal
            .send_message(
                &c.f.responder,
                session,
                message,
                b"received but not acknowledged to sender",
                b"root-cleanup",
                150,
            )
            .expect("actual send");
        peer.receive_message(&c.f.initiator, session, &wire, b"root-cleanup", 150)
            .expect("actual receive");
        let mut archives =
            crate::SessionArchiveStore::provision(&c.path.join("archives"), c.identity)
                .expect("original archive index");
        let archive = c
            .journal
            .archive_session_closure(&c.f.responder, session)
            .expect("original verified context archive");
        archives
            .retain(&c.journal, &c.f.responder, session, &archive)
            .expect("original archive before retirement");
        // Retain a genuine authenticated ordinary write at each transaction cut.
        // The test controls this metadata-only write; it does not claim a network crash.
        let mut image = c.journal.image().expect("actual image");
        let expected = image
            .protection
            .head(image.revision, image.digest)
            .expect("original head");
        image.revision += 1;
        let active = c.journal.active.as_ref().expect("owner");
        let target = seal(&active.key, &image).expect("sealed target");
        let pending = PendingWrite::new(active, &image, &target).expect("authenticated intent");
        reserve(active, &pending).expect("persist original intent");
        if stage > 0 {
            let reply = c
                .client(false)
                .exchange(
                    c.genesis.subject(),
                    crate::AnchorOperation::advance(expected, pending.next_digest)
                        .expect("same advance"),
                )
                .expect("real witness commit");
            assert_eq!(reply.observed_head().digest(), pending.next_digest);
        }
        if stage == 2 {
            apply(&c.journal.active.as_ref().expect("owner").db, &pending)
                .expect("actual local apply");
        }
        let original = rows(&c.journal.active.as_ref().expect("owner").db);
        let proposal = c.proposal(239);
        let mut owner = c
            .journal
            .begin_account_root_replacement(c.pin.clone(), proposal.clone())
            .expect("local fence");
        let receipt = c.receipt(&proposal);
        owner
            .retain_witness_retirement(&receipt)
            .expect("original historical decision");
        let retired = owner
            .retirement()
            .expect("purpose 22")
            .retired_subject(c.genesis.subject())
            .expect("original subject");
        owner.close();
        c.assert_ordinary_refused();
        let path = c.path.join("state.redb");
        let inventory =
            DeviceJournal::retired_cleanup_proposal(&path, c.key(), c.identity, retired)
                .expect("root-bound original inventory");
        assert_eq!(inventory.pending_intent_digest().is_some(), stage != 2);
        let retained = {
            let mut witness = c.witness.lock().expect("controller");
            witness
                .retain_retired_cleanup(&inventory)
                .expect("independent original inventory");
            c.pin
                .verify_retired_cleanup(
                    retired,
                    &inventory,
                    &witness
                        .retired_cleanup_receipt(&inventory)
                        .expect("signature"),
                )
                .expect("inventory receipt")
        };
        let report = DeviceJournal::retired_report(
            &path,
            &c.key(),
            c.identity,
            retired,
            &retained,
            &mut archives,
        )
        .expect("complete actual metadata");
        assert_eq!(matches!(report.intent(), Intent::Write { .. }), stage != 2);
        assert_eq!(
            report
                .views()
                .iter()
                .map(|view| view.role)
                .collect::<Vec<_>>(),
            match stage {
                0 => vec![ViewRole::Authoritative, ViewRole::UncommittedTarget],
                1 => vec![ViewRole::SupersededSource, ViewRole::Authoritative],
                _ => vec![ViewRole::Authoritative],
            }
        );
        for view in report.views() {
            assert_eq!(view.local_account, c.f.local_device().account_id());
            let metadata = view
                .records
                .iter()
                .find_map(|record| match &record.metadata {
                    RecordMetadata::Session(value) if value.session == session => Some(value),
                    _ => None,
                })
                .expect("same original session");
            let epochs = match &metadata.state {
                SessionState::Live { epochs, .. } => Some(epochs),
                SessionState::Terminal { .. } => None,
            }
            .expect("report cannot invent terminal state");
            assert_eq!(epochs.len(), 1);
            let epoch = epochs.first().expect("original epoch");
            assert_eq!(epoch.accounting.acknowledged_before, 0);
            assert_eq!(epoch.accounting.unconfirmed.len(), 1);
            assert_eq!(
                epoch
                    .accounting
                    .unconfirmed
                    .first()
                    .expect("original unconfirmed message")
                    .message_id(),
                message
            );
        }
        assert_eq!(
            rows(&open_private_database(&path).expect("read original")),
            original,
            "historical accounting cannot apply, acknowledge or discard an intent"
        );
    }
}
