// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generic cleanup intent versus independently authorized renewal after expiry.
use super::*;
use crate::enrollment::tests::policy_continuation::{joint, policy, scope};
use crate::{BootstrapContext, CredentialRenewalId, InitiationId};

pub(super) fn session(f: Fixture) -> (Fixture, [u8; 32]) {
    use super::policy_transaction::sessions::{bundle, endpoint, requirements};
    let peer = fixture_on_witness(
        Arc::clone(&f._witness_dir),
        f.pin.clone(),
        f.carrier.clone(),
        Some(f.c.policy.validity().until()),
    );
    let mut a = endpoint(f);
    let mut b = endpoint(peer);
    let bundle = bundle(&a, &mut b);
    let context = |f: &Fixture| -> Arc<BootstrapContext> {
        Arc::new(
            bundle
                .verify(
                    Arc::new(policy(&f.c, 1, f.c.policy.validity().until(), 150)),
                    requirements(&a, &b),
                    150,
                )
                .expect("original context"),
        )
    };
    let ci = context(&a.f);
    let cr = context(&b.f);
    let initiation = InitiationId::generate().expect("original initiation");
    let (service, signer, _) = a.owner.parts().expect("sender");
    let (peer, peer_signer, _) = b.owner.parts().expect("recipient");
    let (sender, archives) = service.stores().expect("sender stores");
    let receiver = peer.stores().expect("recipient stores").0;
    let initial = sender
        .initiate(Arc::clone(&ci), initiation, signer, 150)
        .expect("initial");
    let reply = receiver
        .respond_from_inventory(Arc::clone(&cr), &initial, peer_signer, 150)
        .expect("reply");
    let done = sender
        .accept_reply(Arc::clone(&ci), initiation, &reply, 150)
        .expect("final");
    let session = done.session_id();
    receiver
        .finish(cr, &initial, done.final_message(), 150)
        .expect("confirmed");
    sender
        .activate_initiator_messages(Arc::clone(&ci), initiation, 150)
        .expect("original message state");
    let archive = sender
        .archive_session_closure(&ci, session)
        .expect("original archive");
    archives
        .retain(sender, &ci, session, &archive)
        .expect("retained original archive");
    let message = sender.next_message_id(&ci, session, 150).expect("ID");
    sender
        .send_message(&ci, session, message, b"unconfirmed original", b"", 150)
        .expect("real pending delivery");
    a.owner.close();
    b.owner.close();
    (a.f, session)
}

fn request(
    f: &Fixture,
    id: CredentialRenewalId,
) -> Result<crate::CredentialRenewalRequest, DurableError> {
    let mut owner = open(&f.c);
    let anchor = owner.credential_renewal_request_anchor_client(
        f.c.policy.historical(),
        f.pin.clone(),
        Box::new(f.carrier.clone()),
        Duration::from_secs(3),
    )?;
    owner.witnessed_credential_renewal_request(id, f.c.policy.historical(), anchor)
}

#[test]
fn expired_cleanup_intent_distinguishes_applied_reply_loss_from_blocked_renewal() {
    for policy_expired in [false, true] {
        for applied in [false, true] {
            let (f, session) = session(fixture_with_policy_expiry(Some(if policy_expired {
                160
            } else {
                200
            })));
            let mut cleanup = open(&f.c)
                .recover_session(
                    session,
                    f.c.policy.historical(),
                    Some((
                        f.pin.clone(),
                        Box::new(f.carrier.clone()),
                        Duration::from_secs(3),
                    )),
                )
                .expect("original restricted owner");
            // Actual ordinary Advance (opcode 2), cut before or after the store.
            *f.carrier.cut.lock().expect("cut") = Some((2, applied));
            assert!(matches!(
                cleanup.session().expect("session").begin(),
                Err(DurableError::Anchor(_))
            ));
            assert!(f.carrier.cut.lock().expect("cut consumed").is_none());
            cleanup.close();
            let before = disk(&f);
            assert_eq!(
                before.1.as_deref().and_then(|p| p.get(..8)),
                Some(b"QPWINT01".as_slice())
            );
            f.carrier.clock.store(170, Ordering::SeqCst);
            let operation = CredentialRenewalId::generate().expect("original renewal ID");
            if applied {
                let snapshot = request(&f, operation)
                    .expect("exact applied cleanup can reconcile after expiry");
                assert_eq!(snapshot.journal(), f.id);
                assert_eq!(
                    snapshot.previous_device().credential_digest(),
                    f.original.credential_digest()
                );
                let after = disk(&f);
                assert!(after.1.is_none());
                assert_ne!(after.0, before.0);
                assert_eq!(
                    request(&f, operation).expect("same request").operation(),
                    operation
                );
                assert_eq!(disk(&f), after);
            } else {
                for _ in 0..2 {
                    assert!(matches!(
                        request(&f, operation),
                        Err(DurableError::Anchor(_))
                    ));
                    assert_eq!(
                        disk(&f),
                        before,
                        "failed renewal must retain the exact generic intent"
                    );
                }
                // Even an already available independent G/T grant cannot replace
                // an unrelated pending cleanup intent with its own sealed target.
                let grant = grant(&f, &f.original, 2, 190);
                let target = policy(&f.c, 2, 220, 170);
                let continuation = joint(
                    &f.c,
                    &grant,
                    &scope(&f.c, &grant, f.id),
                    &f.c.policy,
                    &target,
                );
                let mut owner = open(&f.c);
                owner
                    .stage_policy_continuation(
                        &grant,
                        &continuation,
                        grant.operation(),
                        &target,
                        170,
                    )
                    .expect("independent approval may be staged");
                let anchor = client(&f, &mut owner, 170);
                f.carrier.requests.lock().expect("requests").clear();
                assert!(matches!(
                    owner.prepare_witnessed_policy_continuation(
                        f.c.policy.historical(),
                        &target,
                        170,
                        anchor
                    ),
                    Err(DurableError::Conflict)
                ));
                assert!(matches!(owner.status(), Err(DurableError::Closed)));
                assert!(f.carrier.requests.lock().expect("no dispatch").is_empty());
                assert_eq!(disk(&f), before);
            }
            eprintln!("EXPIRED_CLEANUP_RENEWAL policy_expired={policy_expired} applied={applied} request_available={applied} original_intent_preserved={}", !applied);
        }
    }
}

#[test]
fn expired_cleanup_intent_can_be_accounted_only_after_independent_device_retirement() {
    use crate::{retired_device as report, AnchorSubject, RetiredDeviceEnrollment};
    use std::{io::Write, os::unix::fs::DirBuilderExt};
    for applied in [false, true] {
        let (f, session) = session(fixture_with_policy_expiry(Some(160)));
        let mut cleanup = open(&f.c)
            .recover_session(
                session,
                f.c.policy.historical(),
                Some((
                    f.pin.clone(),
                    Box::new(f.carrier.clone()),
                    Duration::from_secs(3),
                )),
            )
            .expect("original restricted cleanup");
        *f.carrier.cut.lock().expect("cut") = Some((2, applied));
        assert!(matches!(
            cleanup.session().expect("session").begin(),
            Err(DurableError::Anchor(_))
        ));
        assert!(f.carrier.cut.lock().expect("cut consumed").is_none());
        cleanup.close();
        f.carrier.clock.store(170, Ordering::SeqCst);
        let before = disk(&f);
        assert!(before.1.is_some());
        if !applied {
            assert!(matches!(
                request(&f, CredentialRenewalId::generate().expect("ID")),
                Err(DurableError::Anchor(_))
            ));
            assert_eq!(disk(&f), before);
        }

        // A separately approved fresh generation is not renewal of the stuck
        // owner. Existing purpose-specific retirement permanently fences it.
        let target = policy(&f.c, 2, 220, 170);
        let signer = DeviceSigningKey::generate().expect("fresh replacement identity");
        let mut description = f.original.description.clone();
        description.generation += 1;
        description.validity = Validity::new(100, 210).expect("new validity");
        let certificate =
            f.c.root
                .issue_device(description, signer.public_key().expect("public key"))
                .expect("independently approved replacement credential");
        let roster =
            f.c.root
                .issue_roster(
                    2,
                    Validity::new(100, 220).expect("new roster validity"),
                    &[f.c
                        .root
                        .roster_entry(&certificate)
                        .expect("replacement member")],
                )
                .expect("independent replacement roster");
        let next = AccountPin::new(
            f.original.account_id(),
            f.c.root.public_key().expect("root"),
            roster.checkpoint(),
            target.family(),
        )
        .expect("independent target pin")
        .verify_device(&certificate, roster.as_bytes(), 170)
        .expect("current replacement");
        let root = f.c.paths.wrapping.parent().expect("private test root");
        let path = root.join("replacement");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("new private directory");
        let mut journal = DeviceJournal::provision_anchored(
            &path.join("journal"),
            JournalKey::provision(&path.join("key")).expect("new wrapping key"),
            &next,
            &target,
            JournalIdentity::generate().expect("new journal"),
            170,
        )
        .expect("new genesis");
        let genesis = journal
            .anchor_genesis(&next, &target)
            .expect("original replacement genesis");
        journal.close();
        let subject =
            AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
        let predecessors = [(
            subject,
            f.original.roster().checkpoint(),
            f.c.policy.historical(),
        )];
        let retired = {
            let mut witness = f.carrier.store.lock().expect("independent operator");
            let proposal = witness
                .device_replacement_proposal(&genesis, &next, &target, &predecessors, 170)
                .expect("exact permanent retirement proposal");
            witness
                .replace_device(&proposal, &genesis, &next, &target, &predecessors, 170)
                .expect("independently approved permanent retirement");
            let wire = witness
                .retired_subject_receipt(&proposal, subject)
                .expect("retirement receipt");
            f.pin
                .verify_retired_subject(&proposal, subject, &wire)
                .expect("verified original retirement")
        };
        let mut owner = RetiredDeviceEnrollment::open(
            f.c.paths.clone(),
            f.c.intent.clone(),
            f.pin.clone(),
            retired,
        )
        .expect("original restricted retired owner");
        let cleanup = owner.installation().expect("original installation");
        let inventory = cleanup.proposal().expect("both original images");
        let wire = {
            let mut witness = f.carrier.store.lock().expect("operator");
            witness
                .retain_retired_cleanup(&inventory)
                .expect("independent inventory retention");
            witness
                .retired_cleanup_receipt(&inventory)
                .expect("inventory receipt")
        };
        let retained = cleanup
            .verify_retained(&f.pin, &wire)
            .expect("retained inventory");
        let expectation = cleanup
            .prepare_report(&retained)
            .expect("complete report proposal");
        let wire = {
            let mut witness = f.carrier.store.lock().expect("operator");
            witness
                .retain_retired_report(&expectation)
                .expect("independent report retention");
            witness
                .retired_report_receipt(&expectation)
                .expect("report receipt")
        };
        let report = cleanup
            .report(&retained, &f.pin, &wire)
            .expect("full verified report");
        assert!(matches!(
            report.intent(),
            report::Intent::Write {
                transaction: report::Transaction::Ordinary,
                ..
            }
        ));
        let roles: Vec<_> = report.views().iter().map(|view| view.role).collect();
        assert_eq!(
            roles,
            if applied {
                vec![
                    report::ViewRole::SupersededSource,
                    report::ViewRole::Authoritative,
                ]
            } else {
                vec![
                    report::ViewRole::Authoritative,
                    report::ViewRole::UncommittedTarget,
                ]
            }
        );
        let mut unconfirmed = None;
        for (i, view) in report.views().iter().enumerate() {
            let sessions: Vec<_> = view
                .records
                .iter()
                .filter_map(|record| match &record.metadata {
                    report::RecordMetadata::Session(s) => Some(s),
                    _ => None,
                })
                .collect();
            assert_eq!(sessions.len(), 1);
            let original = sessions.first().expect("original session");
            assert_eq!(original.session, session);
            let (epochs, previous_closure) = match &original.state {
                report::SessionState::Live {
                    epochs,
                    previous_closure,
                } => Ok((epochs, previous_closure)),
                report::SessionState::Terminal { .. } => Err("unexpected terminal state"),
            }
            .expect("original live state");
            assert_eq!(
                previous_closure.is_some(),
                i == 1,
                "only sealed target contains pending closure"
            );
            let messages: Vec<_> = epochs
                .iter()
                .flat_map(|epoch| &epoch.accounting.unconfirmed)
                .cloned()
                .collect();
            assert_eq!(messages.len(), 1, "unknown delivery remains in both images");
            if let Some(original) = &unconfirmed {
                assert_eq!(&messages, original);
            } else {
                unconfirmed = Some(messages);
            }
        }
        assert_eq!(
            disk(&f),
            before,
            "reporting never applies the refused ordinary write"
        );
        let host_path = root.join("retired-cleanup-host-report.bin");
        let mut file = fs::File::create_new(&host_path).expect("host record");
        file.write_all(report.as_bytes()).expect("complete report");
        file.sync_all().expect("host file sync");
        fs::File::open(root)
            .expect("parent")
            .sync_all()
            .expect("host name sync");
        assert_eq!(
            fs::read(host_path).expect("durable readback"),
            report.as_bytes()
        );
        let verified = f
            .pin
            .verify_retired_report(&retained, &expectation, &wire)
            .expect("retention proof");
        cleanup
            .prepare_host_acknowledgement(report.as_bytes(), &verified)
            .expect("explicit host accounting");
        let ack = {
            let mut witness = f.carrier.store.lock().expect("operator");
            witness
                .acknowledge_retired_report(&expectation)
                .expect("independent report ACK");
            witness
                .retired_report_acknowledgement_receipt(&expectation)
                .expect("purpose21 ACK")
        };
        assert_eq!(disk(&f), before);
        cleanup
            .erase_journal(&f.pin, &ack)
            .expect("exact acknowledged journal erasure");
        owner
            .prepare_signer_erasure(&ack)
            .expect("exact acknowledged signer plan");
        owner
            .erase_signer()
            .expect("separate explicit signer erasure");
        assert!(DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err());
        eprintln!("EXPIRED_CLEANUP_RETIREMENT applied={applied} views=2 unknown_messages_per_view=1 host_accounted=true journal_erased=true signer_erased=true");
    }
}

#[path = "witness_pending_write_recovery_tests.rs"]
pub(super) mod pending_write_recovery;
