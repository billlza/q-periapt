// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture_with_credential_lifetimes, durable::tests::grant, BootstrapRole,
    RetainedInstallationAuthority, RootSigningKey, Validity,
};

fn another_handshake(p: &mut Pair) -> (InitiationId, Vec<u8>, [u8; 32]) {
    let request = InitiationId::generate().expect("independent operation");
    let initial =
        p.ji.initiate(Arc::clone(&p.f.initiator), request, &p.f.signer_i, 150)
            .expect("initial");
    let (pq, classical) = p.f.sources();
    let reply =
        p.jr.respond(
            Arc::clone(&p.f.responder),
            &initial,
            &p.f.signer_r,
            pq,
            classical,
            150,
        )
        .expect("reply");
    let complete =
        p.ji.accept_reply(Arc::clone(&p.f.initiator), request, &reply, 150)
            .expect("final");
    let session = complete.session_id();
    p.jr.finish(
        Arc::clone(&p.f.responder),
        &initial,
        complete.final_message(),
        150,
    )
    .expect("confirmation");
    (request, initial, session)
}

#[test]
fn retained_view_cannot_activate_unfinished_or_replay_another_established_session() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let long = crate::tests::interval();
        let short = Validity::new(100, 160).expect("peer interval");
        let intervals = if role == BootstrapRole::Initiator {
            [long, short]
        } else {
            [short, long]
        };
        let mut p = Pair::with_fixture(fixture_with_credential_lifetimes(
            PrekeyQuality::ReusableBoth,
            intervals,
        ));
        p.activate();
        let (other_request, other_initial, other_session) = another_handshake(&mut p);
        p.ji.activate_initiator_messages(Arc::clone(&p.f.initiator), other_request, 150)
            .expect("second established");
        p.jr.activate_responder_messages(Arc::clone(&p.f.responder), &other_initial, 150)
            .expect("second established");
        let (pending_request, pending_initial, pending_session) = another_handshake(&mut p);
        let peer_role = if role == BootstrapRole::Initiator {
            BootstrapRole::Responder
        } else {
            BootstrapRole::Initiator
        };
        let seed = if peer_role == BootstrapRole::Initiator {
            90
        } else {
            94
        };
        let root = RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("account root");
        let original = p.f.initiator.device(peer_role);
        let certificate = root
            .issue_device(original.description.clone(), original.key.clone())
            .expect("original body");
        let proof = grant(
            &root,
            &certificate,
            original,
            190,
            2,
            [79; 32],
            p.f.initiator
                .current_policy()
                .expect("fixture policy owner")
                .checkpoint()
                .digest(),
        );
        let journal = if role == BootstrapRole::Initiator {
            &mut p.ji
        } else {
            &mut p.jr
        };
        let authority = RetainedInstallationAuthority::active_installation(
            p.f.initiator.device(role),
            p.f.initiator
                .current_policy()
                .expect("fixture policy owner"),
        );
        journal
            .install_peer_credential_renewal(
                &crate::installation::PolicyScope {
                    authority: &authority,
                    original_policy: p.f.initiator.original_policy(),
                    original_device: p.f.initiator.device(role),
                },
                &proof,
                proof.operation(),
                p.f.initiator
                    .current_policy()
                    .expect("fixture policy owner"),
                150,
            )
            .expect("owning transaction");
        assert!(journal
            .prepare_reopened_context(Arc::clone(&p.f.initiator), pending_session, role, 170)
            .is_err());
        let view = journal
            .prepare_reopened_context(Arc::clone(&p.f.initiator), p.session, role, 170)
            .expect("exact established view");
        assert_eq!(view.digest(), p.f.initiator.digest());
        let before = journal.image().expect("before refusal");
        for now in [150, 170] {
            match role {
                BootstrapRole::Initiator => {
                    assert_eq!(
                        journal
                            .activate_initiator_messages(Arc::clone(&view), p.request, now)
                            .expect("exact replay"),
                        p.session
                    );
                    assert!(journal
                        .activate_initiator_messages(Arc::clone(&view), pending_request, now)
                        .is_err());
                    assert!(journal
                        .activate_initiator_messages(Arc::clone(&view), other_request, now)
                        .is_err());
                }
                BootstrapRole::Responder => {
                    assert_eq!(
                        journal
                            .activate_responder_messages(Arc::clone(&view), &p.initial, now)
                            .expect("exact replay"),
                        p.session
                    );
                    assert!(journal
                        .activate_responder_messages(Arc::clone(&view), &pending_initial, now)
                        .is_err());
                    assert!(journal
                        .activate_responder_messages(Arc::clone(&view), &other_initial, now)
                        .is_err());
                }
            }
            assert!(journal.next_message_id(&view, other_session, now).is_err());
            assert!(journal
                .initiate(
                    Arc::clone(&view),
                    InitiationId::generate().expect("new operation"),
                    &p.f.signer_i,
                    now
                )
                .is_err());
        }
        assert!(journal
            .archive_session_closure(&view, other_session)
            .is_err());
        assert!(journal.begin_session_closure(&view, other_session).is_err());
        let after = journal.image().expect("after refusal");
        assert_eq!(
            (after.revision, after.digest),
            (before.revision, before.digest)
        );
        assert!(!after.records.contains_key(&record_id(&pending_session)));
        let pending_op = if role == BootstrapRole::Initiator {
            initiator::operation_id(pending_request)
        } else {
            super::super::super::operation_id(&view.digest(), &pending_initial)
        };
        let expected = if role == BootstrapRole::Initiator {
            DurableStatus::FinalCommitted
        } else {
            DurableStatus::Complete
        };
        assert_eq!(
            after
                .records
                .get(&pending_op)
                .expect("unchanged source")
                .phase,
            expected
        );
        // Individual control uses the original context/session and signing key.
        let signer = if role == BootstrapRole::Initiator {
            &p.f.signer_i
        } else {
            &p.f.signer_r
        };
        journal
            .advance_rekey_control(&view, p.session, 1, signer, 170)
            .expect("current grant admits original control");
        let other_journal = if role == BootstrapRole::Initiator {
            &mut p.jr
        } else {
            &mut p.ji
        };
        assert!(other_journal
            .next_message_id(&view, p.session, 170)
            .is_err());
    }
}
