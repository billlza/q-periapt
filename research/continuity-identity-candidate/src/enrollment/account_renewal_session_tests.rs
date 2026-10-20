// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Both original enrolled devices resume the same encrypted session after expiry.
use super::*;
use crate::{
    BootstrapBundle, BootstrapMaterials, BootstrapRequirements, BootstrapRole,
    DirectoryExpectation, ExpectedDevice, InitiationId, ManifestContext, PrekeyLeaf,
    RekeyControlStep,
};
use q_periapt_sdk::expert::{PqKeySource, TraditionalKeySource};
use std::collections::VecDeque;

fn original_owner(
    c: &AccountCase,
    paths: &EnrollmentPaths,
    intent: &EnrollmentIntent,
) -> EnrolledDevice {
    let mut owner =
        DeviceEnrollment::open(paths.clone(), intent.clone()).expect("original enrollment");
    let anchor = if c.witnessed {
        Some(
            owner
                .anchor_client(
                    &c.f.c.policy,
                    150,
                    c.f.pin.clone(),
                    Box::new(c.f.carrier.clone()),
                    Duration::from_secs(3),
                )
                .expect("original witness client"),
        )
    } else {
        None
    };
    owner
        .activate(&c.f.c.policy, 150, anchor)
        .expect("original operational owner")
}

pub(super) fn renew(
    c: &AccountCase,
    index: usize,
    paths: &EnrollmentPaths,
    intent: &EnrollmentIntent,
) -> EnrolledDevice {
    let grant = c.grants.get(index).expect("original owning role");
    let companions = c
        .grants
        .iter()
        .enumerate()
        .filter_map(|(i, g)| (i != index).then_some(g))
        .collect::<Vec<_>>();
    let mut owner =
        DeviceEnrollment::open(paths.clone(), intent.clone()).expect("same original enrollment");
    owner
        .stage_account_credential_renewal(grant, &companions, grant.operation(), &c.f.c.policy, 170)
        .expect("complete retained account intent");
    if c.witnessed {
        c.f.carrier.clock.store(170, Ordering::SeqCst);
        let anchor = client(&c.f, &mut owner, 170);
        let proposal = owner
            .prepare_witnessed_credential_renewal(&c.f.c.policy, 170, anchor)
            .expect("exact account target");
        c.f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_credential_renewal(proposal, grant, &c.f.c.policy, 170)
            .expect("independent witness approval");
        let mut anchor = client(&c.f, &mut owner, 170);
        owner
            .commit_witnessed_credential_renewal(
                grant.operation(),
                grant.statement_digest(),
                &c.f.c.policy,
                170,
                &mut anchor,
            )
            .expect("original account commit");
    }
    let anchor = if c.witnessed {
        Some(client(&c.f, &mut owner, 170))
    } else {
        None
    };
    owner
        .activate(&c.f.c.policy, 170, anchor)
        .expect("renewed original owner")
}

#[test]
fn both_same_account_installations_keep_original_session_messages_and_rekey_after_expiry() {
    for witnessed in [false, true] {
        let c = AccountCase::new(witnessed);
        let peer = &c.peers[0];
        let key_paths = [
            &c.f.c.paths.signer,
            &c.f.c.paths.wrapping,
            &peer.paths.signer,
            &peer.paths.wrapping,
        ];
        let keys = key_paths
            .iter()
            .map(|path| fs::read(path).expect("original protected file"))
            .collect::<Vec<_>>();
        let (_, issued, pin, _) = crate::tests::session_policy_fixture_with_anchor(
            &[PrekeyQuality::OneTimeBoth],
            c.f.c.policy.anchor_requirement(),
        );
        assert_eq!(issued.checkpoint(), c.f.c.policy.checkpoint());
        let policy = Arc::new(
            pin.verify(issued.as_bytes(), Arc::clone(&c.f.c.policy.runtime), 150)
                .expect("same actual policy and runtime"),
        );
        let mut local = original_owner(&c, &c.f.c.paths, &c.f.c.intent);
        let mut remote = original_owner(&c, &peer.paths, &peer.intent);
        let account = AccountPin::new(
            c.f.original.account_id(),
            c.f.c.intent.root.clone(),
            c.f.original.roster().checkpoint(),
            policy.family(),
        )
        .expect("independent original account pin");
        let requirements = || BootstrapRequirements {
            initiator: ExpectedDevice::new(
                &account,
                peer.device.device_id(),
                peer.device.generation(),
            )
            .expect("original initiator"),
            responder: ExpectedDevice::new(
                &account,
                c.f.original.device_id(),
                c.f.original.generation(),
            )
            .expect("original responder"),
            quality: PrekeyQuality::OneTimeBoth,
            directory: DirectoryExpectation::from_trusted_state([99; 32]).expect("directory pin"),
        };
        let reusable = policy.runtime.generate_key().expect("actual reusable key");
        let once = policy.runtime.generate_key().expect("actual one-time key");
        let reusable_public = reusable.public_key().expect("public").to_bytes();
        let once_public = once.public_key().expect("public").to_bytes();
        let (pq, classical) = reusable_public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let (pq_once, classical_once) = once_public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let validity = Validity::new(100, 155).expect("original advertisement");
        let leaves = [
            (LeafKind::SignedClassical, classical),
            (LeafKind::OneTimeClassical, classical_once),
            (LeafKind::LastResortPq, pq),
            (LeafKind::OneTimePq, pq_once),
        ]
        .map(|(kind, bytes)| PrekeyLeaf::new(kind, bytes, validity).expect("leaf"));
        let (_, signer, device) = local.parts().expect("local signer");
        let manifest = signer
            .issue_manifest(
                device,
                ManifestContext::new(
                    1,
                    policy.runtime.trusted_state().digest(),
                    crate::bootstrap_suite_digest(),
                    [99; 32],
                    validity,
                )
                .expect("manifest context"),
                &leaves,
            )
            .expect("signed manifest");
        let verified = device
            .verify_manifest(manifest.as_bytes(), 150)
            .expect("manifest");
        let proofs = (0..manifest.leaf_count())
            .map(|i| {
                let proof = manifest.proof(i).expect("proof");
                (
                    verified
                        .verify_leaf(&proof, 150)
                        .expect("verified proof")
                        .kind(),
                    proof.encode().expect("proof bytes"),
                )
            })
            .collect::<Vec<_>>();
        let proof = |kind| {
            proofs
                .iter()
                .find(|(k, _)| *k == kind)
                .expect("required proof")
                .1
                .as_slice()
        };
        let bundle = BootstrapBundle::from_materials(
            PrekeyQuality::OneTimeBoth,
            BootstrapMaterials {
                initiator_credential: &c.certificates[1],
                initiator_roster: peer.device.roster().as_bytes(),
                responder_credential: &c.certificates[0],
                responder_roster: c.f.original.roster().as_bytes(),
                responder_manifest: manifest.as_bytes(),
                signed_classical: proof(LeafKind::SignedClassical),
                last_resort_pq: proof(LeafKind::LastResortPq),
                one_time_classical: Some(proof(LeafKind::OneTimeClassical)),
                one_time_pq: Some(proof(LeafKind::OneTimePq)),
            },
        )
        .expect("original signed bundle");
        let context = Arc::new(
            bundle
                .verify(Arc::clone(&policy), requirements(), 150)
                .expect("same-account bundle"),
        );
        let request = InitiationId::generate().expect("original handshake operation");
        let (remote_service, remote_signer, _) = remote.parts().expect("remote original owners");
        let (remote_journal, remote_archives) =
            remote_service.stores().expect("remote original stores");
        let initial = remote_journal
            .initiate(Arc::clone(&context), request, remote_signer, 150)
            .expect("initial");
        let (local_service, local_signer, _) = local.parts().expect("local original owners");
        let (local_journal, local_archives) =
            local_service.stores().expect("local original stores");
        let reply = local_journal
            .respond(
                Arc::clone(&context),
                &initial,
                local_signer,
                PqKeySource::from_key(&once),
                TraditionalKeySource::from_key(&once),
                150,
            )
            .expect("response");
        let final_flight = remote_journal
            .accept_reply(Arc::clone(&context), request, &reply, 150)
            .expect("final");
        let session = final_flight.session_id();
        local_journal
            .finish(
                Arc::clone(&context),
                &initial,
                final_flight.final_message(),
                150,
            )
            .expect("finish");
        remote_journal
            .activate_initiator_messages(Arc::clone(&context), request, 150)
            .expect("remote messages");
        local_journal
            .activate_responder_messages(Arc::clone(&context), &initial, 150)
            .expect("local messages");
        for (journal, archives) in [
            (local_journal, local_archives),
            (remote_journal, remote_archives),
        ] {
            let archive = journal
                .archive_session_closure(&context, session)
                .expect("original closure");
            archives
                .retain(journal, &context, session, &archive)
                .expect("original archive");
        }
        let (local_service, _, _) = local.parts().expect("local stores");
        let journal = local_service.stores().expect("journal").0;
        let identity = journal
            .next_message_id(&context, session, 150)
            .expect("original message");
        let ciphertext = journal
            .send_message(
                &context,
                session,
                identity,
                b"before account renewal",
                b"account",
                150,
            )
            .expect("original retained outbox");
        local.close();
        remote.close();
        // Both original credentials are actually expired at this supplied SDK
        // time. Neither side is kept operational under an earlier test clock.
        assert!(matches!(
            c.f.original.description.validity.check(170),
            Err(Error::Validity)
        ));
        assert!(matches!(
            peer.device.description.validity.check(170),
            Err(Error::Validity)
        ));
        assert!(
            DeviceEnrollment::open(c.f.c.paths.clone(), c.f.c.intent.clone())
                .expect("original")
                .activate(&policy, 170, None)
                .is_err()
        );
        assert!(
            DeviceEnrollment::open(peer.paths.clone(), peer.intent.clone())
                .expect("peer original")
                .activate(&policy, 170, None)
                .is_err()
        );
        let mut local = renew(&c, 0, &c.f.c.paths, &c.f.c.intent);
        let mut remote = renew(&c, 1, &peer.paths, &peer.intent);
        let (local_service, local_signer, _) = local.parts().expect("renewed local owners");
        let (remote_service, remote_signer, _) = remote.parts().expect("renewed remote owners");
        let local_view = local_service
            .reopen_peer_bundle(
                &bundle,
                Arc::clone(&policy),
                requirements(),
                BootstrapRole::Responder,
                session,
                170,
            )
            .expect("local original session");
        let remote_view = remote_service
            .reopen_peer_bundle(
                &bundle,
                Arc::clone(&policy),
                requirements(),
                BootstrapRole::Initiator,
                session,
                170,
            )
            .expect("remote original session");
        assert_eq!(local_view.context().digest(), context.digest());
        assert_eq!(remote_view.context().digest(), context.digest());
        let a = local_service.stores().expect("local journal").0;
        let b = remote_service.stores().expect("remote journal").0;
        assert_eq!(a.identity().expect("original id"), c.f.id);
        assert_eq!(b.identity().expect("peer original id"), peer.id);
        assert_eq!(
            a.resume_message(local_view.context(), session, identity, 170)
                .expect("same ciphertext"),
            ciphertext
        );
        assert_eq!(
            b.receive_message(remote_view.context(), session, &ciphertext, b"account", 170)
                .expect("original plaintext")
                .as_bytes(),
            b"before account renewal"
        );
        b.consume_message(remote_view.context(), session, identity, 170)
            .expect("consume original");
        let ack = b
            .message_acknowledgement(remote_view.context(), session, 170)
            .expect("original ACK");
        a.accept_message_acknowledgement(local_view.context(), session, &ack, 170)
            .expect("accept ACK");
        let mut queue = VecDeque::new();
        if let RekeyControlStep::Output(wire) = a
            .advance_rekey_control(local_view.context(), session, 1, local_signer, 170)
            .expect("start rekey")
        {
            queue.push_back((true, wire.as_bytes().to_vec()));
        }
        let mut steps = 0;
        while let Some((to_remote, wire)) = queue.pop_front() {
            steps += 1;
            assert!(steps <= 16, "bounded actual control exchange");
            let step = if to_remote {
                b.receive_rekey_control(remote_view.context(), session, &wire, remote_signer, 170)
            } else {
                a.receive_rekey_control(local_view.context(), session, &wire, local_signer, 170)
            }
            .expect("rekey control");
            if let RekeyControlStep::Output(wire) = step {
                queue.push_back((!to_remote, wire.as_bytes().to_vec()));
            }
        }
        assert!(matches!(
            a.advance_rekey_control(local_view.context(), session, 1, local_signer, 170)
                .expect("local epoch"),
            RekeyControlStep::LocallyConfirmed(1)
        ));
        assert!(matches!(
            b.advance_rekey_control(remote_view.context(), session, 1, remote_signer, 170)
                .expect("peer epoch"),
            RekeyControlStep::LocallyConfirmed(1)
        ));
        let id = a
            .next_message_id(local_view.context(), session, 170)
            .expect("renewed local id");
        let wire = a
            .send_message(
                local_view.context(),
                session,
                id,
                b"after joint renewal and rekey",
                b"account",
                170,
            )
            .expect("new ciphertext");
        assert_eq!(
            b.receive_message(remote_view.context(), session, &wire, b"account", 170)
                .expect("new plaintext")
                .as_bytes(),
            b"after joint renewal and rekey"
        );
        let id = b
            .next_message_id(remote_view.context(), session, 170)
            .expect("renewed peer id");
        let wire = b
            .send_message(
                remote_view.context(),
                session,
                id,
                b"renewed peer response",
                b"account",
                170,
            )
            .expect("reverse ciphertext");
        assert_eq!(
            a.receive_message(local_view.context(), session, &wire, b"account", 170)
                .expect("reverse plaintext")
                .as_bytes(),
            b"renewed peer response"
        );
        local.close();
        remote.close();
        for (path, before) in key_paths.into_iter().zip(keys) {
            assert_eq!(fs::read(path).expect("original protected file"), before);
        }
        eprintln!("SAME_ACCOUNT_RENEWAL witnessed={witnessed} original_session=true original_ciphertext=true both_expired=true both_enrollments=true rekey_epoch=1");
    }
}
