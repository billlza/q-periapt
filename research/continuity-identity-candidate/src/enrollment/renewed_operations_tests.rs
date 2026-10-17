// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    BootstrapBundle, BootstrapMaterials, BootstrapRequirements, BootstrapRole,
    DirectoryExpectation, ExpectedDevice, InitiationId, ManifestContext, PrekeyLeaf, PrekeyStatus,
};

fn requirements<'a>(
    pins: &'a [AccountPin; 2],
    devices: [&VerifiedDevice; 2],
) -> BootstrapRequirements<'a> {
    BootstrapRequirements {
        initiator: ExpectedDevice::new(&pins[0], devices[0].device_id(), devices[0].generation())
            .expect("initiator pin"),
        responder: ExpectedDevice::new(&pins[1], devices[1].device_id(), devices[1].generation())
            .expect("responder pin"),
        quality: PrekeyQuality::OneTimeBoth,
        directory: DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
    }
}
fn bundle(
    policy: &VerifiedSessionPolicy,
    devices: [&VerifiedDevice; 2],
    certificates: [&[u8]; 2],
    signer: &DeviceSigningKey,
    leaves: &[PrekeyLeaf],
    now: u64,
) -> (BootstrapBundle, [AccountPin; 2]) {
    let manifest = signer
        .issue_manifest(
            devices[1],
            ManifestContext::new(
                1,
                policy.runtime.trusted_state().digest(),
                crate::bootstrap_suite_digest(),
                [99; 32],
                Validity::new(155, 179).expect("new advertisement"),
            )
            .expect("manifest scope"),
            leaves,
        )
        .expect("current signing owner");
    let verified = devices[1]
        .verify_manifest(manifest.as_bytes(), now)
        .expect("manifest");
    let proofs: Vec<_> = (0..manifest.leaf_count())
        .map(|index| {
            let proof = manifest.proof(index).expect("proof");
            (
                verified.verify_leaf(&proof, now).expect("leaf").kind(),
                proof.encode().expect("wire"),
            )
        })
        .collect();
    let proof = |kind| {
        proofs
            .iter()
            .find(|(k, _)| *k == kind)
            .expect("required leaf")
            .1
            .as_slice()
    };
    let bundle = BootstrapBundle::from_materials(
        PrekeyQuality::OneTimeBoth,
        BootstrapMaterials {
            initiator_credential: certificates[0],
            initiator_roster: devices[0].roster().as_bytes(),
            responder_credential: certificates[1],
            responder_roster: devices[1].roster().as_bytes(),
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(LeafKind::SignedClassical),
            last_resort_pq: proof(LeafKind::LastResortPq),
            one_time_classical: Some(proof(LeafKind::OneTimeClassical)),
            one_time_pq: Some(proof(LeafKind::OneTimePq)),
        },
    )
    .expect("portable fresh bundle");
    let pins = devices.map(|d| {
        AccountPin::new(
            d.account_id(),
            d.authority_key.clone(),
            d.roster().checkpoint(),
            policy.family(),
        )
        .expect("independent current pin")
    });
    (bundle, pins)
}
fn opposite(role: BootstrapRole) -> BootstrapRole {
    match role {
        BootstrapRole::Initiator => BootstrapRole::Responder,
        BootstrapRole::Responder => BootstrapRole::Initiator,
    }
}

#[test]
fn current_successor_bootstraps_both_roles_in_original_store_and_reopens_under_next_grant() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let (c, _, original, journal_id) = local();
        let first = grant(&c, &original, &original, 2, 180);
        let second = grant(&c, &original, first.successor_device(), 3, 190);
        let old_id = PrekeyId::from_trusted_state([201; 32]).expect("original ID");
        let retired_id = PrekeyId::from_trusted_state([202; 32]).expect("retired ID");
        let mut old = open(&c)
            .activate(&c.policy, 150, None)
            .expect("original owner");
        let (service, _, device) = old.parts().expect("original parts");
        let journal = service.stores().expect("stores").0;
        let old_leaf = journal
            .generate_prekey(
                &c.policy,
                device,
                old_id,
                LeafKind::OneTimePq,
                Validity::new(100, 160).expect("old validity"),
                150,
            )
            .expect("old available leaf");
        journal
            .generate_prekey(
                &c.policy,
                device,
                retired_id,
                LeafKind::OneTimePq,
                Validity::new(100, 160).expect("old validity"),
                150,
            )
            .expect("retirement input");
        service
            .retire_prekey(&c.policy, retired_id)
            .expect("original retirement");
        old.close();
        let mut enrollment = open(&c);
        enrollment
            .stage_credential_renewal(&first, first.operation(), &c.policy, 155)
            .expect("root intent");
        let mut active = enrollment
            .activate(&c.policy, 155, None)
            .expect("same installed owner");
        let Case {
            paths,
            intent,
            root,
            policy,
            _directory,
        } = c;
        let policy = Arc::new(policy);
        let (_, other_issued, other_pin, other_runtime) =
            session_policy_fixture(&[PrekeyQuality::OneTimeBoth, PrekeyQuality::ReusableBoth]);
        let other_policy = other_pin
            .verify(other_issued.as_bytes(), other_runtime, 155)
            .expect("different authenticated policy");
        assert_ne!(
            other_policy.checkpoint().digest(),
            policy.checkpoint().digest()
        );
        let peer_root = RootSigningKey::generate().expect("peer root");
        let peer_signer = DeviceSigningKey::generate().expect("peer signer");
        let peer_cert = peer_root
            .issue_device(
                DeviceDescription::new([8; 16], 1, policy.family(), interval())
                    .expect("description"),
                peer_signer.public_key().expect("key"),
            )
            .expect("credential");
        let peer_roster = peer_root
            .issue_roster(
                1,
                interval(),
                &[peer_root.roster_entry(&peer_cert).expect("member")],
            )
            .expect("peer roster");
        let peer_pin = AccountPin::new(
            peer_root.account_id().expect("account"),
            peer_root.public_key().expect("root"),
            peer_roster.checkpoint(),
            policy.family(),
        )
        .expect("peer pin");
        let peer_device = peer_pin
            .verify_device(&peer_cert, peer_roster.as_bytes(), 150)
            .expect("peer");
        let folder = directory();
        let mut peer_journal = crate::durable::tests::new_store(
            &folder.path().canonicalize().expect("path"),
            &peer_device,
        );
        peer_journal
            .install_roster(original.roster(), 150)
            .expect("exact predecessor");
        let authority = crate::RetainedInstallationAuthority::active_installation(
            &peer_device,
            policy.as_ref(),
        );
        peer_journal
            .install_peer_credential_renewal(
                &crate::installation::PolicyScope {
                    authority: &authority,
                    original_policy: policy.historical(),
                    original_device: &peer_device,
                },
                &first,
                first.operation(),
                &policy,
                155,
            )
            .expect("independent peer grant");
        let (service, signer, current) = active.parts().expect("current owners");
        let journal = service.stores().expect("original stores").0;
        assert_eq!(journal.identity().expect("identity"), journal_id);
        assert!(
            matches!(
                journal.generate_prekey(
                    &other_policy,
                    current,
                    PrekeyId::from_trusted_state([204; 32]).expect("ID"),
                    LeafKind::OneTimePq,
                    Validity::new(155, 179).expect("interval"),
                    155
                ),
                Err(DurableError::Conflict)
            ),
            "same family and SDK binding must not replace exact root-granted policy"
        );

        assert_eq!(
            journal
                .prekey_leaf(&policy, current, old_id, 155)
                .expect("same original key within validity")
                .key_fingerprint(),
            old_leaf.key_fingerprint()
        );
        assert!(
            journal
                .generate_prekey(
                    &policy,
                    &original,
                    PrekeyId::from_trusted_state([203; 32]).expect("ID"),
                    LeafKind::OneTimePq,
                    Validity::new(100, 160).expect("old validity"),
                    155
                )
                .is_err(),
            "cached original credential cannot create after head advanced"
        );
        assert!(
            journal.prekey_leaf(&policy, current, old_id, 170).is_err(),
            "renewal does not extend original prekey validity"
        );
        assert!(matches!(
            journal.generate_prekey(
                &policy,
                current,
                retired_id,
                LeafKind::OneTimePq,
                Validity::new(100, 160).expect("old validity"),
                155
            ),
            Err(DurableError::KeyRetired)
        ));
        let ids =
            [211, 212, 213, 214].map(|b| PrekeyId::from_trusted_state([b; 32]).expect("fresh ID"));
        let mut leaves = Vec::new();
        for (id, kind) in ids.iter().zip([
            LeafKind::SignedClassical,
            LeafKind::OneTimeClassical,
            LeafKind::LastResortPq,
            LeafKind::OneTimePq,
        ]) {
            let (store, device) = if role == BootstrapRole::Responder {
                (&mut *journal, current)
            } else {
                (&mut peer_journal, &peer_device)
            };
            leaves.push(
                store
                    .generate_prekey(
                        &policy,
                        device,
                        *id,
                        kind,
                        Validity::new(155, 179).expect("new validity"),
                        170,
                    )
                    .expect("fresh owned inventory"),
            );
        }
        let devices = if role == BootstrapRole::Responder {
            [&peer_device, current]
        } else {
            [current, &peer_device]
        };
        let certs = if role == BootstrapRole::Responder {
            [
                peer_cert.as_slice(),
                first.successor_credential().expect("C1"),
            ]
        } else {
            [
                first.successor_credential().expect("C1"),
                peer_cert.as_slice(),
            ]
        };
        let responder_signer = if role == BootstrapRole::Responder {
            signer
        } else {
            &peer_signer
        };
        let (bundle, pins) = bundle(&policy, devices, certs, responder_signer, &leaves, 170);
        let context = Arc::new(
            bundle
                .verify(Arc::clone(&policy), requirements(&pins, devices), 170)
                .expect("fresh verified context"),
        );
        let peer_context = Arc::clone(&context);
        assert!(service
            .admit_peer(Arc::clone(&context), opposite(role), 170)
            .is_err());
        let local = service
            .admit_peer(Arc::clone(&context), role, 170)
            .expect("private original-store binding");
        assert_eq!(local.context().digest(), context.digest());
        assert_eq!(
            local.context().device(role).credential_digest(),
            first.successor_device().credential_digest()
        );
        let context = Arc::clone(local.context());
        let (journal, archives) = service.stores().expect("original stores");
        let request = InitiationId::generate().expect("original new operation");
        let foreign_folder = directory();
        let mut foreign = crate::durable::tests::new_store(
            &foreign_folder.path().canonicalize().expect("foreign path"),
            &original,
        );
        if role == BootstrapRole::Initiator {
            assert!(
                foreign.initiation_status(&context, request).is_err(),
                "scope-only query must reject another journal with same original owner"
            );
        }

        let (initial, reply, session) = if role == BootstrapRole::Responder {
            let initial = peer_journal
                .initiate(Arc::clone(&peer_context), request, &peer_signer, 170)
                .expect("peer initiation");
            assert!(
                foreign.status(&context, &initial).is_err(),
                "responder scope-only query must reject another journal with same original owner"
            );

            assert!(
                journal
                    .respond_from_inventory(Arc::clone(&peer_context), &initial, signer, 170)
                    .is_err(),
                "unbound C1 cannot choose original store"
            );
            let reply = journal
                .respond_from_inventory(Arc::clone(&context), &initial, signer, 170)
                .expect("C1 inventory response");
            let final_flight = peer_journal
                .accept_reply(Arc::clone(&peer_context), request, &reply, 170)
                .expect("final");
            journal
                .finish(
                    Arc::clone(&context),
                    &initial,
                    final_flight.final_message(),
                    170,
                )
                .expect("finish");
            peer_journal
                .activate_initiator_messages(Arc::clone(&peer_context), request, 170)
                .expect("peer messages");
            journal
                .activate_responder_messages(Arc::clone(&context), &initial, 170)
                .expect("local messages");
            (initial, reply, final_flight.session_id())
        } else {
            assert!(
                journal
                    .initiate(Arc::clone(&peer_context), request, signer, 170)
                    .is_err(),
                "unbound C1 cannot choose original store"
            );
            let initial = journal
                .initiate(Arc::clone(&context), request, signer, 170)
                .expect("C1 initiation");
            let reply = peer_journal
                .respond_from_inventory(Arc::clone(&peer_context), &initial, &peer_signer, 170)
                .expect("peer inventory response");
            let final_flight = journal
                .accept_reply(Arc::clone(&context), request, &reply, 170)
                .expect("final");
            peer_journal
                .finish(
                    Arc::clone(&peer_context),
                    &initial,
                    final_flight.final_message(),
                    170,
                )
                .expect("finish");
            journal
                .activate_initiator_messages(Arc::clone(&context), request, 170)
                .expect("local messages");
            peer_journal
                .activate_responder_messages(Arc::clone(&peer_context), &initial, 170)
                .expect("peer messages");
            (initial, reply, final_flight.session_id())
        };
        let responder = if role == BootstrapRole::Responder {
            &mut *journal
        } else {
            &mut peer_journal
        };
        let responder_context = if role == BootstrapRole::Responder {
            &context
        } else {
            &peer_context
        };
        let responder_device = if role == BootstrapRole::Responder {
            first.successor_device()
        } else {
            &peer_device
        };
        assert_eq!(
            responder
                .prekey_status(&policy, responder_device, ids[1])
                .expect("one-time status"),
            PrekeyStatus::Consumed
        );
        assert_eq!(
            responder
                .prekey_status(&policy, responder_device, ids[3])
                .expect("one-time status"),
            PrekeyStatus::Consumed
        );
        let responder_signer = if role == BootstrapRole::Responder {
            signer
        } else {
            &peer_signer
        };
        assert_eq!(
            responder
                .respond_from_inventory(
                    Arc::clone(responder_context),
                    &initial,
                    responder_signer,
                    170
                )
                .expect("exact reply replay"),
            reply
        );
        let archive = journal
            .archive_session_closure(&context, session)
            .expect("C1 session original-store archive");
        archives
            .retain(journal, &context, session, &archive)
            .expect("retained archive");
        let message = journal
            .next_message_id(&context, session, 170)
            .expect("send slot");
        let wire = journal
            .send_message(
                &context,
                session,
                message,
                b"born under C1",
                b"renewed operations",
                170,
            )
            .expect("original C1 outbox");
        let before = journal.test_snapshot();
        assert_eq!(before.owner, crate::bootstrap::storage_owner(&original));
        active.close();
        let mut enrollment =
            DeviceEnrollment::open(paths.clone(), intent.clone()).expect("original enrollment");
        enrollment
            .stage_credential_renewal(&second, second.operation(), &policy, 185)
            .expect("next root grant");
        let mut active = enrollment
            .activate(&policy, 185, None)
            .expect("C2 original owner");
        peer_journal
            .install_peer_credential_renewal(
                &crate::installation::PolicyScope {
                    authority: &authority,
                    original_policy: policy.historical(),
                    original_device: &peer_device,
                },
                &second,
                second.operation(),
                &policy,
                185,
            )
            .expect("peer next grant");
        let peer_current = peer_journal
            .prepare_reopened_context(Arc::clone(&peer_context), session, opposite(role), 185)
            .expect("peer retains C1 transcript");
        let (service, _, current) = active.parts().expect("C2 parts");
        let original_devices = if role == BootstrapRole::Responder {
            [&peer_device, first.successor_device()]
        } else {
            [first.successor_device(), &peer_device]
        };
        assert!(
            service.admit_peer(Arc::clone(&context), role, 170).is_err(),
            "C1 cannot create after C2 even at historical trusted time"
        );
        assert!(service
            .reopen_peer_bundle(
                &bundle,
                Arc::clone(&policy),
                requirements(&pins, original_devices),
                opposite(role),
                session,
                185
            )
            .is_err());
        let reopened = service
            .reopen_peer_bundle(
                &bundle,
                Arc::clone(&policy),
                requirements(&pins, original_devices),
                role,
                session,
                185,
            )
            .expect("C1 bundle resolves exact original storage under C2");
        assert_eq!(reopened.context().digest(), context.digest());
        assert!(
            service
                .admit_peer(Arc::clone(reopened.context()), role, 170)
                .is_err(),
            "retained view never creates"
        );
        let journal = service.stores().expect("stores").0;
        if role == BootstrapRole::Initiator {
            assert!(
                journal.initiation_status(&context, request).is_ok(),
                "expired C1 structural query remains available"
            );
            assert!(
                journal
                    .initiation_status(reopened.context(), request)
                    .is_err(),
                "retained session view cannot query bootstrap"
            );
        } else {
            assert!(
                journal.status(&context, &initial).is_ok(),
                "expired C1 structural query remains available"
            );
            assert!(
                journal.status(reopened.context(), &initial).is_err(),
                "retained session view cannot query bootstrap"
            );
        }
        assert!(
            journal
                .resume_message(&context, session, message, 170)
                .is_err(),
            "cached C1 is fenced by C2"
        );
        assert_eq!(
            journal
                .resume_message(reopened.context(), session, message, 185)
                .expect("exact C1 wire under C2"),
            wire
        );
        let received = peer_journal
            .receive_message(&peer_current, session, &wire, b"renewed operations", 185)
            .expect("real peer decryption");
        assert_eq!(received.as_bytes(), b"born under C1");
        assert_eq!(journal.test_snapshot().owner, before.owner);
        assert_eq!(
            service
                .prekey_status(&policy, retired_id)
                .expect("original tombstone"),
            PrekeyStatus::Retired
        );
        // A later generation removes the renewal grant, but an already-owned
        // installation still permits metadata and irreversible inventory cleanup.
        let replacement = root
            .issue_device(
                DeviceDescription::new(original.device_id(), 2, policy.family(), interval())
                    .expect("new generation"),
                original.key.clone(),
            )
            .expect("replacement");
        let roster = root
            .issue_roster(
                4,
                interval(),
                &[root.roster_entry(&replacement).expect("entry")],
            )
            .expect("replacement roster");
        let pin = AccountPin::new(
            original.account_id(),
            root.public_key().expect("root"),
            roster.checkpoint(),
            policy.family(),
        )
        .expect("current pin");
        let verified = pin
            .verify_device(&replacement, roster.as_bytes(), 185)
            .expect("new generation");
        let journal = service.stores().expect("stores").0;
        journal
            .install_roster(verified.roster(), 185)
            .expect("authoritative replacement");
        assert!(journal
            .generate_prekey(
                &policy,
                current,
                PrekeyId::from_trusted_state([230; 32]).expect("ID"),
                LeafKind::OneTimePq,
                Validity::new(185, 189).expect("validity"),
                185
            )
            .is_err());
        assert!(journal
            .next_message_id(reopened.context(), session, 185)
            .is_err());
        assert_eq!(
            service
                .prekey_status(&policy, old_id)
                .expect("scope-only status after grant pruned"),
            PrekeyStatus::Available
        );
        policy.close();
        assert_eq!(
            service
                .retire_prekey(&policy, old_id)
                .expect("scope-only cleanup after close and replacement"),
            PrekeyStatus::Retired
        );
    }
}
