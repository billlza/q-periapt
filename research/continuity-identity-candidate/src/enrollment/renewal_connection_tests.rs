// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    BootstrapBundle, BootstrapMaterials, BootstrapRequirements, BootstrapRole,
    DirectoryExpectation, ExpectedDevice, InitiationId, ManifestContext, PrekeyLeaf,
    RekeyControlStep,
};
use q_periapt_sdk::expert::{PqKeySource, TraditionalKeySource};
use std::collections::VecDeque;

#[test]
fn original_registered_session_exchanges_old_and_new_data_and_rekeys_after_local_credential_expiry()
{
    let (c, _, original, journal_id) = local();
    let renewal = grant(&c, &original, &original, 2, 190);
    let original_certificate = c
        .root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original signed body");
    let pin_r = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        original.roster().checkpoint(),
        c.policy.family(),
    )
    .expect("original independent local pin");
    let mut active = open(&c)
        .activate(&c.policy, 150, None)
        .expect("original registered service");
    let Case {
        paths,
        intent,
        policy,
        _directory,
        ..
    } = c;
    let policy = Arc::new(policy);
    let peer_root = RootSigningKey::generate().expect("independent peer account");
    let peer_signer = DeviceSigningKey::generate().expect("independent peer signing owner");
    let peer_certificate = peer_root
        .issue_device(
            DeviceDescription::new([8; 16], 1, policy.family(), interval())
                .expect("peer description"),
            peer_signer.public_key().expect("peer key"),
        )
        .expect("peer credential");
    let peer_roster = peer_root
        .issue_roster(
            1,
            interval(),
            &[peer_root.roster_entry(&peer_certificate).expect("member")],
        )
        .expect("peer roster");
    let pin_i = AccountPin::new(
        peer_root.account_id().expect("account"),
        peer_root.public_key().expect("root"),
        peer_roster.checkpoint(),
        policy.family(),
    )
    .expect("independent peer pin");
    let peer_device = pin_i
        .verify_device(&peer_certificate, peer_roster.as_bytes(), 150)
        .expect("verified peer");
    let peer_folder = directory();
    let mut peer_journal = crate::durable::tests::new_store(
        &peer_folder.path().canonicalize().expect("peer path"),
        &peer_device,
    );
    let reusable = policy
        .runtime
        .generate_key()
        .expect("actual SDK reusable prekey");
    let once = policy
        .runtime
        .generate_key()
        .expect("actual SDK one-time prekey");
    let rp = reusable.public_key().expect("public").to_bytes();
    let op = once.public_key().expect("public").to_bytes();
    let (pq, classical) = rp.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let (pq_once, classical_once) = op.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let validity = Validity::new(100, 155).expect("original advertisement");
    let leaves = [
        (LeafKind::SignedClassical, classical),
        (LeafKind::OneTimeClassical, classical_once),
        (LeafKind::LastResortPq, pq),
        (LeafKind::OneTimePq, pq_once),
    ]
    .map(|(kind, bytes)| PrekeyLeaf::new(kind, bytes, validity).expect("leaf"));
    let (_, signer, device) = active.parts().expect("original registered signing owner");
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
            .expect("manifest scope"),
            &leaves,
        )
        .expect("signed manifest");
    let verified = device
        .verify_manifest(manifest.as_bytes(), 150)
        .expect("verified manifest");
    let proofs: Vec<_> = (0..manifest.leaf_count())
        .map(|i| {
            let proof = manifest.proof(i).expect("membership proof");
            (
                verified
                    .verify_leaf(&proof, 150)
                    .expect("verified leaf")
                    .kind(),
                proof.encode().expect("canonical proof"),
            )
        })
        .collect();
    let proof = |kind| {
        proofs
            .iter()
            .find(|(k, _)| *k == kind)
            .expect("required role")
            .1
            .as_slice()
    };
    let bundle = BootstrapBundle::from_materials(
        PrekeyQuality::OneTimeBoth,
        BootstrapMaterials {
            initiator_credential: &peer_certificate,
            initiator_roster: peer_roster.as_bytes(),
            responder_credential: &original_certificate,
            responder_roster: original.roster().as_bytes(),
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(LeafKind::SignedClassical),
            last_resort_pq: proof(LeafKind::LastResortPq),
            one_time_classical: Some(proof(LeafKind::OneTimeClassical)),
            one_time_pq: Some(proof(LeafKind::OneTimePq)),
        },
    )
    .expect("portable original public bundle");
    let required = || BootstrapRequirements {
        initiator: ExpectedDevice::new(&pin_i, peer_device.device_id(), peer_device.generation())
            .expect("peer expectation"),
        responder: ExpectedDevice::new(&pin_r, original.device_id(), original.generation())
            .expect("original local expectation"),
        quality: PrekeyQuality::OneTimeBoth,
        directory: DirectoryExpectation::from_trusted_state([99; 32])
            .expect("independent directory"),
    };
    let context = Arc::new(
        bundle
            .verify(Arc::clone(&policy), required(), 150)
            .expect("independent bundle verification"),
    );
    let request = InitiationId::generate().expect("original handshake operation");
    let initial = peer_journal
        .initiate(Arc::clone(&context), request, &peer_signer, 150)
        .expect("initial");
    let (service, signer, _) = active.parts().expect("original owner");
    let (journal, archives) = service.stores().expect("original stores");
    let reply = journal
        .respond(
            Arc::clone(&context),
            &initial,
            signer,
            PqKeySource::from_key(&once),
            TraditionalKeySource::from_key(&once),
            150,
        )
        .expect("real KEM response");
    let final_flight = peer_journal
        .accept_reply(Arc::clone(&context), request, &reply, 150)
        .expect("real final confirmation");
    let session = final_flight.session_id();
    journal
        .finish(
            Arc::clone(&context),
            &initial,
            final_flight.final_message(),
            150,
        )
        .expect("responder confirmed");
    peer_journal
        .activate_initiator_messages(Arc::clone(&context), request, 150)
        .expect("peer Messages");
    journal
        .activate_responder_messages(Arc::clone(&context), &initial, 150)
        .expect("registered Messages");
    let archive = journal
        .archive_session_closure(&context, session)
        .expect("exact original archive");
    archives
        .retain(journal, &context, session, &archive)
        .expect("retained original archive");
    let original_id = journal
        .next_message_id(&context, session, 150)
        .expect("original slot");
    let original_wire = journal
        .send_message(
            &context,
            session,
            original_id,
            b"before expiry",
            b"registered renewal",
            150,
        )
        .expect("committed unconfirmed original outbox");
    active.close();
    let mut enrollment =
        DeviceEnrollment::open(paths.clone(), intent.clone()).expect("original enrollment");
    enrollment
        .stage_credential_renewal(&renewal, renewal.operation(), &policy, 170)
        .expect("root-authorized extension");
    let mut active = enrollment
        .activate(&policy, 170, None)
        .expect("same installed owner after C0 expiry");
    let peer_authority =
        crate::RetainedInstallationAuthority::active_installation(&peer_device, &policy);
    peer_journal
        .install_peer_credential_renewal(
            &peer_authority,
            &renewal,
            renewal.operation(),
            &policy,
            170,
        )
        .expect("peer independently admits same root grant");
    let peer_context = peer_journal
        .prepare_reopened_context(Arc::clone(&context), session, BootstrapRole::Initiator, 170)
        .expect("peer exact original session");
    let (service, signer, current) = active.parts().expect("renewed controlled owners");
    assert_eq!(
        current.credential_digest(),
        renewal.successor_device().credential_digest()
    );
    let reopened = service
        .reopen_peer_bundle(
            &bundle,
            Arc::clone(&policy),
            required(),
            BootstrapRole::Responder,
            session,
            170,
        )
        .expect("owning service authenticates historical bundle and archive");
    assert_eq!(reopened.context().digest(), context.digest());
    assert_eq!(
        reopened
            .context()
            .device(BootstrapRole::Responder)
            .credential_digest(),
        original.credential_digest()
    );
    let journal = service.stores().expect("same stores").0;
    assert_eq!(journal.identity().expect("journal"), journal_id);
    let resumed = journal
        .resume_message(reopened.context(), session, original_id, 170)
        .expect("exact original outbox after credential renewal");
    assert_eq!(resumed, original_wire);
    assert_eq!(
        peer_journal
            .receive_message(&peer_context, session, &resumed, b"registered renewal", 170)
            .expect("actual peer decryption")
            .as_bytes(),
        b"before expiry"
    );
    peer_journal
        .consume_message(&peer_context, session, original_id, 170)
        .expect("explicit consumption");
    let ack = peer_journal
        .message_acknowledgement(&peer_context, session, 170)
        .expect("ACK");
    journal
        .accept_message_acknowledgement(reopened.context(), session, &ack, 170)
        .expect("original ACK contract");
    let next = journal
        .next_message_id(reopened.context(), session, 170)
        .expect("same chain next slot");
    assert_ne!(next, original_id);
    let wire = journal
        .send_message(
            reopened.context(),
            session,
            next,
            b"after renewal",
            b"registered renewal",
            170,
        )
        .expect("new actual data");
    assert_eq!(
        peer_journal
            .receive_message(&peer_context, session, &wire, b"registered renewal", 170)
            .expect("new actual peer decryption")
            .as_bytes(),
        b"after renewal"
    );
    let mut queue = VecDeque::new();
    if let RekeyControlStep::Output(wire) = journal
        .advance_rekey_control(reopened.context(), session, 1, signer, 170)
        .expect("original-key control")
    {
        queue.push_back((true, wire.as_bytes().to_vec()));
    }
    let mut steps = 0;
    while let Some((to_peer, wire)) = queue.pop_front() {
        steps += 1;
        assert!(steps <= 16, "bounded native control exchange");
        let step = if to_peer {
            peer_journal
                .receive_rekey_control(&peer_context, session, &wire, &peer_signer, 170)
                .expect("peer control")
        } else {
            journal
                .receive_rekey_control(reopened.context(), session, &wire, signer, 170)
                .expect("registered control")
        };
        if let RekeyControlStep::Output(wire) = step {
            queue.push_back((!to_peer, wire.as_bytes().to_vec()));
        }
    }
    assert!(matches!(
        journal
            .advance_rekey_control(reopened.context(), session, 1, signer, 170)
            .expect("local progress"),
        RekeyControlStep::LocallyConfirmed(1)
    ));
    assert!(matches!(
        peer_journal
            .advance_rekey_control(&peer_context, session, 1, &peer_signer, 170)
            .expect("peer progress"),
        RekeyControlStep::LocallyConfirmed(1)
    ));
    eprintln!("LOCAL_RENEWAL_REGISTERED_SESSION original_ciphertext=true peer_decryption=true new_message=true rekey_epoch=1 control_steps={steps}");
}
