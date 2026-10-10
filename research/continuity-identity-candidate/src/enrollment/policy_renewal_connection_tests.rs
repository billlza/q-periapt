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
fn original_registered_session_exchanges_old_and_new_data_and_rekeys_after_policy_only_expiry() {
    continued_session(false);
}
#[test]
fn original_registered_session_survives_a_real_credential_renewal_after_policy_only_adoption() {
    continued_session(true);
}
fn continued_session(renew_credential: bool) {
    let (c, original, journal_id) = local(160, if renew_credential { 180 } else { 200 });
    let grant = renew_credential.then(|| renewal::grant(&c, &original, &original, 2, 240));
    let p1 = Arc::new(policy(&c, 2, 230, 170));
    let local_approval = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, journal_id),
        170,
    );
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
    assert!(policy.check_mode(PrekeyQuality::OneTimeBoth, 170).is_err());
    original
        .description
        .validity
        .check(170)
        .expect("same local credential still current");
    peer_device
        .description
        .validity
        .check(170)
        .expect("same peer credential still current");
    let mut enrollment =
        DeviceEnrollment::open(paths.clone(), intent.clone()).expect("original enrollment");
    enrollment
        .stage_policy_renewal(
            &local_approval,
            local_approval.scope().operation,
            policy.historical(),
            &p1,
            170,
        )
        .expect("durable original policy-only intent");
    let peer_scope = PolicyRenewalScope {
        operation: PolicyRenewalId::generate().expect("peer policy operation"),
        journal: peer_journal.identity().expect("original peer journal"),
        original_owner: crate::bootstrap::storage_owner(&peer_device),
        original_credential: peer_device.credential_digest(),
        current_credential: peer_device.credential_digest(),
        current_roster: peer_device.roster().checkpoint(),
        original_policy: policy.checkpoint(),
        previous_policy: policy.checkpoint(),
        previous_authorization: None,
    };
    let materials = PolicyRenewalMaterials {
        original: policy.historical(),
        previous: policy.historical(),
        target: &p1,
        original_device: &peer_device,
        current_device: &peer_device,
    };
    let statement =
        PolicyRenewalStatement::new(&peer_scope, &materials, 170).expect("peer exact scope");
    let policy_root =
        PolicySigningKey::deterministic([82; 32], [83; 32]).expect("independent policy root");
    let account_approval = peer_root
        .approve_policy_renewal(&statement)
        .expect("peer account approval");
    let policy_approval = policy_root
        .approve_policy_renewal(&statement)
        .expect("peer policy approval");
    let peer_approval = VerifiedPolicyRenewal::verify(
        &account_approval,
        &policy_approval,
        &peer_scope,
        &materials,
        170,
    )
    .expect("peer independent authorization")
    .historical();
    // The peer is a native journal fixture; only the registered local endpoint
    // below claims to exercise the original public enrollment coordinator.
    let receipt = peer_journal
        .commit_local_policy_renewal(
            &crate::durable::LocalPolicyRenewalTarget {
                approval: &peer_approval,
                original: &peer_device,
                current: &peer_device,
                original_policy: policy.historical(),
            },
            &p1,
            170,
            None,
        )
        .expect("peer same-C/R adoption");
    let peer_authority = crate::RetainedInstallationAuthority::active_installation(
        &peer_device,
        policy.historical(),
    );
    let before_ack = peer_journal.test_snapshot();
    assert!(
        matches!(
            peer_journal.prepare_continued_context(
                Arc::clone(&context),
                session,
                BootstrapRole::Initiator,
                Arc::clone(&p1),
                170
            ),
            Err(DurableError::Suspended)
        ),
        "journal receipt alone cannot release a continued session before completion ACK"
    );
    let after_denied = peer_journal.test_snapshot();
    assert_eq!(
        (before_ack.revision, before_ack.digest),
        (after_denied.revision, after_denied.digest)
    );
    peer_journal
        .acknowledge_local_policy_renewal(&peer_authority, &receipt)
        .expect("peer fixture ACK");
    let wrong_role = bundle
        .request_historical_reopen(
            Arc::new(policy.historical().clone()),
            required(),
            BootstrapRole::Initiator,
            session,
            170,
        )
        .expect("authenticated bundle, wrong local role");
    assert!(matches!(
        enrollment.activate_policy_renewed_session(wrong_role, Arc::clone(&p1), 170),
        Err(DurableError::Conflict)
    ));
    let enrollment = DeviceEnrollment::open(paths.clone(), intent.clone())
        .expect("original Pending after wrong role");
    let mut absent_session = session;
    absent_session[0] ^= 1;
    let absent = bundle
        .request_historical_reopen(
            Arc::new(policy.historical().clone()),
            required(),
            BootstrapRole::Responder,
            absent_session,
            170,
        )
        .expect("authenticated history, absent session");
    assert!(matches!(
        enrollment.activate_policy_renewed_session(absent, Arc::clone(&p1), 170),
        Err(DurableError::Absent)
    ));
    let mut enrollment = DeviceEnrollment::open(paths.clone(), intent.clone())
        .expect("original completion after missing-session error");
    let now = if let Some(g) = &grant {
        assert!(original.description.validity.check(190).is_err());
        enrollment
            .stage_credential_renewal(g, g.operation(), &p1, 190)
            .expect("real root-authorized G after local credential expiry");
        peer_journal
            .install_peer_credential_renewal(
                &crate::installation::PolicyScope {
                    authority: &peer_authority,
                    original_policy: policy.historical(),
                    original_device: &peer_device,
                },
                g,
                g.operation(),
                &p1,
                190,
            )
            .expect("peer admits actual responder credential grant under its own P1");
        190
    } else {
        170
    };
    let request = bundle
        .request_historical_reopen(
            Arc::new(policy.historical().clone()),
            required(),
            BootstrapRole::Responder,
            session,
            now,
        )
        .expect("original signed bundle after P0 expiry");
    let (mut active, reopened) = enrollment
        .activate_policy_renewed_session(request, Arc::clone(&p1), now)
        .expect("same registered owner and original session under P1");
    assert!(
        matches!(
            active.parts().expect("parts").0.admit_peer(
                Arc::clone(&context),
                BootstrapRole::Responder,
                150
            ),
            Err(DurableError::Conflict)
        ),
        "cached P0 cannot bootstrap"
    );
    let peer_context = peer_journal
        .prepare_continued_context(
            Arc::clone(&context),
            session,
            BootstrapRole::Initiator,
            Arc::clone(&p1),
            now,
        )
        .expect("peer same original session under P1");
    let (service, signer, current) = active.parts().expect("renewed controlled owners");
    assert_eq!(
        current.credential_digest(),
        grant.as_ref().map_or(original.credential_digest(), |g| g
            .successor_device()
            .credential_digest())
    );
    assert_eq!(reopened.context().digest(), context.digest());
    assert_eq!(
        reopened
            .context()
            .device(BootstrapRole::Responder)
            .credential_digest(),
        original.credential_digest()
    );
    let next_peer_roster = peer_root
        .issue_roster(
            2,
            interval(),
            &[peer_root
                .roster_entry(&peer_certificate)
                .expect("same peer credential")],
        )
        .expect("root-approved peer roster after local P");
    let next_peer_pin = AccountPin::new(
        peer_device.account_id(),
        peer_root.public_key().expect("root"),
        next_peer_roster.checkpoint(),
        p1.family(),
    )
    .expect("independent target pin");
    let next_peer_roster = next_peer_pin
        .verify_roster(next_peer_roster.as_bytes(), now)
        .expect("verified remote target");
    assert_eq!(
        service
            .admit_peer_roster(&next_peer_roster, &p1, now)
            .expect("current local-P service admits peer roster"),
        next_peer_roster.checkpoint()
    );
    let snapshot = service.stores().expect("same stores").0.test_snapshot();
    service
        .admit_peer_roster(&next_peer_roster, &p1, now)
        .expect("same original target retry");
    let journal = service.stores().expect("same stores").0;
    let repeated = journal.test_snapshot();
    assert_eq!(
        (
            snapshot.id,
            snapshot.owner,
            snapshot.revision,
            snapshot.digest
        ),
        (
            repeated.id,
            repeated.owner,
            repeated.revision,
            repeated.digest
        )
    );
    assert_eq!(journal.identity().expect("journal"), journal_id);
    assert_eq!(
        reopened.context().continued_policy_statement(),
        Some(local_approval.statement_digest())
    );
    assert_eq!(
        peer_context.continued_policy_statement(),
        Some(peer_approval.statement_digest())
    );
    let before_denials = journal.test_snapshot();
    assert!(matches!(
        journal.next_message_id(&context, session, 150),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        journal.generate_prekey(
            &p1,
            current,
            PrekeyId::from_trusted_state([98; 32]).expect("fresh key ID"),
            LeafKind::OneTimePq,
            Validity::new(now, now + 10).expect("live interval"),
            now
        ),
        Err(DurableError::Conflict)
    ));
    let after_denials = journal.test_snapshot();
    assert_eq!(
        (before_denials.revision, before_denials.digest),
        (after_denials.revision, after_denials.digest)
    );
    let resumed = journal
        .resume_message(reopened.context(), session, original_id, now)
        .expect("exact original outbox after policy-only renewal");
    assert_eq!(resumed, original_wire);
    assert_eq!(
        peer_journal
            .receive_message(&peer_context, session, &resumed, b"registered renewal", now)
            .expect("actual peer decryption")
            .as_bytes(),
        b"before expiry"
    );
    peer_journal
        .consume_message(&peer_context, session, original_id, now)
        .expect("explicit consumption");
    let ack = peer_journal
        .message_acknowledgement(&peer_context, session, now)
        .expect("ACK");
    journal
        .accept_message_acknowledgement(reopened.context(), session, &ack, now)
        .expect("original ACK contract");
    let next = journal
        .next_message_id(reopened.context(), session, now)
        .expect("same chain next slot");
    assert_ne!(next, original_id);
    let wire = journal
        .send_message(
            reopened.context(),
            session,
            next,
            b"after renewal",
            b"registered renewal",
            now,
        )
        .expect("new actual data");
    assert_eq!(
        peer_journal
            .receive_message(&peer_context, session, &wire, b"registered renewal", now)
            .expect("new actual peer decryption")
            .as_bytes(),
        b"after renewal"
    );
    let mut queue = VecDeque::new();
    if let RekeyControlStep::Output(wire) = journal
        .advance_rekey_control(reopened.context(), session, 1, signer, now)
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
                .receive_rekey_control(&peer_context, session, &wire, &peer_signer, now)
                .expect("peer control")
        } else {
            journal
                .receive_rekey_control(reopened.context(), session, &wire, signer, now)
                .expect("registered control")
        };
        if let RekeyControlStep::Output(wire) = step {
            queue.push_back((!to_peer, wire.as_bytes().to_vec()));
        }
    }
    assert!(matches!(
        journal
            .advance_rekey_control(reopened.context(), session, 1, signer, now)
            .expect("local progress"),
        RekeyControlStep::LocallyConfirmed(1)
    ));
    assert!(matches!(
        peer_journal
            .advance_rekey_control(&peer_context, session, 1, &peer_signer, now)
            .expect("peer progress"),
        RekeyControlStep::LocallyConfirmed(1)
    ));
    let local_next = journal
        .next_message_id(reopened.context(), session, now + 1)
        .expect("post-rekey local ID");
    let local_wire = journal
        .send_message(
            reopened.context(),
            session,
            local_next,
            b"local after epoch",
            b"policy-only epoch",
            now + 1,
        )
        .expect("post-rekey local send");
    assert_eq!(
        peer_journal
            .receive_message(
                &peer_context,
                session,
                &local_wire,
                b"policy-only epoch",
                now + 1
            )
            .expect("post-rekey peer decrypt")
            .as_bytes(),
        b"local after epoch"
    );
    let peer_next = peer_journal
        .next_message_id(&peer_context, session, now + 1)
        .expect("post-rekey peer ID");
    assert_ne!(peer_next, local_next, "original directional ID separation");
    let peer_wire = peer_journal
        .send_message(
            &peer_context,
            session,
            peer_next,
            b"peer after epoch",
            b"policy-only epoch",
            now + 1,
        )
        .expect("post-rekey peer send");
    assert_eq!(
        journal
            .receive_message(
                reopened.context(),
                session,
                &peer_wire,
                b"policy-only epoch",
                now + 1
            )
            .expect("post-rekey local decrypt")
            .as_bytes(),
        b"peer after epoch"
    );
    eprintln!("POLICY_ONLY_REGISTERED_SESSION original_ciphertext=true peer_decryption=true new_message=true rekey_epoch=1 control_steps={steps} real_credential_renewal={renew_credential} unchanged_cr={} no_synthetic_g=true original_enrollment=true post_rekey_bidirectional=true wrong_role_denied=true absent_session_denied=true pre_ack_denied=true", !renew_credential);
}
