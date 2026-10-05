// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    BootstrapBundle, BootstrapContext, BootstrapMaterials, BootstrapRequirements, BootstrapRole,
    DirectoryExpectation, ExpectedDevice, InitiationId, ManifestContext, SessionReopenRequest,
};

struct Endpoint {
    case: Case,
    original: VerifiedDevice,
    journal: JournalIdentity,
    certificate: Vec<u8>,
    pin: AccountPin,
    owner: EnrolledDevice,
}
fn endpoint() -> Endpoint {
    let (case, original, journal) = local();
    let mut enrollment = open(&case);
    let certificate = match enrollment.image().expect("original configuration").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("original accepted enrollment"),
    }
    .expect("original accepted configuration");
    let pin = AccountPin::new(
        original.account_id(),
        case.root.public_key().expect("independent account key"),
        original.roster().checkpoint(),
        case.policy.family(),
    )
    .expect("independent original account pin");
    let owner = enrollment
        .activate(&case.policy, 150, None)
        .expect("original controlled owner");
    Endpoint {
        case,
        original,
        journal,
        certificate,
        pin,
        owner,
    }
}
fn requirements<'a>(left: &'a Endpoint, right: &'a Endpoint) -> BootstrapRequirements<'a> {
    BootstrapRequirements {
        initiator: ExpectedDevice::new(
            &left.pin,
            left.original.device_id(),
            left.original.generation(),
        )
        .expect("initiator expectation"),
        responder: ExpectedDevice::new(
            &right.pin,
            right.original.device_id(),
            right.original.generation(),
        )
        .expect("responder expectation"),
        quality: PrekeyQuality::OneTimeBoth,
        directory: DirectoryExpectation::from_trusted_state([99; 32])
            .expect("independent directory"),
    }
}
fn bundle(left: &Endpoint, right: &mut Endpoint) -> BootstrapBundle {
    let (service, signer, device) = right.owner.parts().expect("original responder owners");
    let mut leaves = Vec::new();
    for (i, kind) in [
        LeafKind::SignedClassical,
        LeafKind::OneTimeClassical,
        LeafKind::LastResortPq,
        LeafKind::OneTimePq,
    ]
    .into_iter()
    .enumerate()
    {
        leaves.push(
            service
                .stores()
                .expect("stores")
                .0
                .generate_prekey(
                    &right.case.policy,
                    device,
                    PrekeyId::from_trusted_state([u8::try_from(i + 1).expect("prekey ID"); 32])
                        .expect("original ID"),
                    kind,
                    Validity::new(100, 160).expect("advertisement"),
                    150,
                )
                .expect("actual owned prekey generation"),
        );
    }
    let manifest = signer
        .issue_manifest(
            device,
            ManifestContext::new(
                1,
                right.case.policy.runtime.trusted_state().digest(),
                crate::bootstrap_suite_digest(),
                [99; 32],
                Validity::new(100, 160).expect("manifest interval"),
            )
            .expect("manifest scope"),
            &leaves,
        )
        .expect("original enrolled signer");
    let verified = device
        .verify_manifest(manifest.as_bytes(), 150)
        .expect("manifest");
    let mut proofs = std::collections::BTreeMap::new();
    for i in 0..manifest.leaf_count() {
        let proof = manifest.proof(i).expect("proof");
        proofs.insert(
            verified.verify_leaf(&proof, 150).expect("leaf").kind() as u8,
            proof.encode().expect("wire"),
        );
    }
    let proof = |kind: LeafKind| {
        proofs
            .get(&(kind as u8))
            .expect("required proof")
            .as_slice()
    };
    BootstrapBundle::from_materials(
        PrekeyQuality::OneTimeBoth,
        BootstrapMaterials {
            initiator_credential: &left.certificate,
            initiator_roster: left.original.roster().as_bytes(),
            responder_credential: &right.certificate,
            responder_roster: right.original.roster().as_bytes(),
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(LeafKind::SignedClassical),
            last_resort_pq: proof(LeafKind::LastResortPq),
            one_time_classical: Some(proof(LeafKind::OneTimeClassical)),
            one_time_pq: Some(proof(LeafKind::OneTimePq)),
        },
    )
    .expect("actual public enrollment bundle")
}
fn request(
    bundle: &BootstrapBundle,
    left: &Endpoint,
    right: &Endpoint,
    role: BootstrapRole,
    session: [u8; 32],
) -> SessionReopenRequest {
    bundle
        .request_historical_reopen(
            Arc::new(left.case.policy.historical().clone()),
            requirements(left, right),
            role,
            session,
            170,
        )
        .expect("original public history, no runtime authority")
}
fn send(
    sender: &mut EnrolledDevice,
    receiver: &mut EnrolledDevice,
    sending: &BootstrapContext,
    receiving: &BootstrapContext,
    session: [u8; 32],
    plaintext: &[u8],
    now: u64,
) {
    let j = sender
        .parts()
        .expect("sender owners")
        .0
        .stores()
        .expect("sender stores")
        .0;
    let id = j
        .next_message_id(sending, session, now)
        .expect("new exact message");
    let wire = j
        .send_message(sending, session, id, plaintext, b"public-enrollment", now)
        .expect("committed ciphertext");
    let clear = receiver
        .parts()
        .expect("receiver owners")
        .0
        .stores()
        .expect("receiver stores")
        .0
        .receive_message(receiving, session, &wire, b"public-enrollment", now)
        .expect("actual peer decryption");
    assert_eq!(clear.as_bytes(), plaintext);
}

#[test]
fn public_joint_enrollment_reopens_original_session_and_signer_after_policy_expiry() {
    let mut left = endpoint();
    let mut right = endpoint();
    assert_eq!(
        left.case.policy.checkpoint(),
        right.case.policy.checkpoint()
    );
    let bundle = bundle(&left, &mut right);
    let p0i = Arc::new(policy(&left.case, 1, 160, 150));
    let p0r = Arc::new(policy(&right.case, 1, 160, 150));
    let ci = Arc::new(
        bundle
            .verify(p0i, requirements(&left, &right), 150)
            .expect("initiator bundle"),
    );
    let cr = Arc::new(
        bundle
            .verify(p0r, requirements(&left, &right), 150)
            .expect("responder bundle"),
    );
    let id = InitiationId::generate().expect("original initiation");
    let session;
    let old_id;
    let old_wire;
    {
        let (is, ik, _) = left.owner.parts().expect("initiator enrollment owners");
        let (rs, rk, _) = right.owner.parts().expect("responder enrollment owners");
        let (ij, ia) = is.stores().expect("initiator stores");
        let (rj, ra) = rs.stores().expect("responder stores");
        let initial = ij.initiate(Arc::clone(&ci), id, ik, 150).expect("initial");
        let reply = rj
            .respond_from_inventory(Arc::clone(&cr), &initial, rk, 150)
            .expect("actual original inventory");
        let done = ij
            .accept_reply(Arc::clone(&ci), id, &reply, 150)
            .expect("final");
        session = done.session_id();
        rj.finish(Arc::clone(&cr), &initial, done.final_message(), 150)
            .expect("confirm");
        ij.activate_initiator_messages(Arc::clone(&ci), id, 150)
            .expect("initiator messages");
        rj.activate_responder_messages(Arc::clone(&cr), &initial, 150)
            .expect("responder messages");
        let archive = ij
            .archive_session_closure(&ci, session)
            .expect("initiator archive");
        ia.retain(ij, &ci, session, &archive)
            .expect("original retained archive");
        let archive = rj
            .archive_session_closure(&cr, session)
            .expect("responder archive");
        ra.retain(rj, &cr, session, &archive)
            .expect("original retained archive");
        old_id = ij
            .next_message_id(&ci, session, 150)
            .expect("original unconfirmed message");
        old_wire = ij
            .send_message(
                &ci,
                session,
                old_id,
                b"before original policy expiry",
                b"old",
                150,
            )
            .expect("original ciphertext");
    }
    let gi = renewal::grant(&left.case, &left.original, &left.original, 2, 200);
    let gr = renewal::grant(&right.case, &right.original, &right.original, 2, 200);
    // This test focuses on public local enrollment/owner release. Peer renewal
    // is independently installed while original P0 is live; post-P0 peer update
    // remains a separate integration obligation.
    left.owner
        .parts()
        .expect("left")
        .0
        .admit_peer_credential_renewal(&gr, gr.operation(), &left.case.policy, 150)
        .expect("peer root grant");
    right
        .owner
        .parts()
        .expect("right")
        .0
        .admit_peer_credential_renewal(&gi, gi.operation(), &right.case.policy, 150)
        .expect("peer root grant");
    left.owner.close();
    right.owner.close();
    let signer_i = fs::read(&left.case.paths.signer).expect("original sealed signer");
    let signer_r = fs::read(&right.case.paths.signer).expect("original sealed signer");
    let pi = Arc::new(policy(&left.case, 2, 190, 170));
    let pr = Arc::new(policy(&right.case, 2, 190, 170));
    let ti = joint(
        &left.case,
        &gi,
        &scope(&left.case, &gi, left.journal),
        &left.case.policy,
        &pi,
    );
    let tr = joint(
        &right.case,
        &gr,
        &scope(&right.case, &gr, right.journal),
        &right.case.policy,
        &pr,
    );
    for (e, g, t, p, finish) in [(&left, &gi, &ti, &pi, true), (&right, &gr, &tr, &pr, false)] {
        let mut owner = open(&e.case);
        let original_id = owner.identity().expect("original signer identity");
        owner
            .stage_policy_continuation(g, t, g.operation(), p, 170)
            .expect("public original Pending");
        if finish {
            assert_eq!(
                owner
                    .reconcile_policy_continuation(e.case.policy.historical(), p, 170)
                    .expect("public exact commit and ACK"),
                committed(t, g)
            );
        }
        owner.close();
        let mut reopened = open(&e.case);
        assert_eq!(
            reopened.identity().expect("unchanged signer identity"),
            original_id
        );
        assert_eq!(
            reopened
                .credential_renewal_status()
                .expect("retained exact progress"),
            if finish { committed(t, g) } else { pending(t) }
        );
        reopened.close();
    }
    // The right side has only staged its exact intent. Continued activation
    // reconciles that authorized transaction before admitting the selected
    // session. A bad session returns no owner but may leave an exact completed
    // renewal; reopening must expose that truthful result, not "nothing happened".
    assert!(open(&right.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Responder, [93; 32]),
            Arc::clone(&pr),
            170,
        )
        .is_err());
    let mut completed_right = open(&right.case);
    assert_eq!(
        completed_right
            .credential_renewal_status()
            .expect("completion despite refused session"),
        committed(&tr, &gr)
    );
    completed_right.close();
    assert!(open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Responder, session),
            Arc::clone(&pi),
            170
        )
        .is_err());
    assert!(open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, [91; 32]),
            Arc::clone(&pi),
            170
        )
        .is_err());
    let wrong_policy = Arc::new(policy(&left.case, 3, 195, 170));
    assert!(open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            wrong_policy,
            170
        )
        .is_err());
    let (owner_i, peer_i) = open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            Arc::clone(&pi),
            170,
        )
        .expect("public continued initiator owner");
    let (owner_r, peer_r) = open(&right.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Responder, session),
            Arc::clone(&pr),
            170,
        )
        .expect("public continued responder owner");
    left.owner = owner_i;
    right.owner = owner_r;
    assert!(
        DeviceEnrollment::open(left.case.paths.clone(), left.case.intent.clone()).is_err(),
        "original enrollment lease stays owned"
    );
    assert!(
        DeviceInstallation::reopen_continued_session(
            left.case.paths.installation.clone(),
            JournalKey::open(&left.case.paths.wrapping).expect("original key"),
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            Arc::clone(&pi),
            170,
            None
        )
        .is_err(),
        "original installation lease stays owned"
    );
    assert_eq!(peer_i.context().digest(), ci.digest());
    assert_eq!(peer_r.context().digest(), cr.digest());
    assert_eq!(
        peer_i.context().original_policy().checkpoint(),
        left.case.policy.checkpoint()
    );
    {
        let (service, signer, device) = left
            .owner
            .parts()
            .expect("original signer and current identity");
        signer
            .check_device(device)
            .expect("original signer matches C1");
        assert_eq!(
            device.credential_digest(),
            gi.successor_device().credential_digest()
        );
        let j = service.stores().expect("original stores").0;
        assert_eq!(j.identity().expect("original journal"), left.journal);
        assert_eq!(
            j.resume_message(peer_i.context(), session, old_id, 170)
                .expect("same original ciphertext"),
            old_wire
        );
        assert!(
            j.generate_prekey(
                &pi,
                device,
                PrekeyId::from_trusted_state([92; 32]).expect("new attempted ID"),
                LeafKind::OneTimePq,
                Validity::new(100, 190).expect("interval"),
                170
            )
            .is_err(),
            "continued owner cannot provision fresh prekeys"
        );
        assert!(
            j.initiate(
                Arc::clone(peer_i.context()),
                InitiationId::generate().expect("new attempt"),
                signer,
                170
            )
            .is_err(),
            "continued owner cannot bootstrap another session"
        );
    }
    let clear = right
        .owner
        .parts()
        .expect("right owner")
        .0
        .stores()
        .expect("right stores")
        .0
        .receive_message(peer_r.context(), session, &old_wire, b"old", 170)
        .expect("original ciphertext still decrypts");
    assert_eq!(clear.as_bytes(), b"before original policy expiry");
    send(
        &mut left.owner,
        &mut right.owner,
        peer_i.context(),
        peer_r.context(),
        session,
        b"continued initiator data",
        170,
    );
    send(
        &mut right.owner,
        &mut left.owner,
        peer_r.context(),
        peer_i.context(),
        session,
        b"continued responder data",
        170,
    );
    {
        let (is, ik, _) = left.owner.parts().expect("owned initiator signer");
        let (rs, rk, _) = right.owner.parts().expect("owned responder signer");
        let ij = is.stores().expect("initiator journal").0;
        let rj = rs.stores().expect("responder journal").0;
        let offer = ij
            .prepare_rekey_offer(peer_i.context(), session, ik, 175)
            .expect("signed retained offer");
        let response = rj
            .respond_rekey_offer(peer_r.context(), session, &offer, rk, 175)
            .expect("signed retained response");
        let final_wire = ij
            .accept_rekey_response(peer_i.context(), session, &response, ik, 175)
            .expect("signed final");
        let receipt = rj
            .finish_rekey(peer_r.context(), session, &final_wire, rk, 175)
            .expect("signed receipt");
        ij.accept_rekey_receipt(peer_i.context(), session, &receipt, 175)
            .expect("confirmed new epoch");
        assert_eq!(
            ij.rekey_progress(peer_i.context(), session)
                .expect("initiator epoch")
                .confirmed_epoch,
            1
        );
        assert_eq!(
            rj.rekey_progress(peer_r.context(), session)
                .expect("responder epoch")
                .confirmed_epoch,
            1
        );
    }
    send(
        &mut left.owner,
        &mut right.owner,
        peer_i.context(),
        peer_r.context(),
        session,
        b"after retained rekey",
        175,
    );
    left.owner.close();
    right.owner.close();
    assert!(left.owner.parts().is_err());
    let (mut owner, reopened) = open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            Arc::clone(&pi),
            175,
        )
        .expect("public owner restart after rekey");
    assert_eq!(
        owner
            .parts()
            .expect("reopened owner")
            .0
            .stores()
            .expect("reopened stores")
            .0
            .rekey_progress(reopened.context(), session)
            .expect("same epoch")
            .confirmed_epoch,
        1
    );
    owner.close();
    let mut saved_owner = open(&left.case);
    let old_configuration = row(&saved_owner);
    saved_owner.close();
    let g2 = renewal::grant(&left.case, &left.original, gi.successor_device(), 3, 210);
    let mut next = open(&left.case);
    next.stage_credential_renewal(&g2, g2.operation(), &pi, 175)
        .expect("credential-only extension preserves adopted T1");
    assert_eq!(
        next.reconcile_policy_continuation(left.case.policy.historical(), &pi, 175)
            .expect("original coordinator completes G2 under T1"),
        renewal::committed(&g2)
    );
    let current_configuration = row(&next);
    next.close();
    let (mut current, current_peer) = open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            Arc::clone(&pi),
            175,
        )
        .expect("T1 independent of latest completed G2");
    {
        let (service, signer, device) = current.parts().expect("G2 current owner");
        assert_eq!(
            device.credential_digest(),
            g2.successor_device().credential_digest()
        );
        signer.check_device(device).expect("same signer under G2");
        assert_eq!(
            current_peer.context().continued_policy_statement(),
            Some(ti.statement_digest())
        );
        let j = service.stores().expect("current journal").0;
        assert!(
            j.next_message_id(peer_i.context(), session, 175).is_err(),
            "cached C1 view must fail even when T1 is unchanged"
        );
        j.next_message_id(current_peer.context(), session, 175)
            .expect("current G2/T1 existing session");
    }
    current.close();
    // Authenticated original configuration rollback models possession of an
    // old valid local snapshot. The current journal remains G2/T1. No fresh
    // credential, signature, journal or completion ACK is fabricated here.
    let mut rollback = open(&left.case);
    write(
        &rollback.active.as_ref().expect("config lease").database,
        &old_configuration,
    )
    .expect("restore exact old valid config row");
    rollback.close();
    assert!(
        open(&left.case)
            .activate_continued_session(
                request(&bundle, &left, &right, BootstrapRole::Initiator, session),
                Arc::clone(&pi),
                175,
            )
            .is_err(),
        "config C1 cannot return an owner over journal G2/C2"
    );
    let mut repair = open(&left.case);
    assert_eq!(
        row(&repair),
        old_configuration,
        "refusal must not silently rewrite the old evidence"
    );
    write(
        &repair.active.as_ref().expect("config lease").database,
        &current_configuration,
    )
    .expect("restore actual current fixture snapshot");
    repair.close();
    let (mut recovered, _) = open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            Arc::clone(&pi),
            175,
        )
        .expect("correct original configuration recovers current G2 owner");
    recovered.close();
    assert!(
        matches!(
            open(&left.case).activate_continued_session(
                request(&bundle, &left, &right, BootstrapRole::Initiator, session),
                Arc::clone(&pi),
                195
            ),
            Err(DurableError::Protocol(Error::Validity))
        ),
        "completed T is not authority after P1 expiry even while C1 is live"
    );
    let mut historical = open(&left.case);
    assert_eq!(
        historical
            .reconcile_policy_continuation(left.case.policy.historical(), &pi, 195)
            .expect("historical completion remains available"),
        renewal::committed(&g2)
    );
    historical.close();
    pi.close();
    assert!(
        open(&left.case)
            .activate_continued_session(
                request(&bundle, &left, &right, BootstrapRole::Initiator, session),
                Arc::clone(&pi),
                175
            )
            .is_err(),
        "closed P1 cannot return owner"
    );
    // A separately verified owner for the same live P1 cannot override an
    // authenticated local revocation observed by this exact journal.
    let independently_live = Arc::new(policy(&left.case, 2, 190, 175));
    let (mut revoking, _) = open(&left.case)
        .activate_continued_session(
            request(&bundle, &left, &right, BootstrapRole::Initiator, session),
            Arc::clone(&independently_live),
            175,
        )
        .expect("independently current P1 before revocation");
    let issued = left
        .case
        .root
        .issue_roster(
            4,
            Validity::new(100, 200).expect("revocation validity"),
            &[],
        )
        .expect("account root revocation");
    let pin = AccountPin::new(
        left.original.account_id(),
        left.case.root.public_key().expect("original root"),
        issued.checkpoint(),
        left.case.policy.family(),
    )
    .expect("independent revocation checkpoint");
    let revoked = pin
        .verify_roster(issued.as_bytes(), 175)
        .expect("authenticated revocation");
    revoking
        .parts()
        .expect("live owner")
        .0
        .stores()
        .expect("original journal")
        .0
        .install_roster(&revoked, 175)
        .expect("observe current local revocation");
    revoking.close();
    assert!(
        open(&left.case)
            .activate_continued_session(
                request(&bundle, &left, &right, BootstrapRole::Initiator, session),
                Arc::clone(&independently_live),
                175,
            )
            .is_err(),
        "live P1, valid config and retained T do not override journal revocation"
    );
    assert_eq!(
        fs::read(&left.case.paths.signer).expect("original sealed signer"),
        signer_i
    );
    assert_eq!(
        fs::read(&right.case.paths.signer).expect("original sealed signer"),
        signer_r
    );
    eprintln!("PUBLIC_JOINT_OWNER original_enrollment=true roles=2 exact_old_ciphertext=true bidirectional_data=true rekey_epoch=1 original_signer=true P1_expiry_refused=true");
}
