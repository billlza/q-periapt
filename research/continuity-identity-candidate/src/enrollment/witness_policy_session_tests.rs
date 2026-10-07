// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public owners, real original sessions and independent witness release.
use super::*;
use crate::{
    BootstrapBundle, BootstrapContext, BootstrapMaterials, BootstrapRequirements, BootstrapRole,
    DirectoryExpectation, ExpectedDevice, FanoutInput, FanoutTarget, InitiationId, ManifestContext,
};
#[path = "witness_policy_fanout_tests.rs"]
pub(in crate::enrollment::tests::witness_renewal) mod fanout;

pub(in crate::enrollment::tests::witness_renewal) struct Endpoint {
    pub(in crate::enrollment::tests::witness_renewal) f: Fixture,
    pub(in crate::enrollment::tests::witness_renewal) owner: EnrolledDevice,
    pub(in crate::enrollment::tests::witness_renewal) certificate: Vec<u8>,
    pin: AccountPin,
}
pub(in crate::enrollment::tests::witness_renewal) fn endpoint(f: Fixture) -> Endpoint {
    let mut owner = open(&f.c);
    let certificate = match owner.image().expect("configuration").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("original enrollment must be accepted"),
    }
    .expect("accepted original enrollment");
    let pin = AccountPin::new(
        f.original.account_id(),
        f.c.intent.root.clone(),
        f.original.roster().checkpoint(),
        f.c.policy.family(),
    )
    .expect("independent original pin");
    let anchor = client(&f, &mut owner, 150);
    let owner = owner
        .activate(&f.c.policy, 150, Some(anchor))
        .expect("original witnessed owner");
    Endpoint {
        f,
        owner,
        certificate,
        pin,
    }
}
pub(in crate::enrollment::tests::witness_renewal) fn requirements<'a>(
    a: &'a Endpoint,
    b: &'a Endpoint,
) -> BootstrapRequirements<'a> {
    BootstrapRequirements {
        initiator: ExpectedDevice::new(&a.pin, a.f.original.device_id(), a.f.original.generation())
            .expect("initiator"),
        responder: ExpectedDevice::new(&b.pin, b.f.original.device_id(), b.f.original.generation())
            .expect("responder"),
        quality: PrekeyQuality::OneTimeBoth,
        directory: DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
    }
}
pub(in crate::enrollment::tests::witness_renewal) fn bundle(
    a: &Endpoint,
    b: &mut Endpoint,
) -> BootstrapBundle {
    let (service, signer, device) = b.owner.parts().expect("original responder");
    let validity = Validity::new(100, b.f.c.policy.validity().until().min(160))
        .expect("fixture advertisement within original policy");
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
                    &b.f.c.policy,
                    device,
                    PrekeyId::from_trusted_state([u8::try_from(i + 1).expect("ID"); 32])
                        .expect("ID"),
                    kind,
                    validity,
                    150,
                )
                .expect("real owned prekey"),
        );
    }
    let manifest = signer
        .issue_manifest(
            device,
            ManifestContext::new(
                1,
                b.f.c.policy.runtime.trusted_state().digest(),
                crate::bootstrap_suite_digest(),
                [99; 32],
                validity,
            )
            .expect("scope"),
            &leaves,
        )
        .expect("original signed manifest");
    let verified = device
        .verify_manifest(manifest.as_bytes(), 150)
        .expect("manifest");
    let mut proofs = std::collections::BTreeMap::new();
    for i in 0..manifest.leaf_count() {
        let p = manifest.proof(i).expect("proof");
        proofs.insert(
            verified.verify_leaf(&p, 150).expect("leaf").kind() as u8,
            p.encode().expect("wire"),
        );
    }
    let proof = |kind: LeafKind| proofs.get(&(kind as u8)).expect("proof").as_slice();
    BootstrapBundle::from_materials(
        PrekeyQuality::OneTimeBoth,
        BootstrapMaterials {
            initiator_credential: &a.certificate,
            initiator_roster: a.f.original.roster().as_bytes(),
            responder_credential: &b.certificate,
            responder_roster: b.f.original.roster().as_bytes(),
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(LeafKind::SignedClassical),
            last_resort_pq: proof(LeafKind::LastResortPq),
            one_time_classical: Some(proof(LeafKind::OneTimeClassical)),
            one_time_pq: Some(proof(LeafKind::OneTimePq)),
        },
    )
    .expect("real enrolled public bundle")
}
fn activate(f: &Fixture, policy: &VerifiedSessionPolicy) -> EnrolledDevice {
    let mut owner = open(&f.c);
    let anchor = client(f, &mut owner, 170);
    owner
        .activate_witnessed_policy_continuation(f.c.policy.historical(), policy, 170, anchor)
        .expect("fresh witnessed continued owner")
}
fn journal(owner: &mut EnrolledDevice) -> &mut DeviceJournal {
    owner.parts().expect("owners").0.stores().expect("stores").0
}
fn send(
    sender: &mut EnrolledDevice,
    receiver: &mut EnrolledDevice,
    sc: &BootstrapContext,
    rc: &BootstrapContext,
    session: [u8; 32],
) {
    let id = journal(sender)
        .next_message_id(sc, session, 170)
        .expect("new message");
    let wire = journal(sender)
        .send_message(sc, session, id, b"P1 traffic", b"new", 170)
        .expect("send");
    assert_eq!(
        journal(receiver)
            .receive_message(rc, session, &wire, b"new", 170)
            .expect("receive")
            .as_bytes(),
        b"P1 traffic"
    );
}

#[test]
fn real_witnessed_session_reopens_after_p0_expiry_and_fences_cached_message_and_fanout() {
    let first = fixture_with_policy_expiry(Some(160));
    let second = fixture_on_witness(
        Arc::clone(&first._witness_dir),
        first.pin.clone(),
        first.carrier.clone(),
        Some(160),
    );
    let mut a = endpoint(first);
    let mut b = endpoint(second);
    assert_eq!(a.f.c.policy.checkpoint(), b.f.c.policy.checkpoint());
    let bundle = bundle(&a, &mut b);
    let ci = Arc::new(
        bundle
            .verify(
                Arc::new(super::super::super::policy_continuation::policy(
                    &a.f.c, 1, 160, 150,
                )),
                requirements(&a, &b),
                150,
            )
            .expect("initiator context"),
    );
    let cr = Arc::new(
        bundle
            .verify(
                Arc::new(super::super::super::policy_continuation::policy(
                    &b.f.c, 1, 160, 150,
                )),
                requirements(&a, &b),
                150,
            )
            .expect("responder context"),
    );
    let id = InitiationId::generate().expect("initiation");
    let (session, old_id, old_wire);
    {
        let (is, ik, _) = a.owner.parts().expect("initiator");
        let (rs, rk, _) = b.owner.parts().expect("responder");
        let (ij, ia) = is.stores().expect("stores");
        let (rj, ra) = rs.stores().expect("stores");
        let initial = ij.initiate(Arc::clone(&ci), id, ik, 150).expect("initial");
        let reply = rj
            .respond_from_inventory(Arc::clone(&cr), &initial, rk, 150)
            .expect("reply");
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
        let archive = ij.archive_session_closure(&ci, session).expect("archive");
        ia.retain(ij, &ci, session, &archive)
            .expect("retained archive");
        let archive = rj.archive_session_closure(&cr, session).expect("archive");
        ra.retain(rj, &cr, session, &archive)
            .expect("retained archive");
        old_id = ij.next_message_id(&ci, session, 150).expect("message ID");
        old_wire = ij
            .send_message(&ci, session, old_id, b"original ciphertext", b"old", 150)
            .expect("message");
    }
    a.owner.close();
    b.owner.close();
    let ga = grant(&a.f, &a.f.original, 2, 210);
    let gb = grant(&b.f, &b.f.original, 2, 210);
    let pa = Arc::new(super::super::super::policy_continuation::policy(
        &a.f.c, 2, 190, 170,
    ));
    let pb = Arc::new(super::super::super::policy_continuation::policy(
        &b.f.c, 2, 190, 170,
    ));
    for (e, g, p) in [(&mut a, &ga, &pa), (&mut b, &gb, &pb)] {
        let scope = super::super::super::policy_continuation::scope(&e.f.c, g, e.f.id);
        let t =
            super::super::super::policy_continuation::joint(&e.f.c, g, &scope, &e.f.c.policy, p);
        let proposal = prepare_policy(&e.f, g, Some(&t), p);
        let mut owner = open(&e.f.c);
        let mut anchor = client(&e.f, &mut owner, 170);
        owner
            .commit_witnessed_policy_continuation(
                &proposal,
                e.f.c.policy.historical(),
                p,
                170,
                &mut anchor,
            )
            .expect("exact joint transaction");
        owner.close();
        e.owner = activate(&e.f, p);
    }
    a.owner
        .parts()
        .expect("owner")
        .0
        .admit_peer_credential_renewal(&gb, gb.operation(), &pa, 170)
        .expect("independent peer renewal under P1");
    b.owner
        .parts()
        .expect("owner")
        .0
        .admit_peer_credential_renewal(&ga, ga.operation(), &pb, 170)
        .expect("independent peer renewal under P1");
    let ri = bundle
        .request_historical_reopen(
            Arc::new(a.f.c.policy.historical().clone()),
            requirements(&a, &b),
            BootstrapRole::Initiator,
            session,
            170,
        )
        .expect("historical bundle");
    let rr = bundle
        .request_historical_reopen(
            Arc::new(b.f.c.policy.historical().clone()),
            requirements(&a, &b),
            BootstrapRole::Responder,
            session,
            170,
        )
        .expect("historical bundle");
    let pi = a
        .owner
        .parts()
        .expect("owner")
        .0
        .reopen_continued_peer(ri, Arc::clone(&pa), 170)
        .expect("continued initiator");
    let pr = b
        .owner
        .parts()
        .expect("owner")
        .0
        .reopen_continued_peer(rr, Arc::clone(&pb), 170)
        .expect("continued responder");
    assert_eq!(
        journal(&mut a.owner)
            .resume_message(pi.context(), session, old_id, 170)
            .expect("original outbox"),
        old_wire
    );
    assert_eq!(
        journal(&mut b.owner)
            .receive_message(pr.context(), session, &old_wire, b"old", 170)
            .expect("real peer decryption")
            .as_bytes(),
        b"original ciphertext"
    );
    send(
        &mut a.owner,
        &mut b.owner,
        pi.context(),
        pr.context(),
        session,
    );
    send(
        &mut b.owner,
        &mut a.owner,
        pr.context(),
        pi.context(),
        session,
    );
    {
        let (is, ik, _) = a.owner.parts().expect("initiator owner");
        let (rs, rk, _) = b.owner.parts().expect("responder owner");
        let ij = is.stores().expect("initiator journal").0;
        let rj = rs.stores().expect("responder journal").0;
        let offer = ij
            .prepare_rekey_offer(pi.context(), session, ik, 170)
            .expect("offer");
        let response = rj
            .respond_rekey_offer(pr.context(), session, &offer, rk, 170)
            .expect("response");
        let final_wire = ij
            .accept_rekey_response(pi.context(), session, &response, ik, 170)
            .expect("final");
        let receipt = rj
            .finish_rekey(pr.context(), session, &final_wire, rk, 170)
            .expect("receipt");
        ij.accept_rekey_receipt(pi.context(), session, &receipt, 170)
            .expect("confirmed epoch");
        assert_eq!(
            ij.rekey_progress(pi.context(), session)
                .expect("epoch")
                .confirmed_epoch,
            1
        );
        assert_eq!(
            rj.rekey_progress(pr.context(), session)
                .expect("epoch")
                .confirmed_epoch,
            1
        );
    }
    send(
        &mut a.owner,
        &mut b.owner,
        pi.context(),
        pr.context(),
        session,
    );
    let cached_id = journal(&mut a.owner)
        .next_message_id(pi.context(), session, 170)
        .expect("cached ID");
    journal(&mut a.owner)
        .send_message(
            pi.context(),
            session,
            cached_id,
            b"cached individual",
            b"new",
            170,
        )
        .expect("cached message");
    let targets = [FanoutTarget {
        context: pi.context(),
        session,
    }];
    let batch = journal(&mut a.owner).next_fanout_id().expect("batch");
    let fanout = journal(&mut a.owner)
        .send_account_message(
            FanoutInput {
                id: batch,
                account: b.f.original.account_id(),
                targets: &targets,
                plaintext: b"cached batch",
                associated_data: b"batch",
            },
            170,
        )
        .expect("actual committed fanout");
    assert_eq!(fanout.len(), 1);
    assert!(a.f.carrier.requests.lock().expect("trace").contains(&10));
    a.owner.close();
    {
        let request = bundle
            .request_historical_reopen(
                Arc::new(a.f.c.policy.historical().clone()),
                requirements(&a, &b),
                BootstrapRole::Initiator,
                session,
                170,
            )
            .expect("standalone original request");
        let mut enrollment = open(&a.f.c);
        let anchor = client(&a.f, &mut enrollment, 170);
        enrollment.close();
        let reopened = DeviceInstallation::reopen_continued_session(
            a.f.c.paths.installation.clone(),
            JournalKey::open(&a.f.c.paths.wrapping).expect("key"),
            request,
            Arc::clone(&pa),
            170,
            Some(anchor),
        )
        .expect("public installation witness session reopen");
        let (mut service, context) = reopened.into_parts();
        assert!(service
            .stores()
            .expect("stores")
            .0
            .resume_message(&context, session, cached_id, 170,)
            .is_ok());
        service.close();
    }
    for fanout in [false, true] {
        a.f.carrier.clock.store(170, Ordering::SeqCst);
        a.owner = activate(&a.f, &pa);
        // Ordinary head remains exact and the credential is still live. Only
        // the independent witness's P1 expiry denies this stale-time client.
        a.f.carrier.clock.store(200, Ordering::SeqCst);
        a.f.carrier.requests.lock().expect("trace").clear();
        if fanout {
            let result = journal(&mut a.owner).resume_account_message(batch, &targets, 170);
            assert!(
                matches!(&result, Err(DurableError::Anchor(e))
                if matches!(e.as_ref(),crate::AnchorClientError::AuthorityDenied)),
                "released_members={:?}, error={:?}",
                result.as_ref().ok().map(Vec::len),
                result.as_ref().err()
            );
        } else {
            assert!(
                matches!(journal(&mut a.owner).resume_message(pi.context(), session, cached_id, 170),
                Err(DurableError::Anchor(e)) if matches!(*e,crate::AnchorClientError::AuthorityDenied))
            );
        }
        assert!(a.f.carrier.requests.lock().expect("trace").contains(&10));
        a.owner.close();
    }
    a.f.carrier.clock.store(170, Ordering::SeqCst);
    a.owner = activate(&a.f, &pa);
    let closing = Arc::clone(&pa);
    *a.f.carrier.after_reply.lock().expect("hook") = Some((10, Box::new(move || closing.close())));
    assert!(matches!(
        journal(&mut a.owner).resume_account_message(batch, &targets, 170),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert!(a
        .f
        .carrier
        .after_reply
        .lock()
        .expect("hook consumed")
        .is_none());
    a.owner.close();
}
