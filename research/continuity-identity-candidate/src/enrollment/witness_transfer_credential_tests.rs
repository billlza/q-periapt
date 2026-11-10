// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Finish the retained real G transaction through the original parent after transfer.
use super::*;
use crate::enrollment::tests::witness_handoff::transfer::Transfer;
use crate::{AnchorOperation, AnchorSubject, LeafKind, PrekeyId, WitnessJournalAdoptionState};
#[path = "witness_transfer_credential_tests/successive.rs"]
mod successive;

#[test]
fn enrollment_witness_selection_prepares_new_credential_after_transfer() {
    new_credential_after_transfer(false);
}
#[test]
fn enrollment_witness_selection_closes_new_credential_after_transfer_and_expiry() {
    new_credential_after_transfer(true);
}
fn new_credential_after_transfer(closed: bool) {
    let f = fixture();
    let g = grant(&f, &f.original, 2, 250);
    let mut owner = open(&f.c);
    owner
        .stage_credential_renewal(&g, g.operation(), &f.c.policy, 170)
        .expect("original grant");
    owner.close();
    let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
    let transfer = Transfer::new(
        &mut f.carrier.store.lock().expect("source"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        175,
    );
    transfer.set_time(190);
    let mut owner = transfer.adopt_parent(&f.c, 180);
    assert!(disk(&f).1.is_none(), "no pre-transfer G journal target");
    let carrier = transfer.client(&mut owner, &f.c);
    let proposal = owner
        .prepare_witnessed_credential_renewal(&f.c.policy, 190, carrier)
        .expect("first preparation under selected witness");
    let saved = disk(&f);
    let carrier = transfer.client(&mut owner, &f.c);
    assert_eq!(
        owner
            .prepare_witnessed_credential_renewal(&f.c.policy, 190, carrier)
            .expect("same proposal retry"),
        proposal
    );
    assert_eq!(disk(&f), saved, "retry preserves exact sealed target");
    {
        let mut target = transfer.target.lock().expect("target");
        assert!(
            target
                .prepare_credential_renewal(proposal, &g, &f.c.policy, 190)
                .is_err(),
            "legacy management remains fenced"
        );
        target
            .transferred_control(&transfer.control)
            .expect("exact target authorization")
            .prepare_credential_renewal(proposal, &g, &f.c.policy, 190)
            .expect("independent current authority approval");
    }
    transfer.reopen_target();
    let mut carrier = transfer.client(&mut owner, &f.c);
    if closed {
        transfer.set_time(290);
        transfer
            .target
            .lock()
            .expect("target")
            .transferred_control(&transfer.control)
            .expect("same cold target authorization")
            .close_credential_renewal(proposal, g.historical(), f.c.policy.historical())
            .expect("independent exact closure after expiry");
        let state = owner
            .close_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                290,
                &mut carrier,
            )
            .expect("closed G and parent ACK after expiry");
        assert!(
            matches!(state, CredentialRenewalStatus::Closed { operation, statement, .. }
            if operation == g.operation() && statement == g.statement_digest())
        );
        owner.close();
        assert_eq!(disk(&f), (saved.0, None));
        transfer.reopen_target();
        return;
    }
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                190,
                &mut carrier
            )
            .expect("current target commit and parent ACK"),
        renewal::committed(&g)
    );
    owner.close();
    assert!(disk(&f).1.is_none());
    transfer.reopen_target();
}

#[test]
fn enrollment_witness_selection_completes_original_pending_credential_and_releases_parent() {
    let f = fixture();
    let mut original = open(&f.c);
    let old_client = client(&f, &mut original, 150);
    let mut device = original
        .activate(&f.c.policy, 150, Some(old_client))
        .expect("original live owner");
    let (service, _, local) = device.parts().expect("owners");
    service
        .stores()
        .expect("journal")
        .0
        .generate_prekey(
            &f.c.policy,
            local,
            PrekeyId::from_trusted_state([79; 32]).expect("retained ID"),
            LeafKind::OneTimePq,
            Validity::new(100, 160).expect("original interval"),
            150,
        )
        .expect("actual retained secret");
    device.close();
    let g = grant(&f, &f.original, 2, 250);
    let proposal = prepare(&f, &g, 170);
    let saved = disk(&f);
    assert!(saved.1.is_some());
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("unchanged subject");
    let transfer = Transfer::new(
        &mut f.carrier.store.lock().expect("source"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        175,
    );
    transfer.set_time(190);
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .prepare_witness_handoff(f.c.policy.historical(), transfer.plan.clone(), || Ok(180))
            .expect("parent fence"),
        WitnessJournalAdoptionState::Prepared
    );
    owner
        .adopt_witness_handoff(
            f.c.policy.historical(),
            transfer.plan.clone(),
            &transfer.receipt,
        )
        .expect("dual selection");
    assert_eq!(
        disk(&f),
        saved,
        "selection cannot reseal or drop original G target"
    );
    let mut carrier = owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            transfer.plan.clone(),
            transfer.carrier(),
            Duration::from_secs(3),
        )
        .expect("original retained signer");
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                190,
                &mut carrier
            )
            .expect("same original G commit, parent terminal and ACK"),
        renewal::committed(&g)
    );
    assert_eq!(
        carrier
            .exchange(subject, AnchorOperation::query())
            .expect("fresh current head")
            .observed_head(),
        proposal.target_head()
    );
    owner.close();
    assert!(disk(&f).1.is_none());
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("retained G history"),
        renewal::committed(&g)
    );
    let carrier = owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            transfer.plan.clone(),
            transfer.carrier(),
            Duration::from_secs(3),
        )
        .expect("cold parent client");
    let mut active = owner
        .activate(&f.c.policy, 190, Some(carrier))
        .expect("original installation with renewed credential");
    let (service, _, current) = active.parts().expect("released controlled owners");
    assert_eq!(
        current.credential_digest(),
        g.successor_device().credential_digest()
    );
    assert_eq!(
        service
            .stores()
            .expect("same children")
            .0
            .identity()
            .expect("journal ID"),
        f.id
    );
    active.close();
}
