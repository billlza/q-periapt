// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::tests::witness_handoff::transfer::Transfer;
use crate::AnchorSubject;
#[path = "witness_transfer_roster_tests/successive.rs"]
mod successive;

#[test]
fn enrollment_witness_selection_prepares_new_roster_after_transfer() {
    new_roster_after_transfer(false);
}
#[test]
fn enrollment_witness_selection_closes_new_roster_after_transfer_and_expiry() {
    new_roster_after_transfer(true);
}
fn new_roster_after_transfer(closed: bool) {
    let c = case(false);
    let subject = AnchorSubject::for_device(c.f.id, &c.f.original, &c.f.c.policy).expect("subject");
    let transfer = Transfer::new(
        &mut c.f.carrier.store.lock().expect("source"),
        &c.f.c,
        &c.f.original,
        &c.previous,
        c.policy.historical(),
        subject,
        151,
    );
    transfer.set_time(153);
    let mut owner = transfer.adopt_parent(&c.f.c, 152);
    assert!(journal(&c.f).1.is_none());
    let operation = RosterRefreshId::generate().expect("R operation");
    let carrier = transfer.client(&mut owner, &c.f.c);
    let p = owner
        .prepare_witnessed_roster_refresh(
            operation,
            c.f.c.policy.historical(),
            &c.policy,
            &c.target,
            153,
            carrier,
        )
        .expect("first R preparation under selected witness");
    let saved = journal(&c.f);
    let carrier = transfer.client(&mut owner, &c.f.c);
    assert_eq!(
        owner
            .prepare_witnessed_roster_refresh(
                operation,
                c.f.c.policy.historical(),
                &c.policy,
                &c.target,
                153,
                carrier
            )
            .expect("exact R retry"),
        p
    );
    assert_eq!(journal(&c.f), saved);
    {
        let mut target = transfer.target.lock().expect("target");
        assert!(
            target
                .prepare_roster_refresh(p, &c.previous, &c.target, &c.policy, 153)
                .is_err(),
            "legacy management remains fenced"
        );
        target
            .transferred_control(&transfer.control)
            .expect("exact target authorization")
            .prepare_roster_refresh(p, &c.previous, &c.target, &c.policy, 153)
            .expect("current target independent R approval");
    }
    transfer.reopen_target();
    let mut carrier = transfer.client(&mut owner, &c.f.c);
    if closed {
        transfer.set_time(301);
        transfer
            .target
            .lock()
            .expect("target")
            .transferred_control(&transfer.control)
            .expect("same cold target authorization")
            .close_roster_refresh(p, &c.previous, &c.target, c.policy.historical())
            .expect("independent exact roster closure after expiry");
        assert_eq!(
            owner
                .close_witnessed_roster_refresh(&p, c.f.c.policy.historical(), &mut carrier)
                .expect("closed R and parent ACK after expiry"),
            RState::Closed
        );
        owner.close();
        assert_eq!(journal(&c.f), (saved.0, None));
        transfer.reopen_target();
        return;
    }
    assert_eq!(
        owner
            .commit_witnessed_roster_refresh(
                &p,
                c.f.c.policy.historical(),
                &c.policy,
                153,
                &mut carrier
            )
            .expect("current R and original parent ACK"),
        RState::Applied
    );
    owner.close();
    assert_eq!(journal(&c.f), (target_image(&saved), None));
    transfer.reopen_target();
}

#[test]
fn enrollment_witness_selection_finishes_original_roster_with_original_or_adopted_policy() {
    for adopted in [false, true] {
        let c = case(adopted);
        let p = prepare_original(&c);
        let saved = journal(&c.f);
        witness_prepare(&c, p);
        let subject = AnchorSubject::for_device(c.f.id, &c.f.original, &c.f.c.policy)
            .expect("immutable subject");
        let transfer = Transfer::new(
            &mut c.f.carrier.store.lock().expect("source"),
            &c.f.c,
            &c.f.original,
            &c.previous,
            c.policy.historical(),
            subject,
            151,
        );
        transfer.set_time(153);
        let mut owner = open(&c.f.c);
        owner
            .prepare_witness_handoff(c.f.c.policy.historical(), transfer.plan.clone(), || Ok(152))
            .expect("prepare parent");
        owner
            .adopt_witness_handoff(
                c.f.c.policy.historical(),
                transfer.plan.clone(),
                &transfer.receipt,
            )
            .expect("select target");
        assert_eq!(journal(&c.f), saved, "no replacement R intent");
        let mut carrier = owner
            .current_witness_anchor_client(
                c.f.c.policy.historical(),
                transfer.plan.clone(),
                transfer.carrier(),
                Duration::from_secs(3),
            )
            .expect("retained signer");
        assert_eq!(
            owner
                .commit_witnessed_roster_refresh(
                    &p,
                    c.f.c.policy.historical(),
                    &c.policy,
                    153,
                    &mut carrier
                )
                .expect("exact R commit and parent ACK"),
            RState::Applied
        );
        owner.close();
        check_terminal(&c, p, false, true);
        assert_eq!(journal(&c.f), (target_image(&saved), None));
        let mut owner = open(&c.f.c);
        let carrier = owner
            .current_witness_anchor_client(
                c.f.c.policy.historical(),
                transfer.plan.clone(),
                transfer.carrier(),
                Duration::from_secs(3),
            )
            .expect("reopened original selection");
        let mut active = if adopted {
            owner.activate_witnessed_policy_renewal(
                c.f.c.policy.historical(),
                &c.policy,
                153,
                carrier,
            )
        } else {
            owner.activate(&c.policy, 153, Some(carrier))
        }
        .expect("current original installation");
        let (service, signer, device) = active.parts().expect("original owners");
        signer.check_device(device).expect("same retained identity");
        assert_eq!(device.roster().checkpoint(), p.scope().target);
        assert_eq!(
            service
                .stores()
                .expect("same journal")
                .0
                .identity()
                .expect("ID"),
            c.f.id
        );
        active.close();
    }
}
