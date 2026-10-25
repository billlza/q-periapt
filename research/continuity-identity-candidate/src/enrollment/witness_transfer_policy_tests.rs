// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::tests::witness_handoff::transfer::Transfer;
use crate::{AnchorOperation, AnchorSubject};
#[path = "witness_transfer_policy_tests/successive.rs"]
mod successive;

#[test]
fn enrollment_witness_selection_policy_metadata_refuses_rollback_before_reporting_absence() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let old = fs::read(f.c.paths.installation.files()[1]).expect("owned pre-selection backup");
    let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
    let transfer = Transfer::new(
        &mut f.carrier.store.lock().expect("source"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        151,
    );
    transfer.set_time(153);
    let mut owner = transfer.adopt_parent(&f.c, 152);
    owner.close();
    let selected = fs::read(f.c.paths.installation.files()[1]).expect("selected child");
    fs::write(f.c.paths.installation.files()[1], old).expect("owned stale child replacement");
    let mut owner = open(&f.c);
    assert!(
        owner
            .recover_witnessed_policy_renewal_preparation(f.c.policy.historical())
            .is_err(),
        "stale child is not proof of absent preparation"
    );
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!(
        transfer.requests.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    fs::write(f.c.paths.installation.files()[1], selected).expect("restore exact selected child");
    let mut owner = open(&f.c);
    let client = transfer.client(&mut owner, &f.c);
    owner
        .prepare_witnessed_policy_renewal(
            f.c.policy.historical(),
            f.c.policy.historical(),
            &a.target,
            153,
            client,
        )
        .expect("same staged operation under exact restored selection");
}

#[test]
fn enrollment_witness_selection_prepares_new_policy_after_transfer() {
    new_policy_after_transfer(false);
}
#[test]
fn enrollment_witness_selection_closes_new_policy_after_transfer_and_expiry() {
    new_policy_after_transfer(true);
}
fn new_policy_after_transfer(closed: bool) {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
    let transfer = Transfer::new(
        &mut f.carrier.store.lock().expect("source"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        151,
    );
    transfer.set_time(153);
    let mut owner = transfer.adopt_parent(&f.c, 152);
    assert!(journal(&f).1.is_none());
    let carrier = transfer.client(&mut owner, &f.c);
    let p = owner
        .prepare_witnessed_policy_renewal(
            f.c.policy.historical(),
            f.c.policy.historical(),
            &a.target,
            153,
            carrier,
        )
        .expect("first P preparation under selected witness");
    let saved = journal(&f);
    let carrier = transfer.client(&mut owner, &f.c);
    assert_eq!(
        owner
            .prepare_witnessed_policy_renewal(
                f.c.policy.historical(),
                f.c.policy.historical(),
                &a.target,
                153,
                carrier
            )
            .expect("exact P retry"),
        p
    );
    assert_eq!(journal(&f), saved);
    let materials =
        a.request
            .materials(f.c.policy.historical(), f.c.policy.historical(), &a.target);
    {
        let mut target = transfer.target.lock().expect("target");
        assert!(
            target
                .prepare_policy_renewal(p, &a.proof, &materials, 153)
                .is_err(),
            "legacy management remains fenced"
        );
        target
            .transferred_control(&transfer.control)
            .expect("exact target authorization")
            .prepare_policy_renewal(p, &a.proof, &materials, 153)
            .expect("current target independent P approval");
    }
    transfer.reopen_target();
    let mut carrier = transfer.client(&mut owner, &f.c);
    if closed {
        transfer.set_time(301);
        transfer
            .target
            .lock()
            .expect("target")
            .transferred_control(&transfer.control)
            .expect("same cold target authorization")
            .close_policy_renewal(p, &a.proof.historical(), &materials.historical())
            .expect("independent exact policy closure after expiry");
        assert_eq!(
            owner
                .close_witnessed_policy_renewal(
                    p.operation(),
                    p.statement(),
                    f.c.policy.historical(),
                    &mut carrier
                )
                .expect("closed P and parent ACK after expiry"),
            State::Closed
        );
        owner.close();
        assert_eq!(journal(&f), (saved.0, None));
        transfer.reopen_target();
        return;
    }
    assert_eq!(
        owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                153,
                &mut carrier
            )
            .expect("current P and parent ACK"),
        State::Applied
    );
    owner.close();
    assert_eq!(journal(&f), (target(&saved), None));
    transfer.reopen_target();
}

#[test]
fn enrollment_witness_selection_finishes_original_policy_at_three_retained_stages() {
    for progress in [0, 1, 2] {
        let f = fixture();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        approve_witness(&f, &a, p);
        let sealed = journal(&f);
        let subject =
            AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
        if progress > 0 {
            let mut owner = open(&f.c);
            let mut client = policy_client(&f, &mut owner);
            assert_eq!(
                client
                    .exchange(subject, AnchorOperation::commit_policy_renewal(&p))
                    .expect("original witness applied")
                    .policy_renewal_state(&p)
                    .expect("exact P"),
                State::Applied
            );
            if progress == 2 {
                assert_eq!(
                    DeviceJournal::recover_policy_renewal(
                        f.c.paths.installation.files()[1],
                        JournalKey::open(&f.c.paths.wrapping).expect("same key"),
                        &f.original,
                        f.c.policy.historical(),
                        f.id,
                        p,
                        &mut client
                    )
                    .expect("installed original sealed target before parent terminal"),
                    State::Applied
                );
            }
            owner.close();
        }
        let before = journal(&f);
        let current_policy = if progress > 0 {
            a.target.historical()
        } else {
            f.c.policy.historical()
        };
        let transfer = Transfer::new(
            &mut f.carrier.store.lock().expect("source"),
            &f.c,
            &f.original,
            &f.original,
            current_policy,
            subject,
            151,
        );
        transfer.set_time(153);
        let mut owner = open(&f.c);
        owner
            .prepare_witness_handoff(f.c.policy.historical(), transfer.plan.clone(), || Ok(152))
            .expect("parent preparation");
        owner
            .adopt_witness_handoff(
                f.c.policy.historical(),
                transfer.plan.clone(),
                &transfer.receipt,
            )
            .expect("same approved target");
        assert_eq!(
            journal(&f),
            before,
            "transfer did not alter original image or pending target"
        );
        let client = owner
            .current_witness_anchor_client(
                f.c.policy.historical(),
                transfer.plan.clone(),
                transfer.carrier(),
                Duration::from_secs(3),
            )
            .expect("current carrier");
        assert!(
            owner
                .activate_witnessed_policy_renewal(f.c.policy.historical(), &a.target, 153, client)
                .is_err(),
            "unretired parent cannot release an owner"
        );
        let mut owner = open(&f.c);
        let mut client = owner
            .current_witness_anchor_client(
                f.c.policy.historical(),
                transfer.plan.clone(),
                transfer.carrier(),
                Duration::from_secs(3),
            )
            .expect("original signer after failed early release");
        assert_eq!(
            owner
                .commit_witnessed_policy_renewal(
                    &p,
                    f.c.policy.historical(),
                    &a.target,
                    153,
                    &mut client
                )
                .expect("original P and parent terminal/ACK"),
            State::Applied
        );
        assert_eq!(
            owner
                .witnessed_policy_renewal_progress()
                .expect("parent receipt"),
            Some(Progress::Terminal {
                proposal: p,
                target: a.target.checkpoint(),
                disposition: Disposition::Applied,
                retired: true
            })
        );
        owner.close();
        assert_eq!(journal(&f), (target(&sealed), None));
        let mut owner = open(&f.c);
        let client = owner
            .current_witness_anchor_client(
                f.c.policy.historical(),
                transfer.plan.clone(),
                transfer.carrier(),
                Duration::from_secs(3),
            )
            .expect("cold current carrier");
        let mut active = owner
            .activate_witnessed_policy_renewal(f.c.policy.historical(), &a.target, 153, client)
            .expect("same installation under new policy");
        assert_eq!(
            active
                .parts()
                .expect("owners")
                .0
                .stores()
                .expect("children")
                .0
                .identity()
                .expect("journal"),
            f.id
        );
        active.close();
    }
}
