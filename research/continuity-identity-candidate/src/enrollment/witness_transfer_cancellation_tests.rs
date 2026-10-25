// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Grant-only cleanup through the original selected Witness and retained parent.
use super::*;
use crate::enrollment::tests::witness_handoff::transfer::Transfer;
use crate::{AnchorSubject, LeafKind, PrekeyId};
#[path = "witness_transfer_cancellation_tests/faults.rs"]
mod faults;
#[path = "witness_transfer_cancellation_tests/process.rs"]
mod process;
#[path = "witness_transfer_cancellation_tests/validation.rs"]
mod validation;

#[test]
fn untransferred_cancellation_preserves_original_grant_without_signer_or_rpc() {
    let f = fixture();
    let g = grant(&f, &f.original, 2, 250);
    open(&f.c)
        .stage_credential_renewal(&g, g.operation(), &f.c.policy, 170)
        .expect("stage");
    let before = disk(&f);
    let calls = f.carrier.requests.lock().expect("requests").len();
    let retained = f.c.paths.signer.with_extension("retained-for-test");
    fs::rename(&f.c.paths.signer, &retained).expect("hold owned signer");
    let mut owner = open(&f.c);
    let cancellation = owner
        .prepare_witnessed_credential_cancellation(f.c.policy.historical(), 290)
        .expect("historical local reservation");
    assert_eq!(cancellation.operation(), g.operation());
    assert_eq!(
        owner
            .prepare_witnessed_credential_cancellation(f.c.policy.historical(), 290)
            .expect("exact retry"),
        cancellation
    );
    owner.close();
    assert!(disk(&f).0 == before.0);
    assert_eq!(
        f.carrier.requests.lock().expect("same requests").len(),
        calls
    );
    assert!(!f.c.paths.signer.exists());
    fs::rename(retained, &f.c.paths.signer).expect("restore exact owned signer");
}

#[test]
fn enrollment_witness_selection_reserves_grant_only_cancel_without_device_signer() {
    reserve_after_transfer(true);
}
#[test]
fn enrollment_witness_selection_reserves_grant_only_cancel_with_retained_signer() {
    reserve_after_transfer(false);
}
fn staged_transfer() -> (Fixture, crate::VerifiedCredentialRenewal, Transfer) {
    let f = fixture();
    let mut original = open(&f.c);
    let carrier = client(&f, &mut original, 150);
    let mut device = original
        .activate(&f.c.policy, 150, Some(carrier))
        .expect("original owner");
    let (service, _, local) = device.parts().expect("original parts");
    service
        .stores()
        .expect("original journal")
        .0
        .generate_prekey(
            &f.c.policy,
            local,
            PrekeyId::from_trusted_state([87; 32]).expect("prekey ID"),
            LeafKind::OneTimePq,
            Validity::new(100, 160).expect("retained expired leaf"),
            150,
        )
        .expect("real sealed secret before transfer");
    device.close();
    let g = grant(&f, &f.original, 2, 250);
    open(&f.c)
        .stage_credential_renewal(&g, g.operation(), &f.c.policy, 170)
        .expect("original staged grant");
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
    transfer.adopt_parent(&f.c, 180).close();
    (f, g, transfer)
}
fn reserve_after_transfer(missing_signer: bool) {
    let (f, g, transfer) = staged_transfer();
    let before = disk(&f);
    assert!(before.1.is_none());
    let retained = f.c.paths.signer.with_extension("retained-for-test");
    if missing_signer {
        fs::rename(&f.c.paths.signer, &retained).expect("hold this fixture's original signer");
    }
    assert!(matches!(
        open(&f.c).prepare_witnessed_credential_cancellation(f.c.policy.historical(), 290),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        disk(&f),
        before,
        "an absent independent plan cannot reserve work"
    );
    let mut owner = open(&f.c);
    let cancellation = owner
        .prepare_witnessed_credential_cancellation_with_witness_plan(
            f.c.policy.historical(),
            transfer.plan.clone(),
            290,
        )
        .expect("post-transfer reservation is local and needs no device signer");
    assert_eq!(cancellation.operation(), g.operation());
    assert_eq!(cancellation.transaction_statement(), g.statement_digest());
    let reserved = disk(&f);
    assert!(reserved.1.is_some());
    assert_eq!(
        owner
            .prepare_witnessed_credential_cancellation_with_witness_plan(
                f.c.policy.historical(),
                transfer.plan.clone(),
                290
            )
            .expect("exact local retry"),
        cancellation
    );
    assert_eq!(disk(&f), reserved);
    owner.close();
    assert_eq!(disk(&f).0, before.0, "no new target image");
    assert_eq!(
        transfer.requests.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    if missing_signer {
        fs::rename(retained, &f.c.paths.signer).expect("restore this fixture's exact signer");
    }
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .prepare_witnessed_credential_cancellation_with_witness_plan(
                f.c.policy.historical(),
                transfer.plan.clone(),
                290
            )
            .expect("reopen exact local reservation"),
        cancellation
    );
    transfer.set_time(290);
    let mut carrier = transfer.client(&mut owner, &f.c);
    assert_eq!(
        owner
            .reconcile_witnessed_credential_renewal(
                g.operation(),
                cancellation.transaction_statement(),
                f.c.policy.historical(),
                290,
                &mut carrier,
            )
            .expect("unavailable stays pending"),
        renewal::pending(&g)
    );
    assert_eq!(disk(&f), reserved);
    {
        let mut target = transfer.target.lock().expect("current target");
        assert!(target
            .close_unprepared_credential_renewal(cancellation, &g, &f.c.policy)
            .is_err());
        for _ in 0..2 {
            assert_eq!(
                target
                    .transferred_control(&transfer.control)
                    .expect("exact committed authorization")
                    .close_unprepared_credential_renewal(
                        cancellation,
                        g.historical(),
                        f.c.policy.historical()
                    )
                    .expect("independent exact cancellation"),
                crate::AnchorCredentialCancellationState::Closed
            );
        }
    }
    transfer.reopen_target();
    assert_eq!(
        owner
            .reconcile_witnessed_credential_renewal(
                g.operation(),
                cancellation.transaction_statement(),
                f.c.policy.historical(),
                290,
                &mut carrier,
            )
            .expect("closed original operation and ACK"),
        CredentialRenewalStatus::Closed {
            operation: g.operation(),
            statement: cancellation.transaction_statement(),
            target: g.successor_device().roster().checkpoint(),
        }
    );
    owner.close();
    assert_eq!(
        disk(&f),
        before,
        "cleanup retains the exact original encrypted image"
    );
    assert_eq!(
        open(&f.c)
            .credential_renewal_status()
            .expect("cold original parent status"),
        CredentialRenewalStatus::Closed {
            operation: g.operation(),
            statement: cancellation.transaction_statement(),
            target: g.successor_device().roster().checkpoint()
        }
    );
}
