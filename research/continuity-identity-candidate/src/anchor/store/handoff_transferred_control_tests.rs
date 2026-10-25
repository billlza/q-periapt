// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Store authority tests use explicit target digests; enrollment tests seal real targets.
use super::*;

fn authorize(f: &mut Prepared) -> crate::AnchorHandoffClientAuthorizationReceipt {
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("exact client authorization")
}
fn policy_materials(c: &PolicyCase) -> crate::PolicyRenewalMaterials<'_> {
    crate::PolicyRenewalMaterials {
        original: &c.original,
        previous: &c.original,
        target: &c.target,
        original_device: &c.device,
        current_device: &c.device,
    }
}
#[test]
fn transferred_control_refuses_foreign_receipt_subject_approval_and_expired_target() {
    let mut f = Prepared::new(None);
    let mut other = Prepared::new(None);
    let foreign = authorize(&mut other);
    let before = f.original_entry();
    assert!(f.active.transferred_control(&foreign).is_err());
    let receipt = authorize(&mut f);
    assert!(f.active.transferred_control(&foreign).is_err());
    assert_eq!(f.original_entry(), before);
    let proof = f.c.approval(&f.c.original, None, &f.c.target);
    let p = f.c.proposal(&proof, f.c.initial, 245);
    let bad_proof = f.c.approval(&f.c.original, None, &f.c.target);
    let other_proof = other.c.approval(&other.c.original, None, &other.c.target);
    let other_p = other.c.proposal(&other_proof, other.c.initial, 246);
    let m = policy_materials(&f.c);
    assert!(f.active.prepare_policy_renewal(p, &proof, &m, 180).is_err());
    {
        let mut control = f
            .active
            .transferred_control(&receipt)
            .expect("own exact scope");
        assert!(control
            .prepare_policy_renewal(other_p, &other_proof, &policy_materials(&other.c), 180)
            .is_err());
        assert!(control
            .prepare_policy_renewal(p, &bad_proof, &m, 180)
            .is_err());
        assert!(control.prepare_policy_renewal(p, &proof, &m, 261).is_err());
    }
    assert_eq!(
        f.original_entry(),
        before,
        "failed admission must not publish any preparation"
    );
    f.active
        .transferred_control(&receipt)
        .expect("same original scope")
        .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180)
        .expect("valid preparation");
    let prepared = f.original_entry();
    f.reopen();
    f.active
        .transferred_control(&receipt)
        .expect("persisted exact authorization")
        .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180)
        .expect("exact retry");
    assert_eq!(f.original_entry(), prepared);
    assert!(f
        .active
        .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180)
        .is_err());
    f.active
        .transferred_control(&receipt)
        .expect("same scope")
        .close_policy_renewal(p, &proof.historical(), &policy_materials(&f.c).historical())
        .expect("historical exact close");
    let closed = f.original_entry();
    f.reopen();
    assert_eq!(f.original_entry(), closed);
    assert_eq!(
        f.active
            .transferred_control(&receipt)
            .expect("same scope")
            .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180)
            .expect("closed remains closed"),
        crate::AnchorPolicyRenewalState::Closed
    );
}

#[test]
fn transferred_control_preparation_sync_faults_recover_exact_proposal_and_authorization() {
    let mut f = Prepared::new(None);
    let receipt = authorize(&mut f);
    let proof = f.c.approval(&f.c.original, None, &f.c.target);
    let p = f.c.proposal(&proof, f.c.initial, 245);
    f.active.close();
    let (db, _, count, _) = fault_database_path(&f.f.db_path(), false);
    f.active = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
        .expect("same target")
        .activate(&f.retired, f.f.signer())
        .expect("same activation")
        .0;
    count.store(0, std::sync::atomic::Ordering::SeqCst);
    f.active
        .transferred_control(&receipt)
        .expect("authorized")
        .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180)
        .expect("calibrate preparation");
    let barriers = count.load(std::sync::atomic::Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    f.active.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut f = Prepared::new(None);
            let receipt = authorize(&mut f);
            let proof = f.c.approval(&f.c.original, None, &f.c.target);
            let p = f.c.proposal(&proof, f.c.initial, 245);
            f.active.close();
            let (db, remaining, _, _) = fault_database_path(&f.f.db_path(), after);
            f.active = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
                .expect("fault-backed target")
                .activate(&f.retired, f.f.signer())
                .expect("same activation")
                .0;
            remaining.store(cut, std::sync::atomic::Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                f.active
                    .transferred_control(&receipt)
                    .expect("authorized")
                    .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180),
                after,
            );
            assert!(matches!(f.active.pin(), Err(DurableError::Closed)));
            f.reopen();
            assert_eq!(
                f.active
                    .handoff_client_authorization(f.c.subject)
                    .expect("same persisted authorization")
                    .as_bytes(),
                receipt.as_bytes()
            );
            assert_eq!(
                f.active
                    .transferred_control(&receipt)
                    .expect("same scope")
                    .prepare_policy_renewal(p, &proof, &policy_materials(&f.c), 180)
                    .expect("exact retry"),
                crate::AnchorPolicyRenewalState::Prepared
            );
            let retained = f.original_entry();
            f.reopen();
            assert_eq!(f.original_entry(), retained);
        }
    }
    eprintln!(
        "TRANSFERRED_CONTROL_SYNC barriers={barriers} faults={}",
        2 * barriers
    );
}
