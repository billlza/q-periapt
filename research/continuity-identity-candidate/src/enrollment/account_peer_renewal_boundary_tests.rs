// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Current local authority gates both single and complete peer-account maintenance.
use super::*;

fn account_case() -> (Endpoint, Vec<Endpoint>, Vec<VerifiedCredentialRenewal>) {
    let mut sender = endpoint(fixture());
    let mut peers = recipients_count(&sender.f, 3);
    for peer in &mut peers {
        connect(&mut sender, peer);
    }
    let grants = grants(&peers);
    sender.f.carrier.clock.store(155, Ordering::SeqCst);
    (sender, peers, grants)
}
fn apply(
    sender: &mut Endpoint,
    grants: &[VerifiedCredentialRenewal],
) -> Result<crate::RosterCheckpoint, DurableError> {
    let primary = grants.first().expect("primary");
    let companions = grants.iter().skip(1).collect::<Vec<_>>();
    sender
        .owner
        .parts()?
        .0
        .admit_peer_account_credential_renewal(
            primary,
            &companions,
            primary.operation(),
            &sender.f.c.policy,
            155,
        )
}
fn reopen(sender: &mut Endpoint) {
    sender.owner.close();
    sender.owner = crate::enrollment::tests::witness_renewal::activate(&sender.f, 155)
        .expect("recover only the original sender installation");
}
fn pending_target(pending: &[u8]) -> Vec<u8> {
    assert_eq!(pending.get(..8), Some(b"QPWINT01".as_slice()));
    let target = pending
        .get(156..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual original sealed target");
    let size = u32::from_be_bytes(
        pending
            .get(152..156)
            .expect("length field")
            .try_into()
            .expect("width"),
    );
    assert_eq!(usize::try_from(size).expect("bounded length"), target.len());
    target.to_vec()
}

#[test]
fn native_common_account_peer_renewal_current_target_requires_each_original_grant() {
    let (mut sender, peers, original) = account_case();
    apply(&mut sender, &original).expect("original complete set");
    let before = journal(&mut sender.owner).test_snapshot().digest;
    let other = super::grants(&peers);
    let primary = original.first().expect("original primary");
    let other_companions = other.iter().skip(1).collect::<Vec<_>>();
    assert_eq!(
        primary.successor_device().roster().checkpoint(),
        other
            .first()
            .expect("other primary")
            .successor_device()
            .roster()
            .checkpoint()
    );
    assert!(matches!(
        sender
            .owner
            .parts()
            .expect("original sender")
            .0
            .admit_peer_account_credential_renewal(
                primary,
                &other_companions,
                primary.operation(),
                &sender.f.c.policy,
                155
            ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(journal(&mut sender.owner).test_snapshot().digest, before);
    assert!(sender
        .owner
        .parts()
        .expect("original sender")
        .0
        .admit_peer_account_credential_renewal(
            primary,
            &[original.get(1).expect("incomplete companion")],
            primary.operation(),
            &sender.f.c.policy,
            155
        )
        .is_err());
    assert_eq!(journal(&mut sender.owner).test_snapshot().digest, before);
    apply(&mut sender, &original).expect("original complete set remains readable");
    assert_eq!(journal(&mut sender.owner).test_snapshot().digest, before);
}

#[test]
fn native_common_account_peer_renewal_lost_advance_recovers_exact_original_target() {
    for processed in [false, true] {
        let (mut sender, _peers, grants) = account_case();
        *sender.f.carrier.cut.lock().expect("lost Advance") = Some((2, processed));
        assert!(matches!(
            apply(&mut sender, &grants),
            Err(DurableError::Anchor(_))
        ));
        assert!(sender.f.carrier.cut.lock().expect("actual loss").is_none());
        sender.owner.close();
        let interrupted = disk(&sender.f);
        let target = pending_target(interrupted.1.as_ref().expect("original pending retained"));
        reopen(&mut sender);
        assert_eq!(
            apply(&mut sender, &grants).expect("same complete set after original recovery"),
            grants
                .first()
                .expect("primary")
                .successor_device()
                .roster()
                .checkpoint()
        );
        sender.owner.close();
        assert_eq!(disk(&sender.f), (target, None));
    }
    eprintln!("COMMON_ACCOUNT_PEER_ADVANCE_LOSS cases=2 original_sealed_target=true complete_grants=true no_reseed=true");
}

#[test]
fn native_common_account_peer_renewal_sync_failures_preserve_complete_original_target() {
    use crate::durable::tests::{assert_sync_failure, fault_existing_journal};
    let (mut sender, _peers, grants) = account_case();
    let path = sender.f.c.paths.installation.files()[1].to_path_buf();
    let (_, counter) = fault_existing_journal(journal(&mut sender.owner), &path, false);
    apply(&mut sender, &grants).expect("calibration");
    let barriers = counter.load(Ordering::SeqCst);
    assert!(barriers > 0 && barriers <= 16);
    sender.owner.close();
    let mut faults = 0;
    for after in [false, true] {
        for cut in 1..=barriers {
            let (mut sender, _peers, grants) = account_case();
            sender.owner.close();
            let before = disk(&sender.f);
            reopen(&mut sender);
            let path = sender.f.c.paths.installation.files()[1].to_path_buf();
            let (remaining, _) = fault_existing_journal(journal(&mut sender.owner), &path, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(apply(&mut sender, &grants), after);
            assert_eq!(remaining.load(Ordering::SeqCst), 0, "injection consumed");
            sender.owner.close();
            let interrupted = disk(&sender.f);
            let expected = interrupted
                .1
                .as_ref()
                .map(|p| pending_target(p))
                .or_else(|| (interrupted.0 != before.0).then(|| interrupted.0.clone()));
            reopen(&mut sender);
            apply(&mut sender, &grants).expect("recover original complete peer update");
            sender.owner.close();
            let recovered = disk(&sender.f);
            assert!(recovered.1.is_none());
            if let Some(target) = expected {
                assert_eq!(recovered.0, target, "no replacement of original target");
            }
            reopen(&mut sender);
            apply(&mut sender, &grants).expect("same original complete readback");
            sender.owner.close();
            assert_eq!(disk(&sender.f), recovered);
            faults += 1;
        }
    }
    eprintln!("COMMON_ACCOUNT_PEER_SYNC faults={faults} complete_grants=true exact_target=true explicit_errors=true");
}

#[test]
fn native_common_account_peer_renewal_single_rejects_expired_local_owner_before_mutation() {
    for expired in [false, true] {
        let mut a = endpoint(fixture());
        let peer = fixture_on_witness(
            Arc::clone(&a.f._witness_dir),
            a.f.pin.clone(),
            a.f.carrier.clone(),
            None,
        );
        let mut b = endpoint(peer);
        let _link = connect(&mut a, &mut b);
        let g = grant(&b.f, &b.f.original, 2, 240);
        a.owner.close();
        let before = disk(&a.f);
        a.owner = crate::enrollment::tests::witness_renewal::activate(&a.f, 150)
            .expect("same original live owner");
        let now = if expired { 170 } else { 155 };
        a.f.carrier.clock.store(now, Ordering::SeqCst);
        let result = a
            .owner
            .parts()
            .expect("original sender")
            .0
            .admit_peer_credential_renewal(&g, g.operation(), &a.f.c.policy, now);
        a.owner.close();
        let after = disk(&a.f);
        if expired {
            assert!(
                matches!(result, Err(DurableError::Protocol(Error::Validity))),
                "expired local result: {result:?}"
            );
            assert_eq!(
                after, before,
                "expired local maintenance must not reserve a write"
            );
        } else {
            assert_eq!(
                result.expect("live local control"),
                g.successor_device().roster().checkpoint()
            );
            assert_ne!(after.0, before.0);
            assert!(after.1.is_none());
        }
    }
}

#[test]
fn native_common_account_peer_renewal_batch_rejects_expired_local_owner_before_mutation() {
    let mut a = endpoint(fixture());
    let mut peers = recipients_count(&a.f, 3);
    let _links = peers
        .iter_mut()
        .map(|p| connect(&mut a, p))
        .collect::<Vec<_>>();
    let set = grants(&peers);
    let primary = set.first().expect("primary");
    let companions = set.iter().skip(1).collect::<Vec<_>>();
    let before = journal(&mut a.owner).test_snapshot().digest;
    a.f.carrier.clock.store(170, Ordering::SeqCst);
    a.f.carrier.requests.lock().expect("trace").clear();
    let result = a
        .owner
        .parts()
        .expect("original sender")
        .0
        .admit_peer_account_credential_renewal(
            primary,
            &companions,
            primary.operation(),
            &a.f.c.policy,
            170,
        );
    assert!(
        matches!(result, Err(DurableError::Protocol(Error::Validity))),
        "expired local result: {result:?}"
    );
    let calls = a.f.carrier.requests.lock().expect("trace").clone();
    assert!(!calls.is_empty() && calls.iter().all(|&op| op == 1),
        "opening the authenticated image may query the original head, but never advance it: {calls:?}");
    assert_eq!(journal(&mut a.owner).test_snapshot().digest, before);
}

#[test]
fn native_common_account_peer_renewal_requires_adopted_joint_policy_instead_of_live_p0() {
    let (mut sender, _peers, grants) = account_case();
    let local = grant(&sender.f, &sender.f.original, 2, 240);
    let previous = policy(&sender.f.c, 1, 200, 150);
    let current = policy(&sender.f.c, 2, 250, 170);
    adopt(&mut sender, &local, &previous, None, &current);
    let primary = grants.first().expect("primary");
    let companions = grants.iter().skip(1).collect::<Vec<_>>();
    let before = journal(&mut sender.owner).test_snapshot().digest;
    assert!(sender
        .owner
        .parts()
        .expect("continued sender")
        .0
        .admit_peer_account_credential_renewal(
            primary,
            &companions,
            primary.operation(),
            &previous,
            170
        )
        .is_err());
    assert_eq!(journal(&mut sender.owner).test_snapshot().digest, before);
    assert_eq!(
        sender
            .owner
            .parts()
            .expect("continued sender")
            .0
            .admit_peer_account_credential_renewal(
                primary,
                &companions,
                primary.operation(),
                &current,
                170
            )
            .expect("actual adopted T authority"),
        primary.successor_device().roster().checkpoint()
    );
}

#[test]
fn native_common_account_peer_renewal_runtime_closure_after_witness_refuses_without_commit() {
    for single in [false, true] {
        let mut a = endpoint(fixture());
        let mut peers = recipients_count(&a.f, 3);
        let _links = peers
            .iter_mut()
            .map(|p| connect(&mut a, p))
            .collect::<Vec<_>>();
        let set = grants(&peers);
        let (mut other, one) = if single {
            let peer = fixture_on_witness(
                Arc::clone(&a.f._witness_dir),
                a.f.pin.clone(),
                a.f.carrier.clone(),
                None,
            );
            let mut other = endpoint(peer);
            connect(&mut a, &mut other);
            let one = grant(&other.f, &other.f.original, 2, 240);
            (Some(other), Some(one))
        } else {
            (None, None)
        };
        let primary = one
            .as_ref()
            .unwrap_or_else(|| set.first().expect("primary"));
        let companions = set.iter().skip(1).collect::<Vec<_>>();
        let before = journal(&mut a.owner).test_snapshot().digest;
        let runtime = Arc::clone(&a.f.c.policy.runtime);
        a.f.carrier.clock.store(155, Ordering::SeqCst);
        *a.f.carrier.after_reply.lock().expect("hook") =
            Some((1, Box::new(move || runtime.close())));
        let service = a.owner.parts().expect("sender").0;
        let result = if single {
            service.admit_peer_credential_renewal(primary, primary.operation(), &a.f.c.policy, 155)
        } else {
            service.admit_peer_account_credential_renewal(
                primary,
                &companions,
                primary.operation(),
                &a.f.c.policy,
                155,
            )
        };
        assert!(matches!(
            result,
            Err(DurableError::Protocol(Error::Closed | Error::Runtime(_)))
        ));
        assert!(
            a.f.carrier.after_reply.lock().expect("hook").is_none(),
            "actual witness reply consumed hook"
        );
        assert_eq!(journal(&mut a.owner).test_snapshot().digest, before);
        if let Some(other) = other.as_mut() {
            other.owner.close();
        }
    }
}
