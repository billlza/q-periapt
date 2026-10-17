// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public service admission of current remote rosters, including unknown commits.
use super::*;

fn snapshot(e: &mut Endpoint) -> ([u8; 32], [u8; 32], u64, [u8; 32]) {
    let image = journal_of(e).test_snapshot();
    (image.id, image.owner, image.revision, image.digest)
}

fn target(n: &UpdatedPair) -> crate::VerifiedRoster {
    target_for(&n.b, 3, 155)
}
fn target_for(e: &Endpoint, version: u64, now: u64) -> crate::VerifiedRoster {
    let issued =
        e.f.c
            .root
            .issue_roster(
                version,
                interval(),
                &[e.f
                    .c
                    .root
                    .roster_entry(&e.certificate)
                    .expect("retained public credential")],
            )
            .expect("independent signed roster");
    AccountPin::new(
        e.f.original.account_id(),
        e.f.c.intent.root.clone(),
        issued.checkpoint(),
        e.f.c.policy.family(),
    )
    .expect("independent current pin")
    .verify_roster(issued.as_bytes(), now)
    .expect("verified current target")
}
fn admit(
    n: &mut UpdatedPair,
    roster: &crate::VerifiedRoster,
) -> Result<crate::RosterCheckpoint, DurableError> {
    n.a.owner
        .parts()
        .expect("original owner")
        .0
        .admit_peer_roster(roster, &n.pa, 155)
}
pub(super) fn original_pending_target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let pending = saved.1.as_ref().expect("actual ordinary intent");
    assert_eq!(pending.get(..8), Some(b"QPWINT01".as_slice()));
    let end = pending.len().checked_sub(32).expect("intent MAC");
    let length = u32::from_be_bytes(
        pending
            .get(152..156)
            .expect("target length")
            .try_into()
            .expect("four bytes"),
    );
    let bytes = pending.get(156..end).expect("original encrypted target");
    assert_eq!(
        usize::try_from(length).expect("bounded target"),
        bytes.len()
    );
    bytes.to_vec()
}
fn reopen_sender(n: &mut UpdatedPair) {
    n.a.owner.close();
    let (request, _) = requests(&n.link, &n.a, &n.b, 155);
    n.pi = reopen(&mut n.a, request, &n.pa, 155);
}

#[test]
fn peer_roster_original_policy_checks_live_local_identity_and_runtime_even_on_retry() {
    let f = fixture();
    let peer = fixture_on_witness(
        Arc::clone(&f._witness_dir),
        f.pin.clone(),
        f.carrier.clone(),
        None,
    );
    let mut a = endpoint(f);
    let mut b = endpoint(peer);
    let _link = connect(&mut a, &mut b);
    let current = policy(&a.f.c, 1, a.f.c.policy.validity().until(), 150);
    assert_eq!(current.checkpoint(), a.f.c.policy.checkpoint());
    let next = target_for(&b, 2, 150);
    assert_eq!(
        a.owner
            .parts()
            .expect("original service")
            .0
            .admit_peer_roster(&next, &current, 150)
            .expect("P0 current update"),
        next.checkpoint()
    );
    let committed = snapshot(&mut a);
    assert!(matches!(
        a.owner
            .parts()
            .expect("service")
            .0
            .admit_peer_roster(&next, &current, 161),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert_eq!(snapshot(&mut a), committed);
    current.runtime.close();
    let result = a
        .owner
        .parts()
        .expect("same service")
        .0
        .admit_peer_roster(&next, &current, 150);
    assert!(
        matches!(
            result,
            Err(DurableError::Protocol(Error::Closed | Error::Runtime(_)))
        ),
        "closed P0 runtime: {result:?}"
    );
    assert_eq!(snapshot(&mut a), committed);
}

#[test]
fn peer_roster_requires_known_remote_authority_current_policy_and_monotonic_head() {
    let mut n = updated_pair();
    let next = target(&n);
    let before = snapshot(&mut n.a);
    let local =
        n.a.owner
            .parts()
            .expect("local identity")
            .2
            .roster()
            .clone();
    assert!(matches!(admit(&mut n, &local), Err(DurableError::Conflict)));
    let old = n.b.f.original.roster().clone();
    assert!(matches!(
        admit(&mut n, &old),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    let fork =
        n.b.f
            .c
            .root
            .issue_roster(2, interval(), &[])
            .expect("root signed fork");
    let pin = AccountPin::new(
        n.b.f.original.account_id(),
        n.b.f.c.intent.root.clone(),
        fork.checkpoint(),
        n.pa.family(),
    )
    .expect("pin");
    let fork = pin
        .verify_roster(fork.as_bytes(), 155)
        .expect("verified fork");
    assert!(matches!(
        admit(&mut n, &fork),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    let unknown = fixture();
    assert!(matches!(
        admit(&mut n, unknown.original.roster()),
        Err(DurableError::Absent)
    ));
    let wrong_family = AccountPin::new(
        n.b.f.original.account_id(),
        n.b.f.c.intent.root.clone(),
        next.checkpoint(),
        [79; 32],
    )
    .expect("wrong family pin")
    .verify_roster(next.as_bytes(), 155)
    .expect("signed document under unrelated family");
    assert!(matches!(
        admit(&mut n, &wrong_family),
        Err(DurableError::Conflict)
    ));
    let stale =
        n.a.owner
            .parts()
            .expect("owner")
            .0
            .admit_peer_roster(&next, &n.a.f.c.policy, 150);
    assert!(
        matches!(stale, Err(DurableError::Protocol(Error::Scope))),
        "stale P0: {stale:?}"
    );
    assert_eq!(snapshot(&mut n.a), before);
    let calls = n.a.f.carrier.requests.lock().expect("requests").len();
    assert_eq!(
        admit(&mut n, &next).expect("current original service update"),
        next.checkpoint()
    );
    assert!(n.a.f.carrier.requests.lock().expect("requests").len() > calls);
    let committed = snapshot(&mut n.a);
    assert_ne!(before, committed);
    assert_eq!(
        admit(&mut n, &next).expect("same original target retry"),
        next.checkpoint()
    );
    assert_eq!(snapshot(&mut n.a), committed);
    eprintln!("PEER_ROSTER_ADMISSION known_remote=true no_local_R_bypass=true no_P0_fallback=true monotonic=true current_witness=true exact_retry_no_rewrite=true");
}

#[test]
fn peer_roster_current_runtime_is_rechecked_after_witness_reply_without_mutation() {
    let mut n = updated_pair();
    let next = target(&n);
    n.a.owner.close();
    let before = journal(&n.a.f);
    reopen_sender(&mut n);
    let runtime = Arc::clone(&n.pa.runtime);
    *n.a.f.carrier.after_reply.lock().expect("hook") =
        Some((15, Box::new(move || runtime.close())));
    let result = admit(&mut n, &next);
    assert!(
        matches!(
            result,
            Err(DurableError::Protocol(Error::Closed | Error::Runtime(_)))
        ),
        "runtime release: {result:?}"
    );
    n.a.owner.close();
    assert_eq!(journal(&n.a.f), before);
}

#[test]
fn peer_roster_identical_target_never_bypasses_expiry_or_closed_runtime() {
    for failure in 0..3 {
        let mut n = updated_pair();
        let next = target(&n);
        admit(&mut n, &next).expect("initial original target");
        n.a.owner.close();
        let committed = journal(&n.a.f);
        reopen_sender(&mut n);
        let expiry = n.pa.validity().until();
        let result = match failure {
            0 => {
                n.a.owner
                    .parts()
                    .expect("original owner")
                    .0
                    .admit_peer_roster(&next, &n.pa, expiry)
            }
            1 => {
                n.a.f.carrier.clock.store(expiry, Ordering::SeqCst);
                admit(&mut n, &next)
            }
            _ => {
                n.pa.runtime.close();
                admit(&mut n, &next)
            }
        };
        match failure {
            0 => assert!(
                matches!(result, Err(DurableError::Protocol(Error::Validity))),
                "local expiry: {result:?}"
            ),
            1 => assert!(
                matches!(result, Err(DurableError::Anchor(ref e)) if matches!(**e, crate::AnchorClientError::AuthorityDenied)),
                "witness expiry: {result:?}"
            ),
            _ => assert!(
                matches!(
                    result,
                    Err(DurableError::Protocol(Error::Closed | Error::Runtime(_)))
                ),
                "closed runtime: {result:?}"
            ),
        }
        n.a.owner.close();
        assert_eq!(journal(&n.a.f), committed);
    }
    eprintln!("PEER_ROSTER_IDENTICAL_TARGET_REFUSALS cases=3 local_expiry=true witness_expiry=true closed_runtime=true unchanged_journal=true");
}

#[test]
fn peer_roster_processed_or_unprocessed_advance_loss_recovers_the_original_sealed_target() {
    for after in [false, true] {
        let mut n = updated_pair();
        let next = target(&n);
        *n.a.f.carrier.cut.lock().expect("loss") = Some((2, after));
        assert!(matches!(admit(&mut n, &next), Err(DurableError::Anchor(_))));
        assert!(n.a.f.carrier.cut.lock().expect("consumed loss").is_none());
        n.a.owner.close();
        let interrupted = journal(&n.a.f);
        let original = original_pending_target(&interrupted);
        reopen_sender(&mut n);
        assert_eq!(
            admit(&mut n, &next).expect("original target after reopen"),
            next.checkpoint()
        );
        n.a.owner.close();
        assert_eq!(journal(&n.a.f), (original, None));
    }
    eprintln!("PEER_ROSTER_ADVANCE_LOSS cases=2 preserved_pending=true original_ciphertext=true exact_retry=true");
}

#[test]
fn peer_roster_post_commit_admission_loss_is_not_relabelled_as_no_commit() {
    let mut n = updated_pair();
    let next = target(&n);
    let cut = Arc::clone(&n.a.f.carrier.cut);
    *n.a.f.carrier.after_reply.lock().expect("hook") = Some((
        2,
        Box::new(move || {
            *cut.lock().expect("post-advance cut") = Some((15, false));
        }),
    ));
    assert!(matches!(admit(&mut n, &next), Err(DurableError::Anchor(_))));
    assert!(n
        .a
        .f
        .carrier
        .cut
        .lock()
        .expect("consumed post-commit loss")
        .is_none());
    n.a.owner.close();
    let committed = journal(&n.a.f);
    assert!(committed.1.is_none());
    reopen_sender(&mut n);
    assert_eq!(
        admit(&mut n, &next).expect("same target current after committed error"),
        next.checkpoint()
    );
    n.a.owner.close();
    assert_eq!(journal(&n.a.f), committed);
}

#[test]
fn peer_roster_sync_failures_keep_exact_original_intent_and_recover_with_current_owner() {
    use crate::durable::tests::{assert_sync_failure, fault_existing_journal};
    let mut n = updated_pair();
    let next = target(&n);
    let path = n.a.f.c.paths.installation.files()[1].to_path_buf();
    let (_, count) = fault_existing_journal(journal_of(&mut n.a), &path, false);
    admit(&mut n, &next).expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!(barriers > 0 && barriers <= 16);
    n.a.owner.close();
    let mut faults = 0;
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut n = updated_pair();
            let next = target(&n);
            let path = n.a.f.c.paths.installation.files()[1].to_path_buf();
            let (remaining, _) = fault_existing_journal(journal_of(&mut n.a), &path, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(admit(&mut n, &next), after);
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            n.a.owner.close();
            let interrupted = journal(&n.a.f);
            let retained = interrupted
                .1
                .as_ref()
                .map(|_| original_pending_target(&interrupted));
            reopen_sender(&mut n);
            admit(&mut n, &next)
                .expect("original target recovered or first admitted after pre-intent failure");
            n.a.owner.close();
            let recovered = journal(&n.a.f);
            assert!(recovered.1.is_none());
            if let Some(retained) = retained {
                assert_eq!(recovered.0, retained);
            }
            reopen_sender(&mut n);
            admit(&mut n, &next).expect("idempotent current readback");
            n.a.owner.close();
            assert_eq!(journal(&n.a.f), recovered);
            faults += 1;
        }
    }
    eprintln!("PEER_ROSTER_SYNC faults={faults} real_original_journal=true sealed_target_preserved=true explicit_errors=true");
}
