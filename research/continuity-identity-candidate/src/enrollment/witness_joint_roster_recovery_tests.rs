// SPDX-License-Identifier: Apache-2.0 OR MIT
//! R preserves the exact adopted T through hostile records and historical recovery.
use super::*;
use crate::enrollment::tests::policy_renewal::{replace_authenticated, row};

#[test]
fn original_joint_roster_history_tag_cannot_claim_t_authority_for_earlier_r(
) -> Result<(), DurableError> {
    let f = original();
    let r2 = roster(&f, &f.original, 2, 150);
    refresh(&f, &f.original, &r2, &f.c.policy, 150)?;
    let (_, _, _) = adopt_t(&f, &r2, 3);
    let mut owner = open(&f.c);
    let original = row(&owner);
    assert_eq!(original.get(..8), Some(b"QPENST21".as_slice()));
    owner.close();
    let before = disk(&f);
    let mut changed = b"QPENST22".to_vec();
    changed.extend_from_slice(&original);
    replace_authenticated(&f.c, &changed);
    let result = DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone());
    let accepted = match result {
        Ok(mut owner) => {
            owner.close();
            true
        }
        Err(DurableError::Corrupt) => false,
        Err(error) => return Err(keep(f, error)),
    };
    assert_eq!(disk(&f), before);
    replace_authenticated(&f.c, &original);
    if accepted {
        return Err(keep(f, DurableError::Conflict));
    }
    Ok(())
}

#[test]
fn original_joint_roster_next_joint_authorization_preserves_retired_r_history() {
    let f = original();
    let (g1, p1, t1) = adopt_t(&f, &f.original, 2);
    let r3 = roster(&f, g1.successor_device(), 3, 170);
    refresh(&f, g1.successor_device(), &r3, &p1, 170).expect("R after first T");
    let mut owner = open(&f.c);
    let old_r = owner
        .witnessed_roster_refresh_progress()
        .expect("first R history");
    owner.close();
    let g2 = grant(&f, &r3, 4, 340);
    let p2 = continuation::policy(&f.c, 3, 360, 170);
    let mut scope = continuation::scope(&f.c, &g2, f.id);
    scope.previous_policy = p1.checkpoint();
    scope.previous_authorization = Some(t1.statement_digest());
    let t2 = continuation::joint(&f.c, &g2, &scope, &p1, &p2);
    let mut owner = open(&f.c);
    owner
        .stage_policy_continuation(&g2, &t2, g2.operation(), &p2, 170)
        .expect("second T");
    let anchor = client(&f, &mut owner, 170);
    let proposal = owner
        .prepare_witnessed_policy_continuation(f.c.policy.historical(), &p2, 170, anchor)
        .expect("actual second T target");
    f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_policy_continuation(
            proposal,
            &t2,
            &PolicyContinuationMaterials {
                original: f.c.policy.historical(),
                previous: p1.historical(),
                target: &p2,
                credential: &g2,
            },
            170,
        )
        .expect("both authorities approve actual predecessor");
    let mut anchor = client(&f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_policy_continuation(
                &proposal,
                f.c.policy.historical(),
                &p2,
                170,
                &mut anchor
            )
            .expect("second T retired"),
        committed(&g2, &proposal)
    );
    assert_eq!(
        owner
            .witnessed_roster_refresh_progress()
            .expect("retained R"),
        old_r
    );
    assert_eq!(
        owner
            .image()
            .expect("current original state")
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_predecessor)
            .expect("second T"),
        t2.historical().journal_bytes()
    );
    owner.close();
    active(&f, &p2, g2.successor_device());
    let r5 = roster(&f, g2.successor_device(), 5, 170);
    refresh(&f, g2.successor_device(), &r5, &p2, 170).expect("R under second T");
    active(&f, &p2, &r5);
}

#[test]
fn original_joint_roster_authenticated_downgrade_and_valid_t_substitution_are_refused() {
    let f = original();
    let (g, p, t) = adopt_t(&f, &f.original, 2);
    let next = roster(&f, g.successor_device(), 3, 170);
    let proposal = prepare_r(&f, g.successor_device(), &next, &p, 170).expect("original R");
    let mut owner = open(&f.c);
    let original = row(&owner);
    assert_eq!(original.get(..16), Some(b"QPENST22QPENST21".as_slice()));
    owner.close();
    let before = disk(&f);
    let mut downgrade = original.clone();
    downgrade.drain(..8);
    replace_authenticated(&f.c, &downgrade);
    assert!(DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err());
    assert_eq!(disk(&f), before);

    let other_p = continuation::policy(&f.c, 3, 310, 170);
    let other = continuation::joint(
        &f.c,
        &g,
        &continuation::scope(&f.c, &g, f.id),
        &f.c.policy,
        &other_p,
    );
    let mut changed = original.clone();
    replace_exact(
        &mut changed,
        &t.historical().journal_bytes(),
        &other.historical().journal_bytes(),
        1,
    );
    replace_authenticated(&f.c, &changed);
    f.carrier.requests.lock().expect("trace").clear();
    match DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()) {
        Ok(mut owner) => {
            assert!(owner
                .roster_refresh_anchor_client(
                    f.c.policy.historical(),
                    f.pin.clone(),
                    Box::new(f.carrier.clone()),
                    Duration::from_secs(3)
                )
                .is_err());
            assert!(owner.active.is_none());
        }
        Err(error) => assert!(matches!(
            error,
            DurableError::Corrupt | DurableError::Conflict
        )),
    }
    assert!(f.carrier.requests.lock().expect("trace").is_empty());
    assert_eq!(disk(&f), before);
    replace_authenticated(&f.c, &original);
    let mut owner = open(&f.c);
    let mut anchor = r_client(&f, &mut owner);
    assert_eq!(
        owner
            .commit_witnessed_roster_refresh(
                &proposal,
                f.c.policy.historical(),
                &p,
                170,
                &mut anchor
            )
            .expect("same original remains usable"),
        RState::Applied
    );
    owner.close();
    active(&f, &p, &next);
}

#[test]
fn original_joint_roster_does_not_accept_original_policy_or_low_level_completion_bypass() {
    let f = original();
    let (g, p, _) = adopt_t(&f, &f.original, 2);
    let next = roster(&f, g.successor_device(), 3, 170);
    let before = disk(&f);
    let mut owner = open(&f.c);
    let anchor = r_client(&f, &mut owner);
    // A fresh runtime for signed P0 must not become the adopted T policy.
    let old = continuation::policy(&f.c, 1, 160, 150);
    assert!(owner
        .prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("ID"),
            f.c.policy.historical(),
            &old,
            &next,
            150,
            anchor
        )
        .is_err());
    owner.close();
    assert_eq!(disk(&f), before);
    let mut owner = open(&f.c);
    let anchor = client(&f, &mut owner, 170);
    let mut current = owner
        .activate_witnessed_policy_continuation(f.c.policy.historical(), &p, 170, anchor)
        .expect("original continued installation");
    assert!(matches!(
        current
            .parts()
            .expect("owners")
            .0
            .stores()
            .expect("stores")
            .0
            .prepare_roster_refresh(
                RosterRefreshId::generate().expect("ID"),
                &crate::RosterRefreshMaterials {
                    original: &f.original,
                    original_policy: f.c.policy.historical(),
                    policy: &p,
                    target: &next
                },
                170
            ),
        Err(DurableError::Suspended)
    ));
    current.close();
    assert_eq!(disk(&f), before);
    refresh(&f, g.successor_device(), &next, &p, 170).expect("original completion capability");
}

#[test]
fn original_joint_roster_pending_and_unacknowledged_operations_exclude_each_other() {
    let f = original();
    let g = grant(&f, &f.original, 2, 280);
    let p = continuation::policy(&f.c, 2, 300, 170);
    let t = continuation::joint(
        &f.c,
        &g,
        &continuation::scope(&f.c, &g, f.id),
        &f.c.policy,
        &p,
    );
    let proposal = prepare_policy(&f, &g, Some(&t), &p);
    let before = disk(&f);
    let mut owner = open(&f.c);
    assert!(owner
        .roster_refresh_anchor_client(
            f.c.policy.historical(),
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3)
        )
        .is_err());
    assert_eq!(disk(&f), before);
    *f.carrier.cut.lock().expect("lost ACK") = Some((8, false));
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    assert!(owner
        .commit_witnessed_policy_continuation(
            &proposal,
            f.c.policy.historical(),
            &p,
            170,
            &mut anchor
        )
        .is_err());
    let before = disk(&f);
    let mut owner = open(&f.c);
    assert!(owner
        .roster_refresh_anchor_client(
            f.c.policy.historical(),
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3)
        )
        .is_err());
    assert_eq!(disk(&f), before);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    owner
        .reconcile_witnessed_credential_renewal(
            g.operation(),
            t.statement_digest(),
            f.c.policy.historical(),
            170,
            &mut anchor,
        )
        .expect("original T ACK");
    owner.close();
    let next = roster(&f, g.successor_device(), 3, 170);
    let rp = prepare_r(&f, g.successor_device(), &next, &p, 170).expect("R after T retired");
    let next_g = grant(&f, g.successor_device(), 4, 290);
    let before = disk(&f);
    let mut owner = open(&f.c);
    let configured = row(&owner);
    assert!(owner
        .stage_credential_renewal(&next_g, next_g.operation(), &p, 170)
        .is_err());
    assert_eq!(disk(&f), before);
    let mut owner = open(&f.c);
    assert_eq!(row(&owner), configured);
    let mut anchor = r_client(&f, &mut owner);
    owner
        .close_witnessed_roster_refresh(&rp, f.c.policy.historical(), &mut anchor)
        .expect("original R closed");
}

#[test]
fn original_joint_roster_closed_targets_share_g_r_floor() {
    let f = original();
    let (g, p, _) = adopt_t(&f, &f.original, 2);
    let next = roster(&f, g.successor_device(), 3, 170);
    let rp = prepare_r(&f, g.successor_device(), &next, &p, 170).expect("R3");
    let mut owner = open(&f.c);
    let mut anchor = r_client(&f, &mut owner);
    assert_eq!(
        owner
            .close_witnessed_roster_refresh(&rp, f.c.policy.historical(), &mut anchor)
            .expect("Closed R3"),
        RState::Closed
    );
    owner.close();
    let before = disk(&f);
    let reused = grant(&f, g.successor_device(), 3, 290);
    let mut owner = open(&f.c);
    assert!(matches!(
        owner.stage_credential_renewal(&reused, reused.operation(), &p, 170),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(disk(&f), before);
    let g4 = adopt_g(&f, g.successor_device(), 4, &p);
    let g5 = grant(&f, g4.successor_device(), 5, 295);
    prepare_policy(&f, &g5, None, &p);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    owner
        .close_witnessed_credential_renewal(
            g5.operation(),
            g5.statement_digest(),
            f.c.policy.historical(),
            170,
            &mut anchor,
        )
        .expect("Closed G5");
    owner.close();
    let before = disk(&f);
    let reused = roster(&f, g4.successor_device(), 5, 170);
    let mut owner = open(&f.c);
    let anchor = r_client(&f, &mut owner);
    assert!(matches!(
        owner.prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("ID"),
            f.c.policy.historical(),
            &p,
            &reused,
            170,
            anchor
        ),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    assert_eq!(disk(&f), before);
    let next = roster(&f, g4.successor_device(), 6, 170);
    refresh(&f, g4.successor_device(), &next, &p, 170).expect("R6 after Closed G5");
    active(&f, &p, &next);
}

#[test]
fn original_joint_roster_lost_replies_recover_expired_original_without_live_release() {
    for (opcode, processed) in [
        (16, false),
        (16, true),
        (17, false),
        (17, true),
        (19, false),
        (19, true),
    ] {
        let f = original();
        let (g, p, _) = adopt_t(&f, &f.original, 2);
        let next = roster(&f, g.successor_device(), 3, 170);
        let proposal = prepare_r(&f, g.successor_device(), &next, &p, 170).expect("exact R");
        let before = disk(&f);
        *f.carrier.cut.lock().expect("lost reply") = Some((opcode, processed));
        let mut owner = open(&f.c);
        let mut anchor = r_client(&f, &mut owner);
        assert!(owner
            .commit_witnessed_roster_refresh(
                &proposal,
                f.c.policy.historical(),
                &p,
                170,
                &mut anchor
            )
            .is_err());
        owner.close();
        assert!(disk(&f).1.is_some());
        f.carrier.clock.store(500, Ordering::SeqCst);
        p.close();
        f.c.policy.close();
        f.carrier.requests.lock().expect("trace").clear();
        let mut owner = open(&f.c);
        let mut anchor = r_client(&f, &mut owner);
        let applied = opcode != 16 || processed;
        assert_eq!(
            owner
                .reconcile_witnessed_roster_refresh(&proposal, f.c.policy.historical(), &mut anchor)
                .expect("exact historical outcome"),
            if applied {
                RState::Applied
            } else {
                RState::Prepared
            }
        );
        assert_eq!(
            owner
                .close_witnessed_roster_refresh(&proposal, f.c.policy.historical(), &mut anchor)
                .expect("historical cleanup"),
            if applied {
                RState::Applied
            } else {
                RState::Closed
            }
        );
        owner.close();
        assert_eq!(
            disk(&f),
            (if applied { target_r(&before) } else { before.0 }, None)
        );
        assert!(!f.carrier.requests.lock().expect("trace").contains(&16));
        let mut owner = open(&f.c);
        let anchor = client(&f, &mut owner, 500);
        assert!(owner
            .activate_witnessed_policy_continuation(f.c.policy.historical(), &p, 500, anchor)
            .is_err());
    }
}
