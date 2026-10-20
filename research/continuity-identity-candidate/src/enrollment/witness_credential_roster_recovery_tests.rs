// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual original G/R targets, strict capability scope and historical recovery.
use super::*;

#[test]
fn original_credential_roster_closed_targets_share_one_version_floor_in_both_directions() {
    let (f, a) = with_existing_prekey();
    let g = credential::grant(&f, &f.original, 2, 280);
    let gp = prepared_g(&f, &a, &g);
    committed_g(&f, &a, &g, gp);
    let closed_g = credential::grant(&f, g.successor_device(), 3, 300);
    prepared_g(&f, &a, &closed_g);
    let mut owner = open(&f.c);
    let mut client = credential::client(&f, &mut owner, 180);
    assert!(matches!(owner.close_witnessed_credential_renewal(
        closed_g.operation(), closed_g.statement_digest(), &f.c.policy, 180, &mut client,
    ).expect("close second G"), GStatus::Closed { target, .. } if target.version() == 3));
    owner.close();
    let reused = roster_target(&f, g.successor_device(), 3, 180);
    let before = journal(&f);
    let mut owner = open(&f.c);
    let client = policy_client(&f, &mut owner);
    assert!(matches!(
        owner.prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("R ID"),
            f.c.policy.historical(),
            &a.target,
            &reused,
            180,
            client,
        ),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    owner.close();
    assert_eq!(journal(&f), before);
    let r4 = roster_target(&f, g.successor_device(), 4, 180);
    refresh(&f, &a.target, g.successor_device(), &r4, 180).expect("R4 after closed G3");
    assert_original_owner(&f, &a, &r4);
    let r5 = roster_target(&f, &r4, 5, 180);
    let rp = prepare_roster(&f, &a.target, &r4, &r5, 180).expect("R5 prepared");
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .close_witnessed_roster_refresh(&rp, f.c.policy.historical(), &mut client,)
            .expect("R5 closed"),
        RState::Closed
    );
    owner.close();
    let reused_g = credential::grant(&f, &r4, 5, 320);
    let before = journal(&f);
    let mut owner = open(&f.c);
    assert!(matches!(
        owner.stage_credential_renewal(&reused_g, reused_g.operation(), &a.target, 180,),
        Err(DurableError::Protocol(Error::Retired))
    ));
    owner.close();
    assert_eq!(journal(&f), before);
    let next_g = credential::grant(&f, &r4, 6, 320);
    let gp = prepared_g(&f, &a, &next_g);
    committed_g(&f, &a, &next_g, gp);
    assert_original_owner(&f, &a, next_g.successor_device());
}

#[test]
fn original_credential_roster_g_then_p_then_r_preserves_both_completed_authorizations() {
    let f = original_with_prekey();
    let g = credential::grant(&f, &f.original, 2, 240);
    credential::prepare(&f, &g, 170);
    let mut owner = open(&f.c);
    let mut client = credential::client(&f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                170,
                &mut client,
            )
            .expect("G first"),
        renewal::committed(&g)
    );
    owner.close();
    let a = approved_at(&f, &f.c.policy, 2, 300, 170);
    let p = prepared_at(&f, &a, &f.c.policy, 170);
    applied_at(&f, &a, p, 170);
    let next = roster_target(&f, g.successor_device(), 3, 170);
    refresh(&f, &a.target, g.successor_device(), &next, 170).expect("R after G/P");
    assert_original_owner(&f, &a, &next);
    let mut owner = open(&f.c);
    assert_eq!(
        owner.credential_renewal_status().expect("retained G"),
        renewal::committed(&g)
    );
    assert!(matches!(owner.policy_renewal_status().expect("retained P"),
        crate::PolicyRenewalStatus::Committed { statement, .. }
            if statement == a.proof.statement_digest()));
}

#[test]
fn original_credential_roster_both_orders_preserve_original_policy_without_p_update() {
    for roster_first in [false, true] {
        let f = original_with_prekey();
        let previous = if roster_first {
            let next = roster_target(&f, &f.original, 2, 155);
            refresh(&f, &f.c.policy, &f.original, &next, 155).expect("R under P0");
            next
        } else {
            f.original.clone()
        };
        let g = credential::grant(&f, &previous, if roster_first { 3 } else { 2 }, 240);
        credential::prepare(&f, &g, 170);
        let mut owner = open(&f.c);
        let mut client = credential::client(&f, &mut owner, 170);
        assert_eq!(
            owner
                .commit_witnessed_credential_renewal(
                    g.operation(),
                    g.statement_digest(),
                    &f.c.policy,
                    170,
                    &mut client,
                )
                .expect("G under P0"),
            renewal::committed(&g)
        );
        owner.close();
        let expected = if roster_first {
            g.successor_device().clone()
        } else {
            let next = roster_target(&f, g.successor_device(), 3, 170);
            refresh(&f, &f.c.policy, g.successor_device(), &next, 170).expect("R after G under P0");
            next
        };
        let before = journal(&f);
        let mut active = credential::activate(&f, 170).expect("original P0 owner");
        let (service, signer, current) = active.parts().expect("owners");
        signer.check_device(current).expect("same signer");
        assert_eq!(current.credential_digest(), expected.credential_digest());
        assert_eq!(
            current.roster().checkpoint(),
            expected.roster().checkpoint()
        );
        assert_eq!(
            service
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("journal"),
            f.id
        );
        active.close();
        assert_eq!(journal(&f), before);
    }
}

#[test]
fn original_credential_roster_pending_operations_exclude_each_other_without_writes() {
    use crate::enrollment::tests::policy_renewal::row;
    let (f, a) = with_existing_prekey();
    let g = credential::grant(&f, &f.original, 2, 280);
    let gp = prepared_g(&f, &a, &g);
    let next = roster_target(&f, g.successor_device(), 3, 180);
    let before = journal(&f);
    let mut owner = open(&f.c);
    let configured = row(&owner);
    let client = policy_client(&f, &mut owner);
    assert!(matches!(
        owner.prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("R ID"),
            f.c.policy.historical(),
            &a.target,
            &next,
            180,
            client,
        ),
        Err(DurableError::Suspended)
    ));
    owner.close();
    assert_eq!(journal(&f), before);
    assert_eq!(row(&open(&f.c)), configured);
    committed_g(&f, &a, &g, gp);
    let rp = prepare_roster(&f, &a.target, g.successor_device(), &next, 180).expect("exact R");
    let g2 = credential::grant(&f, g.successor_device(), 4, 300);
    let before = journal(&f);
    let mut owner = open(&f.c);
    let configured = row(&owner);
    assert!(matches!(
        owner.stage_credential_renewal(&g2, g2.operation(), &a.target, 180,),
        Err(DurableError::Suspended)
    ));
    owner.close();
    assert_eq!(journal(&f), before);
    assert_eq!(row(&open(&f.c)), configured);
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .commit_witnessed_roster_refresh(
                &rp,
                f.c.policy.historical(),
                &a.target,
                180,
                &mut client,
            )
            .expect("original R remains recoverable"),
        RState::Applied
    );
    owner.close();
    let before = journal(&f);
    let mut owner = open(&f.c);
    assert!(
        matches!(
            owner.stage_credential_renewal(&g2, g2.operation(), &a.target, 180,),
            Err(DurableError::Conflict)
        ),
        "G must bind the actually adopted R3"
    );
    owner.close();
    assert_eq!(journal(&f), before);
}

#[test]
fn original_credential_roster_alternates_without_replacing_keys_or_assets() {
    let (f, a) = with_existing_prekey();
    let signer = fs::read(&f.c.paths.signer).expect("original signer");
    let wrapping = fs::read(&f.c.paths.wrapping).expect("original wrapping key");
    let mut current = f.original.clone();
    for cycle in 0..3 {
        let g = credential::grant(&f, &current, 2 + cycle * 2, 280 + cycle * 20);
        let p = prepared_g(&f, &a, &g);
        committed_g(&f, &a, &g, p);
        let next = roster_target(&f, g.successor_device(), 3 + cycle * 2, 180);
        refresh(&f, &a.target, g.successor_device(), &next, 180).expect("actual original R");
        assert_original_owner(&f, &a, &next);
        current = next;
    }
    assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
    assert_eq!(
        fs::read(&f.c.paths.wrapping).expect("same wrapping"),
        wrapping
    );
}

#[test]
fn original_credential_roster_rejects_new_credential_without_g_and_uncompleted_low_level_use() {
    let (f, a) = with_existing_prekey();
    let g = credential::grant(&f, &f.original, 2, 280);
    let p = prepared_g(&f, &a, &g);
    committed_g(&f, &a, &g, p);
    let mut substituted = g.successor_device().clone();
    substituted.description.validity =
        Validity::new(100, 290).expect("different still-live credential");
    let target = roster_target(&f, &substituted, 3, 180);
    let before = journal(&f);
    let mut owner = open(&f.c);
    let client = policy_client(&f, &mut owner);
    assert!(matches!(
        owner.prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("operation"),
            f.c.policy.historical(),
            &a.target,
            &target,
            180,
            client,
        ),
        Err(DurableError::Conflict)
    ));
    owner.close();
    assert_eq!(journal(&f), before);
    let next = roster_target(&f, g.successor_device(), 3, 180);
    let mut active = activate(&f, &a.target, 180).expect("original owner");
    let journal = active
        .parts()
        .expect("owners")
        .0
        .stores()
        .expect("stores")
        .0;
    assert!(
        matches!(
            journal.prepare_roster_refresh(
                RosterRefreshId::generate().expect("operation"),
                &crate::RosterRefreshMaterials {
                    original: &f.original,
                    original_policy: f.c.policy.historical(),
                    policy: &a.target,
                    target: &next,
                },
                180,
            ),
            Err(DurableError::Suspended)
        ),
        "public low-level input cannot supply original enrollment G completion"
    );
    active.close();
    assert_eq!(super::journal(&f), before);
    refresh(&f, &a.target, g.successor_device(), &next, 180)
        .expect("original coordinator carries exact completion");
}

#[test]
fn original_credential_roster_promotes_old_r_history_and_refuses_authenticated_downgrade() {
    use crate::enrollment::tests::policy_renewal::{replace_authenticated, row};
    let (f, a) = with_existing_prekey();
    let target = roster_target(&f, &f.original, 2, 155);
    refresh(&f, &a.target, &f.original, &target, 155).expect("old-compatible R");
    let mut owner = open(&f.c);
    assert_eq!(row(&owner).get(..8), Some(b"QPENST17".as_slice()));
    let original_r = owner
        .witnessed_roster_refresh_progress()
        .expect("original R");
    owner.close();
    let g = credential::grant(&f, &target, 3, 280);
    let p = prepared_g(&f, &a, &g);
    committed_g(&f, &a, &g, p);
    let mut owner = open(&f.c);
    let bytes = row(&owner);
    assert_eq!(bytes.get(..8), Some(b"QPENST21".as_slice()));
    assert_eq!(
        owner
            .witnessed_roster_refresh_progress()
            .expect("retained R"),
        original_r
    );
    owner.close();
    let before = journal(&f);
    let mut old = bytes.clone();
    old.drain(..8);
    replace_authenticated(&f.c, &old);
    assert!(DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err());
    assert_eq!(
        journal(&f),
        before,
        "old authenticated tag cannot reinterpret new history"
    );
    replace_authenticated(&f.c, &bytes);
    assert_original_owner(&f, &a, g.successor_device());
}

#[test]
fn original_credential_roster_lost_r_replies_preserve_exact_history_after_expiry() {
    for (opcode, processed) in [(16, false), (16, true), (19, false), (19, true)] {
        let (f, a) = with_existing_prekey();
        let g = credential::grant(&f, &f.original, 2, 280);
        let gp = prepared_g(&f, &a, &g);
        committed_g(&f, &a, &g, gp);
        let next = roster_target(&f, g.successor_device(), 3, 180);
        let p = prepare_roster(&f, &a.target, g.successor_device(), &next, 180).expect("exact R");
        let saved = journal(&f);
        *f.carrier.cut.lock().expect("lost reply") = Some((opcode, processed));
        let mut owner = open(&f.c);
        let mut client = policy_client(&f, &mut owner);
        assert!(owner
            .commit_witnessed_roster_refresh(
                &p,
                f.c.policy.historical(),
                &a.target,
                180,
                &mut client,
            )
            .is_err());
        owner.close();
        assert!(
            journal(&f).1.is_some(),
            "unknown result retains original pending"
        );
        f.carrier.clock.store(500, Ordering::SeqCst);
        a.target.close();
        f.c.policy.close();
        let mut owner = open(&f.c);
        let mut client = policy_client(&f, &mut owner);
        let observed = owner
            .reconcile_witnessed_roster_refresh(&p, f.c.policy.historical(), &mut client)
            .expect("historical exact status");
        let applied = opcode != 16 || processed;
        if applied {
            assert_eq!(observed, RState::Applied);
        } else {
            assert_eq!(observed, RState::Prepared);
        }
        assert_eq!(
            owner
                .close_witnessed_roster_refresh(&p, f.c.policy.historical(), &mut client,)
                .expect("close preserves actual Applied"),
            if applied {
                RState::Applied
            } else {
                RState::Closed
            }
        );
        owner.close();
        assert_eq!(
            journal(&f),
            (
                if applied {
                    roster_target_image(&saved)
                } else {
                    saved.0
                },
                None,
            )
        );
        assert!(
            activate(&f, &a.target, 500).is_err(),
            "historical terminal is not live permission"
        );
    }
}
