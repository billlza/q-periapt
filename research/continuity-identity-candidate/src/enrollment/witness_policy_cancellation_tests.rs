// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorCredentialCancellationState as State,
    AnchorCredentialRenewalCancellation as Cancellation, HistoricalPolicyContinuation,
    HistoricalPolicyContinuationMaterials,
};

fn reserve(f: &Fixture, now: u64) -> Cancellation {
    open(&f.c)
        .prepare_witnessed_credential_cancellation(f.c.policy.historical(), now)
        .expect("original target-free G/T intent")
}
fn reconcile(f: &Fixture, g: &VerifiedCredentialRenewal, c: Cancellation, now: u64) {
    f.carrier.clock.store(now, Ordering::SeqCst);
    let mut owner = open(&f.c);
    let mut anchor = client(f, &mut owner, now);
    assert_eq!(
        owner
            .reconcile_witnessed_credential_renewal(
                g.operation(),
                c.transaction_statement(),
                f.c.policy.historical(),
                now,
                &mut anchor,
            )
            .expect("historical exact close and ACK"),
        CredentialRenewalStatus::Closed {
            operation: g.operation(),
            statement: c.transaction_statement(),
            target: g.successor_device().roster().checkpoint(),
        }
    );
}
fn restart_witness(f: &Fixture) {
    let mut store = f.carrier.store.lock().expect("witness");
    store.close();
    let dir = f
        ._witness_dir
        .path()
        .canonicalize()
        .expect("canonical path");
    *store = AnchorStore::open(
        &dir.join("witness.redb"),
        JournalKey::open(&dir.join("witness.key")).expect("key"),
        crate::AnchorSigningKey::deterministic([226; 32], [227; 32]).expect("same signer"),
        f.pin.identity(),
    )
    .expect("same witness restart");
}
fn legacy(c: Cancellation) -> Cancellation {
    let mut bytes = c.to_bytes().get(..248).expect("legacy fields").to_vec();
    bytes
        .get_mut(..8)
        .expect("tag")
        .copy_from_slice(b"QPCRNC01");
    Cancellation::from_trusted_state(&bytes).expect("explicit G-only metadata")
}

#[test]
fn policy_cancellation_wire_and_durable_intent_refuse_mode_t_and_legacy_downgrades() {
    let f = fixture_with_policy_expiry(Some(160));
    let g = grant(&f, &f.original, 2, 180);
    let p = super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let p2 = super::super::super::policy_continuation::policy(&f.c, 3, 195, 170);
    let scope = super::super::super::policy_continuation::scope(&f.c, &g, f.id);
    let t = super::super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p);
    let t2 = super::super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p2);
    open(&f.c)
        .stage_policy_continuation(&g, &t, g.operation(), &p, 170)
        .expect("stage");
    let c = reserve(&f, 170);
    let wire = c.to_bytes();
    for size in 0..wire.len() {
        assert!(Cancellation::from_trusted_state(wire.get(..size).expect("prefix")).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(Cancellation::from_trusted_state(&trailing).is_err());
    let mut mode = wire.clone();
    *mode.get_mut(248).expect("mode") = 0;
    let carry = Cancellation::from_trusted_state(&mode).expect("explicit alternative expectation");
    assert_ne!(carry.binding(), c.binding());
    *mode.get_mut(248).expect("mode") = 2;
    assert!(Cancellation::from_trusted_state(&mode).is_err());
    let mut zero = wire.clone();
    zero.get_mut(249..281).expect("T").fill(0);
    assert!(Cancellation::from_trusted_state(&zero).is_err());
    let alternate = legacy(c)
        .with_policy_continuation(&t2.historical())
        .expect("other valid target");
    assert_ne!(alternate.binding(), c.binding());
    assert!(c.with_policy_continuation(&t2.historical()).is_err());
    let materials = HistoricalPolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: f.c.policy.historical(),
        target: p.historical(),
        credential: g.historical(),
    };
    let other_materials = HistoricalPolicyContinuationMaterials {
        target: p2.historical(),
        ..materials
    };
    {
        let mut store = f.carrier.store.lock().expect("store");
        store
            .close_unprepared_policy_continuation(c, &t.historical(), &materials)
            .expect("exact independent close");
        assert!(store
            .close_unprepared_policy_continuation(alternate, &t2.historical(), &other_materials)
            .is_err());
        assert!(store
            .close_unprepared_continued_credential_renewal(
                carry,
                &g,
                f.c.policy.historical(),
                &t.historical(),
                p.historical()
            )
            .is_err());
    }
    // A valid configuration MAC does not authorize changing the original
    // cancellation retained by the journal.
    let mut owner = open(&f.c);
    let image = owner.image().expect("configuration");
    let original = encode(&owner.key().expect("key"), owner.binding, &image).expect("wire");
    assert_eq!(original.get(..8), Some(b"QPENST08".as_slice()));
    owner.close();
    let before = disk(&f);
    for downgrade in [false, true] {
        let mut body = original.get(..original.len() - 32).expect("body").to_vec();
        if downgrade {
            body.get_mut(..8)
                .expect("version")
                .copy_from_slice(b"QPENST05");
        } else {
            replace_exact(&mut body, &c.to_bytes(), &alternate.to_bytes(), 1);
        }
        let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
        let mut mac = auth(&key).expect("MAC");
        mac.update(&body);
        body.extend_from_slice(&mac.finalize().into_bytes());
        {
            let db = open_private_database(&f.c.paths.configuration).expect("db");
            write(&db, &body).expect("fixture");
        }
        assert!(DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err());
        assert_eq!(disk(&f), before);
    }
    {
        let db = open_private_database(&f.c.paths.configuration).expect("db");
        write(&db, &original).expect("restore");
    }
    reconcile(&f, &g, c, 170);
}

#[test]
fn target_free_policy_cancel_cannot_replace_an_actual_sealed_proposal() {
    let f = fixture_with_policy_expiry(Some(160));
    let g = grant(&f, &f.original, 2, 180);
    let p = super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let scope = super::super::super::policy_continuation::scope(&f.c, &g, f.id);
    let t = super::super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p);
    let proposal = prepare_policy(&f, &g, Some(&t), &p);
    let before = disk(&f);
    assert!(open(&f.c)
        .prepare_witnessed_credential_cancellation(f.c.policy.historical(), 250)
        .is_err());
    let mut bytes = b"QPCRNC01".to_vec();
    bytes.extend_from_slice(&proposal.witness_binding());
    bytes.extend_from_slice(&proposal.subject().to_bytes());
    bytes.extend_from_slice(g.operation().as_bytes());
    bytes.extend_from_slice(&g.statement_digest());
    let head = proposal.expected_head();
    bytes.extend_from_slice(&head.fence().to_be_bytes());
    bytes.extend_from_slice(&head.revision().to_be_bytes());
    bytes.extend_from_slice(&head.digest());
    let c = Cancellation::from_trusted_state(&bytes)
        .expect("expectation")
        .with_policy_continuation(&t.historical())
        .expect("T");
    let materials = HistoricalPolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: f.c.policy.historical(),
        target: p.historical(),
        credential: g.historical(),
    };
    assert!(matches!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .close_unprepared_policy_continuation(c, &t.historical(), &materials),
        Err(DurableError::Conflict)
    ));
    assert_eq!(disk(&f), before);
}

#[test]
fn expired_sealed_joint_target_can_close_before_or_after_witness_preparation_but_not_after_apply() {
    for phase in 0..3 {
        let f = fixture_with_policy_expiry(Some(160));
        let g = grant(&f, &f.original, 2, 180);
        let p = super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
        let scope = super::super::super::policy_continuation::scope(&f.c, &g, f.id);
        let t = super::super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p);
        let mut owner = open(&f.c);
        owner
            .stage_policy_continuation(&g, &t, g.operation(), &p, 170)
            .expect("stage");
        let anchor = client(&f, &mut owner, 170);
        let proposal = owner
            .prepare_witnessed_policy_continuation(f.c.policy.historical(), &p, 170, anchor)
            .expect("real sealed proposal only");
        let pending_image = disk(&f);
        if phase > 0 {
            f.carrier
                .store
                .lock()
                .expect("store")
                .prepare_policy_continuation(
                    proposal,
                    &t,
                    &PolicyContinuationMaterials {
                        original: f.c.policy.historical(),
                        previous: f.c.policy.historical(),
                        target: &p,
                        credential: &g,
                    },
                    170,
                )
                .expect("independent prepare");
        }
        if phase == 2 {
            *f.carrier.cut.lock().expect("cut") = Some((5, true));
            let mut anchor = client(&f, &mut owner, 170);
            f.carrier.clock.store(170, Ordering::SeqCst);
            assert!(owner
                .commit_witnessed_policy_continuation(
                    &proposal,
                    f.c.policy.historical(),
                    &p,
                    170,
                    &mut anchor
                )
                .is_err());
        }
        owner.close();
        p.close();
        f.c.policy.close();
        let materials = HistoricalPolicyContinuationMaterials {
            original: f.c.policy.historical(),
            previous: f.c.policy.historical(),
            target: p.historical(),
            credential: g.historical(),
        };
        let expected = if phase == 2 {
            crate::AnchorCredentialRenewalState::Applied
        } else {
            crate::AnchorCredentialRenewalState::Closed
        };
        for _ in 0..2 {
            assert_eq!(
                f.carrier
                    .store
                    .lock()
                    .expect("store")
                    .close_policy_continuation(proposal, &t.historical(), &materials)
                    .expect("original historical close or Applied readback"),
                expected
            );
            restart_witness(&f);
        }
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 250);
        f.carrier.clock.store(250, Ordering::SeqCst);
        let outcome = owner
            .reconcile_witnessed_credential_renewal(
                g.operation(),
                t.statement_digest(),
                f.c.policy.historical(),
                250,
                &mut anchor,
            )
            .expect("historical terminal and ACK");
        assert_eq!(
            outcome,
            if phase == 2 {
                committed(&g, &proposal)
            } else {
                CredentialRenewalStatus::Closed {
                    operation: g.operation(),
                    statement: t.statement_digest(),
                    target: g.successor_device().roster().checkpoint(),
                }
            }
        );
        owner.close();
        let saved = disk(&f);
        assert!(saved.1.is_none());
        if phase != 2 {
            assert_eq!(saved.0, pending_image.0);
        } else {
            assert_eq!(
                crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2", &saved.0),
                proposal.target_head().digest()
            );
        }
    }
}

#[test]
fn expired_joint_pending_without_a_sealed_target_closes_without_current_policy_or_resealing() {
    for cut in [
        None,
        Some((6, false)),
        Some((6, true)),
        Some((8, false)),
        Some((8, true)),
    ] {
        let f = fixture_with_policy_expiry(Some(160));
        let g = grant(&f, &f.original, 2, 180);
        let p = super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
        let scope = super::super::super::policy_continuation::scope(&f.c, &g, f.id);
        let t = super::super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p);
        open(&f.c)
            .stage_policy_continuation(&g, &t, g.operation(), &p, 170)
            .expect("stage only");
        let wire = t.as_bytes().to_vec();
        p.close();
        f.c.policy.close();
        let materials = HistoricalPolicyContinuationMaterials {
            original: f.c.policy.historical(),
            previous: f.c.policy.historical(),
            target: p.historical(),
            credential: g.historical(),
        };
        let t = HistoricalPolicyContinuation::from_bytes(&wire, &scope, &materials)
            .expect("root-verified history after all policy runtime owners closed");
        let before = disk(&f).0;
        f.carrier.requests.lock().expect("trace").clear();
        let c = reserve(&f, 250);
        assert_eq!(reserve(&f, 250), c);
        assert_eq!(c.statement(), g.statement_digest());
        assert_eq!(c.transaction_statement(), t.statement_digest());
        assert!(c.adopts_policy());
        assert_eq!(c.to_bytes().len(), 281);
        let saved = disk(&f);
        assert_eq!(saved.0, before);
        let pending = saved.1.expect("no-target intent");
        assert_eq!(pending.len(), 353);
        assert_eq!(pending.get(..8), Some(b"QPWINT05".as_slice()));
        assert!(f.carrier.requests.lock().expect("trace").is_empty());
        {
            let mut store = f.carrier.store.lock().expect("independent control plane");
            assert!(store
                .close_unprepared_credential_renewal(c, &g, &f.c.policy)
                .is_err());
            assert_eq!(
                store
                    .close_unprepared_policy_continuation(c, &t, &materials)
                    .expect("independent close"),
                State::Closed
            );
            assert_eq!(
                store
                    .close_unprepared_policy_continuation(c, &t, &materials)
                    .expect("exact close retry"),
                State::Closed
            );
        }
        restart_witness(&f);
        if let Some(cut) = cut {
            *f.carrier.cut.lock().expect("cut") = Some(cut);
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 250);
            f.carrier.clock.store(250, Ordering::SeqCst);
            assert!(owner
                .reconcile_witnessed_credential_renewal(
                    g.operation(),
                    t.statement_digest(),
                    f.c.policy.historical(),
                    250,
                    &mut anchor,
                )
                .is_err());
            assert!(owner.active.is_none());
            assert_eq!(disk(&f), (before.clone(), Some(pending)));
        }
        reconcile(&f, &g, c, 250);
        assert_eq!(disk(&f), (before, None));
        assert!(!f.carrier.requests.lock().expect("trace").contains(&5));
        restart_witness(&f);
        assert!(matches!(
            f.carrier
                .store
                .lock()
                .expect("store")
                .close_unprepared_policy_continuation(c, &t, &materials),
            Err(DurableError::Protocol(Error::Retired))
        ));
    }
}

#[test]
fn cancelled_t2_then_carry_cancel_keeps_t1_and_never_rewinds_policy_floor() {
    let f = fixture_with_policy_expiry(Some(160));
    let g1 = grant(&f, &f.original, 2, 180);
    let p1 = super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let s1 = super::super::super::policy_continuation::scope(&f.c, &g1, f.id);
    let t1 = super::super::super::policy_continuation::joint(&f.c, &g1, &s1, &f.c.policy, &p1);
    let proposal = prepare_policy(&f, &g1, Some(&t1), &p1);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    owner
        .commit_witnessed_policy_continuation(
            &proposal,
            f.c.policy.historical(),
            &p1,
            170,
            &mut anchor,
        )
        .expect("adopt real T1");
    owner.close();
    let retained = disk(&f).0;
    let g2 = grant(&f, g1.successor_device(), 3, 220);
    let p2 = super::super::super::policy_continuation::policy(&f.c, 3, 230, 170);
    let mut s2 = super::super::super::policy_continuation::scope(&f.c, &g2, f.id);
    s2.previous_policy = p1.checkpoint();
    s2.previous_authorization = Some(t1.statement_digest());
    let t2 = super::super::super::policy_continuation::joint(&f.c, &g2, &s2, &p1, &p2);
    open(&f.c)
        .stage_policy_continuation(&g2, &t2, g2.operation(), &p2, 170)
        .expect("stage T2 only");
    let c2 = reserve(&f, 170);
    let m2 = HistoricalPolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: p1.historical(),
        target: p2.historical(),
        credential: g2.historical(),
    };
    f.carrier
        .store
        .lock()
        .expect("store")
        .close_unprepared_policy_continuation(c2, &t2.historical(), &m2)
        .expect("T2 close consumes policy version3");
    reconcile(&f, &g2, c2, 170);
    restart_witness(&f);
    assert_eq!(disk(&f), (retained.clone(), None));
    let g3 = grant(&f, g1.successor_device(), 4, 225);
    open(&f.c)
        .stage_credential_renewal(&g3, g3.operation(), &p1, 170)
        .expect("G carry under T1");
    let c3 = reserve(&f, 170);
    assert!(!c3.adopts_policy());
    assert_eq!(c3.policy_continuation(), Some(t1.statement_digest()));
    assert_eq!(c3.transaction_statement(), g3.statement_digest());
    {
        let mut store = f.carrier.store.lock().expect("store");
        let legacy_result = store.close_unprepared_credential_renewal(legacy(c3), &g3, &f.c.policy);
        assert!(
            matches!(legacy_result, Err(DurableError::Conflict)),
            "G-only legacy cancellation inherited T1: {legacy_result:?}"
        );
        store
            .close_unprepared_continued_credential_renewal(
                c3,
                &g3,
                f.c.policy.historical(),
                &t1.historical(),
                p1.historical(),
            )
            .expect("explicit carry close");
    }
    reconcile(&f, &g3, c3, 170);
    restart_witness(&f);
    assert_eq!(disk(&f), (retained, None));
    let mut owner = open(&f.c);
    let anchor = client(&f, &mut owner, 170);
    owner
        .activate_witnessed_policy_continuation(f.c.policy.historical(), &p1, 170, anchor)
        .expect("actual T1 still current")
        .close();
    let g4 = grant(&f, g1.successor_device(), 5, 230);
    let mut s4 = s2.clone();
    s4.operation = g4.operation();
    let t4 = super::super::super::policy_continuation::joint(&f.c, &g4, &s4, &p1, &p2);
    let mut bytes = legacy(c3).to_bytes();
    bytes
        .get_mut(136..168)
        .expect("operation")
        .copy_from_slice(g4.operation().as_bytes());
    bytes
        .get_mut(168..200)
        .expect("G")
        .copy_from_slice(&g4.statement_digest());
    let c4 = Cancellation::from_trusted_state(&bytes)
        .expect("new independent cancellation")
        .with_policy_continuation(&t4.historical())
        .expect("new G attempts retired P2");
    let m4 = HistoricalPolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: p1.historical(),
        target: p2.historical(),
        credential: g4.historical(),
    };
    assert!(
        matches!(
            f.carrier
                .store
                .lock()
                .expect("store")
                .close_unprepared_policy_continuation(c4, &t4.historical(), &m4),
            Err(DurableError::Conflict)
        ),
        "carry cancellation must not rewind retired policy version"
    );
}

#[test]
fn policy_cancellation_configuration_sync_faults_preserve_original_image_and_terminal_before_ack() {
    fn staged() -> (
        Fixture,
        VerifiedCredentialRenewal,
        VerifiedSessionPolicy,
        VerifiedPolicyContinuation,
    ) {
        let f = fixture_with_policy_expiry(Some(160));
        let g = grant(&f, &f.original, 2, 180);
        let p = super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
        let scope = super::super::super::policy_continuation::scope(&f.c, &g, f.id);
        let t = super::super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p);
        open(&f.c)
            .stage_policy_continuation(&g, &t, g.operation(), &p, 170)
            .expect("stage");
        (f, g, p, t)
    }
    fn approve(
        f: &Fixture,
        g: &VerifiedCredentialRenewal,
        p: &VerifiedSessionPolicy,
        t: &VerifiedPolicyContinuation,
        c: Cancellation,
    ) {
        f.carrier
            .store
            .lock()
            .expect("store")
            .close_unprepared_policy_continuation(
                c,
                &t.historical(),
                &HistoricalPolicyContinuationMaterials {
                    original: f.c.policy.historical(),
                    previous: f.c.policy.historical(),
                    target: p.historical(),
                    credential: g.historical(),
                },
            )
            .expect("independent original close");
    }
    let mut faults = 0;
    for completing in [false, true] {
        let (f, g, p, t) = staged();
        if completing {
            let c = reserve(&f, 170);
            approve(&f, &g, &p, &t, c);
        }
        let (mut owner, _, count) = faulty(&f.c, false);
        let mut anchor = client(&f, &mut owner, 170);
        count.store(0, Ordering::SeqCst);
        if completing {
            owner
                .reconcile_witnessed_credential_renewal(
                    g.operation(),
                    t.statement_digest(),
                    f.c.policy.historical(),
                    170,
                    &mut anchor,
                )
                .expect("calibrate completion");
        } else {
            owner
                .prepare_witnessed_credential_cancellation(f.c.policy.historical(), 170)
                .expect("calibrate reservation");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((1..=12).contains(&barriers));
        owner.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                let (f, g, p, t) = staged();
                if completing {
                    let c = reserve(&f, 170);
                    approve(&f, &g, &p, &t, c);
                }
                let before = disk(&f).0;
                let (mut owner, remaining, _) = faulty(&f.c, after);
                let mut anchor = client(&f, &mut owner, 170);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(
                        owner.reconcile_witnessed_credential_renewal(
                            g.operation(),
                            t.statement_digest(),
                            f.c.policy.historical(),
                            170,
                            &mut anchor,
                        ),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        owner.prepare_witnessed_credential_cancellation(
                            f.c.policy.historical(),
                            170,
                        ),
                        after,
                    );
                }
                assert!(owner.active.is_none());
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                p.close();
                f.c.policy.close();
                let mut owner = open(&f.c);
                let mut anchor = client(&f, &mut owner, 250);
                f.carrier.clock.store(250, Ordering::SeqCst);
                if !completing {
                    let c = owner
                        .prepare_witnessed_credential_cancellation(f.c.policy.historical(), 250)
                        .expect("recover reservation");
                    approve(&f, &g, &p, &t, c);
                }
                assert!(matches!(
                    owner
                        .reconcile_witnessed_credential_renewal(
                            g.operation(),
                            t.statement_digest(),
                            f.c.policy.historical(),
                            250,
                            &mut anchor,
                        )
                        .expect("original historical recovery"),
                    CredentialRenewalStatus::Closed { .. }
                ));
                owner.close();
                assert_eq!(disk(&f), (before, None));
                faults += 1;
            }
        }
        eprintln!("POLICY_CANCELLATION_CONFIG completing={completing} barriers={barriers}");
    }
    eprintln!("POLICY_CANCELLATION_CONFIG injected={faults}");
}
