// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real sealed journal targets, independent witness approvals and original ACK.
use super::*;
use crate::{PolicyContinuationMaterials, VerifiedCredentialRenewal, VerifiedPolicyContinuation};
#[path = "witness_policy_cancellation_tests.rs"]
mod policy_cancellation;
#[path = "witness_policy_session_tests.rs"]
pub(super) mod sessions;

fn prepare_policy(
    f: &Fixture,
    g: &VerifiedCredentialRenewal,
    t: Option<&VerifiedPolicyContinuation>,
    p: &VerifiedSessionPolicy,
) -> Proposal {
    f.carrier.clock.store(170, Ordering::SeqCst);
    let mut owner = open(&f.c);
    match t {
        Some(t) => owner.stage_policy_continuation(g, t, g.operation(), p, 170),
        None => owner.stage_credential_renewal(g, g.operation(), p, 170),
    }
    .expect("exact staged transaction");
    let anchor = client(f, &mut owner, 170);
    let proposal = owner
        .prepare_witnessed_policy_continuation(f.c.policy.historical(), p, 170, anchor)
        .expect("actual sealed target");
    let anchor = client(f, &mut owner, 170);
    assert_eq!(
        owner
            .prepare_witnessed_policy_continuation(f.c.policy.historical(), p, 170, anchor,)
            .expect("same original target"),
        proposal
    );
    let mut store = f.carrier.store.lock().expect("independent witness");
    match t {
        Some(t) => store.prepare_policy_continuation(
            proposal,
            t,
            &PolicyContinuationMaterials {
                original: f.c.policy.historical(),
                previous: f.c.policy.historical(),
                target: p,
                credential: g,
            },
            170,
        ),
        None => {
            store.prepare_continued_credential_renewal(proposal, g, f.c.policy.historical(), p, 170)
        }
    }
    .expect("independent exact G/T approval");
    proposal
}
fn target_bytes(f: &Fixture, p: &Proposal) -> Vec<u8> {
    let pending = disk(f).1.expect("durable intent");
    assert_eq!(pending.get(..8), Some(b"QPWINT04".as_slice()));
    let target = pending
        .get(253..pending.len() - 32)
        .expect("bounded v4 target")
        .to_vec();
    assert_eq!(
        crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2", &target,),
        p.target_head().digest()
    );
    target
}
fn committed(g: &VerifiedCredentialRenewal, p: &Proposal) -> CredentialRenewalStatus {
    CredentialRenewalStatus::Committed {
        operation: g.operation(),
        statement: p.transaction_statement(),
        target: g.successor_device().roster().checkpoint(),
    }
}

fn replace_exact(bytes: &mut [u8], from: &[u8], to: &[u8], expected: usize) {
    assert_eq!(from.len(), to.len());
    let offsets: Vec<_> = bytes
        .windows(from.len())
        .enumerate()
        .filter_map(|(index, part)| (part == from).then_some(index))
        .collect();
    assert_eq!(offsets.len(), expected);
    for offset in offsets {
        bytes
            .get_mut(offset..offset + to.len())
            .expect("exact field")
            .copy_from_slice(to);
    }
}

#[test]
fn original_sealed_intent_rejects_another_valid_t_and_mode_or_format_rebinding_before_dispatch() {
    let f = fixture_with_policy_expiry(Some(160));
    let g = grant(&f, &f.original, 2, 180);
    let p1 = super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let p2 = super::super::policy_continuation::policy(&f.c, 3, 195, 170);
    let scope = super::super::policy_continuation::scope(&f.c, &g, f.id);
    let t1 = super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p1);
    let t2 = super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p2);
    let proposal = prepare_policy(&f, &g, Some(&t1), &p1);
    let base = Proposal::from_journal(
        proposal.witness_binding(),
        proposal.subject(),
        g.operation(),
        g.statement_digest(),
        proposal.expected_head(),
        proposal.target_head(),
    )
    .expect("same G/head");
    let different = base
        .with_policy_continuation(&t2)
        .expect("other independently valid T");
    let retained = base
        .with_retained_policy_continuation(&t1.historical())
        .expect("different mode");
    let mut owner = open(&f.c);
    let image = owner.image().expect("original configuration");
    let original =
        encode(&owner.key().expect("key"), owner.binding, &image).expect("original wire");
    owner.close();
    let disk_before = disk(&f);
    for control in 0..3 {
        let mut body = original
            .get(..original.len() - 32)
            .expect("MAC body")
            .to_vec();
        match control {
            0 => {
                // Model wrapping-key access and a second fully signed target:
                // config now consistently claims T2, but the original sealed intent remains T1.
                replace_exact(&mut body, &proposal.to_bytes(), &different.to_bytes(), 1);
                replace_exact(&mut body, &t1.statement_digest(), &t2.statement_digest(), 1);
                replace_exact(
                    &mut body,
                    &t1.historical().journal_bytes(),
                    &t2.historical().journal_bytes(),
                    1,
                );
            }
            1 => replace_exact(&mut body, &proposal.to_bytes(), &retained.to_bytes(), 1),
            _ => body
                .get_mut(..8)
                .expect("version")
                .copy_from_slice(b"QPENST06"),
        }
        let key = JournalKey::open(&f.c.paths.wrapping).expect("wrapping key");
        let mut mac = auth(&key).expect("configuration authentication");
        mac.update(&body);
        body.extend_from_slice(&mac.finalize().into_bytes());
        {
            let db = open_private_database(&f.c.paths.configuration).expect("configuration");
            write(&db, &body).expect("authenticated adversarial configuration");
        }
        f.carrier.requests.lock().expect("trace").clear();
        if control == 0 {
            let mut owner = open(&f.c);
            assert!(matches!(
                owner
                    .recover_witnessed_credential_renewal_preparation(f.c.policy.historical(), 170),
                Err(DurableError::Conflict)
            ));
            assert!(owner.active.is_none());
        } else {
            assert!(
                matches!(
                    DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()),
                    Err(DurableError::Corrupt)
                ),
                "accepted control {control}"
            );
        }
        assert!(f.carrier.requests.lock().expect("trace").is_empty());
        assert_eq!(disk(&f), disk_before);
    }
    {
        let db = open_private_database(&f.c.paths.configuration).expect("configuration");
        write(&db, &original).expect("restore original transaction");
    }
    assert_eq!(
        open(&f.c)
            .recover_witnessed_credential_renewal_preparation(f.c.policy.historical(), 170,)
            .expect("original remains recoverable"),
        Some(proposal)
    );
}

#[test]
fn sealed_g1_t1_then_g2_retains_t1_and_exact_ciphertext_through_ack() {
    let f = fixture_with_policy_expiry(Some(160));
    let g1 = grant(&f, &f.original, 2, 180);
    let p1 = super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let scope = super::super::policy_continuation::scope(&f.c, &g1, f.id);
    let t1 = super::super::policy_continuation::joint(&f.c, &g1, &scope, &f.c.policy, &p1);
    let g2 = grant(&f, g1.successor_device(), 3, 185);
    for (g, t) in [(&g1, Some(&t1)), (&g2, None)] {
        let p = prepare_policy(&f, g, t, &p1);
        assert_eq!(p.statement(), g.statement_digest());
        assert_eq!(p.policy_continuation(), Some(t1.statement_digest()));
        assert_eq!(p.adopts_policy(), t.is_some());
        let target = target_bytes(&f, &p);
        let mut owner = open(&f.c);
        let image = owner.image().expect("configuration readback");
        let bytes = encode(&owner.key().expect("key"), owner.binding, &image).expect("wire");
        assert_eq!(bytes.get(..8), Some(b"QPENST07".as_slice()));
        let mut anchor = client(&f, &mut owner, 170);
        assert_eq!(
            owner
                .commit_witnessed_policy_continuation(
                    &p,
                    f.c.policy.historical(),
                    &p1,
                    170,
                    &mut anchor,
                )
                .expect("exact original commit and ACK"),
            committed(g, &p)
        );
        let image = owner.image().expect("completion");
        let bytes =
            encode(&owner.key().expect("key"), owner.binding, &image).expect("completion wire");
        assert_eq!(bytes.get(..8), Some(b"QPENST06".as_slice()));
        let t_bytes = t1.historical().journal_bytes();
        assert_eq!(
            bytes
                .windows(t_bytes.len())
                .filter(|part| *part == t_bytes)
                .count(),
            1
        );
        assert_eq!(
            owner
                .recover_witnessed_credential_renewal_preparation(f.c.policy.historical(), 170,)
                .expect("no remaining transaction slot"),
            None
        );
        owner.close();
        assert_eq!(disk(&f), (target, None));
    }
}

#[test]
fn applied_policy_target_recovers_after_completion_sync_loss_and_expiry_then_lost_ack() {
    for after in [false, true] {
        let f = fixture_with_policy_expiry(Some(160));
        let g = grant(&f, &f.original, 2, 180);
        let p1 = super::super::policy_continuation::policy(&f.c, 2, 190, 170);
        let scope = super::super::policy_continuation::scope(&f.c, &g, f.id);
        let t1 = super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p1);
        let p = prepare_policy(&f, &g, Some(&t1), &p1);
        let target = target_bytes(&f, &p);
        let pending = disk(&f).1.expect("original intent");
        let (mut owner, remaining, _) = faulty(&f.c, after);
        let mut anchor = client(&f, &mut owner, 170);
        remaining.store(1, Ordering::SeqCst);
        assert_sync_failure(
            owner.commit_witnessed_policy_continuation(
                &p,
                f.c.policy.historical(),
                &p1,
                170,
                &mut anchor,
            ),
            after,
        );
        assert!(owner.active.is_none());
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
        assert_eq!(disk(&f), (target.clone(), Some(pending.clone())));
        f.carrier.clock.store(200, Ordering::SeqCst);
        f.c.policy.close();
        p1.close();
        f.carrier.requests.lock().expect("trace").clear();
        *f.carrier.cut.lock().expect("lost ACK") = Some((8, true));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 200);
        assert!(owner
            .reconcile_witnessed_credential_renewal(
                g.operation(),
                t1.statement_digest(),
                f.c.policy.historical(),
                200,
                &mut anchor,
            )
            .is_err());
        assert!(owner.active.is_none());
        assert_eq!(disk(&f), (target.clone(), Some(pending)));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 200);
        assert_eq!(
            owner
                .reconcile_witnessed_credential_renewal(
                    g.operation(),
                    t1.statement_digest(),
                    f.c.policy.historical(),
                    200,
                    &mut anchor,
                )
                .expect("historical exact terminal and ACK recovery"),
            committed(&g, &p)
        );
        let image = owner.image().expect("terminal readback");
        let bytes =
            encode(&owner.key().expect("key"), owner.binding, &image).expect("completion wire");
        assert_eq!(bytes.get(..8), Some(b"QPENST06".as_slice()));
        let t_bytes = t1.historical().journal_bytes();
        assert_eq!(
            bytes
                .windows(t_bytes.len())
                .filter(|part| *part == t_bytes)
                .count(),
            1
        );
        owner.close();
        assert_eq!(disk(&f), (target, None));
        assert!(!f.carrier.requests.lock().expect("trace").contains(&5));
        assert!(open(&f.c)
            .activate_policy_continuation(f.c.policy.historical(), &p1, 200)
            .is_err());
    }
}

#[test]
fn lost_policy_commit_status_and_ack_replies_preserve_original_terminal_or_pending() {
    for opcode in [5, 6, 8] {
        for after in [false, true] {
            let f = fixture_with_policy_expiry(Some(160));
            let g = grant(&f, &f.original, 2, 180);
            let p1 = super::super::policy_continuation::policy(&f.c, 2, 190, 170);
            let scope = super::super::policy_continuation::scope(&f.c, &g, f.id);
            let t1 = super::super::policy_continuation::joint(&f.c, &g, &scope, &f.c.policy, &p1);
            let p = prepare_policy(&f, &g, Some(&t1), &p1);
            let target = target_bytes(&f, &p);
            let before = disk(&f);
            *f.carrier.cut.lock().expect("cut") = Some((opcode, after));
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 170);
            assert!(owner
                .commit_witnessed_policy_continuation(
                    &p,
                    f.c.policy.historical(),
                    &p1,
                    170,
                    &mut anchor,
                )
                .is_err());
            assert!(owner.active.is_none());
            f.carrier.clock.store(200, Ordering::SeqCst);
            p1.close();
            f.c.policy.close();
            f.carrier.requests.lock().expect("trace").clear();
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 200);
            let status = owner
                .reconcile_witnessed_credential_renewal(
                    g.operation(),
                    t1.statement_digest(),
                    f.c.policy.historical(),
                    200,
                    &mut anchor,
                )
                .expect("original historical reconciliation");
            if opcode == 5 && !after {
                assert_eq!(
                    status,
                    CredentialRenewalStatus::Pending {
                        operation: g.operation(),
                        statement: t1.statement_digest(),
                    }
                );
                assert_eq!(disk(&f), before);
                assert_eq!(
                    owner
                        .close_witnessed_credential_renewal(
                            g.operation(),
                            t1.statement_digest(),
                            f.c.policy.historical(),
                            200,
                            &mut anchor,
                        )
                        .expect("close exact uncommitted T"),
                    CredentialRenewalStatus::Closed {
                        operation: g.operation(),
                        statement: t1.statement_digest(),
                        target: g.successor_device().roster().checkpoint(),
                    }
                );
                assert_eq!(disk(&f), (before.0, None));
                let image = owner.image().expect("closed record");
                let bytes =
                    encode(&owner.key().expect("key"), owner.binding, &image).expect("closed wire");
                assert_eq!(bytes.get(..8), Some(b"QPENST04".as_slice()));
            } else {
                assert_eq!(status, committed(&g, &p));
                assert_eq!(disk(&f), (target, None));
            }
            assert!(!f
                .carrier
                .requests
                .lock()
                .expect("historical trace")
                .contains(&5));
        }
    }
}

#[test]
fn durable_applied_terminal_cannot_ack_with_a_substituted_adopted_policy() {
    for carry in [false, true] {
        let f = fixture_with_policy_expiry(Some(160));
        let g1 = grant(&f, &f.original, 2, 180);
        let g2 = grant(&f, g1.successor_device(), 3, 185);
        let p1 = super::super::policy_continuation::policy(&f.c, 2, 190, 170);
        let p2 = super::super::policy_continuation::policy(&f.c, 3, 195, 170);
        let scope = super::super::policy_continuation::scope(&f.c, &g1, f.id);
        let t1 = super::super::policy_continuation::joint(&f.c, &g1, &scope, &f.c.policy, &p1);
        let t2 = super::super::policy_continuation::joint(&f.c, &g1, &scope, &f.c.policy, &p2);
        let first = prepare_policy(&f, &g1, Some(&t1), &p1);
        let (g, proposal) = if carry {
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 170);
            owner
                .commit_witnessed_policy_continuation(
                    &first,
                    f.c.policy.historical(),
                    &p1,
                    170,
                    &mut anchor,
                )
                .expect("complete first T");
            owner.close();
            (&g2, prepare_policy(&f, &g2, None, &p1))
        } else {
            (&g1, first)
        };
        *f.carrier.cut.lock().expect("cut") = Some((8, false));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 170);
        assert!(owner
            .commit_witnessed_policy_continuation(
                &proposal,
                f.c.policy.historical(),
                &p1,
                170,
                &mut anchor,
            )
            .is_err());
        assert!(owner.active.is_none());
        let mut owner = open(&f.c);
        assert_eq!(
            owner
                .credential_renewal_status()
                .expect("durable completion"),
            committed(g, &proposal)
        );
        let image = owner.image().expect("terminal");
        let original =
            encode(&owner.key().expect("key"), owner.binding, &image).expect("terminal wire");
        owner.close();
        let mut body = original
            .get(..original.len() - 32)
            .expect("authenticated body")
            .to_vec();
        replace_exact(
            &mut body,
            &t1.historical().journal_bytes(),
            &t2.historical().journal_bytes(),
            1,
        );
        let key = JournalKey::open(&f.c.paths.wrapping).expect("wrapping key");
        let mut mac = auth(&key).expect("authentication");
        mac.update(&body);
        body.extend_from_slice(&mac.finalize().into_bytes());
        {
            let db = open_private_database(&f.c.paths.configuration).expect("config");
            write(&db, &body).expect("authenticated alternate T");
        }
        let before = disk(&f);
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 170);
        f.carrier.requests.lock().expect("trace").clear();
        let result = owner.reconcile_witnessed_credential_renewal(
            g.operation(),
            proposal.transaction_statement(),
            f.c.policy.historical(),
            170,
            &mut anchor,
        );
        assert!(
            matches!(result, Err(DurableError::Conflict)),
            "substituted adopted T reached ACK: carry={carry}, result={result:?}"
        );
        assert!(owner.active.is_none());
        assert!(f.carrier.requests.lock().expect("trace").is_empty());
        assert_eq!(disk(&f), before);
        {
            let db = open_private_database(&f.c.paths.configuration).expect("config");
            write(&db, &original).expect("restore durable original");
        }
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 170);
        assert_eq!(
            owner
                .reconcile_witnessed_credential_renewal(
                    g.operation(),
                    proposal.transaction_statement(),
                    f.c.policy.historical(),
                    170,
                    &mut anchor,
                )
                .expect("original terminal still retires"),
            committed(g, &proposal)
        );
    }
}

#[test]
fn witnessed_policy_owner_requires_ack_and_fresh_current_g_t_after_each_reopen() {
    let f = fixture_with_policy_expiry(Some(160));
    let g1 = grant(&f, &f.original, 2, 180);
    let g2 = grant(&f, g1.successor_device(), 3, 185);
    let p1 = super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let scope = super::super::policy_continuation::scope(&f.c, &g1, f.id);
    let t1 = super::super::policy_continuation::joint(&f.c, &g1, &scope, &f.c.policy, &p1);
    for (g, t) in [(&g1, Some(&t1)), (&g2, None)] {
        let p = prepare_policy(&f, g, t, &p1);
        let mut owner = open(&f.c);
        let anchor = client(&f, &mut owner, 170);
        assert!(matches!(
            owner
                .activate_witnessed_policy_continuation(f.c.policy.historical(), &p1, 170, anchor,),
            Err(DurableError::Suspended)
        ));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 170);
        owner
            .commit_witnessed_policy_continuation(
                &p,
                f.c.policy.historical(),
                &p1,
                170,
                &mut anchor,
            )
            .expect("completed transaction and ACK");
        owner.close();
        let before = disk(&f);
        for _ in 0..2 {
            let mut owner = open(&f.c);
            let anchor = client(&f, &mut owner, 170);
            f.carrier.requests.lock().expect("trace").clear();
            let mut active = owner
                .activate_witnessed_policy_continuation(f.c.policy.historical(), &p1, 170, anchor)
                .expect("current witnessed P1 owner");
            let (service, signer, current) = active.parts().expect("controlled original owners");
            assert_eq!(
                current.credential_digest(),
                g.successor_device().credential_digest()
            );
            signer
                .check_device(current)
                .expect("original signing owner");
            assert_eq!(
                service
                    .stores()
                    .expect("stores")
                    .0
                    .identity()
                    .expect("journal"),
                f.id
            );
            assert!(f.carrier.requests.lock().expect("trace").contains(&10));
            active.close();
            assert_eq!(
                disk(&f),
                before,
                "activation must retain exact receipt and target"
            );
        }
        for after in [false, true] {
            *f.carrier.cut.lock().expect("cut") = Some((10, after));
            let mut owner = open(&f.c);
            let anchor = client(&f, &mut owner, 170);
            assert!(owner
                .activate_witnessed_policy_continuation(f.c.policy.historical(), &p1, 170, anchor,)
                .is_err());
            assert_eq!(disk(&f), before);
        }
    }
}
