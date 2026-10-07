// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::tests::policy_continuation::policy;

fn approved_at(
    f: &Fixture,
    previous: &VerifiedSessionPolicy,
    version: u64,
    until: u64,
    now: u64,
) -> Approval {
    f.carrier.clock.store(now, Ordering::SeqCst);
    let mut owner = open(&f.c);
    let client = policy_client(f, &mut owner);
    let request = owner
        .witnessed_policy_renewal_request(
            PolicyRenewalId::generate().expect("retain next P operation"),
            f.c.policy.historical(),
            client,
        )
        .expect("actual original request, including expired predecessor");
    owner.close();
    let target = policy(&f.c, version, until, now);
    let materials = request.materials(f.c.policy.historical(), previous.historical(), &target);
    let statement =
        PolicyRenewalStatement::new(request.scope(), &materials, now).expect("exact previous P");
    let issuer = crate::PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy issuer");
    let proof = VerifiedPolicyRenewal::verify(
        &f.c.root
            .approve_policy_renewal(&statement)
            .expect("account root approval"),
        &issuer
            .approve_policy_renewal(&statement)
            .expect("policy root approval"),
        request.scope(),
        &materials,
        now,
    )
    .expect("two independent roots");
    Approval {
        request,
        target,
        proof,
    }
}
fn prepared_at(
    f: &Fixture,
    a: &Approval,
    previous: &VerifiedSessionPolicy,
    now: u64,
) -> PolicyProposal {
    let mut owner = open(&f.c);
    owner
        .stage_policy_renewal(
            &a.proof,
            a.proof.scope().operation,
            f.c.policy.historical(),
            &a.target,
            now,
        )
        .expect("retain next approval and original completion");
    let client = policy_client(f, &mut owner);
    let proposal = owner
        .prepare_witnessed_policy_renewal(
            f.c.policy.historical(),
            previous.historical(),
            &a.target,
            now,
            client,
        )
        .expect("prepare actual next sealed image");
    owner.close();
    let materials = a
        .request
        .materials(f.c.policy.historical(), previous.historical(), &a.target);
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_policy_renewal(proposal, &a.proof, &materials, now)
            .expect("separately authorize same proposal"),
        State::Prepared
    );
    proposal
}
fn applied_at(f: &Fixture, a: &Approval, p: PolicyProposal, now: u64) {
    let mut owner = open(&f.c);
    let mut client = policy_client(f, &mut owner);
    assert_eq!(
        owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                now,
                &mut client
            )
            .expect("apply original operation"),
        State::Applied
    );
    owner.close();
}
fn activate(
    f: &Fixture,
    policy: &VerifiedSessionPolicy,
    now: u64,
) -> Result<EnrolledDevice, DurableError> {
    let mut owner = open(&f.c);
    let client = policy_client(f, &mut owner);
    owner.activate_witnessed_policy_renewal(f.c.policy.historical(), policy, now, client)
}
#[test]
fn original_required_policy_owner_retains_leases_and_needs_no_ack_head_advance() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    approve_witness(&f, &a, p);
    applied_at(&f, &a, p, 150);
    let before = journal(&f);
    let signer = fs::read(&f.c.paths.signer).expect("original signer");
    let start = f.carrier.requests.lock().expect("calls").len();
    let mut active = activate(&f, &a.target, 150).expect("same original operational owner");
    assert!(
        DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err(),
        "registration lease remains owned"
    );
    let (service, key, device) = active.parts().expect("same owners");
    key.check_device(device).expect("original signing identity");
    assert_eq!(device.credential_digest(), f.original.credential_digest());
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("identity"),
        f.id
    );
    active.close();
    assert!(active.parts().is_err());
    assert_eq!(
        journal(&f),
        before,
        "owner release must not rewrite receipt or sealed state"
    );
    assert_eq!(fs::read(&f.c.paths.signer).expect("signer bytes"), signer);
    let calls = f.carrier.requests.lock().expect("calls");
    let calls = calls.get(start..).expect("activation calls");
    assert!(calls.contains(&15));
    assert!(!calls.contains(&2), "no metadata-only Advance");
}
#[test]
fn required_policy_history_cannot_replace_fresh_witness_runtime_or_owner_evidence() {
    for failure in 0..5 {
        let f = fixture();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        approve_witness(&f, &a, p);
        applied_at(&f, &a, p, 150);
        let before = journal(&f);
        let start = f.carrier.requests.lock().expect("calls").len();
        match failure {
            0 | 1 => *f.carrier.cut.lock().expect("cut") = Some((15, failure == 1)),
            2 => f.carrier.clock.store(401, Ordering::SeqCst),
            3 => {
                // Close after the genuinely signed P admission, before returning an owner.
                let target = Arc::clone(&a.target.runtime);
                *f.carrier.after_reply.lock().expect("hook") =
                    Some((15, Box::new(move || target.close())));
            }
            _ => {
                let mut owner = open(&f.c);
                let client = policy_client(&f, &mut owner);
                let mut journal = DeviceJournal::open_anchored_retained(
                    f.c.paths.installation.files()[1],
                    owner.key().expect("original key"),
                    &f.original,
                    f.c.policy.historical(),
                    f.id,
                    client,
                )
                .expect("metadata journal only");
                let authority = crate::RetainedInstallationAuthority::active_installation(
                    &f.original,
                    f.c.policy.historical(),
                );
                assert!(
                    journal
                        .admit_continued_local_device(
                            &crate::installation::PolicyScope {
                                authority: &authority,
                                original_policy: f.c.policy.historical(),
                                original_device: &f.original
                            },
                            &f.original,
                            &a.target,
                            150
                        )
                        .is_err(),
                    "direct journal lacks original enrollment completion"
                );
                journal.close();
                owner.close();
            }
        }
        if failure < 4 {
            assert!(
                activate(&f, &a.target, 150).is_err(),
                "fresh gate {failure}"
            );
            assert!(f
                .carrier
                .requests
                .lock()
                .expect("calls")
                .get(start..)
                .expect("calls")
                .contains(&15));
        } else {
            activate(&f, &a.target, 150)
                .expect("same history through owning enrollment")
                .close();
        }
        assert_eq!(
            journal(&f),
            before,
            "failed release leaves historical journal unchanged"
        );
        assert_eq!(
            open(&f.c).policy_renewal_status().expect("history"),
            crate::PolicyRenewalStatus::Committed {
                operation: p.operation(),
                statement: p.statement(),
                target: a.target.checkpoint()
            }
        );
    }
}
#[test]
fn lost_terminal_ack_recovers_after_policy_expiry_and_next_policy_uses_same_journal() {
    let f = fixture_with_policy_expiry(Some(151));
    let a = approved_at(&f, &f.c.policy, 2, 154, 150);
    let p = prepared_at(&f, &a, &f.c.policy, 150);
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    *f.carrier.cut.lock().expect("cut") = Some((14, false));
    assert!(owner
        .commit_witnessed_policy_renewal(&p, f.c.policy.historical(), &a.target, 150, &mut client)
        .is_err());
    let before = journal(&f);
    f.carrier.clock.store(155, Ordering::SeqCst);
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    let start = f.carrier.requests.lock().expect("calls").len();
    assert_eq!(
        owner
            .reconcile_witnessed_policy_renewal(
                p.operation(),
                p.statement(),
                f.c.policy.historical(),
                &mut client
            )
            .expect("expired exact terminal recovery"),
        State::Applied
    );
    owner.close();
    assert_eq!(journal(&f).0, before.0);
    assert!(journal(&f).1.is_none());
    assert!(!f
        .carrier
        .requests
        .lock()
        .expect("calls")
        .get(start..)
        .expect("calls")
        .contains(&2));
    assert!(
        activate(&f, &a.target, 155).is_err(),
        "expired P remains unusable"
    );
    let b = approved_at(&f, &a.target, 3, 159, 155);
    assert_eq!(
        b.request.scope().previous_authorization,
        Some(a.proof.statement_digest())
    );
    let q = prepared_at(&f, &b, &a.target, 155);
    applied_at(&f, &b, q, 155);
    let mut active = activate(&f, &b.target, 155).expect("next live policy after expired previous");
    assert_eq!(
        active
            .parts()
            .expect("owners")
            .0
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("id"),
        f.id
    );
    active.close();
    assert!(
        activate(&f, &a.target, 155).is_err(),
        "old authentic policy does not regain authority"
    );
}
#[test]
fn closing_second_policy_preserves_first_enrollment_completion_and_owner() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    approve_witness(&f, &a, p);
    applied_at(&f, &a, p, 150);
    let before = journal(&f);
    let b = approved_at(&f, &a.target, 3, 350, 150);
    let q = prepared_at(&f, &b, &a.target, 150);
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .close_witnessed_policy_renewal(
                q.operation(),
                q.statement(),
                f.c.policy.historical(),
                &mut client
            )
            .expect("close second original target"),
        State::Closed
    );
    owner.close();
    assert_eq!(journal(&f), before);
    activate(&f, &a.target, 150)
        .expect("first actual P and original completion survive")
        .close();
    assert!(
        activate(&f, &b.target, 150).is_err(),
        "closed target is never operational"
    );
}

#[test]
fn original_required_session_exchanges_rekeys_and_fences_cached_ciphertext_under_independent_p() {
    use crate::enrollment::tests::witness_renewal::policy_transaction::sessions::{
        bundle, endpoint, requirements,
    };
    use crate::{BootstrapRole, FanoutInput, FanoutTarget, InitiationId};
    let first = fixture_with_policy_expiry(Some(151));
    let second = fixture_on_witness(
        Arc::clone(&first._witness_dir),
        first.pin.clone(),
        first.carrier.clone(),
        Some(151),
    );
    let mut a = endpoint(first);
    let mut b = endpoint(second);
    let bundle = bundle(&a, &mut b);
    let ci = Arc::new(
        bundle
            .verify(
                Arc::new(policy(&a.f.c, 1, 151, 150)),
                requirements(&a, &b),
                150,
            )
            .expect("initiator context"),
    );
    let cr = Arc::new(
        bundle
            .verify(
                Arc::new(policy(&b.f.c, 1, 151, 150)),
                requirements(&a, &b),
                150,
            )
            .expect("responder context"),
    );
    let initiation = InitiationId::generate().expect("original initiation");
    let (session, old_id, old_wire);
    {
        let (is, ik, _) = a.owner.parts().expect("initiator owners");
        let (rs, rk, _) = b.owner.parts().expect("responder owners");
        let (ij, ia) = is.stores().expect("initiator stores");
        let (rj, ra) = rs.stores().expect("responder stores");
        let initial = ij
            .initiate(Arc::clone(&ci), initiation, ik, 150)
            .expect("original initiate");
        let reply = rj
            .respond_from_inventory(Arc::clone(&cr), &initial, rk, 150)
            .expect("real prekeys");
        let final_msg = ij
            .accept_reply(Arc::clone(&ci), initiation, &reply, 150)
            .expect("original accept");
        session = final_msg.session_id();
        rj.finish(Arc::clone(&cr), &initial, final_msg.final_message(), 150)
            .expect("original finish");
        ij.activate_initiator_messages(Arc::clone(&ci), initiation, 150)
            .expect("initiator messages");
        rj.activate_responder_messages(Arc::clone(&cr), &initial, 150)
            .expect("responder messages");
        let archive = ij
            .archive_session_closure(&ci, session)
            .expect("initiator archive");
        ia.retain(ij, &ci, session, &archive)
            .expect("retain original archive");
        let archive = rj
            .archive_session_closure(&cr, session)
            .expect("responder archive");
        ra.retain(rj, &cr, session, &archive)
            .expect("retain original archive");
        old_id = ij
            .next_message_id(&ci, session, 150)
            .expect("original message");
        old_wire = ij
            .send_message(&ci, session, old_id, b"original ciphertext", b"old", 150)
            .expect("original send");
    }
    a.owner.close();
    b.owner.close();
    let ap = approved_at(&a.f, &a.f.c.policy, 2, 159, 155);
    let aq = prepared_at(&a.f, &ap, &a.f.c.policy, 155);
    applied_at(&a.f, &ap, aq, 155);
    let bp = approved_at(&b.f, &b.f.c.policy, 2, 159, 155);
    let bq = prepared_at(&b.f, &bp, &b.f.c.policy, 155);
    applied_at(&b.f, &bp, bq, 155);
    let pa = Arc::new(ap.target);
    let pb = Arc::new(bp.target);
    let ri = bundle
        .request_historical_reopen(
            Arc::new(a.f.c.policy.historical().clone()),
            requirements(&a, &b),
            BootstrapRole::Initiator,
            session,
            155,
        )
        .expect("original initiator archive request");
    let rr = bundle
        .request_historical_reopen(
            Arc::new(b.f.c.policy.historical().clone()),
            requirements(&a, &b),
            BootstrapRole::Responder,
            session,
            155,
        )
        .expect("original responder archive request");
    let mut owner = open(&a.f.c);
    let client = policy_client(&a.f, &mut owner);
    let (ao, pi) = owner
        .activate_witnessed_policy_renewed_session(ri, Arc::clone(&pa), 155, client)
        .expect("owning initiator reopen");
    a.owner = ao;
    let mut owner = open(&b.f.c);
    let client = policy_client(&b.f, &mut owner);
    let (bo, pr) = owner
        .activate_witnessed_policy_renewed_session(rr, Arc::clone(&pb), 155, client)
        .expect("owning responder reopen");
    b.owner = bo;
    let (is, ik, _) = a.owner.parts().expect("original owners");
    let (rs, rk, _) = b.owner.parts().expect("peer owners");
    let ij = is.stores().expect("stores").0;
    let rj = rs.stores().expect("stores").0;
    assert_eq!(
        ij.resume_message(pi.context(), session, old_id, 155)
            .expect("original outbox"),
        old_wire
    );
    assert_eq!(
        rj.receive_message(pr.context(), session, &old_wire, b"old", 155)
            .expect("decrypt old ciphertext")
            .as_bytes(),
        b"original ciphertext"
    );
    let id = ij
        .next_message_id(pi.context(), session, 155)
        .expect("new original-session message");
    let wire = ij
        .send_message(
            pi.context(),
            session,
            id,
            b"independent P traffic",
            b"new",
            155,
        )
        .expect("new traffic");
    assert_eq!(
        rj.receive_message(pr.context(), session, &wire, b"new", 155)
            .expect("actual peer decryption")
            .as_bytes(),
        b"independent P traffic"
    );
    let offer = ij
        .prepare_rekey_offer(pi.context(), session, ik, 155)
        .expect("PQ offer");
    let response = rj
        .respond_rekey_offer(pr.context(), session, &offer, rk, 155)
        .expect("PQ response");
    let final_msg = ij
        .accept_rekey_response(pi.context(), session, &response, ik, 155)
        .expect("PQ final");
    let receipt = rj
        .finish_rekey(pr.context(), session, &final_msg, rk, 155)
        .expect("PQ receipt");
    ij.accept_rekey_receipt(pi.context(), session, &receipt, 155)
        .expect("confirmed epoch");
    assert_eq!(
        ij.rekey_progress(pi.context(), session)
            .expect("initiator epoch")
            .confirmed_epoch,
        1
    );
    assert_eq!(
        rj.rekey_progress(pr.context(), session)
            .expect("responder epoch")
            .confirmed_epoch,
        1
    );
    let id = rj
        .next_message_id(pr.context(), session, 155)
        .expect("peer ID");
    let wire = rj
        .send_message(pr.context(), session, id, b"new epoch", b"epoch", 155)
        .expect("reverse direction");
    assert_eq!(
        ij.receive_message(pi.context(), session, &wire, b"epoch", 155)
            .expect("decrypt new epoch")
            .as_bytes(),
        b"new epoch"
    );
    let cached = ij
        .next_message_id(pi.context(), session, 155)
        .expect("cached ID");
    ij.send_message(pi.context(), session, cached, b"cached", b"cache", 155)
        .expect("cached individual");
    let batch = rj.next_fanout_id().expect("batch");
    let targets = [FanoutTarget {
        context: pr.context(),
        session,
    }];
    rj.send_account_message(
        FanoutInput {
            id: batch,
            account: a.f.original.account_id(),
            targets: &targets,
            plaintext: b"cached batch",
            associated_data: b"batch",
        },
        155,
    )
    .expect("real account fanout");
    // Current SDK time alone is insufficient: witness time independently expires P.
    a.f.carrier.clock.store(159, Ordering::SeqCst);
    assert!(
        matches!(ij.resume_message(pi.context(), session, cached, 155), Err(DurableError::Anchor(e)) if matches!(*e, crate::AnchorClientError::AuthorityDenied)),
        "cached ciphertext needs fresh P admission"
    );
    assert!(
        matches!(rj.resume_account_message(batch, &targets, 155), Err(DurableError::Anchor(e)) if matches!(*e, crate::AnchorClientError::AuthorityDenied)),
        "cached fanout needs fresh P admission"
    );
    a.owner.close();
    b.owner.close();
    // Reopen metadata independently; a new operational owner still cannot pass the witness.
    assert!(activate(&a.f, &pa, 155).is_err());
    assert_eq!(
        open(&a.f.c)
            .policy_renewal_status()
            .expect("preserved original terminal"),
        crate::PolicyRenewalStatus::Committed {
            operation: aq.operation(),
            statement: aq.statement(),
            target: pa.checkpoint()
        }
    );
}

#[path = "witness_independent_policy_process_tests.rs"]
mod process;

#[test]
fn original_completion_codec_rejects_substitution_and_reads_legacy_terminal_without_rewriting() {
    use crate::enrollment::tests::policy_renewal::{replace_authenticated, row};
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    approve_witness(&f, &a, p);
    applied_at(&f, &a, p, 150);
    let saved = row(&open(&f.c));
    assert_eq!(saved.get(..8), Some(b"QPENST16".as_slice()));
    let marker = saved
        .len()
        .checked_sub(32 + 296 + 1)
        .expect("completed marker");
    assert_eq!(saved.get(marker), Some(&1));
    let mut changed = saved.clone();
    *changed
        .get_mut(saved.len() - 33)
        .expect("completion target digest") ^= 1;
    let mut missing = saved.clone();
    missing.drain(marker + 1..marker + 297);
    *missing.get_mut(marker).expect("completion flag") = 0;
    let mut tail = saved.clone();
    tail.insert(tail.len() - 32, 0);
    let before = journal(&f);
    let calls = f.carrier.requests.lock().expect("calls").len();
    for bytes in [changed, missing, tail] {
        replace_authenticated(&f.c, &bytes);
        assert!(
            DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err(),
            "malformed completed marker cannot become a capability"
        );
        assert_eq!(journal(&f), before);
        assert_eq!(f.carrier.requests.lock().expect("calls").len(), calls);
        replace_authenticated(&f.c, &saved);
    }
    let mut legacy = saved.clone();
    legacy
        .get_mut(..8)
        .expect("tag")
        .copy_from_slice(b"QPENST15");
    legacy.drain(marker..marker + 297);
    replace_authenticated(&f.c, &legacy);
    let old = row(&open(&f.c));
    activate(&f, &a.target, 150)
        .expect("old exact AppliedRetired supplies original completion")
        .close();
    assert_eq!(
        row(&open(&f.c)),
        old,
        "opening old format never rewrites it"
    );
    assert_eq!(journal(&f), before);
    replace_authenticated(&f.c, &saved);
}

#[test]
fn actual_roster_revocation_or_witness_roster_advance_blocks_original_policy_owner() {
    for witness_only in [false, true] {
        let f = fixture();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        approve_witness(&f, &a, p);
        applied_at(&f, &a, p, 150);
        let mut owner = open(&f.c);
        let certificate = match owner.image().expect("original enrollment").phase {
            Phase::Accepted { admission, .. } => Ok(admission.certificate),
            _ => Err("original accepted identity"),
        }
        .expect("original certificate");
        let entries = if witness_only {
            vec![f
                .c
                .root
                .roster_entry(&certificate)
                .expect("same credential")]
        } else {
            Vec::new()
        };
        let roster =
            f.c.root
                .issue_roster(2, interval(), &entries)
                .expect("root-authorized actual roster");
        let pin = AccountPin::new(
            f.original.account_id(),
            f.c.intent.root.clone(),
            roster.checkpoint(),
            a.target.family(),
        )
        .expect("new independently retained root pin");
        if witness_only {
            let next = pin
                .verify_device(&certificate, roster.as_bytes(), 150)
                .expect("same C, real new R");
            f.carrier
                .store
                .lock()
                .expect("witness")
                .update_roster_authority(
                    p.subject(),
                    f.original.roster().checkpoint(),
                    &next,
                    &a.target,
                    150,
                )
                .expect("independent witness adopts R2");
            owner.close();
            assert!(
                matches!(activate(&f,&a.target,150),Err(DurableError::Anchor(e)) if matches!(*e,crate::AnchorClientError::AuthorityDenied)),
                "old local roster cannot replace fresh witness authority"
            );
        } else {
            let current = pin
                .verify_roster(roster.as_bytes(), 150)
                .expect("root-signed actual revocation");
            let client = policy_client(&f, &mut owner);
            let mut journal = DeviceJournal::open_anchored_retained(
                f.c.paths.installation.files()[1],
                owner.key().expect("key"),
                &f.original,
                f.c.policy.historical(),
                f.id,
                client,
            )
            .expect("original journal");
            journal
                .install_roster(&current, 150)
                .expect("actual committed revocation");
            journal.close();
            owner.close();
            assert!(
                activate(&f, &a.target, 150).is_err(),
                "historical completion cannot revive revoked current membership"
            );
        }
        assert_eq!(
            open(&f.c)
                .policy_renewal_status()
                .expect("original historical completion"),
            crate::PolicyRenewalStatus::Committed {
                operation: p.operation(),
                statement: p.statement(),
                target: a.target.checkpoint()
            }
        );
    }
}

#[path = "witness_roster_atomicity_tests.rs"]
mod roster_atomicity;
