// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real original journal, independent approval, existing G/T and complete cleanup.
use super::*;
use crate::{
    AnchorOperation, AnchorOutcome, AnchorPendingWriteRecoveryProposal, AnchorSubject,
    PendingWriteRecoveryView, PolicyContinuationMaterials, SessionClosureStatus,
};
use std::{io::Write, os::unix::fs::OpenOptionsExt};

pub(in crate::enrollment::tests::witness_renewal) fn retain(
    directory: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let path = directory.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("independent retained host input");
    file.write_all(bytes).expect("whole input");
    file.sync_all().expect("input sync");
    fs::File::open(directory)
        .expect("host directory")
        .sync_all()
        .expect("directory sync");
    let readback = fs::read(path).expect("exact readback");
    assert_eq!(readback, bytes);
    readback
}
fn state(view: &PendingWriteRecoveryView, id: [u8; 32]) -> &crate::retired_device::SessionState {
    view.records
        .iter()
        .find_map(|r| match &r.metadata {
            crate::retired_device::RecordMetadata::Session(s) if s.session == id => Some(&s.state),
            _ => None,
        })
        .expect("complete original session metadata")
}
fn adopt(
    f: &Fixture,
    g: &crate::VerifiedCredentialRenewal,
    t: &crate::VerifiedPolicyContinuation,
    previous: &VerifiedSessionPolicy,
    target: &VerifiedSessionPolicy,
    now: u64,
) {
    f.carrier.clock.store(now, Ordering::SeqCst);
    let mut owner = open(&f.c);
    owner
        .stage_policy_continuation(g, t, g.operation(), target, now)
        .expect("independent G/T staged");
    let anchor = client(f, &mut owner, now);
    let proposal = owner
        .prepare_witnessed_policy_continuation(f.c.policy.historical(), target, now, anchor)
        .expect("original G/T target");
    f.carrier
        .store
        .lock()
        .expect("independent controller")
        .prepare_policy_continuation(
            proposal,
            t,
            &PolicyContinuationMaterials {
                original: f.c.policy.historical(),
                previous: previous.historical(),
                target,
                credential: g,
            },
            now,
        )
        .expect("independent current approval");
    let mut anchor = client(f, &mut owner, now);
    owner
        .commit_witnessed_policy_continuation(
            &proposal,
            f.c.policy.historical(),
            target,
            now,
            &mut anchor,
        )
        .expect("existing joint completion");
    owner.close();
}

pub(in crate::enrollment::tests::witness_renewal) fn confirm(
    f: &Fixture,
    p: &AnchorPendingWriteRecoveryProposal,
    metadata: &[u8],
) -> Result<crate::AnchorHead, DurableError> {
    open(&f.c).confirm_pending_write_recovery(
        p,
        metadata,
        f.c.policy.historical(),
        f.pin.clone(),
        Box::new(f.carrier.clone()),
        Duration::from_secs(3),
    )
}

#[test]
fn public_pending_write_recovery_preserves_staged_joint_authorization() {
    for applied in [false, true] {
        let (f, id) = session(fixture_with_policy_expiry(Some(160)));
        let g = grant(&f, &f.original, 2, 190);
        let p = policy(&f.c, 2, 220, 150);
        let t = joint(&f.c, &g, &scope(&f.c, &g, f.id), &f.c.policy, &p);
        let mut cleanup = open(&f.c)
            .recover_session(
                id,
                f.c.policy.historical(),
                Some((
                    f.pin.clone(),
                    Box::new(f.carrier.clone()),
                    Duration::from_secs(3),
                )),
            )
            .expect("original cleanup");
        *f.carrier.cut.lock().expect("cut") = Some((2, applied));
        assert!(matches!(
            cleanup.session().expect("session").begin(),
            Err(DurableError::Anchor(_))
        ));
        cleanup.close();
        f.carrier.clock.store(170, Ordering::SeqCst);
        let mut owner = open(&f.c);
        owner
            .stage_policy_continuation(&g, &t, g.operation(), &p, 170)
            .expect("original independent G/T staged");
        let before = disk(&f);
        let pending = owner
            .pending_write_recovery_request(f.c.policy.historical(), &f.pin)
            .expect("generic original intent remains inspectable with local staged G/T");
        let inspected = pending
            .proposal()
            .inspect_metadata(pending.metadata())
            .expect("complete controller inspection");
        assert_eq!(inspected.source(), pending.source());
        assert_eq!(inspected.target(), pending.target());
        owner.close();
        assert_eq!(disk(&f), before);
        let directory = f.c.paths.wrapping.parent().expect("private host directory");
        let proposal = AnchorPendingWriteRecoveryProposal::from_trusted_state(&retain(
            directory,
            "approved-proposal",
            &pending.proposal().to_bytes(),
        ))
        .expect("retained original proposal");
        let metadata = retain(directory, "approved-metadata", pending.metadata());
        let signed = retain(directory, "original-request", pending.signed_request());
        if !applied {
            assert!(
                confirm(&f, &proposal, &metadata).is_err(),
                "preparation is not witness completion"
            );
            assert_eq!(disk(&f), before);
            for at in [150, 160] {
                assert!(
                    f.carrier
                        .store
                        .lock()
                        .expect("controller")
                        .complete_pending_write_recovery(&proposal, &signed, &metadata, at)
                        .is_err(),
                    "live authority must use ordinary admission"
                );
            }
        }
        let mut changed = metadata.clone();
        *changed.last_mut().expect("nonempty metadata") ^= 1;
        let calls = f.carrier.requests.lock().expect("calls").len();
        assert!(confirm(&f, &proposal, &changed).is_err());
        assert_eq!(f.carrier.requests.lock().expect("calls").len(), calls);
        assert_eq!(disk(&f), before);
        f.carrier
            .store
            .lock()
            .expect("independent controller")
            .complete_pending_write_recovery(&proposal, &signed, &metadata, 170)
            .expect("exact independent approval");
        f.c.policy.close();
        for processed in [false, true] {
            *f.carrier.cut.lock().expect("cut") = Some((1, processed));
            assert!(confirm(&f, &proposal, &metadata).is_err());
            assert!(f.carrier.cut.lock().expect("cut consumed").is_none());
            assert_eq!(
                disk(&f),
                before,
                "missing query result must retain original intent"
            );
        }
        f.carrier.requests.lock().expect("calls").clear();
        for _ in 0..2 {
            assert_eq!(
                confirm(&f, &proposal, &metadata).expect("fresh exact confirmation"),
                proposal.target_head()
            );
        }
        assert_eq!(*f.carrier.requests.lock().expect("query only"), vec![1, 1]);
        assert!(disk(&f).1.is_none());
        // Existing staging is idempotent for these exact first G/T bytes. Its
        // preparation/commit and witness validation must preserve that operation.
        adopt(&f, &g, &t, &f.c.policy, &p, 170);
        assert!(
            confirm(&f, &proposal, &metadata).is_err(),
            "later heads are not exact retries"
        );
        let renewed = request(&f, CredentialRenewalId::generate().expect("next request"))
            .expect("same G adopted");
        assert_eq!(
            renewed.previous_device().credential_digest(),
            g.successor_device().credential_digest()
        );
        let mut cleanup = open(&f.c)
            .recover_session(
                id,
                f.c.policy.historical(),
                Some((
                    f.pin.clone(),
                    Box::new(f.carrier.clone()),
                    Duration::from_secs(3),
                )),
            )
            .expect("same original cleanup");
        let report = cleanup
            .session()
            .expect("session")
            .begin()
            .expect("original report");
        let (epochs, closure) = match state(pending.target(), id) {
            crate::retired_device::SessionState::Live {
                epochs,
                previous_closure,
            } => Ok((epochs, previous_closure.expect("original closure"))),
            _ => Err("expected original target"),
        }
        .expect("target metadata");
        assert_eq!(report.report, closure);
        assert_eq!(
            report.epochs,
            epochs
                .iter()
                .map(|e| e.accounting.clone())
                .collect::<Vec<_>>()
        );
        retain(
            directory,
            "complete-host-report",
            format!("{report:#?}").as_bytes(),
        );
        cleanup
            .session()
            .expect("session")
            .acknowledge(report.report)
            .expect("actual original report ACK");
        assert_eq!(
            cleanup
                .session()
                .expect("session")
                .status()
                .expect("closed"),
            SessionClosureStatus::Closed(report.report)
        );
        cleanup.close();
        eprintln!("PUBLIC_PENDING_STAGED originally_applied={applied} closed_p0=true query_loss_before_after=true exact_query_retry=true staged_gt_preserved=true complete_report_ack=true");
    }
}

#[test]
fn public_pending_write_recovery_preserves_original_operation_through_joint_renewal() {
    for policy_expired in [false, true] {
        for applied in [false, true] {
            let (f, id) = session(fixture_with_policy_expiry(Some(if policy_expired {
                160
            } else {
                200
            })));
            let mut cleanup = open(&f.c)
                .recover_session(
                    id,
                    f.c.policy.historical(),
                    Some((
                        f.pin.clone(),
                        Box::new(f.carrier.clone()),
                        Duration::from_secs(3),
                    )),
                )
                .expect("original restricted owner");
            *f.carrier.cut.lock().expect("cut") = Some((2, applied));
            assert!(matches!(
                cleanup.session().expect("session").begin(),
                Err(DurableError::Anchor(_))
            ));
            cleanup.close();
            f.carrier.clock.store(170, Ordering::SeqCst);
            let before = disk(&f);
            if !applied {
                assert!(request(&f, CredentialRenewalId::generate().expect("G request")).is_err());
                assert_eq!(disk(&f), before);
            }
            let network = f.carrier.requests.lock().expect("calls").len();
            let mut owner = open(&f.c);
            let pending = owner
                .pending_write_recovery_request(f.c.policy.historical(), &f.pin)
                .expect("public read-only original intent preparation");
            let inspected = pending
                .proposal()
                .inspect_metadata(pending.metadata())
                .expect("complete controller inspection");
            assert_eq!(inspected.source(), pending.source());
            assert_eq!(inspected.target(), pending.target());
            let repeated = owner
                .pending_write_recovery_request(f.c.policy.historical(), &f.pin)
                .expect("same original snapshot");
            assert_eq!(pending.proposal(), repeated.proposal());
            assert_eq!(pending.metadata(), repeated.metadata());
            assert_eq!(pending.source(), repeated.source());
            assert_eq!(pending.target(), repeated.target());
            let identity = owner.image().expect("enrollment").identity;
            let wrong_signature = owner
                .signer(identity, false)
                .expect("test adversarial old signer")
                .sign(
                    crate::crypto::Purpose::AnchorRequest,
                    &pending.proposal().to_bytes(),
                )
                .expect("wrong-purpose signature");
            let wrong_purpose =
                crate::crypto::envelope(&pending.proposal().to_bytes(), &wrong_signature)
                    .expect("well-formed wrong-purpose request");
            owner.close();
            assert_eq!(
                f.carrier.requests.lock().expect("calls").len(),
                network,
                "preparation sent network traffic"
            );
            assert_eq!(
                disk(&f),
                before,
                "preparation rewrote original intent or image"
            );
            let (epochs, closure) = match state(pending.source(), id) {
                crate::retired_device::SessionState::Live {
                    epochs,
                    previous_closure,
                } => Ok((epochs, previous_closure)),
                _ => Err("fixture has live unknown delivery"),
            }
            .expect("source live session");
            assert!(closure.is_none());
            assert_eq!(epochs.len(), 1);
            let source_epoch = epochs.first().expect("one original epoch");
            assert_eq!(source_epoch.accounting.unconfirmed.len(), 1);
            let (target_epochs, original_closure) = match state(pending.target(), id) {
                crate::retired_device::SessionState::Live {
                    epochs,
                    previous_closure,
                } => Ok((epochs, previous_closure.expect("original closure"))),
                _ => Err("pending closure retains private state"),
            }
            .expect("target live session");
            assert_eq!(
                source_epoch.accounting,
                target_epochs
                    .first()
                    .expect("one retained target epoch")
                    .accounting
            );
            assert!(pending
                .metadata()
                .windows(b"unconfirmed original".len())
                .all(|w| w != b"unconfirmed original"));
            let directory = f.c.paths.wrapping.parent().expect("private host directory");
            let approved = AnchorPendingWriteRecoveryProposal::from_trusted_state(&retain(
                directory,
                "approved-proposal",
                &pending.proposal().to_bytes(),
            ))
            .expect("retained approval");
            let metadata = retain(directory, "approved-metadata", pending.metadata());
            let signed = retain(directory, "original-request", pending.signed_request());
            let mut changed = metadata.clone();
            *changed.last_mut().expect("nonempty metadata") ^= 1;
            let mut damaged = signed.clone();
            *damaged.last_mut().expect("nonempty signed request") ^= 1;
            let next = {
                let mut witness = f.carrier.store.lock().expect("independent controller");
                assert!(
                    witness.handle(&signed, 170).is_err(),
                    "ordinary endpoint accepted an approval request"
                );
                for (wire, recorded) in [
                    (&wrong_purpose, &metadata),
                    (&damaged, &metadata),
                    (&signed, &changed),
                ] {
                    assert!(witness
                        .complete_pending_write_recovery(&approved, wire, recorded, 170)
                        .is_err());
                }
                let next = witness
                    .complete_pending_write_recovery(&approved, &signed, &metadata, 170)
                    .expect("independently approved exact write");
                assert_eq!(next, pending.proposal().target_head());
                assert_eq!(
                    witness
                        .complete_pending_write_recovery(&approved, &signed, &metadata, 170)
                        .expect("retry exact approval"),
                    next
                );
                next
            };
            assert_eq!(disk(&f), before, "controller altered device storage");
            let mut owner = open(&f.c);
            let mut anchor = owner
                .credential_renewal_request_anchor_client(
                    f.c.policy.historical(),
                    f.pin.clone(),
                    Box::new(f.carrier.clone()),
                    Duration::from_secs(3),
                )
                .expect("historical client");
            let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy)
                .expect("original subject");
            assert_eq!(
                anchor
                    .exchange(
                        subject,
                        AnchorOperation::admit_authority(f.original.authority_binding())
                            .expect("request")
                    )
                    .expect("signed denial")
                    .outcome(),
                AnchorOutcome::AuthorityDenied
            );
            assert!(anchor
                .exchange(
                    subject,
                    AnchorOperation::advance(next, [93; 32]).expect("other write")
                )
                .is_err());
            owner.close();
            let g = grant(&f, &f.original, 2, 190);
            let req =
                request(&f, g.operation()).expect("existing exact confirmation unblocks request");
            assert_eq!(req.journal(), f.id);
            assert!(disk(&f).1.is_none());
            let p = policy(&f.c, 2, 220, 170);
            let t = joint(&f.c, &g, &req.policy_continuation_scope(), &f.c.policy, &p);
            adopt(&f, &g, &t, &f.c.policy, &p, 170);
            let renewed = request(&f, CredentialRenewalId::generate().expect("next ID"))
                .expect("renewed predecessor");
            assert_eq!(renewed.current_policy(), p.checkpoint());
            assert_eq!(
                renewed.previous_device().credential_digest(),
                g.successor_device().credential_digest()
            );
            let mut cleanup = open(&f.c)
                .recover_session(
                    id,
                    f.c.policy.historical(),
                    Some((
                        f.pin.clone(),
                        Box::new(f.carrier.clone()),
                        Duration::from_secs(3),
                    )),
                )
                .expect("original renewed cleanup");
            let report = cleanup
                .session()
                .expect("session")
                .begin()
                .expect("original report");
            assert_eq!(report.report, original_closure);
            assert_eq!(
                report.epochs,
                epochs
                    .iter()
                    .map(|e| e.accounting.clone())
                    .collect::<Vec<_>>()
            );
            retain(
                directory,
                "complete-host-report",
                format!("{report:#?}").as_bytes(),
            );
            cleanup
                .session()
                .expect("session")
                .acknowledge(report.report)
                .expect("current witness ACK");
            assert_eq!(
                cleanup
                    .session()
                    .expect("session")
                    .status()
                    .expect("terminal"),
                SessionClosureStatus::Closed(report.report)
            );
            cleanup.close();
            eprintln!("PUBLIC_PENDING_RECOVERY policy_expired={policy_expired} originally_applied={applied} exact_intent=true joint_renewal=true cleanup_complete=true");
        }
    }
}
