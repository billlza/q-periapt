// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Store-only targets are explicit digest expectations, not sealed journal qualification.
use super::*;
use crate::anchor::store::policy_renewal::tests::{policy, Case};
use crate::{AccountPin, RosterRefreshId, RosterRefreshScope};

fn setup(adopted: bool) -> (Case, VerifiedSessionPolicy, Option<[u8; 32]>, AnchorHead) {
    let mut c = Case::new();
    if adopted {
        let approval = c.approval(&c.original, None, &c.target);
        let p = c.proposal(&approval, c.initial, 44);
        c.prepare(p, &approval).expect("admit independent P");
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170);
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 170);
        let current = policy(&c.issuer, &c.runtime, &c.pin, 2, 260, 170);
        (
            c,
            current,
            Some(approval.statement_digest()),
            p.target_head(),
        )
    } else {
        let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
        let head = c.initial;
        (c, current, None, head)
    }
}
fn next(c: &Case, version: u64) -> VerifiedDevice {
    let roster = c
        .account
        .issue_roster(
            version,
            Validity::new(100, 400).expect("validity"),
            &[c.account
                .roster_entry(&c.certificate)
                .expect("same original credential")],
        )
        .expect("signed target R");
    AccountPin::new(
        c.device.account_id(),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        c.original.family(),
    )
    .expect("independent next pin")
    .verify_device(&c.certificate, roster.as_bytes(), 150)
    .expect("actual next root roster")
}
fn proposal(
    c: &Case,
    next: &VerifiedDevice,
    current: &VerifiedSessionPolicy,
    statement: Option<[u8; 32]>,
    head: AnchorHead,
    digest: u8,
) -> Proposal {
    Proposal::from_journal(
        c.pin.binding(),
        c.subject,
        RosterRefreshScope {
            operation: RosterRefreshId::generate().expect("operation"),
            previous: c.device.roster().checkpoint(),
            target: next.roster().checkpoint(),
            policy: current.checkpoint(),
            policy_authorization: statement,
        },
        head,
        AnchorHead::from_trusted_state(head.fence(), head.revision() + 1, [digest; 32])
            .expect("explicit store-only expected ciphertext digest"),
    )
    .expect("proposal")
}
fn exchange(c: &mut Case, p: Proposal, operation: AnchorOperation, now: u64) -> State {
    let request =
        AnchorRequest::new(&c.pin, c.subject, operation, &c.signer).expect("fresh signed command");
    let wire = c
        .store
        .handle(request.as_bytes(), now)
        .expect("witness reply");
    let reply = c
        .pin
        .verify_reply(&request, &wire)
        .expect("fresh exact response");
    assert!(
        reply.applied_head().is_err(),
        "ordinary advance interpreter cannot admit R"
    );
    reply
        .roster_refresh_state(&p)
        .expect("original typed roster/head outcome")
}
fn authority(
    c: &mut Case,
    device: &VerifiedDevice,
    statement: Option<[u8; 32]>,
    now: u64,
) -> AnchorOutcome {
    let op = match statement {
        Some(s) => AnchorOperation::admit_policy_renewal(device.authority_binding(), s),
        None => AnchorOperation::admit_authority(device.authority_binding()),
    }
    .expect("exact current authority");
    c.admission(op, now)
}
#[test]
fn roster_and_head_apply_together_under_original_or_independent_policy() {
    for adopted in [false, true] {
        let (mut c, current, statement, head) = setup(adopted);
        let device = c.device.clone();
        let next = next(&c, 2);
        let p = proposal(&c, &next, &current, statement, head, 81);
        let now = if adopted { 170 } else { 150 };
        assert_eq!(
            c.store
                .prepare_roster_refresh(p, &device, &next, &current, now)
                .expect("independent root preparation"),
            State::Prepared
        );
        let image = c.store.image().expect("stored preparation");
        let entry = image
            .entries
            .get(&c.subject.id(&c.pin.binding()))
            .expect("subject");
        assert_eq!(
            (entry.head, entry.authority),
            (head, device.authority_binding())
        );
        drop(image);
        assert_eq!(
            authority(&mut c, &device, statement, now),
            AnchorOutcome::AuthorityDenied,
            "unretired R prevents operational release"
        );
        assert_eq!(
            exchange(&mut c, p, AnchorOperation::commit_roster_refresh(&p), now),
            State::Applied
        );
        c.reopen();
        let image = c.store.image().expect("durable atomic state");
        let entry = image
            .entries
            .get(&c.subject.id(&c.pin.binding()))
            .expect("subject");
        assert_eq!(
            (entry.head, entry.authority),
            (p.target_head(), next.authority_binding())
        );
        assert_eq!(entry.credential_owner, c.subject.owner);
        assert_eq!(
            entry
                .independent_policy
                .as_ref()
                .and_then(|s| s.current)
                .map(|s| s.statement),
            statement
        );
        drop(image);
        let before = c.fingerprint();
        assert_eq!(
            exchange(&mut c, p, AnchorOperation::close_roster_refresh(&p), 401),
            State::Applied
        );
        assert_eq!(before, c.fingerprint());
        assert_eq!(
            exchange(
                &mut c,
                p,
                AnchorOperation::acknowledge_roster_refresh(&p),
                401
            ),
            State::Acknowledged
        );
        c.reopen();
        assert_eq!(
            exchange(
                &mut c,
                p,
                AnchorOperation::acknowledge_roster_refresh(&p),
                401
            ),
            State::Acknowledged
        );
        assert_eq!(
            exchange(&mut c, p, AnchorOperation::roster_refresh_status(&p), 401),
            State::Unavailable
        );
        assert_eq!(
            authority(&mut c, &next, statement, now),
            AnchorOutcome::AuthorityCurrent
        );
        assert_eq!(
            authority(&mut c, &device, statement, now),
            AnchorOutcome::AuthorityDenied
        );
        assert!(
            c.store
                .update_roster_authority(
                    c.subject,
                    device.roster().checkpoint(),
                    &next,
                    &current,
                    now
                )
                .is_err(),
            "standalone update cannot bypass retained atomic-R history"
        );
    }
}
#[test]
fn expired_roster_preparation_closes_without_splitting_authority_and_allows_next_policy() {
    let (mut c, current, statement, head) = setup(true);
    let device = c.device.clone();
    let next = next(&c, 2);
    let p = proposal(&c, &next, &current, statement, head, 82);
    c.store
        .prepare_roster_refresh(p, &device, &next, &current, 200)
        .expect("prepare before expiry");
    let before = c.fingerprint();
    let request = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::commit_roster_refresh(&p),
        &c.signer,
    )
    .expect("original commit");
    assert!(c.store.handle(request.as_bytes(), 300).is_err());
    assert_eq!(c.fingerprint(), before);
    assert_eq!(
        c.store
            .close_roster_refresh(p, &device, &next, current.historical())
            .expect("historical close"),
        State::Closed
    );
    assert_eq!(
        exchange(&mut c, p, AnchorOperation::commit_roster_refresh(&p), 300),
        State::Closed
    );
    assert_eq!(
        exchange(
            &mut c,
            p,
            AnchorOperation::acknowledge_roster_refresh(&p),
            300
        ),
        State::Acknowledged
    );
    let image = c.store.image().expect("actual unchanged predecessor");
    let entry = image
        .entries
        .get(&c.subject.id(&c.pin.binding()))
        .expect("subject");
    assert_eq!(
        (entry.head, entry.authority),
        (head, device.authority_binding())
    );
    drop(image);
    assert!(matches!(
        c.store
            .prepare_roster_refresh(p, &device, &next, &current, 200),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let p2 = policy(&c.issuer, &c.runtime, &c.pin, 3, 380, 300);
    let approval = c.approval(current.historical(), statement, &p2);
    let next_policy = c.proposal(&approval, head, 83);
    let materials = crate::PolicyRenewalMaterials {
        original: &c.original,
        previous: current.historical(),
        target: &p2,
        original_device: &device,
        current_device: &device,
    };
    assert_eq!(
        c.store
            .prepare_policy_renewal(next_policy, &approval, &materials, 300)
            .expect("P2 still has one actual R1 predecessor"),
        crate::AnchorPolicyRenewalState::Prepared
    );
    assert_eq!(
        c.exchange(
            &next_policy,
            AnchorOperation::commit_policy_renewal(&next_policy),
            300
        ),
        crate::AnchorPolicyRenewalState::Applied
    );
}
#[test]
fn roster_proposal_and_commands_are_distinct_exact_and_canonical() {
    let (mut c, current, statement, head) = setup(true);
    let device = c.device.clone();
    let next = next(&c, 2);
    let p = proposal(&c, &next, &current, statement, head, 84);
    let bytes = p.to_bytes();
    assert_eq!(bytes.len(), ROSTER_REFRESH_PROPOSAL_BYTES);
    assert!(crate::AnchorPolicyRenewalProposal::from_trusted_state(&bytes).is_err());
    for length in 0..bytes.len() {
        assert!(Proposal::from_trusted_state(bytes.get(..length).expect("prefix")).is_err());
    }
    for operation in [
        AnchorOperation::commit_roster_refresh(&p),
        AnchorOperation::roster_refresh_status(&p),
        AnchorOperation::close_roster_refresh(&p),
        AnchorOperation::acknowledge_roster_refresh(&p),
    ] {
        let bytes = operation.to_bytes();
        assert_eq!(bytes.len(), 97);
        assert_eq!(
            AnchorOperation::from_trusted_state(&bytes).expect("canonical"),
            operation
        );
        let mut wrong = bytes;
        *wrong.last_mut().expect("reserved zero") = 1;
        assert!(AnchorOperation::from_trusted_state(&wrong).is_err());
    }
    c.store
        .prepare_roster_refresh(p, &device, &next, &current, 200)
        .expect("prepare");
    let other = proposal(&c, &next, &current, statement, head, 85);
    let before = c.fingerprint();
    assert!(c
        .store
        .prepare_roster_refresh(other, &device, &next, &current, 200)
        .is_err());
    assert_eq!(
        exchange(
            &mut c,
            other,
            AnchorOperation::roster_refresh_status(&other),
            200
        ),
        State::Unavailable
    );
    assert_eq!(before, c.fingerprint());
    let advance = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::advance(head, [86; 32]).expect("ordinary advance"),
        &c.signer,
    )
    .expect("request");
    assert!(c.store.handle(advance.as_bytes(), 200).is_err());
    assert_eq!(before, c.fingerprint());
}

#[test]
fn roster_slot_refuses_changed_scope_policy_overlap_and_preterminal_ack() {
    let (mut c, current, statement, head) = setup(true);
    let device = c.device.clone();
    let next = next(&c, 2);
    let p = proposal(&c, &next, &current, statement, head, 87);
    let mut changed = p.to_bytes();
    *changed.last_mut().expect("target digest") ^= 1;
    let changed = Proposal::from_trusted_state(&changed).expect("same operation, another target");
    c.store
        .prepare_roster_refresh(p, &device, &next, &current, 200)
        .expect("original slot");
    let before = c.fingerprint();
    assert!(c
        .store
        .prepare_roster_refresh(changed, &device, &next, &current, 200)
        .is_err());
    for op in [
        AnchorOperation::acknowledge_roster_refresh(&p),
        AnchorOperation::fence_writer(head).expect("fence"),
    ] {
        let rq = AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("signed request");
        assert!(c.store.handle(rq.as_bytes(), 200).is_err());
    }
    let p2 = policy(&c.issuer, &c.runtime, &c.pin, 3, 380, 200);
    let approval = c.approval(current.historical(), statement, &p2);
    let policy_proposal = c.proposal(&approval, head, 88);
    let materials = crate::PolicyRenewalMaterials {
        original: &c.original,
        previous: current.historical(),
        target: &p2,
        original_device: &device,
        current_device: &device,
    };
    assert!(
        c.store
            .prepare_policy_renewal(policy_proposal, &approval, &materials, 200)
            .is_err(),
        "P cannot overlap retained R"
    );
    assert_eq!(before, c.fingerprint());
    current.close();
    assert_eq!(
        c.store
            .close_roster_refresh(p, &device, &next, current.historical())
            .expect("historical close after runtime closure"),
        State::Closed
    );
}
#[test]
fn policy_after_atomic_roster_binds_actual_new_roster_and_preserves_roster_floor() {
    let (mut c, current, statement, head) = setup(true);
    let device = c.device.clone();
    let next = next(&c, 2);
    let p = proposal(&c, &next, &current, statement, head, 89);
    c.store
        .prepare_roster_refresh(p, &device, &next, &current, 200)
        .expect("prepare R2");
    exchange(&mut c, p, AnchorOperation::commit_roster_refresh(&p), 200);
    assert_eq!(
        authority(&mut c, &next, statement, 200),
        AnchorOutcome::AuthorityDenied,
        "Applied requires original terminal ACK"
    );
    exchange(
        &mut c,
        p,
        AnchorOperation::acknowledge_roster_refresh(&p),
        200,
    );
    c.device = next.clone();
    let p2 = policy(&c.issuer, &c.runtime, &c.pin, 3, 380, 300);
    let approval = c.approval(current.historical(), statement, &p2);
    let pp = c.proposal(&approval, p.target_head(), 90);
    let materials = crate::PolicyRenewalMaterials {
        original: &c.original,
        previous: current.historical(),
        target: &p2,
        original_device: &device,
        current_device: &next,
    };
    c.store
        .prepare_policy_renewal(pp, &approval, &materials, 300)
        .expect("P after actual R2");
    c.exchange(&pp, AnchorOperation::commit_policy_renewal(&pp), 300);
    c.exchange(&pp, AnchorOperation::acknowledge_policy_renewal(&pp), 300);
    c.reopen();
    let image = c.store.image().expect("state");
    let entry = image
        .entries
        .get(&c.subject.id(&c.pin.binding()))
        .expect("subject");
    assert_eq!(entry.authority, next.authority_binding());
    assert_eq!(entry.head, pp.target_head());
    assert_eq!(
        entry
            .independent_roster
            .as_ref()
            .expect("retained R floor")
            .floor,
        2
    );
    assert_eq!(
        entry
            .independent_policy
            .as_ref()
            .and_then(|s| s.current)
            .expect("P2")
            .statement,
        approval.statement_digest()
    );
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Prepare,
    CloseUnprepared,
    Commit,
    ClosePrepared,
    AcknowledgeApplied,
    AcknowledgeClosed,
}
#[derive(Debug)]
enum MutationFailure {
    Durable(DurableError),
    Request(AnchorError),
}
impl Mutation {
    fn setup(
        self,
        c: &mut Case,
        p: Proposal,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
    ) {
        if matches!(
            self,
            Self::Commit | Self::ClosePrepared | Self::AcknowledgeApplied | Self::AcknowledgeClosed
        ) {
            c.store
                .prepare_roster_refresh(p, &c.device, next, policy, 200)
                .expect("prepare original R");
        }
        match self {
            Self::AcknowledgeApplied => {
                exchange(c, p, AnchorOperation::commit_roster_refresh(&p), 200);
            }
            Self::AcknowledgeClosed => {
                exchange(c, p, AnchorOperation::close_roster_refresh(&p), 200);
            }
            _ => {}
        }
    }
    fn run(
        self,
        c: &mut Case,
        p: Proposal,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
    ) -> Result<State, MutationFailure> {
        let op = match self {
            Self::Prepare => {
                return c
                    .store
                    .prepare_roster_refresh(p, &c.device, next, policy, 200)
                    .map_err(MutationFailure::Durable)
            }
            Self::CloseUnprepared => {
                return c
                    .store
                    .close_roster_refresh(p, &c.device, next, policy.historical())
                    .map_err(MutationFailure::Durable)
            }
            Self::Commit => AnchorOperation::commit_roster_refresh(&p),
            Self::ClosePrepared => AnchorOperation::close_roster_refresh(&p),
            Self::AcknowledgeApplied | Self::AcknowledgeClosed => {
                AnchorOperation::acknowledge_roster_refresh(&p)
            }
        };
        let request =
            AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("fresh original command");
        let wire = c
            .store
            .handle(request.as_bytes(), 200)
            .map_err(MutationFailure::Request)?;
        Ok(c.pin
            .verify_reply(&request, &wire)
            .expect("authenticated reply")
            .roster_refresh_state(&p)
            .expect("exact R outcome"))
    }
    fn expected(self) -> State {
        match self {
            Self::Prepare => State::Prepared,
            Self::CloseUnprepared | Self::ClosePrepared => State::Closed,
            Self::Commit => State::Applied,
            Self::AcknowledgeApplied | Self::AcknowledgeClosed => State::Acknowledged,
        }
    }
}
#[test]
fn every_roster_sync_fault_preserves_joint_head_authority_and_original_retry() {
    use crate::anchor::store::policy_renewal::tests::fault;
    use std::sync::atomic::Ordering;
    let mut faults = 0;
    for mutation in [
        Mutation::Prepare,
        Mutation::CloseUnprepared,
        Mutation::Commit,
        Mutation::ClosePrepared,
        Mutation::AcknowledgeApplied,
        Mutation::AcknowledgeClosed,
    ] {
        let (mut calibration, policy, statement, head) = setup(true);
        let successor = next(&calibration, 2);
        let p = proposal(&calibration, &successor, &policy, statement, head, 91);
        mutation.setup(&mut calibration, p, &successor, &policy);
        let (_, count) = fault(&mut calibration, false);
        assert_eq!(
            mutation
                .run(&mut calibration, p, &successor, &policy)
                .expect("calibration"),
            mutation.expected()
        );
        let barriers = count.load(Ordering::SeqCst);
        assert!((1..=8).contains(&barriers));
        for after in [false, true] {
            for cut in 1..=barriers {
                let (mut c, policy, statement, head) = setup(true);
                let successor = next(&c, 2);
                let p = proposal(&c, &successor, &policy, statement, head, 92);
                mutation.setup(&mut c, p, &successor, &policy);
                let (remaining, _) = fault(&mut c, after);
                remaining.store(cut, Ordering::SeqCst);
                let error = match mutation.run(&mut c, p, &successor, &policy) {
                    Err(MutationFailure::Durable(e))
                    | Err(MutationFailure::Request(AnchorError::Storage(e))) => Ok(e),
                    other => Err(other),
                }
                .expect("exact injected storage error");
                crate::durable::tests::assert_sync_failure::<()>(Err(error), after);
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                assert!(c.store.active.is_none());
                c.reopen();
                let image = c
                    .store
                    .image()
                    .expect("authenticated atomic state after fault");
                let entry = image
                    .entries
                    .get(&c.subject.id(&c.pin.binding()))
                    .expect("subject");
                assert!(
                    (entry.head == head && entry.authority == c.device.authority_binding())
                        || (entry.head == p.target_head()
                            && entry.authority == successor.authority_binding()),
                    "never a mixed head/roster"
                );
                assert_eq!(
                    entry
                        .independent_policy
                        .as_ref()
                        .and_then(|s| s.current)
                        .map(|p| p.statement),
                    statement
                );
                drop(image);
                assert_eq!(
                    mutation
                        .run(&mut c, p, &successor, &policy)
                        .expect("original exact recovery"),
                    mutation.expected()
                );
                let stable = c.fingerprint();
                assert_eq!(
                    mutation
                        .run(&mut c, p, &successor, &policy)
                        .expect("idempotent retry"),
                    mutation.expected()
                );
                assert_eq!(stable, c.fingerprint());
                faults += 1;
            }
        }
    }
    assert!(faults >= 24);
    eprintln!("ROSTER_STORE_SYNC faults={faults} exact_injected_error=true atomic_head_and_authority=true original_retry=true");
}
