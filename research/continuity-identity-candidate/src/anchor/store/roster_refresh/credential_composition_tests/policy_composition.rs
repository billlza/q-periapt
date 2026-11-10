// SPDX-License-Identifier: Apache-2.0 OR MIT
//! G/R preserve the exact separately adopted P or jointly adopted T.
use super::*;
use crate::{
    JournalIdentity, PolicyContinuationMaterials, PolicyContinuationScope,
    PolicyContinuationStatement, PolicyRenewalId, PolicyRenewalMaterials, PolicyRenewalScope,
    PolicyRenewalStatement, VerifiedPolicyContinuation, VerifiedPolicyRenewal,
};

#[test]
fn independent_policy_composes_in_each_order_without_losing_its_authority() {
    // 0: P -> G -> R; 1: G -> P -> R; 2: R -> P -> G.
    for order in 0..3 {
        let mut c = Case::new();
        let original = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
        let mut current = c.device.clone();
        let mut head = c.initial;
        if order == 1 {
            let g = grant(&c, &current, 2);
            let p = g_proposal(&c, &g, head);
            c.store
                .prepare_credential_renewal(p, &g, &original, 150)
                .expect("G first");
            g_exchange(&mut c, &p, AnchorOperation::commit_credential_renewal(&p));
            g_exchange(
                &mut c,
                &p,
                AnchorOperation::acknowledge_credential_renewal(&p),
            );
            current = g.successor_device().clone();
            head = p.target_head();
        } else if order == 2 {
            let next = same_credential_roster(&c, &current, 2);
            let p = r_proposal(&c, &current, &next, &original, head);
            c.store
                .prepare_roster_refresh(p, &current, &next, &original, 150)
                .expect("R first");
            r_exchange(&mut c, &p, AnchorOperation::commit_roster_refresh(&p));
            r_exchange(&mut c, &p, AnchorOperation::acknowledge_roster_refresh(&p));
            current = next;
            head = p.target_head();
        }
        let scope = PolicyRenewalScope {
            operation: PolicyRenewalId::generate().expect("P ID"),
            journal: JournalIdentity::from_trusted_state(c.subject.journal).expect("journal"),
            original_owner: c.subject.owner,
            original_credential: c.device.credential_digest(),
            current_credential: current.credential_digest(),
            current_roster: current.roster().checkpoint(),
            original_policy: c.original.checkpoint(),
            previous_policy: c.original.checkpoint(),
            previous_authorization: None,
        };
        let materials = PolicyRenewalMaterials {
            original: &c.original,
            previous: &c.original,
            target: &c.target,
            original_device: &c.device,
            current_device: &current,
        };
        let statement = PolicyRenewalStatement::new(&scope, &materials, 170).expect("P statement");
        let approval = VerifiedPolicyRenewal::verify(
            &c.account
                .approve_policy_renewal(&statement)
                .expect("account"),
            &c.issuer.approve_policy_renewal(&statement).expect("policy"),
            &scope,
            &materials,
            170,
        )
        .expect("independent dual P approval");
        let pp = c.proposal(&approval, head, 95);
        c.store
            .prepare_policy_renewal(pp, &approval, &materials, 170)
            .expect("P");
        let next =
            same_credential_roster(&c, &current, current.roster().checkpoint().version() + 1);
        let rp = r_policy_proposal(
            &c,
            &current,
            &next,
            &c.target,
            pp.target_head(),
            Some(approval.statement_digest()),
        );
        for committed in [false, true] {
            if committed {
                c.exchange(&pp, AnchorOperation::commit_policy_renewal(&pp), 170);
            }
            let before = c.fingerprint();
            assert!(matches!(
                c.store
                    .prepare_roster_refresh(rp, &current, &next, &c.target, 170),
                Err(DurableError::Conflict)
            ));
            assert_eq!(c.fingerprint(), before, "P requires terminal ACK before R");
        }
        c.exchange(&pp, AnchorOperation::acknowledge_policy_renewal(&pp), 170);
        head = pp.target_head();
        if order != 1 {
            let g = grant(&c, &current, current.roster().checkpoint().version() + 1);
            let p = g_proposal(&c, &g, head)
                .with_retained_policy_renewal(&approval.historical())
                .expect("retained P");
            c.store
                .prepare_policy_renewed_credential_renewal(p, &g, &c.original, &c.target, 180)
                .expect("G after P");
            g_exchange_at(
                &mut c,
                &p,
                AnchorOperation::commit_credential_renewal(&p),
                180,
            );
            g_exchange_at(
                &mut c,
                &p,
                AnchorOperation::acknowledge_credential_renewal(&p),
                180,
            );
            current = g.successor_device().clone();
            head = p.target_head();
        }
        if order != 2 {
            let next =
                same_credential_roster(&c, &current, current.roster().checkpoint().version() + 1);
            let wrong = r_policy_proposal(&c, &current, &next, &c.target, head, Some([37; 32]));
            let before = c.fingerprint();
            assert!(matches!(
                c.store
                    .prepare_roster_refresh(wrong, &current, &next, &c.target, 180),
                Err(DurableError::Conflict)
            ));
            assert_eq!(c.fingerprint(), before);
            let p = r_policy_proposal(
                &c,
                &current,
                &next,
                &c.target,
                head,
                Some(approval.statement_digest()),
            );
            let mut omitted = *p.scope();
            omitted.policy_authorization = None;
            assert!(
                matches!(
                    Proposal::from_journal(
                        c.pin.binding(),
                        c.subject,
                        omitted,
                        head,
                        p.target_head()
                    ),
                    Err(Error::Conflict)
                ),
                "non-original P cannot omit authorization even in a proposal"
            );
            c.store
                .prepare_roster_refresh(p, &current, &next, &c.target, 180)
                .expect("R after G/P");
            r_exchange_at(&mut c, &p, AnchorOperation::commit_roster_refresh(&p), 180);
            r_exchange_at(
                &mut c,
                &p,
                AnchorOperation::acknowledge_roster_refresh(&p),
                180,
            );
            current = next;
        }
        c.reopen();
        explicit_format(&mut c, b"QPANC020");
        assert_eq!(
            c.admission(
                AnchorOperation::admit_policy_renewal(
                    current.authority_binding(),
                    approval.statement_digest()
                )
                .expect("exact P"),
                180
            ),
            AnchorOutcome::AuthorityCurrent
        );
        assert_eq!(
            c.admission(
                AnchorOperation::admit_authority(current.authority_binding()).expect("omitted P"),
                180
            ),
            AnchorOutcome::AuthorityDenied
        );
    }
}

#[test]
fn joint_policy_continuation_preserves_its_grant_across_later_roster_refresh() {
    let mut c = Case::new();
    let g = grant(&c, &c.device, 2);
    let scope = PolicyContinuationScope {
        operation: g.operation(),
        journal: JournalIdentity::from_trusted_state(c.subject.journal).expect("journal"),
        original_owner: c.subject.owner,
        original_credential: c.device.credential_digest(),
        previous_credential: c.device.credential_digest(),
        previous_roster: c.device.roster().checkpoint(),
        original_policy: c.original.checkpoint(),
        previous_policy: c.original.checkpoint(),
        previous_authorization: None,
    };
    let materials = PolicyContinuationMaterials {
        original: &c.original,
        previous: &c.original,
        target: &c.target,
        credential: &g,
    };
    let statement = PolicyContinuationStatement::new(&scope, &materials, 170).expect("T");
    let approval = VerifiedPolicyContinuation::verify(
        &c.account
            .approve_policy_continuation(&statement)
            .expect("account"),
        &c.issuer
            .approve_policy_continuation(&statement)
            .expect("policy"),
        &scope,
        &materials,
        170,
    )
    .expect("both roots");
    let gp = g_proposal(&c, &g, c.initial)
        .with_policy_continuation(&approval)
        .expect("G+T");
    c.store
        .prepare_policy_continuation(gp, &approval, &materials, 170)
        .expect("admit G+T");
    g_exchange_at(
        &mut c,
        &gp,
        AnchorOperation::commit_credential_renewal(&gp),
        170,
    );
    g_exchange_at(
        &mut c,
        &gp,
        AnchorOperation::acknowledge_credential_renewal(&gp),
        170,
    );
    c.reopen();
    let next = same_credential_roster(&c, g.successor_device(), 3);
    let rp = r_policy_proposal(
        &c,
        g.successor_device(),
        &next,
        &c.target,
        gp.target_head(),
        Some(approval.statement_digest()),
    );
    c.store
        .prepare_roster_refresh(rp, g.successor_device(), &next, &c.target, 180)
        .expect("R retains exact T");
    r_exchange_at(
        &mut c,
        &rp,
        AnchorOperation::commit_roster_refresh(&rp),
        180,
    );
    r_exchange_at(
        &mut c,
        &rp,
        AnchorOperation::acknowledge_roster_refresh(&rp),
        180,
    );
    c.reopen();
    explicit_format(&mut c, b"QPANC020");
    let image = c.store.image().expect("current state");
    let entry = image
        .entries
        .get(&c.subject.id(&c.pin.binding()))
        .expect("original owner");
    assert_eq!(entry.credential_authorization, Some(g.statement_digest()));
    assert_eq!(
        entry.policy_authorization.expect("T").statement,
        approval.statement_digest()
    );
    assert_eq!(entry.credential_owner, storage_owner(g.successor_device()));
    assert_eq!(entry.authority, next.authority_binding());
    assert_eq!(entry.head, rp.target_head());
}
