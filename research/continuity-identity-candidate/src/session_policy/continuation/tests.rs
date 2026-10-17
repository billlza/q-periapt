// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalMaterials, DeviceDescription,
    DeviceSigningKey,
};

#[test]
fn historical_joint_approvals_verify_after_runtime_close_without_weakening_scope_or_roots() {
    let c = Case::new();
    let (a, p) = c.approvals();
    let verified = VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("current original approval");
    let wire = verified.as_bytes().to_vec();
    let changed = c.target_policy(3, 195, 3);
    c.target.close();
    c.runtime.close();
    let materials = c.materials().historical();
    let historical = HistoricalPolicyContinuation::from_bytes(&wire, &c.scope, &materials)
        .expect("authentic historical relation without live runtime");
    assert_eq!(historical.statement_digest(), verified.statement_digest());
    assert_eq!(
        historical.credential_statement(),
        c.grant.statement_digest()
    );
    assert_eq!(historical.as_bytes(), wire);
    assert!(VerifiedPolicyContinuation::from_bytes(&wire, &c.scope, &c.materials(), 250).is_err());
    let mismatched = HistoricalPolicyContinuationMaterials {
        target: changed.historical(),
        ..materials
    };
    assert!(HistoricalPolicyContinuation::from_bytes(&wire, &c.scope, &mismatched).is_err());
    let materials = c.materials().historical();
    let mut wrong_scope = c.scope.clone();
    wrong_scope.journal = crate::JournalIdentity::generate().expect("other journal");
    assert!(HistoricalPolicyContinuation::from_bytes(&wire, &wrong_scope, &materials).is_err());
    for index in [0, 8, wire.len() / 2, wire.len() - 1] {
        let mut corrupt = wire.clone();
        *corrupt.get_mut(index).expect("field") ^= 1;
        assert!(HistoricalPolicyContinuation::from_bytes(&corrupt, &c.scope, &materials).is_err());
    }
    for size in [0, 8, wire.len() - 1] {
        assert!(HistoricalPolicyContinuation::from_bytes(
            wire.get(..size).expect("prefix"),
            &c.scope,
            &materials
        )
        .is_err());
    }
}

pub(crate) struct Case {
    pub(crate) account: RootSigningKey,
    issuer: PolicySigningKey,
    runtime: Arc<Runtime>,
    pub(crate) old: HistoricalSessionPolicy,
    target: VerifiedSessionPolicy,
    pub(crate) grant: VerifiedCredentialRenewal,
    pub(crate) scope: PolicyContinuationScope,
}
impl Case {
    pub(crate) fn new() -> Self {
        let (_, _, _, runtime) =
            crate::tests::session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
        let issuer = PolicySigningKey::generate().expect("policy root");
        let issue = |version, until| {
            issuer
                .issue_session_policy(
                    &runtime,
                    SessionPolicyParameters::new(
                        version,
                        Validity::new(100, until).expect("policy validity"),
                        AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                        AnchorRequirement::local_only(),
                        ApplicationSendBudget::new(3).expect("budget"),
                    )
                    .expect("policy parameters"),
                )
                .expect("signed policy")
        };
        let p0 = issue(1, 160);
        let p1 = issue(2, 190);
        let pin = |checkpoint| {
            PolicyPin::new(
                issuer.policy_family().expect("family"),
                issuer.public_key().expect("policy key"),
                checkpoint,
            )
            .expect("independent pin")
        };
        let old = pin(p0.checkpoint())
            .verify_historical(p0.as_bytes())
            .expect("P0 history");
        assert!(matches!(
            pin(p0.checkpoint()).verify(p0.as_bytes(), Arc::clone(&runtime), 170),
            Err(Error::Validity)
        ));
        let target = pin(p1.checkpoint())
            .verify(p1.as_bytes(), Arc::clone(&runtime), 170)
            .expect("P1 now");
        let account = RootSigningKey::generate().expect("account root");
        let device = DeviceSigningKey::generate().expect("device key");
        let credential = |until| {
            account
                .issue_device(
                    DeviceDescription::new(
                        [7; 16],
                        1,
                        old.family(),
                        Validity::new(100, until).expect("credential validity"),
                    )
                    .expect("device"),
                    device.public_key().expect("public key"),
                )
                .expect("credential")
        };
        let c0 = credential(160);
        let c1 = credential(190);
        let r0 = account
            .issue_roster(
                1,
                Validity::new(100, 160).expect("R0"),
                &[account.roster_entry(&c0).expect("C0 member")],
            )
            .expect("roster");
        let r1 = account
            .issue_roster(
                2,
                Validity::new(100, 190).expect("R1"),
                &[account.roster_entry(&c1).expect("C1 member")],
            )
            .expect("roster");
        let current = AccountPin::new(
            account.account_id().expect("account"),
            account.public_key().expect("root"),
            r1.checkpoint(),
            old.family(),
        )
        .expect("independent current account pin");
        let authorization = CredentialRenewalAuthorization {
            operation: CredentialRenewalId::generate().expect("operation"),
            previous: r0.checkpoint(),
            policy_digest: old.checkpoint().digest(),
        };
        let issued = account
            .issue_credential_renewal(
                CredentialRenewalMaterials {
                    original_credential: &c0,
                    previous_credential: &c0,
                    successor_credential: &c1,
                    previous_roster: r0.as_bytes(),
                    successor_roster: r1.as_bytes(),
                },
                &authorization,
                &current,
                170,
            )
            .expect("current account grant");
        let grant = VerifiedCredentialRenewal::verify(
            issued.as_bytes(),
            &current,
            old.checkpoint().digest(),
            170,
        )
        .expect("current grant");
        let scope = PolicyContinuationScope {
            operation: grant.operation(),
            journal: JournalIdentity::generate().expect("journal"),
            original_owner: grant.original_storage_owner(),
            original_credential: grant.original_credential_digest(),
            previous_credential: grant.previous_device().credential_digest(),
            previous_roster: grant.previous_device().roster().checkpoint(),
            original_policy: old.checkpoint(),
            previous_policy: old.checkpoint(),
            previous_authorization: None,
        };
        Self {
            account,
            issuer,
            runtime,
            old,
            target,
            grant,
            scope,
        }
    }
    pub(crate) fn materials(&self) -> PolicyContinuationMaterials<'_> {
        PolicyContinuationMaterials {
            original: &self.old,
            previous: &self.old,
            target: &self.target,
            credential: &self.grant,
        }
    }
    pub(crate) fn approvals(&self) -> (PolicyContinuationApproval, PolicyContinuationApproval) {
        let statement = PolicyContinuationStatement::new(&self.scope, &self.materials(), 170)
            .expect("joint statement");
        (
            self.account
                .approve_policy_continuation(&statement)
                .expect("account approval"),
            self.issuer
                .approve_policy_continuation(&statement)
                .expect("policy approval"),
        )
    }
    fn target_policy(&self, version: u64, until: u64, budget: u16) -> VerifiedSessionPolicy {
        let issued = self
            .issuer
            .issue_session_policy(
                &self.runtime,
                SessionPolicyParameters::new(
                    version,
                    Validity::new(100, until).expect("validity"),
                    self.old.allowed_modes(),
                    self.old.anchor_requirement(),
                    ApplicationSendBudget::new(budget).expect("budget"),
                )
                .expect("parameters"),
            )
            .expect("policy");
        PolicyPin::new(
            self.old.family(),
            self.issuer.public_key().expect("key"),
            issued.checkpoint(),
        )
        .expect("target pin")
        .verify(issued.as_bytes(), Arc::clone(&self.runtime), 170)
        .expect("target owner")
    }
}

#[test]
fn joint_authorization_after_both_expiries_preserves_exact_original_bindings() {
    let c = Case::new();
    let (a, p) = c.approvals();
    assert!(c.old.validity().check(170).is_err());
    assert!(c
        .grant
        .previous_device()
        .description
        .validity
        .check(170)
        .is_err());
    let verified = VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("both independent approvals");
    assert_eq!(verified.as_bytes().len(), MAX_POLICY_CONTINUATION_BYTES);
    assert_eq!(verified.scope(), &c.scope);
    assert_eq!(verified.credential_statement(), c.grant.statement_digest());
    assert_ne!(verified.statement_digest(), c.grant.statement_digest());
    assert_eq!(verified.target_policy(), c.target.checkpoint());
    let restored =
        VerifiedPolicyContinuation::from_bytes(verified.as_bytes(), &c.scope, &c.materials(), 175)
            .expect("same original wire");
    assert_eq!(restored.as_bytes(), verified.as_bytes());
    assert_eq!(restored.statement_digest(), verified.statement_digest());
    for now in [99, 190, u64::MAX] {
        assert!(VerifiedPolicyContinuation::from_bytes(
            verified.as_bytes(),
            &c.scope,
            &c.materials(),
            now
        )
        .is_err());
    }
}

#[test]
fn witness_proposal_binds_g_and_t_independently_without_aliasing_legacy_requests() {
    use crate::{AnchorCredentialRenewalProposal, AnchorHead, AnchorOperation, AnchorSubject};
    let c = Case::new();
    let (a, p) = c.approvals();
    let t1 = VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("real independent T1 approvals");
    let p2 = c.target_policy(3, 195, 3);
    let materials = PolicyContinuationMaterials {
        target: &p2,
        ..c.materials()
    };
    let s = PolicyContinuationStatement::new(&c.scope, &materials, 170).expect("alternative T2");
    let a2 = c
        .account
        .approve_policy_continuation(&s)
        .expect("account T2");
    let p2 = c.issuer.approve_policy_continuation(&s).expect("policy T2");
    let t2 = VerifiedPolicyContinuation::verify(&a2, &p2, &c.scope, &materials, 170)
        .expect("authentic different target under same G");
    // These heads are wire expectations only, not an actual journal commit.
    let g = AnchorCredentialRenewalProposal::from_journal(
        [91; 32],
        AnchorSubject::for_device(c.scope.journal, c.grant.previous_device(), &c.old)
            .expect("original immutable subject"),
        c.grant.operation(),
        c.grant.statement_digest(),
        AnchorHead::from_trusted_state(1, 1, [92; 32]).expect("before"),
        AnchorHead::from_trusted_state(1, 2, [93; 32]).expect("after"),
    )
    .expect("exact G expectation");
    let p1 = g.with_policy_continuation(&t1).expect("G and T1");
    let p2 = g.with_policy_continuation(&t2).expect("G and T2");
    let carry = g
        .with_retained_policy_continuation(&t1.historical())
        .expect("carry expectation");
    assert_ne!(
        p1.binding(),
        carry.binding(),
        "adopting T and retaining T must not alias a recovery transaction"
    );
    assert!(p1.adopts_policy());
    assert!(!carry.adopts_policy());
    assert_eq!(p1.transaction_statement(), t1.statement_digest());
    assert_eq!(carry.transaction_statement(), g.statement());
    assert!(carry.with_policy_continuation(&t1).is_err());
    assert!(p1
        .with_retained_policy_continuation(&t1.historical())
        .is_err());
    assert_eq!(g.to_bytes().len(), 296);
    assert_eq!(p1.to_bytes().len(), 329);
    assert_eq!(g.statement(), p1.statement());
    assert_eq!(p1.statement(), p2.statement());
    assert_eq!(p1.target_head(), p2.target_head());
    assert_eq!(p1.policy_continuation(), Some(t1.statement_digest()));
    assert_eq!(p2.policy_continuation(), Some(t2.statement_digest()));
    assert_ne!(g.binding(), p1.binding());
    assert_ne!(p1.binding(), p2.binding());
    assert_ne!(
        AnchorOperation::commit_credential_renewal(&p1).to_bytes(),
        AnchorOperation::commit_credential_renewal(&p2).to_bytes()
    );
    assert!(p1.with_policy_continuation(&t2).is_err());
    assert_eq!(p1.with_policy_continuation(&t1).expect("exact repeat"), p1);
    for proposal in [g, p1, p2, carry] {
        assert_eq!(
            AnchorCredentialRenewalProposal::from_trusted_state(&proposal.to_bytes())
                .expect("exact restored public expectation"),
            proposal
        );
    }
    let bytes = p1.to_bytes();
    for end in 0..bytes.len() {
        assert!(AnchorCredentialRenewalProposal::from_trusted_state(
            bytes.get(..end).expect("proper prefix")
        )
        .is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(AnchorCredentialRenewalProposal::from_trusted_state(&trailing).is_err());
    let mut zero = bytes.clone();
    zero.get_mut(297..).expect("T field").fill(0);
    assert!(AnchorCredentialRenewalProposal::from_trusted_state(&zero).is_err());
    let mut bad_mode = bytes.clone();
    *bad_mode.get_mut(296).expect("transition tag") = 2;
    assert!(AnchorCredentialRenewalProposal::from_trusted_state(&bad_mode).is_err());
    let mut legacy_tag = bytes;
    legacy_tag
        .get_mut(..8)
        .expect("version tag")
        .copy_from_slice(b"QPCRNP01");
    assert!(AnchorCredentialRenewalProposal::from_trusted_state(&legacy_tag).is_err());
    for offset in [40, 72, 104, 136, 168] {
        let mut changed = g.to_bytes();
        *changed.get_mut(offset).expect("selected binding") ^= 1;
        let changed = AnchorCredentialRenewalProposal::from_trusted_state(&changed)
            .expect("different well-formed scope");
        assert!(changed.with_policy_continuation(&t1).is_err());
    }
}

#[test]
fn authentic_alternative_targets_and_predecessors_never_become_the_same_retry() {
    let c = Case::new();
    let (a, p) = c.approvals();
    let original =
        VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170).expect("T1");
    let alternative = c.target_policy(3, 195, 3);
    let materials = PolicyContinuationMaterials {
        target: &alternative,
        ..c.materials()
    };
    let s = PolicyContinuationStatement::new(&c.scope, &materials, 170)
        .expect("independent second target");
    let a2 = c
        .account
        .approve_policy_continuation(&s)
        .expect("second account approval");
    let p2 = c
        .issuer
        .approve_policy_continuation(&s)
        .expect("second policy approval");
    let other =
        VerifiedPolicyContinuation::verify(&a2, &p2, &c.scope, &materials, 170).expect("T2");
    assert_ne!(original.statement_digest(), other.statement_digest());
    assert_eq!(original.scope().operation, other.scope().operation);
    for (account, policy) in [(&a, &p2), (&a2, &p), (&a, &p)] {
        assert!(
            VerifiedPolicyContinuation::verify(account, policy, &c.scope, &materials, 170).is_err()
        );
    }
    let mut scope = c.scope.clone();
    scope.previous_policy = c.target.checkpoint();
    scope.previous_authorization = Some(original.statement_digest());
    let chained = PolicyContinuationMaterials {
        previous: c.target.historical(),
        ..materials
    };
    let s = PolicyContinuationStatement::new(&scope, &chained, 170)
        .expect("explicit predecessor chain");
    let ca = c
        .account
        .approve_policy_continuation(&s)
        .expect("chained account approval");
    let cp = c
        .issuer
        .approve_policy_continuation(&s)
        .expect("chained policy approval");
    assert!(VerifiedPolicyContinuation::verify(&ca, &cp, &scope, &chained, 170).is_ok());
    scope.previous_authorization = Some([9; 32]);
    assert!(VerifiedPolicyContinuation::verify(&ca, &cp, &scope, &chained, 170).is_err());
    scope.previous_authorization = None;
    assert!(PolicyContinuationStatement::new(&scope, &chained, 170).is_err());
    let expanded = c.target_policy(3, 195, 4);
    assert!(PolicyContinuationStatement::new(
        &c.scope,
        &PolicyContinuationMaterials {
            target: &expanded,
            ..c.materials()
        },
        170
    )
    .is_err());
}

#[test]
fn joint_approval_rejects_wrong_issuer_purpose_signature_and_original_scope() {
    let c = Case::new();
    let (a, p) = c.approvals();
    let statement =
        PolicyContinuationStatement::new(&c.scope, &c.materials(), 170).expect("statement");
    assert!(RootSigningKey::generate()
        .expect("other root")
        .approve_policy_continuation(&statement)
        .is_err());
    assert!(PolicySigningKey::generate()
        .expect("other policy")
        .approve_policy_continuation(&statement)
        .is_err());
    for source in [&a, &p] {
        let mut wire = source.as_bytes().to_vec();
        *wire.last_mut().expect("signature") ^= 1;
        let changed =
            PolicyContinuationApproval::from_bytes(&wire).expect("grammar not authentication");
        assert!(
            VerifiedPolicyContinuation::verify(&changed, &p, &c.scope, &c.materials(), 170)
                .is_err()
        );
        assert!(
            VerifiedPolicyContinuation::verify(&a, &changed, &c.scope, &c.materials(), 170)
                .is_err()
        );
    }
    let body = statement.bound.encode();
    let wrong = PolicyContinuationApproval::from_bytes(
        &envelope(
            &body,
            &c.account
                .sign(Purpose::CredentialRenewal, &body)
                .expect("different signature purpose"),
        )
        .expect("envelope"),
    )
    .expect("same grammar");
    assert!(VerifiedPolicyContinuation::verify(&wrong, &p, &c.scope, &c.materials(), 170).is_err());
    let mut other = c.scope.clone();
    other.journal = JournalIdentity::generate().expect("different journal");
    assert!(VerifiedPolicyContinuation::verify(&a, &p, &other, &c.materials(), 170).is_err());
    for field in 0..4 {
        let mut scope = c.scope.clone();
        match field {
            0 => scope.original_owner = [9; 32],
            1 => scope.original_credential = [9; 32],
            2 => scope.previous_credential = [9; 32],
            _ => {
                scope.previous_roster =
                    RosterCheckpoint::from_trusted_state(1, [9; 32]).expect("different head")
            }
        };
        assert!(PolicyContinuationStatement::new(&scope, &c.materials(), 170).is_err());
    }
    c.target.close();
    assert!(matches!(
        VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170),
        Err(Error::Closed)
    ));
}

#[test]
fn joint_container_rejects_every_truncation_trailing_bytes_and_runtime_close() {
    let c = Case::new();
    let (a, p) = c.approvals();
    let verified = VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("joint grant");
    for length in 0..verified.as_bytes().len() {
        assert!(VerifiedPolicyContinuation::from_bytes(
            verified.as_bytes().get(..length).expect("prefix"),
            &c.scope,
            &c.materials(),
            170
        )
        .is_err());
    }
    let mut wire = verified.as_bytes().to_vec();
    wire.push(0);
    assert!(VerifiedPolicyContinuation::from_bytes(&wire, &c.scope, &c.materials(), 170).is_err());
    c.runtime.close();
    assert!(VerifiedPolicyContinuation::from_bytes(
        verified.as_bytes(),
        &c.scope,
        &c.materials(),
        170
    )
    .is_err());
}
