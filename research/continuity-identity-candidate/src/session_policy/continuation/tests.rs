// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalMaterials, DeviceDescription,
    DeviceSigningKey,
};

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
