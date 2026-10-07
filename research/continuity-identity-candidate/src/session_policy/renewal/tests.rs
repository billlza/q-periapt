// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    DeviceDescription, DeviceSigningKey, IssuedRoster,
};

pub(crate) struct Case {
    pub(crate) account: RootSigningKey,
    issuer: PolicySigningKey,
    runtime: Arc<Runtime>,
    pub(crate) old: HistoricalSessionPolicy,
    pub(crate) target: VerifiedSessionPolicy,
    pub(crate) device: VerifiedDevice,
    certificate: Vec<u8>,
    roster: IssuedRoster,
    pub(crate) scope: PolicyRenewalScope,
}
impl Case {
    pub(crate) fn new(credential_until: u64, roster_until: u64) -> Self {
        let (_, _, _, runtime) =
            crate::tests::session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
        let issuer = PolicySigningKey::generate().expect("policy issuer");
        let issue = |version, until| {
            issuer
                .issue_session_policy(
                    &runtime,
                    SessionPolicyParameters::new(
                        version,
                        Validity::new(100, until).expect("time"),
                        AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                        AnchorRequirement::local_only(),
                        ApplicationSendBudget::new(3).expect("budget"),
                    )
                    .expect("parameters"),
                )
                .expect("policy")
        };
        let p0 = issue(1, 160);
        let p1 = issue(2, 260);
        let pin = |checkpoint| {
            PolicyPin::new(
                issuer.policy_family().expect("family"),
                issuer.public_key().expect("policy key"),
                checkpoint,
            )
            .expect("independent policy pin")
        };
        let old = pin(p0.checkpoint())
            .verify_historical(p0.as_bytes())
            .expect("original P0");
        assert!(matches!(
            pin(p0.checkpoint()).verify(p0.as_bytes(), Arc::clone(&runtime), 170),
            Err(Error::Validity)
        ));
        let target = pin(p1.checkpoint())
            .verify(p1.as_bytes(), Arc::clone(&runtime), 170)
            .expect("current P1");
        let account = RootSigningKey::generate().expect("account root");
        let signer = DeviceSigningKey::generate().expect("original device signer");
        let certificate = account
            .issue_device(
                DeviceDescription::new(
                    [9; 16],
                    1,
                    old.family(),
                    Validity::new(100, credential_until).expect("credential interval"),
                )
                .expect("description"),
                signer.public_key().expect("device key"),
            )
            .expect("credential");
        let roster = account
            .issue_roster(
                1,
                Validity::new(100, roster_until).expect("roster time"),
                &[account.roster_entry(&certificate).expect("member")],
            )
            .expect("roster");
        let account_pin = AccountPin::new(
            account.account_id().expect("account"),
            account.public_key().expect("account key"),
            roster.checkpoint(),
            old.family(),
        )
        .expect("independent account pin");
        let device = account_pin
            .verify_device(&certificate, roster.as_bytes(), 150)
            .expect("original device");
        let scope = PolicyRenewalScope {
            operation: PolicyRenewalId::generate().expect("policy-only ID"),
            journal: JournalIdentity::generate().expect("original journal"),
            original_owner: crate::bootstrap::storage_owner(&device),
            original_credential: device.credential_digest(),
            current_credential: device.credential_digest(),
            current_roster: roster.checkpoint(),
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
            device,
            certificate,
            roster,
            scope,
        }
    }
    pub(crate) fn materials(&self) -> PolicyRenewalMaterials<'_> {
        PolicyRenewalMaterials {
            original: &self.old,
            previous: &self.old,
            target: &self.target,
            original_device: &self.device,
            current_device: &self.device,
        }
    }
    pub(crate) fn approvals(&self) -> (PolicyRenewalApproval, PolicyRenewalApproval) {
        let statement = PolicyRenewalStatement::new(&self.scope, &self.materials(), 170)
            .expect("current policy-only relation");
        (
            self.account
                .approve_policy_renewal(&statement)
                .expect("account approval"),
            self.issuer
                .approve_policy_renewal(&statement)
                .expect("policy approval"),
        )
    }
    pub(crate) fn policy(
        &self,
        version: u64,
        until: u64,
        budget: u16,
        anchor: AnchorRequirement,
        at: u64,
    ) -> VerifiedSessionPolicy {
        let issued = self
            .issuer
            .issue_session_policy(
                &self.runtime,
                SessionPolicyParameters::new(
                    version,
                    Validity::new(100, until).expect("time"),
                    self.old.allowed_modes(),
                    anchor,
                    ApplicationSendBudget::new(budget).expect("budget"),
                )
                .expect("parameters"),
            )
            .expect("signed policy");
        PolicyPin::new(
            self.old.family(),
            self.issuer.public_key().expect("key"),
            issued.checkpoint(),
        )
        .expect("target pin")
        .verify(issued.as_bytes(), Arc::clone(&self.runtime), at)
        .expect("target")
    }
}

#[test]
fn policy_only_approval_retains_one_current_credential_and_roster_after_p0_expiry() {
    let c = Case::new(220, 240);
    let certificate = c.certificate.clone();
    let roster = c.roster.as_bytes().to_vec();
    let (a, p) = c.approvals();
    let verified = VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("two approvals");
    assert_eq!(verified.as_bytes().len(), MAX_POLICY_RENEWAL_BYTES);
    assert_eq!(verified.target_policy(), c.target.checkpoint());
    assert_eq!(
        verified.scope().current_credential,
        c.device.credential_digest()
    );
    assert_eq!(verified.scope().current_roster.version(), 1);
    assert_eq!(verified.scope().current_roster, c.roster.checkpoint());
    assert_eq!(
        verified.scope().original_credential,
        verified.scope().current_credential
    );
    let replay =
        VerifiedPolicyRenewal::from_bytes(verified.as_bytes(), &c.scope, &c.materials(), 171)
            .expect("exact replay");
    assert_eq!(replay.as_bytes(), verified.as_bytes());
    assert_eq!(replay.statement_digest(), verified.statement_digest());
    assert_eq!(c.certificate, certificate);
    assert_eq!(c.roster.as_bytes(), roster);

    // A policy-only statement must not manufacture a same-C/same-R G.
    let pin = AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        c.roster.checkpoint(),
        c.old.family(),
    )
    .expect("pin");
    let fake_grant = c.account.issue_credential_renewal(
        CredentialRenewalMaterials {
            original_credential: &c.certificate,
            previous_credential: &c.certificate,
            successor_credential: &c.certificate,
            previous_roster: c.roster.as_bytes(),
            successor_roster: c.roster.as_bytes(),
        },
        &CredentialRenewalAuthorization {
            operation: CredentialRenewalId::generate().expect("separate G ID"),
            previous: c.roster.checkpoint(),
            policy_digest: c.old.checkpoint().digest(),
        },
        &pin,
        170,
    );
    assert!(matches!(fake_grant, Err(Error::Checkpoint)));
}

#[test]
fn current_policy_only_verification_never_extends_credential_roster_or_runtime() {
    for (credential_until, roster_until, later) in
        [(180, 240, 180), (240, 180, 180), (400, 400, 260)]
    {
        let c = Case::new(credential_until, roster_until);
        let (a, p) = c.approvals();
        let v = VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &c.materials(), 170)
            .expect("initial approval");
        assert!(matches!(
            VerifiedPolicyRenewal::from_bytes(v.as_bytes(), &c.scope, &c.materials(), later),
            Err(Error::Validity)
        ));
        assert!(HistoricalPolicyRenewal::from_bytes(
            v.as_bytes(),
            &c.scope,
            &c.materials().historical()
        )
        .is_ok());
    }
    for close_runtime in [false, true] {
        let c = Case::new(400, 400);
        let (a, p) = c.approvals();
        let v = VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &c.materials(), 170)
            .expect("initial approval");
        if close_runtime {
            c.runtime.close();
        } else {
            c.target.close();
        }
        assert!(
            VerifiedPolicyRenewal::from_bytes(v.as_bytes(), &c.scope, &c.materials(), 171).is_err()
        );
        let historical = HistoricalPolicyRenewal::from_bytes(
            v.as_bytes(),
            &c.scope,
            &c.materials().historical(),
        )
        .expect("history only");
        assert_eq!(historical.statement_digest(), v.statement_digest());
        assert_eq!(historical.as_bytes(), v.as_bytes());
    }
}

#[test]
fn both_roots_exact_predecessor_and_policy_profile_remain_required() {
    let c = Case::new(400, 400);
    let (a, p) = c.approvals();
    assert!(VerifiedPolicyRenewal::verify(&a, &a, &c.scope, &c.materials(), 170).is_err());
    assert!(VerifiedPolicyRenewal::verify(&p, &p, &c.scope, &c.materials(), 170).is_err());
    assert!(VerifiedPolicyRenewal::verify(&p, &a, &c.scope, &c.materials(), 170).is_err());
    let statement = PolicyRenewalStatement::new(&c.scope, &c.materials(), 170).expect("statement");
    assert!(matches!(
        RootSigningKey::generate()
            .expect("wrong root")
            .approve_policy_renewal(&statement),
        Err(Error::Scope)
    ));
    assert!(matches!(
        PolicySigningKey::generate()
            .expect("wrong issuer")
            .approve_policy_renewal(&statement),
        Err(Error::Scope)
    ));
    let mut changed = c.scope.clone();
    changed.operation = PolicyRenewalId::generate().expect("different operation");
    assert!(VerifiedPolicyRenewal::verify(&a, &p, &changed, &c.materials(), 170).is_err());
    changed = c.scope.clone();
    changed.journal = JournalIdentity::generate().expect("different journal");
    assert!(VerifiedPolicyRenewal::verify(&a, &p, &changed, &c.materials(), 170).is_err());
    for field in 0..3 {
        changed = c.scope.clone();
        match field {
            0 => changed.original_owner = [88; 32],
            1 => changed.original_credential = [88; 32],
            _ => changed.current_credential = [88; 32],
        }
        assert!(PolicyRenewalStatement::new(&changed, &c.materials(), 170).is_err());
    }
    changed = c.scope.clone();
    changed.current_roster =
        RosterCheckpoint::from_trusted_state(2, [88; 32]).expect("other roster");
    assert!(PolicyRenewalStatement::new(&changed, &c.materials(), 170).is_err());
    for (version, until, budget, anchor, at) in [
        (1, 260, 3, AnchorRequirement::local_only(), 170),
        (3, 160, 3, AnchorRequirement::local_only(), 150),
        (3, 280, 4, AnchorRequirement::local_only(), 170),
        (3, 280, 3, AnchorRequirement(Some([88; 32])), 170),
    ] {
        let other = c.policy(version, until, budget, anchor, at);
        let m = PolicyRenewalMaterials {
            target: &other,
            ..c.materials()
        };
        assert!(PolicyRenewalStatement::new(&c.scope, &m, at).is_err());
    }
    let other = c.policy(3, 280, 3, AnchorRequirement::local_only(), 170);
    let m = PolicyRenewalMaterials {
        target: &other,
        ..c.materials()
    };
    assert!(VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &m, 170).is_err());
}

#[test]
fn policy_only_chain_requires_explicit_previous_authorization() {
    let c = Case::new(400, 400);
    let (a, p) = c.approvals();
    let first =
        VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &c.materials(), 170).expect("P1 approval");
    let next = c.policy(3, 320, 3, AnchorRequirement::local_only(), 170);
    let mut scope = c.scope.clone();
    scope.operation = PolicyRenewalId::generate().expect("new operation");
    scope.previous_policy = c.target.checkpoint();
    let m = PolicyRenewalMaterials {
        previous: c.target.historical(),
        target: &next,
        ..c.materials()
    };
    assert!(matches!(
        PolicyRenewalStatement::new(&scope, &m, 270),
        Err(Error::Checkpoint)
    ));
    scope.previous_authorization = Some(first.statement_digest());
    let second = PolicyRenewalStatement::new(&scope, &m, 270).expect("same C/R after P1 expiry");
    let a2 = c.account.approve_policy_renewal(&second).expect("account");
    let p2 = c.issuer.approve_policy_renewal(&second).expect("policy");
    let verified = VerifiedPolicyRenewal::verify(&a2, &p2, &scope, &m, 270).expect("P2 approval");
    assert_ne!(verified.statement_digest(), first.statement_digest());
    assert_eq!(
        verified.scope().current_credential,
        first.scope().current_credential
    );
    assert_eq!(
        verified.scope().current_roster,
        first.scope().current_roster
    );
    assert!(VerifiedPolicyRenewal::verify(&a, &p2, &scope, &m, 270).is_err());
    // Signature verification still cannot decide which approval a journal adopted.
    // The future coordinator must compare this exact predecessor against storage.
}

#[test]
fn policy_only_grammar_rejects_noncanonical_predecessor_and_permission_before_signatures() {
    let c = Case::new(400, 400);
    let (approval, _) = c.approvals();
    let prefix = 4; // Signed envelope body length, not part of the statement.
    for (offset, value, expected) in [
        (prefix + BODY_BYTES - 34, 2, Error::Encoding),
        (prefix + BODY_BYTES - 33, 1, Error::Encoding),
        (prefix + BODY_BYTES - 1, 0, Error::Scope),
        (prefix + BODY_BYTES - 1, 2, Error::Scope),
    ] {
        let mut wire = approval.as_bytes().to_vec();
        *wire.get_mut(offset).expect("canonical grammar field") = value;
        // This parser performs no signature verification: an error here proves
        // that unknown modes and nonzero absent predecessors are not normalized.
        assert!(
            matches!(PolicyRenewalApproval::from_bytes(&wire), Err(error) if error == expected)
        );
    }
    assert!(matches!(
        PolicyRenewalId::from_trusted_state([0; 32]),
        Err(Error::Encoding)
    ));
}

#[test]
fn policy_only_parser_and_signature_purpose_do_not_accept_joint_g_t() {
    let c = Case::new(400, 400);
    let (a, p) = c.approvals();
    let v =
        VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &c.materials(), 170).expect("policy-only");
    let wire = v.as_bytes();
    for length in [0, 8, wire.len() - 1] {
        assert!(VerifiedPolicyRenewal::from_bytes(
            wire.get(..length).expect("prefix"),
            &c.scope,
            &c.materials(),
            170
        )
        .is_err());
    }
    let mut trailing = wire.to_vec();
    trailing.push(0);
    assert!(VerifiedPolicyRenewal::from_bytes(&trailing, &c.scope, &c.materials(), 170).is_err());
    for index in [0, 8, 10, wire.len() / 2, wire.len() - 1] {
        let mut bad = wire.to_vec();
        *bad.get_mut(index).expect("field") ^= 1;
        assert!(VerifiedPolicyRenewal::from_bytes(&bad, &c.scope, &c.materials(), 170).is_err());
        assert!(
            HistoricalPolicyRenewal::from_bytes(&bad, &c.scope, &c.materials().historical())
                .is_err()
        );
    }
    assert!(PolicyContinuationApproval::from_bytes(a.as_bytes()).is_err());
    let joint = continuation::tests::Case::new();
    let (joint_a, _) = joint.approvals();
    assert!(PolicyRenewalApproval::from_bytes(joint_a.as_bytes()).is_err());
    let statement = PolicyRenewalStatement::new(&c.scope, &c.materials(), 170).expect("statement");
    let body = statement.bound.encode();
    assert_eq!(body.len(), BODY_BYTES);
    let wrong_a = PolicyRenewalApproval::from_bytes(
        &envelope(
            &body,
            &c.account
                .sign(Purpose::PolicyContinuation, &body)
                .expect("wrong-purpose signature"),
        )
        .expect("envelope"),
    )
    .expect("grammar only");
    let wrong_p = PolicyRenewalApproval::from_bytes(
        &envelope(
            &body,
            &c.issuer
                .sign(Purpose::PolicyContinuation, &body)
                .expect("wrong-purpose signature"),
        )
        .expect("envelope"),
    )
    .expect("grammar only");
    assert!(matches!(
        VerifiedPolicyRenewal::verify(&wrong_a, &wrong_p, &c.scope, &c.materials(), 170),
        Err(Error::Authentication)
    ));
}
