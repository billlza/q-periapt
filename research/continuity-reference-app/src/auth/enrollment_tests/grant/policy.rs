// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual G-to-P lifecycle using the two independent protected issuers.
use super::*;
use crate::{
    native_device::PolicyRecoveryInputs,
    policy_approval::{
        IssuedPolicyApproval, PolicyApprovalRequest, PolicyApprovalStatus, PolicyInput,
    },
    policy_publisher::RenewalRequest,
};
mod crash;

struct PolicyCase {
    base: Case,
    publisher: Publisher,
    request: PolicyApprovalRequest,
}
impl PolicyCase {
    fn new(extended: bool) -> Result<Self> {
        Self::with_validity(extended, 7200, 3600)
    }
    fn with_validity(extended: bool, original_seconds: u64, extension: u64) -> Result<Self> {
        let mut base = Case::with_policy_duration(extended, None, original_seconds)?;
        base.host.store.enable_credential_grants()?;
        let issued: IssuedCredentialGrant = serde_json::from_slice(&base.issue()?)?;
        let grant = sdk::VerifiedCredentialRenewal::verify(
            &issued.grant,
            &base.pin()?,
            base.input.retained.original_policy.digest,
            crate::enrollment::now()?,
        )?;
        let mut owner = base.open_owner()?;
        owner.stage_credential_renewal(
            &grant,
            grant.operation(),
            &base.policy,
            crate::enrollment::now()?,
        )?;
        owner
            .activate(&base.policy, crate::enrollment::now()?, None)?
            .close();
        let mut native = NativeDevice::open(
            &base.path.join("device"),
            &base.path.join("wrap.key"),
            base.invitation.clone(),
        )?;
        let retained =
            native.policy_renewal_request(sdk::PolicyRenewalId::generate()?, &base.historical)?;
        native.close();
        let mut publisher = Publisher::open(&base.path.join("publisher.redb"), [90; 32])?;
        let original = publisher.result([91; 32])?;
        publisher.issue(
            [94; 32],
            Request {
                valid_until: original.request.valid_until + extension,
                ..original.request
            },
            crate::enrollment::now()?,
        )?;
        let input = |id| -> Result<PolicyInput> {
            let (pins, materials) = publisher.export(id)?;
            Ok(PolicyInput { pins, materials })
        };
        let request = PolicyApprovalRequest {
            retained,
            original_extension: base.input.original_extension,
            current_extension: Some(base.input.successor_extension),
            original: input([91; 32])?,
            previous: input([91; 32])?,
            target: input([94; 32])?,
        };
        Ok(Self {
            base,
            publisher,
            request,
        })
    }
    fn issue(&mut self) -> Result<Vec<u8>> {
        Ok(self
            .base
            .host
            .issue_policy_approval(&self.base.token, &self.request)?)
    }
    fn adopt(&mut self, response: &[u8]) -> Result<()> {
        let account: IssuedPolicyApproval = serde_json::from_slice(response)?;
        let current = self.base.host.enrollment_root(&self.base.token)?;
        self.publisher.enable_renewals()?;
        let policy = self.publisher.approve_renewal(
            &RenewalRequest {
                retained: self.request.retained.clone(),
                original_publication: [91; 32],
                previous_publication: [91; 32],
                target_publication: [94; 32],
            },
            &current,
        )?;
        assert_eq!(account.statement, policy.statement);
        let original = self
            .request
            .original
            .pins
            .verify_historical(&self.request.original.materials, current.family)?
            .0;
        let previous = self
            .request
            .previous
            .pins
            .verify_historical(&self.request.previous.materials, current.family)?
            .0;
        let target = self
            .request
            .target
            .pins
            .verify(
                &self.request.target.materials,
                current.family,
                crate::enrollment::now()?,
            )?
            .0;
        let mut native = NativeDevice::open(
            &self.base.path.join("device"),
            &self.base.path.join("wrap.key"),
            self.base.invitation.clone(),
        )?;
        let result = native.adopt_policy(
            &PolicyRecoveryInputs {
                request: &self.request.retained,
                account_approval: &account.approval,
                policy_approval: &policy.approval,
                current: &current,
                original: &original,
                previous: &previous,
                target: &target,
            },
            crate::enrollment::now()?,
        )?;
        assert!(
            matches!(result, sdk::PolicyRenewalStatus::Committed { statement, .. } if statement == account.statement)
        );
        native.close();
        Ok(())
    }
}

#[test]
fn both_protected_issuers_adopt_policy_after_original_credential_recovery() -> Result {
    for extended in [false, true] {
        let mut c = PolicyCase::new(extended)?;
        let before = c.base.host.enrollment_root(&c.base.token)?;
        let device_key = fs::read(c.base.path.join("device/device.key"))?;
        let wrapping = fs::read(c.base.path.join("wrap.key"))?;
        assert!(c.issue().is_err());
        c.base.host.store.enable_policy_approvals()?;
        c.base.host.store.enable_policy_approvals()?;
        let issued = c.issue()?;
        c.adopt(&issued)?;
        assert_eq!(c.issue()?, issued);
        assert_eq!(c.base.host.enrollment_root(&c.base.token)?, before);
        assert_eq!(fs::read(c.base.path.join("device/device.key"))?, device_key);
        assert_eq!(fs::read(c.base.path.join("wrap.key"))?, wrapping);
        c.base.host.suspend_enrollment_root(&c.base.token)?;
        drop(c.base.host);
        let mut host = reopen(&c.base.path)?;
        let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
        assert_eq!(host.issue_policy_approval(&token, &c.request)?, issued);
        for entry in fs::read_dir(&c.base.path)? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("enrollment-") && v.ends_with(".signer"))
            {
                fs::rename(&path, path.with_extension("signer.held"))?;
            }
        }
        let PolicyApprovalStatus::Issued { response } =
            host.policy_approval_status(&token, &c.request)?
        else {
            return Err("original policy result".into());
        };
        assert_eq!(response, issued);
        assert_eq!(host.issue_policy_approval(&token, &c.request)?, issued);
        assert!(host.cancel_policy_approval(&token, &c.request).is_err());
    }
    Ok(())
}

#[test]
fn account_policy_approval_requires_login_and_exact_host_credential_ancestry() -> Result {
    let mut c = PolicyCase::new(false)?;
    c.base.host.store.enable_policy_approvals()?;
    let mut bob = authenticator();
    register(&mut c.base.host, &mut bob, "bob")?;
    let (other, _) = login(&mut c.base.host, &mut bob, "bob")?;
    for token in ["invalid", other.as_str()] {
        assert!(matches!(
            c.base.host.issue_policy_approval(token, &c.request),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            c.base.host.policy_approval_status(token, &c.request),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            c.base.host.cancel_policy_approval(token, &c.request),
            Err(Error::Unauthorized)
        ));
    }
    for field in ["original_extension", "current_extension"] {
        let mut missing = serde_json::to_value(&c.request)?;
        missing.as_object_mut().ok_or("request")?.remove(field);
        assert!(serde_json::from_value::<PolicyApprovalRequest>(missing).is_err());
    }
    let mut variants = Vec::new();
    let mut bad = c.request.clone();
    bad.original_extension = bad.current_extension;
    variants.push(bad);
    let mut bad = c.request.clone();
    bad.current_extension = None;
    variants.push(bad);
    let mut bad = c.request.clone();
    bad.retained.current_certificate[20] ^= 1;
    variants.push(bad);
    let mut bad = c.request.clone();
    bad.retained.scope.current_roster.digest[0] ^= 1;
    variants.push(bad);
    let mut bad = c.request.clone();
    bad.retained.scope.original_owner[0] ^= 1;
    variants.push(bad);
    let mut bad = c.request.clone();
    bad.target = bad.original.clone();
    variants.push(bad);
    let mut foreign_policy = serde_json::to_value(&c.request)?;
    foreign_policy["target"]["pins"]["policy_root"] = serde_json::json!(
        URL_SAFE_NO_PAD.encode(sdk::PolicySigningKey::generate()?.public_key()?.encode())
    );
    variants.push(serde_json::from_value(foreign_policy)?);
    // This alternate SDK document/signature is valid under its own root. The
    // trusted protocol policy still commits to the original SDK root digest.
    let sdk_input = crate::test_support::sdk_input()?;
    sdk_input.verify()?;
    let mut foreign_sdk = serde_json::to_value(&c.request)?;
    foreign_sdk["target"]["pins"]["sdk_root"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(sdk_input.root));
    foreign_sdk["target"]["pins"]["sdk_state"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(sdk_input.state));
    foreign_sdk["target"]["materials"]["sdk_document"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(sdk_input.document));
    foreign_sdk["target"]["materials"]["sdk_signature"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(sdk_input.signature));
    variants.push(serde_json::from_value(foreign_sdk)?);
    let mut bad = c.request.clone();
    bad.retained.application[0] ^= 1;
    variants.push(bad);
    for bad in variants {
        assert!(c
            .base
            .host
            .issue_policy_approval(&c.base.token, &bad)
            .is_err());
        assert!(matches!(
            c.base
                .host
                .policy_approval_status(&c.base.token, &c.request)?,
            PolicyApprovalStatus::Absent
        ));
    }
    let issued = c.issue()?;
    let mut changed = c.request.clone();
    changed.retained.scope.journal[0] ^= 1;
    assert!(c
        .base
        .host
        .issue_policy_approval(&c.base.token, &changed)
        .is_err());
    assert_eq!(c.issue()?, issued);
    c.base
        .host
        .sessions
        .get_mut(&c.base.token)
        .ok_or("session")?
        .deadline = Instant::now();
    assert!(matches!(
        c.base.host.issue_policy_approval(&c.base.token, &c.request),
        Err(Error::Unauthorized)
    ));
    Ok(())
}

#[test]
fn account_policy_tombstone_fences_an_original_delayed_request() -> Result {
    let mut c = PolicyCase::new(false)?;
    c.base.host.store.enable_policy_approvals()?;
    c.base
        .host
        .cancel_policy_approval(&c.base.token, &c.request)?;
    drop(c.base.host);
    let mut host = reopen(&c.base.path)?;
    let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
    assert!(matches!(
        host.policy_approval_status(&token, &c.request)?,
        PolicyApprovalStatus::Closed
    ));
    host.cancel_policy_approval(&token, &c.request)?;
    assert!(matches!(
        host.issue_policy_approval(&token, &c.request),
        Err(Error::Conflict("Original policy approval is closed"))
    ));
    Ok(())
}
