// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit test-controller approvals, distinct from the device/network carrier.
use crate::{
    account_fixture::Published,
    fixture::{save, Fixture},
    Result,
};
use q_periapt_continuity_identity_candidate::{
    AccountPin, AllowedPrekeyModes, AnchorRequirement, ApplicationSendBudget, BootstrapRole,
    JournalIdentity, PolicyCheckpoint, PolicyPin, PolicyRenewalId, PolicyRenewalMaterials,
    PolicyRenewalScope, PolicyRenewalStatement, PolicySigningKey, PrekeyQuality, RootSigningKey,
    RosterCheckpoint, SessionPolicyParameters, Validity, VerifiedDevice, VerifiedPolicyRenewal,
    VerifiedSessionPolicy,
};
use q_periapt_sdk::Runtime;
use std::{fs, path::Path, sync::Arc};

pub(super) struct Authority {
    account: RootSigningKey,
    issuer: PolicySigningKey,
    policies: Vec<Arc<VerifiedSessionPolicy>>,
}

pub(super) fn publish_account(
    path: &Path,
    root: &RootSigningKey,
    certificates: &[Vec<u8>],
) -> Result<Published> {
    fs::create_dir(path)?;
    let entries = certificates
        .iter()
        .map(|c| root.roster_entry(c))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let roster = root.issue_roster(1, Validity::new(100, 450)?, &entries)?;
    save(path, "root", &root.public_key()?.encode())?;
    save(path, "account", &root.account_id()?)?;
    save(path, "roster-1", roster.as_bytes())?;
    let mut checkpoint = 1u64.to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&roster.checkpoint().digest());
    save(path, "checkpoint-1", &checkpoint)?;
    for (index, wire) in certificates.iter().enumerate() {
        save(path, &format!("credential-1-{}", index + 1), wire)?;
    }
    Ok(Published {
        initial_roster: roster.as_bytes().to_vec(),
        checkpoint: roster.checkpoint(),
        local_grants: Vec::new(),
        local_rosters: Vec::new(),
    })
}

impl Authority {
    pub fn new(
        path: &Path,
        issuer: PolicySigningKey,
        account: RootSigningKey,
        runtime: &Arc<Runtime>,
        original: Arc<VerifiedSessionPolicy>,
    ) -> Result<Self> {
        let mut policies = vec![original];
        for (version, until) in [(2, 260), (3, 330), (4, 400)] {
            let original = policies.first().ok_or("missing original policy")?;
            let issued = issuer.issue_session_policy(
                runtime,
                SessionPolicyParameters::new(
                    version,
                    Validity::new(100, until)?,
                    AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth])?,
                    AnchorRequirement::local_only(),
                    ApplicationSendBudget::new(original.application_send_budget().messages())?,
                )?,
            )?;
            save(path, &format!("policy-{version}"), issued.as_bytes())?;
            let mut head = version.to_be_bytes().to_vec();
            head.extend_from_slice(&issued.checkpoint().digest());
            save(path, &format!("policy-head-{version}"), &head)?;
            let pin = PolicyPin::new(
                issuer.policy_family()?,
                issuer.public_key()?,
                issued.checkpoint(),
            )?;
            policies.push(Arc::new(pin.verify(
                issued.as_bytes(),
                Arc::clone(runtime),
                150,
            )?));
        }
        Ok(Self {
            account,
            issuer,
            policies,
        })
    }

    pub fn policy(&self, version: u64) -> Result<Arc<VerifiedSessionPolicy>> {
        self.policies
            .iter()
            .find(|p| p.checkpoint().version() == version)
            .cloned()
            .ok_or("unissued policy version".into())
    }

    pub fn approve(
        &self,
        scope: &PolicyRenewalScope,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
        version: u64,
        now: u64,
    ) -> Result<VerifiedPolicyRenewal> {
        let first = self.policies.first().ok_or("missing original policy")?;
        let previous = self.policy(scope.previous_policy.version())?;
        let target = self.policy(version)?;
        let materials = PolicyRenewalMaterials {
            original: first.historical(),
            previous: previous.historical(),
            target: &target,
            original_device: original,
            current_device: current,
        };
        let statement = PolicyRenewalStatement::new(scope, &materials, now)?;
        Ok(VerifiedPolicyRenewal::verify(
            &self.account.approve_policy_renewal(&statement)?,
            &self.issuer.approve_policy_renewal(&statement)?,
            scope,
            &materials,
            now,
        )?)
    }

    pub fn approve_request(&self, fixture: &Fixture, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut r = Request(bytes);
        let version = r.u64()?;
        let now = r.u64()?;
        let scope = PolicyRenewalScope {
            operation: PolicyRenewalId::from_trusted_state(r.array()?)?,
            journal: JournalIdentity::from_trusted_state(r.array()?)?,
            original_owner: r.array()?,
            original_credential: r.array()?,
            current_credential: r.array()?,
            current_roster: RosterCheckpoint::from_trusted_state(r.u64()?, r.array()?)?,
            original_policy: PolicyCheckpoint::from_trusted_state(r.u64()?, r.array()?)?,
            previous_policy: PolicyCheckpoint::from_trusted_state(r.u64()?, r.array()?)?,
            previous_authorization: match (r.array::<1>()?, r.array::<32>()?) {
                ([0], value) if value == [0; 32] => None,
                ([1], value) if value != [0; 32] => Some(value),
                _ => return Err("policy request predecessor flag".into()),
            },
        };
        let certificate = r.field()?;
        let roster = r.field()?;
        if !r.0.is_empty() {
            return Err("policy request trailing bytes".into());
        }
        let original = fixture.context.device(BootstrapRole::Initiator);
        let pin = AccountPin::new(
            original.account_id(),
            self.account.public_key()?,
            scope.current_roster,
            fixture.policy.family(),
        )?;
        let current = pin.verify_device(certificate, roster, now)?;
        Ok(self
            .approve(&scope, original, &current, version, now)?
            .as_bytes()
            .to_vec())
    }
}

struct Request<'a>(&'a [u8]);
impl<'a> Request<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let result = self.0.get(..size).ok_or("short policy request")?;
        self.0 = self.0.get(size..).ok_or("short policy request")?;
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into()?)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn field(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > 8192 {
            return Err("policy public material capacity".into());
        }
        self.take(length)
    }
}
