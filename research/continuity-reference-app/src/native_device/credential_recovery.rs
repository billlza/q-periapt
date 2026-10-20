// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original-owner G recovery; issuer metadata never selects current trust.
use super::*;
use crate::credential_grant::{CredentialGrantRequest, IssuedCredentialGrant};

pub struct CredentialRecoveryInputs<'a> {
    pub approval: &'a CredentialGrantRequest,
    pub issued: &'a IssuedCredentialGrant,
    pub current: &'a RootInfo,
    pub original_policy: &'a sdk::HistoricalSessionPolicy,
    pub policy: &'a sdk::VerifiedSessionPolicy,
}

fn current_time(floor: u64) -> Result<u64> {
    let at = clock()?;
    if at < floor {
        return Err("Host time moved behind the recovery invocation".into());
    }
    Ok(at)
}

impl NativeDevice {
    /// Historical progress only, including after target expiry or a lost reply.
    pub fn credential_recovery_status(&mut self) -> Result<sdk::CredentialRenewalStatus> {
        Ok(self.owner.credential_renewal_status()?)
    }
    fn check_credential_recovery(
        &mut self,
        inputs: &CredentialRecoveryInputs<'_>,
        now: u64,
    ) -> Result<sdk::VerifiedCredentialRenewal> {
        let request = &inputs.approval.retained;
        let issued = inputs.issued;
        if request.schema != "qperiapt-retained-credential-request/1"
            || request.application != self.invitation.application
            || request.enrollment != self.invitation.operation
            || request.root_revision != self.invitation.root_revision
            || issued.enrollment != request.enrollment
            || issued.root_revision != request.root_revision
            || issued.operation != request.operation
            || issued.journal != request.journal
            || issued.checkpoint != inputs.approval.target_checkpoint
            || inputs.original_policy.family() != self.invitation.family
            || inputs.policy.family() != self.invitation.family
            || inputs.original_policy.checkpoint().version() != request.original_policy.version
            || inputs.original_policy.checkpoint().digest() != request.original_policy.digest
        {
            return Err("Credential recovery differs from retained approval or policy".into());
        }
        let pin = self.pin(inputs.current)?;
        let current = inputs
            .current
            .roster
            .as_ref()
            .ok_or("Current roster is required")?;
        if current.checkpoint != issued.checkpoint
            || *self.owner.public_admission()?.journal().as_bytes() != request.journal
        {
            return Err("Credential recovery journal or selected target differs".into());
        }
        let grant = sdk::VerifiedCredentialRenewal::verify(
            &issued.grant,
            &pin,
            request.original_policy.digest,
            now,
        )?;
        if *grant.operation().as_bytes() != request.operation
            || grant.statement_digest() != issued.statement
            || grant.original_storage_owner() != request.original_owner
            || grant.previous_device().roster().checkpoint()
                != request.previous_checkpoint.as_sdk()?
        {
            return Err("Signed credential grant differs from original decision".into());
        }
        Ok(grant)
    }
    /// Retain the exact SDK intent. This returns progress, never a runtime owner.
    pub fn stage_credential_recovery(
        &mut self,
        inputs: &CredentialRecoveryInputs<'_>,
        now: u64,
    ) -> Result<sdk::CredentialRenewalStatus> {
        let result = (|| {
            let grant = self.check_credential_recovery(inputs, now)?;
            Ok(self.owner.stage_credential_renewal(
                &grant,
                grant.operation(),
                inputs.policy,
                now,
            )?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn recovery_anchor(
        &mut self,
        inputs: &CredentialRecoveryInputs<'_>,
        pin: sdk::AnchorPin,
        address: SocketAddr,
        now: u64,
    ) -> Result<sdk::AnchorClient> {
        if inputs.original_policy.anchor_requirement() != inputs.policy.anchor_requirement()
            || inputs.policy.anchor_requirement() != sdk::AnchorRequirement::required(&pin)
        {
            return Err(
                "Credential recovery witness differs from independently pinned policies".into(),
            );
        }
        Ok(self.owner.credential_renewal_anchor_client(
            inputs.original_policy,
            now,
            pin,
            Box::new(sdk::AnchorTcpTransport::new(address)),
            Duration::from_secs(10),
        )?)
    }
    /// Export the exact witness proposal. The witness must separately approve it.
    pub fn prepare_credential_recovery_witness(
        &mut self,
        inputs: &CredentialRecoveryInputs<'_>,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<sdk::AnchorCredentialRenewalProposal> {
        let result = (|| {
            self.stage_credential_recovery(inputs, now)?;
            let anchor = self.recovery_anchor(inputs, witness, endpoint, current_time(now)?)?;
            Ok(self.owner.prepare_witnessed_policy_continuation(
                inputs.original_policy,
                inputs.policy,
                current_time(now)?,
                anchor,
            )?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Resume the exact original G. Required-witness Commit succeeds only after
    /// independent approval. Any uncertain result requires reopening this owner.
    pub fn activate_credential_recovery(
        mut self,
        inputs: &CredentialRecoveryInputs<'_>,
        witness: Option<sdk::AnchorPin>,
        endpoint: Option<SocketAddr>,
        now: u64,
    ) -> Result<ActiveDevice> {
        let expected = witness.as_ref().map_or_else(
            sdk::AnchorRequirement::local_only,
            sdk::AnchorRequirement::required,
        );
        if expected != inputs.policy.anchor_requirement() || witness.is_some() != endpoint.is_some()
        {
            return Err("Credential recovery requires the exact witness configuration".into());
        }
        let progress = self.stage_credential_recovery(inputs, now)?;
        let anchor = match (witness, endpoint) {
            (Some(pin), Some(address)) => {
                if matches!(progress, sdk::CredentialRenewalStatus::Pending { .. }) {
                    let proposal = self.prepare_credential_recovery_witness(
                        inputs,
                        pin.clone(),
                        address,
                        current_time(now)?,
                    )?;
                    let mut carrier =
                        self.recovery_anchor(inputs, pin.clone(), address, current_time(now)?)?;
                    self.owner.commit_witnessed_policy_continuation(
                        &proposal,
                        inputs.original_policy,
                        inputs.policy,
                        current_time(now)?,
                        &mut carrier,
                    )?;
                }
                Some(self.recovery_anchor(inputs, pin, address, current_time(now)?)?)
            }
            (None, None) => None,
            _ => return Err("Credential recovery witness configuration changed".into()),
        };
        self.admit_recovered_owner(inputs, anchor, current_time(now)?)
    }
    fn admit_recovered_owner(
        mut self,
        inputs: &CredentialRecoveryInputs<'_>,
        anchor: Option<sdk::AnchorClient>,
        now: u64,
    ) -> Result<ActiveDevice> {
        let independent_policy = matches!(
            self.owner.policy_renewal_status()?,
            sdk::PolicyRenewalStatus::Committed { .. }
        );
        let now = current_time(now)?;
        let owner = if inputs.original_policy.checkpoint() == inputs.policy.checkpoint() {
            self.owner.activate(inputs.policy, now, anchor)?
        } else if independent_policy {
            match anchor {
                Some(carrier) => self.owner.activate_witnessed_policy_renewal(
                    inputs.original_policy,
                    inputs.policy,
                    now,
                    carrier,
                )?,
                None => self.owner.activate_policy_renewal(
                    inputs.original_policy,
                    inputs.policy,
                    now,
                )?,
            }
        } else {
            match anchor {
                Some(carrier) => self.owner.activate_witnessed_policy_continuation(
                    inputs.original_policy,
                    inputs.policy,
                    now,
                    carrier,
                )?,
                None => self.owner.activate_policy_continuation(
                    inputs.original_policy,
                    inputs.policy,
                    now,
                )?,
            }
        };
        let active = ActiveDevice::from_owner(owner)?;
        if active.journal() != inputs.issued.journal
            || active.public.checkpoint() != inputs.issued.checkpoint.as_sdk()?
        {
            return Err("Recovered admission differs from the selected journal and target".into());
        }
        // Recheck actual current target membership after cross-store recovery.
        let pin = sdk::AccountPin::new(
            inputs.current.account,
            sdk::PublicKey::decode(&inputs.current.public_key)?,
            inputs.issued.checkpoint.as_sdk()?,
            inputs.current.family,
        )?;
        let at = current_time(now)?;
        let validity = inputs.policy.validity();
        if at < validity.from() || at >= validity.until() {
            return Err("Current policy expired during credential recovery".into());
        }
        pin.verify_device(active.public.certificate(), active.public.roster(), at)?;
        Ok(active)
    }
}
