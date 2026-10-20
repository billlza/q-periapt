// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original-owner G recovery; issuer metadata never selects current trust.
use super::*;
use crate::credential_grant::{CredentialGrantRequest, IssuedCredentialGrant};

pub struct CredentialRecoveryInputs<'a> {
    pub approval: &'a CredentialGrantRequest,
    pub issued: &'a IssuedCredentialGrant,
    /// None selects the single-credential workflow. Some selects a complete,
    /// nonempty set of other changed credentials under the same account.
    /// It must be supplied again on every stage/prepare/activate retry.
    pub companions: Option<&'a [IssuedCredentialGrant]>,
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
    /// Observe the exact retained witness operation, including after expiry.
    /// SDK recovery can finish local terminal records and ACK their durability;
    /// this call never prepares, commits or closes a remote target.
    pub fn observe_credential_recovery(
        &mut self,
        operation: sdk::CredentialRenewalId,
        statement: [u8; 32],
        original_policy: &sdk::HistoricalSessionPolicy,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<sdk::CredentialRenewalStatus> {
        let result = (|| {
            if original_policy.family() != self.invitation.family
                || original_policy.anchor_requirement()
                    != sdk::AnchorRequirement::required(&witness)
            {
                return Err("Historical witness differs from the original policy".into());
            }
            let mut carrier = self.owner.credential_renewal_anchor_client(
                original_policy,
                current_time(now)?,
                witness,
                Box::new(sdk::AnchorTcpTransport::new(endpoint)),
                Duration::from_secs(10),
            )?;
            Ok(self.owner.reconcile_witnessed_credential_renewal(
                operation,
                statement,
                original_policy,
                current_time(now)?,
                &mut carrier,
            )?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Reconcile an exact retained local-only G under its unchanged live policy.
    /// The issued response selects the original intent; the SDK validates the
    /// retained signed grant and journal. No new grant is staged or owner released.
    pub fn reconcile_expired_credential_recovery(
        &mut self,
        issued: &IssuedCredentialGrant,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<sdk::CredentialRenewalStatus> {
        let result = (|| {
            if issued.enrollment != self.invitation.operation
                || issued.root_revision != self.invitation.root_revision
                || policy.family() != self.invitation.family
                || policy.anchor_requirement() != sdk::AnchorRequirement::local_only()
                || *self.owner.public_admission()?.journal().as_bytes() != issued.journal
            {
                return Err("Expiry selection differs from the original local installation".into());
            }
            Ok(self.owner.reconcile_expired_credential_renewal(
                sdk::CredentialRenewalId::from_trusted_state(issued.operation)?,
                issued.statement,
                policy,
                current_time(now)?,
            )?)
        })();
        if result.is_err() {
            self.close();
        }
        result
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
            match inputs.companions {
                None => Ok(self.owner.stage_credential_renewal(
                    &grant,
                    grant.operation(),
                    inputs.policy,
                    now,
                )?),
                Some(issued) => {
                    if issued.is_empty() || issued.len() >= sdk::MAX_DEVICES {
                        return Err("Account renewal requires 1 to 31 companion grants".into());
                    }
                    let pin = self.pin(inputs.current)?;
                    let mut companions = Vec::with_capacity(issued.len());
                    for companion in issued {
                        if companion.root_revision != inputs.current.revision
                            || companion.checkpoint != inputs.issued.checkpoint
                        {
                            return Err("Companion grant selects a different account target".into());
                        }
                        let checked = sdk::VerifiedCredentialRenewal::verify(
                            &companion.grant,
                            &pin,
                            inputs.original_policy.checkpoint().digest(),
                            now,
                        )?;
                        if checked.operation().as_bytes() != &companion.operation
                            || checked.statement_digest() != companion.statement
                        {
                            return Err("Companion grant differs from its signed decision".into());
                        }
                        companions.push(checked);
                    }
                    let references = companions.iter().collect::<Vec<_>>();
                    Ok(self.owner.stage_account_credential_renewal(
                        &grant,
                        &references,
                        grant.operation(),
                        inputs.policy,
                        now,
                    )?)
                }
            }
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
