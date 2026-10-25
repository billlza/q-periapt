// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit management of one independently adopted inherited subject.
use super::*;
use crate::{
    AnchorCredentialRenewalProposal, AnchorCredentialRenewalState, AnchorPolicyRenewalProposal,
    AnchorPolicyRenewalState, AnchorRosterRefreshProposal, AnchorRosterRefreshState,
    HistoricalSessionPolicy, VerifiedCredentialRenewal, VerifiedPolicyRenewal,
};

#[derive(Clone)]
pub(super) struct Scope {
    subject: AnchorSubject,
    pub(super) logical: AnchorPin,
    current: AnchorPin,
    context: Option<crate::AnchorHandoffReplyContext>,
}
pub(super) struct Proposal<P> {
    pub(super) scope: Scope,
    pub(super) value: P,
}
impl Scope {
    pub(super) fn original(
        store: &AnchorStore,
        subject: AnchorSubject,
    ) -> Result<Self, DurableError> {
        let current = store.pin()?;
        Ok(Self {
            subject,
            logical: current.clone(),
            current,
            context: None,
        })
    }
    pub(super) fn bind<P>(
        &self,
        value: P,
        subject: AnchorSubject,
    ) -> Result<Proposal<P>, DurableError> {
        if subject != self.subject {
            return Err(Error::Scope.into());
        }
        Ok(Proposal {
            scope: self.clone(),
            value,
        })
    }
    pub(super) fn live(&self, store: &AnchorStore, image: &Image) -> Result<(), DurableError> {
        if store.pin()?.binding() != self.current.binding() {
            return Err(Error::Scope.into());
        }
        match self.context {
            None => image.require_live(self.subject),
            Some(context) => {
                let active = store.active.as_ref().ok_or(DurableError::Closed)?;
                let transferred = active.transferred.as_ref().ok_or(DurableError::Suspended)?;
                let id = self.subject.id(&image.namespace);
                if transferred.client_context(self.subject)? != context
                    || context.namespace_binding() != image.namespace
                    || !image.inherited.contains(&id)
                    || image
                        .entries
                        .get(&id)
                        .is_none_or(|e| e.subject != self.subject)
                    || image.subject_retired(self.subject)
                    || image.subject_frozen(self.subject)
                {
                    return Err(Error::Scope.into());
                }
                Ok(())
            }
        }
    }
    pub(super) fn check_keys(
        &self,
        device: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
    ) -> Result<(), DurableError> {
        for pin in [&self.logical, &self.current] {
            if pin.key.shares_component(&device.key)
                || pin.key.shares_component(&device.authority_key)
            {
                return Err(Error::Scope.into());
            }
            policy.check_external_signer(&pin.key)?;
        }
        Ok(())
    }
    pub(super) fn admit(
        &self,
        store: &AnchorStore,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Validity, DurableError> {
        self.check_keys(device, policy.historical())?;
        store.admit_current_device_with_binding(device, policy, now, self.logical.binding())
    }
}

/// Restricted independent control plane for one exact adopted subject. The
/// current witness and retained authorization are checked separately from the
/// immutable logical identity of G/P/R commands. It never changes the store pin,
/// adopts a client, releases traffic, or makes legacy management admissible.
pub struct AnchorTransferredControl<'a> {
    store: &'a mut AnchorStore,
    scope: Scope,
}
impl AnchorStore {
    /// Select the target's exact already committed client authorization. Operator
    /// authentication and independent G/P/R issuer approvals remain required.
    /// An unrelated, substituted or absent receipt cannot select another subject.
    pub fn transferred_control(
        &mut self,
        receipt: &AnchorHandoffClientAuthorizationReceipt,
    ) -> Result<AnchorTransferredControl<'_>, DurableError> {
        let subject = receipt.scope().subject;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let transferred = active.transferred.as_ref().ok_or(DurableError::Suspended)?;
        let context = transferred.client_context(subject)?;
        if context.authorization_digest()
            != digest(
                b"Q-PERIAPT-TRANSFERRED-WITNESS-AUTHORIZATION/v1",
                receipt.as_bytes(),
            )
            || context.namespace_binding() != receipt.scope().namespace
            || context.logical_witness_binding() != receipt.scope().logical
            || context.current_witness_binding() != receipt.scope().successor
            || context.history_checkpoint() != receipt.scope().history
            || context.current_witness_binding() != active.pin.binding()
        {
            return Err(Error::Scope.into());
        }
        let scope = Scope {
            subject,
            logical: transferred.logical_pin(context.logical_witness_binding())?,
            current: active.pin.clone(),
            context: Some(context),
        };
        let image = self.image()?;
        scope.live(self, &image)?;
        Ok(AnchorTransferredControl { store: self, scope })
    }
}
impl AnchorTransferredControl<'_> {
    /// Close the exact originally approved credential target, including after
    /// expiry. Applied remains Applied; this cannot issue a new credential.
    pub fn close_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &crate::HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        self.store.retain_credential_renewal_controlled(
            self.scope.bind(proposal, proposal.subject())?,
            grant,
            policy,
            policy,
            None,
            None,
        )
    }
    /// Close an exact independently approved policy target without extending
    /// either issuer's validity or replacing an already applied target.
    pub fn close_policy_renewal(
        &mut self,
        proposal: AnchorPolicyRenewalProposal,
        approval: &crate::HistoricalPolicyRenewal,
        materials: &crate::HistoricalPolicyRenewalMaterials<'_>,
    ) -> Result<AnchorPolicyRenewalState, DurableError> {
        self.store.retain_policy_renewal_controlled(
            self.scope.bind(proposal, proposal.subject())?,
            approval,
            materials,
            policy_renewal::Phase::Closed,
        )
    }
    /// Close the exact signed roster target; retain its permanent version floor.
    pub fn close_roster_refresh(
        &mut self,
        proposal: AnchorRosterRefreshProposal,
        previous: &VerifiedDevice,
        next: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorRosterRefreshState, DurableError> {
        self.store.retain_roster_refresh_controlled(
            self.scope.bind(proposal, proposal.subject())?,
            previous,
            next,
            roster_refresh::Admission::Close(policy),
        )
    }
    /// Independently prepare a credential target while retaining original IDs.
    pub fn prepare_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        self.store.retain_credential_renewal_controlled(
            self.scope.bind(proposal, proposal.subject())?,
            grant.as_ref(),
            policy.historical(),
            policy.historical(),
            Some((policy, now)),
            None,
        )
    }
    /// Independently prepare an exact policy target approved by both issuers.
    pub fn prepare_policy_renewal(
        &mut self,
        proposal: AnchorPolicyRenewalProposal,
        approval: &VerifiedPolicyRenewal,
        materials: &crate::PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<AnchorPolicyRenewalState, DurableError> {
        let verified = VerifiedPolicyRenewal::from_bytes(
            approval.as_bytes(),
            approval.scope(),
            materials,
            now,
        )?;
        self.store.retain_policy_renewal_controlled(
            self.scope.bind(proposal, proposal.subject())?,
            &verified.historical(),
            &materials.historical(),
            policy_renewal::Phase::Prepared,
        )
    }
    /// Independently prepare the original roster and journal target together.
    pub fn prepare_roster_refresh(
        &mut self,
        proposal: AnchorRosterRefreshProposal,
        previous: &VerifiedDevice,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorRosterRefreshState, DurableError> {
        self.store.retain_roster_refresh_controlled(
            self.scope.bind(proposal, proposal.subject())?,
            previous,
            next,
            roster_refresh::Admission::Prepare(policy, now),
        )
    }
}
