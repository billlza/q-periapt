// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Issuer request scope from matching original enrollment and journal history.
use super::*;

/// Exact public identity materials accompanying a policy-only request scope.
/// Signature-verified snapshots do not track later revocation or time and give
/// no current authority. Keep the whole request and operation for issuer dedup.
/// Account/user authentication and issuer serialization remain independent.
pub struct PolicyRenewalRequest {
    scope: crate::PolicyRenewalScope,
    original: VerifiedDevice,
    current: VerifiedDevice,
    original_credential: Vec<u8>,
    current_credential: Vec<u8>,
}
impl PolicyRenewalRequest {
    pub(in crate::enrollment) fn new(
        scope: crate::PolicyRenewalScope,
        original: VerifiedDevice,
        current: VerifiedDevice,
        original_credential: Vec<u8>,
        current_credential: Vec<u8>,
    ) -> Self {
        Self {
            scope,
            original,
            current,
            original_credential,
            current_credential,
        }
    }
    /// Exact original journal and actual acknowledged C/R/P predecessor.
    pub fn scope(&self) -> &crate::PolicyRenewalScope {
        &self.scope
    }
    /// Original signature-verified identity; never a signer or live owner.
    pub fn original_device(&self) -> &VerifiedDevice {
        &self.original
    }
    /// Exact retained current credential/roster, including an adopted real G.
    pub fn current_device(&self) -> &VerifiedDevice {
        &self.current
    }
    /// Exact original signed credential, without re-signing.
    pub fn original_credential(&self) -> &[u8] {
        &self.original_credential
    }
    /// Signed roster that authenticated the original retained identity snapshot.
    pub fn original_roster(&self) -> &[u8] {
        self.original.roster().as_bytes()
    }
    /// Exact currently retained signed credential, without replacement.
    pub fn current_credential(&self) -> &[u8] {
        &self.current_credential
    }
    /// Exact signed current roster already compared against the original journal.
    pub fn current_roster(&self) -> &[u8] {
        self.current.roster().as_bytes()
    }
    /// Combine request identities with independently authenticated policies.
    /// Statement construction still checks their full scope and current target,
    /// credential and roster validity; this helper itself grants no permission.
    pub fn materials<'a>(
        &'a self,
        original: &'a HistoricalSessionPolicy,
        previous: &'a HistoricalSessionPolicy,
        target: &'a VerifiedSessionPolicy,
    ) -> crate::PolicyRenewalMaterials<'a> {
        crate::PolicyRenewalMaterials {
            original,
            previous,
            target,
            original_device: &self.original,
            current_device: &self.current,
        }
    }
}

impl DeviceEnrollment {
    /// Prepare the exact original/current signed identity materials together with
    /// the actual policy-only scope. This is the same read-only admission as
    /// `policy_renewal_scope`, with no fabricated credential operation, issuer
    /// authorization, private signer, runtime lease or durable reservation.
    /// After any admitted error, close and resume this original enrollment.
    pub fn policy_renewal_request(
        &mut self,
        operation: PolicyRenewalId,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<PolicyRenewalRequest, DurableError> {
        let result = self
            .prepare_renewal_request(original_policy)
            .and_then(|prepared| prepared.policy_request(operation, original_policy));
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Derive the exact predecessor scope for an independent policy-only request
    /// from this original enrollment and its actual journal. Retain `operation`
    /// before asking either issuer to approve it. This snapshot does not reserve
    /// a transition or authorize current work; staging and commit still recheck
    /// the exact predecessor and current C/R/Pnext/runtime.
    ///
    /// Metadata remains readable after expiry without a private signer. Pending
    /// credential/policy/roster operations and unacknowledged journal receipts
    /// must be reconciled first. If the actual roster has advanced, refresh the
    /// original enrollment before requesting a scope. Required-witness policy
    /// renewal is not supported by this local-only entry point.
    pub fn policy_renewal_scope(
        &mut self,
        operation: PolicyRenewalId,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<crate::PolicyRenewalScope, DurableError> {
        let result = (|| {
            let mut prepared = self.prepare_renewal_request(original_policy)?;
            prepared.policy_scope(operation, original_policy)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
