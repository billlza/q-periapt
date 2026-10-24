// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Privileged exact completion; ordinary expiry admission remains unchanged.
use super::*;
use crate::AnchorPendingWriteRecoveryProposal;

impl AnchorStore {
    /// Complete only this independently approved original ordinary write after
    /// its current witness authority has expired. This privileged control-plane
    /// method must not be exposed through the ordinary device request handler.
    /// Authenticate the account and intended effect independently of the old
    /// device, then persist the exact proposal and full metadata before invoking.
    /// The device signature proves request origin, never independent approval or
    /// creation before expiry. Compromised-device recovery has separate assumptions.
    ///
    /// No validity, credential, policy, roster, fence or operation identity is
    /// replaced. Exact already-applied retries confirm the current target; they
    /// do not say which invocation committed it. On missing results, retain these
    /// same inputs and reconcile. The original enrollment subsequently confirms
    /// the exact head and original command through a fresh signed query (or its
    /// existing AlreadyAppliedExact path); no live Runtime is granted here.
    pub fn complete_pending_write_recovery(
        &mut self,
        independently_approved: &AnchorPendingWriteRecoveryProposal,
        signed_request: &[u8],
        recorded_metadata: &[u8],
        now: u64,
    ) -> Result<AnchorHead, DurableError> {
        if signed_request.len()
            != 4 + AnchorPendingWriteRecoveryProposal::ENCODED_BYTES
                + crate::crypto::SIGNATURE_BYTES
        {
            return Err(Error::Encoding.into());
        }
        let (body, signature) = open_envelope(signed_request)?;
        let submitted = AnchorPendingWriteRecoveryProposal::from_trusted_state(body)?;
        if &submitted != independently_approved {
            return Err(Error::Authentication.into());
        }
        submitted.check_metadata(recorded_metadata)?;
        let scope = &submitted.scope;
        let pin = self.pin()?;
        if scope.witness != pin.binding {
            return Err(Error::Scope.into());
        }
        let mut image = self.image()?;
        image.require_live(scope.subject)?;
        let entry = image
            .entries
            .get_mut(&scope.subject.id(&self.namespace()?))
            .ok_or(DurableError::Absent)?;
        let policy = entry
            .independent_policy
            .as_ref()
            .and_then(|p| p.current)
            .or(entry.policy_authorization);
        if entry.subject != scope.subject
            || entry.authority != scope.authority
            || policy.map_or(entry.subject.policy, |p| p.checkpoint.digest()) != scope.policy
            || policy.map(|p| p.statement) != scope.policy_authorization
        {
            return Err(DurableError::Conflict);
        }
        entry
            .device
            .verify(Purpose::PendingWriteRecovery, body, signature)?;
        if entry.renewal.is_some()
            || entry
                .independent_roster
                .as_ref()
                .is_some_and(RosterRefresh::pending)
            || entry
                .independent_policy
                .as_ref()
                .is_some_and(PolicyRenewal::pending)
        {
            return Err(DurableError::Suspended);
        }
        let operation = AnchorOperation::advance(scope.expected, scope.target.digest())?;
        let command = command_id(&pin.binding, scope.subject, operation);
        if entry.head == scope.target && entry.last == Some(command) {
            return Ok(scope.target);
        }
        if entry.head != scope.expected {
            return Err(DurableError::Conflict);
        }
        match entry.validity.check(now) {
            Err(Error::Validity) if now > entry.validity.until() => {}
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Error::Scope.into()),
        }
        entry.head = scope.target;
        entry.last = Some(command);
        self.persist(&mut image)?;
        Ok(scope.target)
    }
}
