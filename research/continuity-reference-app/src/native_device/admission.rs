// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::IssuedCredentialExtension;

impl NativeDevice {
    pub(super) fn monotonic(
        next: sdk::RosterCheckpoint,
        previous: sdk::RosterCheckpoint,
    ) -> Result<()> {
        if next.version() < previous.version()
            || (next.version() == previous.version() && next != previous)
        {
            return Err("Current roster rolled back or forked".into());
        }
        Ok(())
    }
    pub(super) fn pin(&self, current: &RootInfo) -> Result<sdk::AccountPin> {
        if current.public_key != self.invitation.root
            || current.revision != self.invitation.root_revision
            || current.family != self.invitation.family
        {
            return Err(
                "Current root differs from independently retained enrollment authority".into(),
            );
        }
        let roster = current
            .roster
            .as_ref()
            .ok_or("Current signed roster is required")?;
        Ok(sdk::AccountPin::new(
            current.account,
            sdk::PublicKey::decode(&current.public_key)?,
            roster.checkpoint.as_sdk()?,
            current.family,
        )?)
    }
    pub fn accept(
        &mut self,
        issued: &IssuedEnrollment,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<[u8; 32]> {
        let result = self.accept_attempt(issued, current, policy, now);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn accept_attempt(
        &mut self,
        issued: &IssuedEnrollment,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<[u8; 32]> {
        if issued.operation != self.invitation.operation
            || issued.root_revision != self.invitation.root_revision
        {
            return Err("Issuance differs from the selected host invitation".into());
        }
        let pin = self.pin(current)?;
        let roster = current
            .roster
            .as_ref()
            .ok_or("Current signed roster is required")?;
        Self::monotonic(roster.checkpoint.as_sdk()?, issued.checkpoint.as_sdk()?)?;
        // Historical issuer metadata is checked for signature/consistency only.
        // It never selects current authority: the separately supplied current pin
        // must independently authorize the same certificate at actual time.
        let historical = sdk::AccountPin::new(
            current.account,
            sdk::PublicKey::decode(&self.invitation.root)?,
            issued.checkpoint.as_sdk()?,
            self.invitation.family,
        )?
        .verify_historical_device(&issued.certificate, &issued.roster)?;
        let live = pin.verify_device(&issued.certificate, &roster.bytes, now)?;
        if historical.credential_digest() != live.credential_digest() {
            return Err("Issuance identity differs".into());
        }
        Ok(*self
            .owner
            .accept(&issued.certificate, &roster.bytes, &pin, policy, now)?
            .as_bytes())
    }
    pub fn extend(
        &mut self,
        approval: &CredentialExtensionRequest,
        issued: &IssuedCredentialExtension,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<[u8; 32]> {
        let result = self.extend_attempt(approval, issued, current, policy, now);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn extend_attempt(
        &mut self,
        approval: &CredentialExtensionRequest,
        issued: &IssuedCredentialExtension,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<[u8; 32]> {
        if approval.enrollment != self.invitation.operation
            || issued.request != *approval
            || issued.root_revision != self.invitation.root_revision
        {
            return Err("Extension differs from the independently retained approval".into());
        }
        let pin = self.pin(current)?;
        let roster = current
            .roster
            .as_ref()
            .ok_or("Current signed roster is required")?;
        let trusted = sdk::EnrollmentExtensionApproval::from_trusted_state(
            approval.request_id,
            approval.previous_extension,
            approval.predecessor.as_sdk()?,
            approval.valid_until,
        )?;
        Ok(*self
            .owner
            .adopt_credential_extension(
                sdk::EnrollmentExtensionInputs {
                    approval: &trusted,
                    certificate: &issued.certificate,
                    issued_roster: &issued.roster,
                    issued_checkpoint: issued.checkpoint.as_sdk()?,
                    current_roster: &roster.bytes,
                },
                &pin,
                policy,
                now,
            )?
            .as_bytes())
    }
}
