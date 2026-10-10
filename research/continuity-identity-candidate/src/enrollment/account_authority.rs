// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Carry one explicit original registry admission through the owning enrollment.
use super::*;
use crate::JournalAccountAuthority;
impl DeviceEnrollment {
    pub(super) fn authorize_journal_commit(
        &self,
        original: &VerifiedDevice,
        identity: JournalIdentity,
    ) -> Result<(), DurableError> {
        crate::DeviceJournal::check_original_account_authority(
            self.paths.installation.files()[1],
            self.key()?,
            original,
            identity,
            self.account_authority.as_ref(),
        )
    }
    pub(super) fn open_original_journal(
        &self,
        original: &VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        identity: JournalIdentity,
        client: AnchorClient,
    ) -> Result<crate::DeviceJournal, DurableError> {
        crate::DeviceJournal::open_anchored_admitted(
            self.paths.installation.files()[1],
            self.key()?,
            original,
            policy,
            identity,
            client,
            crate::durable::AccountAuthorityOpen::Existing(self.account_authority.clone()),
        )
    }
    /// Supply the independently retained application/registry descriptor for this
    /// original enrollment. Activation durably binds an unbound witnessed journal
    /// before returning an owner, or reconciles that same pending/committed binding.
    /// Reopen must supply this descriptor again; absence never means a new registry.
    /// This does not register a root or replace the enrollment's original identity.
    pub fn with_account_authority(
        mut self,
        authority: JournalAccountAuthority,
    ) -> Result<Self, DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        authority.check_enrollment(
            crate::identity::account_id(&self.intent.root),
            self.intent.description.family,
        )?;
        if self
            .account_authority
            .as_ref()
            .is_some_and(|old| !old.same_scope(&authority))
        {
            return Err(DurableError::Conflict);
        }
        self.account_authority = Some(authority);
        Ok(self)
    }
    pub(super) fn reconcile_installation(
        &self,
        original: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        anchor: Option<AnchorClient>,
    ) -> Result<DeviceService, DurableError> {
        DeviceInstallation::reconcile_original_enrollment(
            self.paths.installation.clone(),
            self.key()?,
            original,
            policy,
            crate::installation::InstallationAdmission {
                anchor,
                account: self.account_authority.clone(),
            },
        )
    }
}
