// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Carry one explicit original registry admission through the owning enrollment.
use super::*;
use crate::JournalAccountAuthority;
impl EnrollmentIntent {
    fn check_account_authority(
        &self,
        authority: &JournalAccountAuthority,
    ) -> Result<(), DurableError> {
        authority.check_enrollment(
            crate::identity::account_id(&self.root),
            self.description.family,
        )
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Check the selected registry and approved intent before creating the
    /// original registration record. A later error can still follow I/O (for
    /// example, concurrent registry closure); reconcile the same original intent.
    pub async fn provision_with_account_authority(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        authority: JournalAccountAuthority,
    ) -> Result<Self, DurableError> {
        intent.check_account_authority(&authority)?;
        Self::provision(paths, intent)
            .await?
            .with_account_authority(authority)
    }
    /// Check the original registry/intent before opening the existing record.
    /// This never provisions on absence or replaces the original enrollment.
    pub async fn open_with_account_authority(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        authority: JournalAccountAuthority,
    ) -> Result<Self, DurableError> {
        intent.check_account_authority(&authority)?;
        Self::open(paths, intent)
            .await?
            .with_account_authority(authority)
    }
    pub(super) async fn authorize_journal_commit(
        &self,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        client: &AnchorClient,
    ) -> Result<(), DurableError> {
        self.check_witness_client(Some(client))?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        crate::DeviceJournal::check_original_account_authority(
            &db,
            &self.key().await?,
            original,
            identity,
            self.account_authority.as_ref(),
            client,
        )
    }
    pub(super) async fn check_original_witness_selection(
        &self,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        client: &AnchorClient,
    ) -> Result<(), DurableError> {
        self.check_witness_client(Some(client))?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        crate::DeviceJournal::check_original_witness_selection(
            &db,
            &self.key().await?,
            original,
            identity,
            client,
        )
    }
    pub(super) async fn open_original_journal(
        &self,
        original: &VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        identity: JournalIdentity,
        client: AnchorClient,
    ) -> Result<crate::DeviceJournal, DurableError> {
        self.check_witness_client(Some(&client))?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        crate::DeviceJournal::open_anchored_database_admitted(
            db,
            self.key().await?,
            original,
            policy,
            identity,
            client,
            crate::durable::AccountAuthorityOpen::Existing(self.account_authority.clone()),
        )
        .await
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
        self.select_account_authority(authority)?;
        Ok(self)
    }
    /// Select the original registry after the first device's request has been
    /// issued and its real account associated. Known admission failures leave the
    /// prior selection unchanged. This performs no I/O and grants no operational
    /// authority before activation checks and binds the same descriptor.
    pub fn select_account_authority(
        &mut self,
        authority: JournalAccountAuthority,
    ) -> Result<(), DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        self.intent.check_account_authority(&authority)?;
        if self
            .account_authority
            .as_ref()
            .is_some_and(|old| !old.same_scope(&authority))
        {
            return Err(DurableError::Conflict);
        }
        self.account_authority = Some(authority);
        Ok(())
    }
    pub(super) async fn reconcile_installation(
        &self,
        original: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        anchor: Option<AnchorClient>,
    ) -> Result<DeviceService, DurableError> {
        self.check_witness_client(anchor.as_ref())?;
        DeviceInstallation::reconcile_original_enrollment_with_storage(
            self.storage.clone(),
            self.paths.installation.clone(),
            self.key().await?,
            original,
            policy,
            crate::installation::InstallationAdmission {
                anchor,
                account: self.account_authority.clone(),
            },
        )
        .await
    }
}
