// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Platform-owned installation admission, preserving the original configuration.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceInstallation {
    /// Durably retain a fresh journal ID and exact key/device/policy/path bindings
    /// before any journal creation. Existing child paths cannot be adopted.
    pub async fn provision(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Self, DurableError> {
        Self::provision_inner(
            crate::storage::Storage::native()?,
            paths,
            key,
            device,
            policy,
            now,
            None,
        )
        .await
    }
    pub(crate) async fn provision_with_identity(
        store: crate::storage::Storage,
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        identity: JournalIdentity,
    ) -> Result<Self, DurableError> {
        Self::provision_inner(store, paths, key, device, policy, now, Some(identity)).await
    }
    async fn provision_inner(
        store: crate::storage::Storage,
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        retained_identity: Option<JournalIdentity>,
    ) -> Result<Self, DurableError> {
        admit(device, policy, now)?;
        if !store.missing(&paths.journal).await? || !store.missing(&paths.archives).await? {
            return Err(DurableError::Conflict);
        }
        let identity = match retained_identity {
            Some(identity) => identity,
            None => JournalIdentity::generate()?,
        };
        let key_binding = key.installation_binding();
        let scope = scope(&paths, identity, key_binding, device, policy)?;
        let db = store
            .provision_database(&paths.configuration, |db| {
                let mut row = scope.clone();
                row.push(InstallationStatus::Creating.byte());
                let tx = transaction(db)?;
                tx.open_table(TABLE)
                    .map_err(storage)?
                    .insert("installation", row.as_slice())
                    .map_err(storage)?;
                #[cfg(all(test, unix))]
                tests::at_boundary("intent-before-commit");
                tx.commit().map_err(DurableError::CommitUncertain)?;
                Ok::<_, DurableError>(())
            })
            .await?;
        let mut owner = Self {
            storage: store,
            active: Some(db),
            paths,
            identity,
            key_binding,
            scope,
        };
        if owner.status()? != InstallationStatus::Creating {
            return Err(DurableError::Conflict);
        }
        admit(device, policy, now)?;
        #[cfg(all(test, unix))]
        tests::at_boundary("intent");
        Ok(owner)
    }
    /// Reopen only existing independent configuration and verify every binding.
    /// Missing, corrupt, wrong-key, changed-device/policy/path and busy states fail.
    pub async fn open(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Self, DurableError> {
        Self::open_with_storage(
            crate::storage::Storage::native()?,
            paths,
            key,
            device,
            policy,
            now,
        )
        .await
    }
    pub(crate) async fn open_with_storage(
        store: crate::storage::Storage,
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Self, DurableError> {
        admit(device, policy, now)?;
        Self::open_bound_with_storage(store, paths, key, device, policy).await
    }
    pub(crate) async fn open_bound(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    ) -> Result<Self, DurableError> {
        Self::open_bound_with_storage(
            crate::storage::Storage::native()?,
            paths,
            key,
            device,
            policy,
        )
        .await
    }
    pub(crate) async fn open_bound_with_storage(
        store: crate::storage::Storage,
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    ) -> Result<Self, DurableError> {
        let policy = policy.as_ref();
        let db = store.open_database(&paths.configuration).await?;
        let (identity, saved, _) = read(&db)?;
        let key_binding = key.installation_binding();
        let expected = scope(&paths, identity, key_binding, device, policy)?;
        if saved != expected {
            return Err(DurableError::Conflict);
        }
        Ok(Self {
            storage: store,
            active: Some(db),
            paths,
            identity,
            key_binding,
            scope: expected,
        })
    }
}
