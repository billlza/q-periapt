// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{io::ErrorKind, path::PathBuf};

impl Store {
    /// Explicit first-use or recovery of that same prepared root, for a host-authorized account.
    pub fn prepare_enrollment_root(&mut self, account: &Account) -> Result<RootInfo, Error> {
        self.action(|store| {
            store.authorized(account)?;
            let tx = transaction(&store.db)?;
            let original = tx
                .open_table(ROOTS)
                .map_err(db_error)?
                .get(account.application_id.as_slice())
                .map_err(db_error)?
                .map(|v| decode::<Root>(v.value(), MAX_ROOT))
                .transpose()?;
            let mut root = match original {
                Some(root) => {
                    tx.abort().map_err(db_error)?;
                    root
                }
                None => {
                    let root = Root {
                        application: account.application_id,
                        signing_id: random()?,
                        revision: 1,
                        phase: RootPhase::Wrapping,
                        members: Vec::new(),
                        roster: None,
                        authority: None,
                    };
                    save_root(&tx, &root)?;
                    tx.commit().map_err(db_error)?;
                    root
                }
            };
            if root.application != account.application_id
                || root.signing_id == [0; 32]
                || root.revision == 0
            {
                return Err(Error::Internal);
            }
            store.prepare_root_keys(&mut root, |changed| {
                let tx = transaction(&store.db)?;
                save_root(&tx, changed)?;
                tx.commit().map_err(db_error)
            })
        })
    }

    /// Reconcile one retained root signer. Each caller persists the same root's
    /// phase in its own original account transaction; no identity is generated here.
    pub(super) fn prepare_root_keys(
        &self,
        root: &mut Root,
        persist: impl Fn(&Root) -> Result<(), Error>,
    ) -> Result<RootInfo, Error> {
        let (wrap_path, signer_path) = self.root_paths(root)?;
        if matches!(root.phase, RootPhase::Wrapping) {
            // A signer cannot precede the durable wrapping-key admission.
            if exists(&signer_path)? {
                return Err(Error::Conflict("Signer precedes its original preparation"));
            }
            let wrapping = if exists(&wrap_path)? {
                sdk::JournalKey::open(&wrap_path)
            } else {
                sdk::JournalKey::provision(&wrap_path)
            }
            .map_err(|e| Error::issuer_key("original root wrapping key", e))?;
            drop(wrapping);
            #[cfg(test)]
            test_boundary("root-wrapping-published", b"wrapping")?;
            root.phase = RootPhase::Signing;
            persist(root)?;
            #[cfg(test)]
            test_boundary("root-signing-prepared", b"signing")?;
        }
        if matches!(root.phase, RootPhase::Signing) {
            // From this phase onward, a missing wrapping key is an error.
            let wrapping = sdk::JournalKey::open(&wrap_path)
                .map_err(|e| Error::issuer_key("reopen root wrapping key", e))?;
            let identity =
                sdk::SigningKeyId::from_trusted_state(root.signing_id).map_err(db_error)?;
            let signer = if exists(&signer_path)? {
                sdk::RootSigningKey::open(&signer_path, &wrapping, identity)
            } else {
                sdk::RootSigningKey::provision(&signer_path, &wrapping, identity)
            }
            .map_err(|e| Error::issuer_key("original root signing owner", e))?;
            root.phase = RootPhase::Ready {
                public: signer.public_key().map_err(db_error)?.encode(),
                account: signer.account_id().map_err(db_error)?,
                suspended: false,
            };
            #[cfg(test)]
            test_boundary(
                "root-signer-published",
                &signer.public_key().map_err(db_error)?.encode(),
            )?;
            persist(root)?;
            #[cfg(test)]
            test_boundary(
                "root-ready-committed",
                &signer.public_key().map_err(db_error)?.encode(),
            )?;
        }
        // Ready never regenerates a missing key or resets a suspension.
        self.open_signer(root)?;
        root.info(self.family()?)
    }
    /// Current host observation. It grants no traffic permission to an SDK client.
    pub fn enrollment_root(&mut self, account: &Account) -> Result<RootInfo, Error> {
        self.action(|store| {
            store.authorized(account)?;
            store.root(account)?.info(store.family()?)
        })
    }
    /// Fence new and pending enrollment before root replacement. Historical results remain readable.
    /// There is deliberately no implicit unfreeze or successor-root selection.
    pub fn suspend_enrollment_root(&mut self, account: &Account) -> Result<RootInfo, Error> {
        self.action(|store| {
            store.authorized(account)?;
            let mut root = store.root(account)?;
            match &mut root.phase {
                RootPhase::Ready { suspended, .. } => *suspended = true,
                _ => return Err(Error::Conflict("Original root is not ready")),
            }
            let tx = transaction(&store.db)?;
            save_root(&tx, &root)?;
            tx.commit().map_err(db_error)?;
            root.info(store.family()?)
        })
    }
    pub(super) fn root_paths(&self, root: &Root) -> Result<(PathBuf, PathBuf), Error> {
        let parent = self.path.parent().ok_or(Error::Internal)?;
        let stem = URL_SAFE_NO_PAD.encode(root.signing_id);
        Ok((
            parent.join(format!("enrollment-{stem}.wrap")),
            parent.join(format!("enrollment-{stem}.signer")),
        ))
    }
    pub(super) fn open_signer(&self, root: &Root) -> Result<sdk::RootSigningKey, Error> {
        let (wrap_path, signer_path) = self.root_paths(root)?;
        let wrapping = sdk::JournalKey::open(&wrap_path)
            .map_err(|e| Error::issuer_key("open original issuer wrapping key", e))?;
        let signer = sdk::RootSigningKey::open(
            &signer_path,
            &wrapping,
            sdk::SigningKeyId::from_trusted_state(root.signing_id).map_err(db_error)?,
        )
        .map_err(|e| Error::issuer_key("open original issuer signing key", e))?;
        let info = root.info(self.family()?)?;
        if signer.public_key().map_err(db_error)?.encode() != info.public_key
            || signer.account_id().map_err(db_error)? != info.account
        {
            return Err(Error::IssuerUnavailable);
        }
        Ok(signer)
    }
}
fn exists(path: &std::path::Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::issuer_key("inspect original issuer file", e)),
    }
}
