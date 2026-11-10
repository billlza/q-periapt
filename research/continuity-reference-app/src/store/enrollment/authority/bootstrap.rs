// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initial publication only; Ready always opens the original native registry and key.
use super::*;
use std::{io::ErrorKind, path::PathBuf};

fn unavailable(context: &'static str, error: impl std::fmt::Display) -> Error {
    eprintln!("{context}: {error}");
    Error::AuthorityUnavailable
}
fn exists(path: &std::path::Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(unavailable("inspect original authority file", e)),
    }
}
impl Store {
    fn authority_paths(&self, record: &AssociationRecord) -> Result<(PathBuf, PathBuf), Error> {
        let parent = self.path.parent().ok_or(Error::Internal)?;
        let stem = URL_SAFE_NO_PAD.encode(record.registry);
        Ok((
            parent.join(format!("authority-{stem}.wrap")),
            parent.join(format!("authority-{stem}.redb")),
        ))
    }
    pub(super) fn open_authority_registry(
        &self,
        record: &AssociationRecord,
        pin: &sdk::AnchorPin,
    ) -> Result<sdk::AccountAuthorityStore, Error> {
        let (wrap, registry) = self.authority_paths(record)?;
        sdk::AccountAuthorityStore::open(
            &registry,
            sdk::JournalKey::open(&wrap)
                .map_err(|e| unavailable("open original authority wrapping key", e))?,
            sdk::AccountAuthorityIdentity::from_trusted_state(record.registry).map_err(db_error)?,
            self.family()?,
            pin.clone(),
        )
        .map_err(|e| unavailable("open original authority registry", e))
    }
    pub(super) fn prepare_authority_registry(
        &self,
        record: &mut AssociationRecord,
        device: &sdk::VerifiedDevice,
        pin: &sdk::AnchorPin,
    ) -> Result<(), Error> {
        let (wrap, registry) = self.authority_paths(record)?;
        if matches!(record.phase, RegistryPhase::Wrapping) {
            if exists(&registry)? {
                return Err(Error::Conflict(
                    "Authority registry precedes its original wrapping admission",
                ));
            }
            let key = if exists(&wrap)? {
                sdk::JournalKey::open(&wrap)
            } else {
                sdk::JournalKey::provision(&wrap)
            }
            .map_err(|e| unavailable("original authority wrapping key", e))?;
            drop(key);
            #[cfg(test)]
            test_boundary("authority-wrapping-published", &record.registry)?;
            record.phase = RegistryPhase::Registry;
            let tx = transaction(&self.db)?;
            save(&tx, record)?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("authority-registry-prepared", &record.registry)?;
        }
        if matches!(record.phase, RegistryPhase::Registry) {
            let mut owner = if exists(&registry)? {
                self.open_authority_registry(record, pin)?
            } else {
                sdk::AccountAuthorityStore::provision(
                    &registry,
                    sdk::JournalKey::open(&wrap)
                        .map_err(|e| unavailable("reopen original authority wrapping key", e))?,
                    sdk::AccountAuthorityIdentity::from_trusted_state(record.registry)
                        .map_err(db_error)?,
                    self.family()?,
                    pin.clone(),
                )
                .map_err(|e| unavailable("provision original authority registry", e))?
            };
            let application = sdk::ApplicationAccountId::from_trusted_state(record.application)
                .map_err(db_error)?;
            let original = owner.associate(application, device).map_err(db_error)?;
            if original.application() != application
                || original.revision() != 1
                || original.account() != record.request.root.account
            {
                return Err(Error::Internal);
            }
            #[cfg(test)]
            test_boundary("authority-registry-committed", &record.registry)?;
            record.phase = RegistryPhase::Ready;
            let tx = transaction(&self.db)?;
            save(&tx, record)?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("authority-ready-committed", &record.registry)?;
        }
        // Initialization history remains readable, but Ready cannot replace a lost file.
        drop(self.open_authority_registry(record, pin)?);
        Ok(())
    }
}
