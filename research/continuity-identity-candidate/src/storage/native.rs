// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{DeviceSigningKey, DurableError, JournalKey, SigningKeyId};
use redb::Database;
use std::path::Path;
#[derive(Clone)]
pub(crate) struct Storage;
impl Storage {
    pub(crate) fn native() -> Result<Self, DurableError> {
        Ok(Self)
    }
    pub(crate) fn missing(&self, path: &Path) -> Result<bool, DurableError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
    pub(crate) fn open_key(&self, path: &Path) -> Result<JournalKey, DurableError> {
        JournalKey::open(path)
    }
    pub(crate) fn open_signer(
        &self,
        path: &Path,
        key: &JournalKey,
        id: SigningKeyId,
    ) -> Result<DeviceSigningKey, DurableError> {
        DeviceSigningKey::open(path, key, id)
    }
    pub(crate) fn provision_signer(
        &self,
        path: &Path,
        key: &JournalKey,
        id: SigningKeyId,
    ) -> Result<DeviceSigningKey, DurableError> {
        DeviceSigningKey::provision(path, key, id)
    }
    pub(crate) fn open_database(&self, path: &Path) -> Result<Database, DurableError> {
        q_periapt_host_store::filesystem::open_private_database(path).map_err(Into::into)
    }
    pub(crate) fn provision_database(
        &self,
        path: &Path,
        initialize: impl FnOnce(&Database) -> Result<(), DurableError>,
    ) -> Result<Database, DurableError> {
        q_periapt_host_store::filesystem::provision_private_database(path, initialize)
    }
}
