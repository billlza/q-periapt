// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Check retained registry scope before a new control-plane commit is dispatched.
use super::*;
impl DeviceJournal {
    pub(crate) fn check_original_account_authority(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        identity: JournalIdentity,
        authority: Option<&JournalAccountAuthority>,
    ) -> Result<(), DurableError> {
        let db = open_private_database(path)?;
        let (image, pending) = load_snapshot_as(
            &db,
            &key,
            bootstrap::storage_owner(original),
            SnapshotAdmission::AuthorityCheck,
        )?;
        if image.id != *identity.as_bytes() || image.local_account != original.account_id() {
            return Err(DurableError::Conflict);
        }
        super::super::account_authority::admit_reopen(&image, pending.as_ref(), &key, authority)
    }
}
