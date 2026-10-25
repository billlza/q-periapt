// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Check retained registry scope before a new control-plane commit is dispatched.
use super::*;
impl DeviceJournal {
    pub(crate) fn check_original_account_authority(
        db: &Database,
        key: &JournalKey,
        original: &crate::VerifiedDevice,
        identity: JournalIdentity,
        authority: Option<&JournalAccountAuthority>,
        client: &crate::AnchorClient,
    ) -> Result<(), DurableError> {
        let (image, pending) = load_snapshot_as_with_client(
            db,
            key,
            bootstrap::storage_owner(original),
            SnapshotAdmission::AuthorityCheck,
            Some(client),
        )?;
        if image.id != *identity.as_bytes() || image.local_account != original.account_id() {
            return Err(DurableError::Conflict);
        }
        super::super::account_authority::admit_reopen(&image, pending.as_ref(), key, authority)
    }

    // Historical status/close/ACK need the selected witness but must not be
    // mistaken for current account permission. This also admits cancellation
    // records without inventing a sealed write target.
    pub(crate) fn check_original_witness_selection(
        db: &Database,
        key: &JournalKey,
        original: &crate::VerifiedDevice,
        identity: JournalIdentity,
        client: &crate::AnchorClient,
    ) -> Result<(), DurableError> {
        let (image, _) = load_pending_snapshot_with_client(
            db,
            key,
            bootstrap::storage_owner(original),
            SnapshotAdmission::AuthorityCheck,
            Some(client),
        )?;
        let Protection::Required { witness, .. } = image.protection else {
            return Err(DurableError::AnchorRequired);
        };
        if image.id != *identity.as_bytes()
            || image.local_account != original.account_id()
            || witness != client.pin().binding()
        {
            return Err(DurableError::Conflict);
        }
        client.check_device(original)?;
        Ok(())
    }
}
