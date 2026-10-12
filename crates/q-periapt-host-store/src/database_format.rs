// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared redb recovery-format rule, independent of a platform's file admission.
//!
//! Callers must separately establish their storage lease, extent and ownership.
//! This only excludes recovery of an unclean image written without two-phase
//! commit. It neither authenticates records nor admits a storage platform.

pub(crate) fn refuse_unclean_foreign_redb(
    backend: &impl redb::StorageBackend,
) -> std::io::Result<()> {
    const GOD_BYTE_OFFSET: u64 = 9;
    const RECOVERY_REQUIRED: u8 = 2;
    const TWO_PHASE_COMMIT: u8 = 4;

    if backend.len()? <= GOD_BYTE_OFFSET {
        return Ok(()); // The complete redb parser rejects truncated headers.
    }
    let mut header = [0u8; 1];
    backend.read(GOD_BYTE_OFFSET, &mut header)?;
    let [god] = header;
    if god & RECOVERY_REQUIRED != 0 && god & TWO_PHASE_COMMIT == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unclean redb image was not committed in two phases",
        ));
    }
    Ok(())
}
