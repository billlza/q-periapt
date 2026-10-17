// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Logical removal of an acknowledged original device signer's sealed seed.
use super::*;
use crate::{AnchorRetiredReportAcknowledgement, AnchorRetiredReportProposal, VerifiedDevice};
#[cfg(any(unix, windows))]
use q_periapt_host_store::filesystem::{LockedFileBackend, OwnedPrivateDirectory};
#[cfg(any(unix, windows))]
use redb::StorageBackend;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(any(unix, windows))]
const TAG: &[u8; 8] = b"QPSRET01";
#[cfg(any(unix, windows))]
const ORIGINAL: &[u8; 8] = b"QPSIGN01";

// Unix device/inode and Windows volume/index have distinct persistent domains.
// QPSRPL02 belongs to browser record identities; never reinterpret another domain.
#[cfg(not(windows))]
const PLAN_TAG: &[u8; 8] = b"QPSRPL01";
#[cfg(windows)]
const PLAN_TAG: &[u8; 8] = b"QPSRPL03";

#[cfg(all(test, any(unix, windows)))]
mod faults;
#[cfg(all(test, any(unix, windows)))]
use faults::test_boundary;
#[cfg(all(test, any(unix, windows)))]
pub(crate) use faults::{inject, IoFault, IoStage};
#[cfg(all(test, any(unix, windows)))]
mod tests;

/// Only a MAC-authenticated original enrollment may restore this plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SigningFilePlan {
    identity: SigningKeyId,
    device: u64,
    inode: u64,
    digest: [u8; 32],
    report: AnchorRetiredReportProposal,
}
impl SigningFilePlan {
    pub(crate) fn identity(&self) -> SigningKeyId {
        self.identity
    }
    pub(crate) fn report(&self) -> &AnchorRetiredReportProposal {
        &self.report
    }
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(PLAN_TAG);
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.device.to_be_bytes());
        out.extend_from_slice(&self.inode.to_be_bytes());
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.report.to_bytes());
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        if d.array::<8>()? != *PLAN_TAG {
            return Err(Error::Encoding);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let device = d.u64()?;
        let inode = d.u64()?;
        #[cfg(not(windows))]
        if inode == 0 {
            return Err(Error::Scope);
        }
        #[cfg(windows)]
        if u32::try_from(device).is_err() {
            return Err(Error::Scope);
        }
        let digest = d.array()?;
        let report = AnchorRetiredReportProposal::from_trusted_state(d.take(353)?)?;
        Ok(Self {
            identity,
            device,
            inode,
            digest,
            report,
        })
    }
    fn check_ack(
        &self,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<(), DurableError> {
        if &self.report != ack.proposal()
            || self.report.inventory().subject().journal_parts().1
                != crate::bootstrap::storage_owner(original)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn capture(
        _store: &crate::storage::Storage,
        path: &Path,
        key: &JournalKey,
        identity: SigningKeyId,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<Self, DurableError> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (path, key, identity, original, ack);
            Err(DurableError::PrivateFile)
        }
        #[cfg(any(unix, windows))]
        {
            let file = Admitted::open(path)?;
            check_file(&file.file, FILE_BYTES)?;
            let mut wire = vec![0; FILE_BYTES];
            file.backend.read(0, &mut wire)?;
            if unseal(key, identity, 2, &wire)?.public != original.key {
                return Err(DurableError::Conflict);
            }
            let (device, inode) = file_identity(&file.file)?;
            let plan = Self {
                identity,
                device,
                inode,
                digest: crate::crypto::digest(
                    b"Q-PERIAPT-CONTINUITY-RETIRED-SIGNER-FILE/v1",
                    &wire,
                ),
                report: ack.proposal().clone(),
            };
            plan.check_ack(original, ack)?;
            file.file.sync_all()?;
            file.parent
                .sync_entries()
                .map_err(|_| DurableError::PrivateFile)?;
            file.check_name(&plan)?;
            Ok(plan)
        }
    }
    pub(crate) fn erased(
        &self,
        _store: &crate::storage::Storage,
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<bool, DurableError> {
        self.check_ack(original, ack)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (path, key);
            Err(DurableError::PrivateFile)
        }
        #[cfg(any(unix, windows))]
        {
            let file = Admitted::open(path)?;
            let erased = self.inspect(&file, key, original)?;
            // A recovered terminal is not durable evidence until its exact file is synced.
            if erased {
                file.file.sync_all()?;
                file.parent
                    .sync_entries()
                    .map_err(|_| DurableError::PrivateFile)?;
            }
            file.check_name(self)?;
            Ok(erased)
        }
    }
    pub(crate) fn erase(
        &self,
        _store: &crate::storage::Storage,
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<(), DurableError> {
        self.check_ack(original, ack)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (path, key);
            Err(DurableError::PrivateFile)
        }
        #[cfg(any(unix, windows))]
        {
            let file = Admitted::open(path)?;
            if !self.inspect(&file, key, original)? {
                #[cfg(test)]
                test_boundary(IoStage::HeaderWrite, false, &file)?;
                file.backend.write(0, TAG)?;
                #[cfg(test)]
                test_boundary(IoStage::HeaderWrite, true, &file)?;
                #[cfg(test)]
                test_boundary(IoStage::HeaderSync, false, &file)?;
                file.file.sync_all()?;
                #[cfg(test)]
                test_boundary(IoStage::HeaderSync, true, &file)?;
                #[cfg(test)]
                test_boundary(IoStage::Truncate, false, &file)?;
                file.backend.set_len(8)?;
                #[cfg(test)]
                test_boundary(IoStage::Truncate, true, &file)?;
            }
            #[cfg(test)]
            test_boundary(IoStage::TerminalSync, false, &file)?;
            file.file.sync_all()?;
            #[cfg(test)]
            test_boundary(IoStage::TerminalSync, true, &file)?;
            #[cfg(test)]
            test_boundary(IoStage::DirectorySync, false, &file)?;
            file.parent
                .sync_entries()
                .map_err(|_| DurableError::PrivateFile)?;
            #[cfg(test)]
            test_boundary(IoStage::DirectorySync, true, &file)?;
            if !self.inspect(&file, key, original)? {
                return Err(DurableError::Conflict);
            }
            file.check_name(self)?;
            Ok(())
        }
    }
    #[cfg(any(unix, windows))]
    fn inspect(
        &self,
        file: &Admitted,
        key: &JournalKey,
        original: &VerifiedDevice,
    ) -> Result<bool, DurableError> {
        file.check_identity(self)?;
        match file.backend.len()? {
            8 => {
                let mut tag = [0; 8];
                file.backend.read(0, &mut tag)?;
                if tag != *TAG {
                    return Err(DurableError::Corrupt);
                }
                Ok(true)
            }
            size if size == FILE_BYTES as u64 => {
                let mut wire = vec![0; FILE_BYTES];
                file.backend.read(0, &mut wire)?;
                let header = wire.get_mut(..8).ok_or(DurableError::Corrupt)?;
                // Only these public header bytes may have been overwritten. Restoring
                // the original tag in memory must reproduce the exact original file,
                // including its authenticated ciphertext and device-role identity.
                if header
                    .iter()
                    .zip(ORIGINAL.iter().zip(TAG.iter()))
                    .any(|(b, (old, new))| b != old && b != new)
                {
                    return Err(DurableError::Corrupt);
                }
                header.copy_from_slice(ORIGINAL);
                if crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-RETIRED-SIGNER-FILE/v1", &wire)
                    != self.digest
                {
                    return Err(DurableError::Conflict);
                }
                if unseal(key, self.identity, 2, &wire)?.public != original.key {
                    return Err(DurableError::Conflict);
                }
                Ok(false)
            }
            _ => Err(DurableError::Corrupt),
        }
    }
}
#[cfg(any(unix, windows))]
struct Admitted {
    file: File,
    backend: LockedFileBackend,
    parent: OwnedPrivateDirectory,
    leaf: std::ffi::OsString,
}
#[cfg(any(unix, windows))]
impl Admitted {
    fn open(path: &Path) -> Result<Self, DurableError> {
        let (parent, leaf) = open_private_parent(path).map_err(|_| DurableError::PrivateFile)?;
        let file = parent
            .open_state_file(leaf)
            .map_err(|_| DurableError::PrivateFile)?;
        let backend = LockedFileBackend::new(file.try_clone()?).map_err(crate::durable::storage)?;
        file_identity(&file)?;
        Ok(Self {
            file,
            backend,
            parent,
            leaf: leaf.to_owned(),
        })
    }
    fn check_identity(&self, plan: &SigningFilePlan) -> Result<(), DurableError> {
        if file_identity(&self.file)? != (plan.device, plan.inode) {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn check_name(&self, plan: &SigningFilePlan) -> Result<(), DurableError> {
        self.check_identity(plan)?;
        let current = self
            .parent
            .open_state_file(&self.leaf)
            .map_err(|_| DurableError::PrivateFile)?;
        if file_identity(&current)? != (plan.device, plan.inode) {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64), DurableError> {
    let metadata = file.metadata()?;
    if metadata.nlink() != 1 {
        return Err(DurableError::PrivateFile);
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<(u64, u64), DurableError> {
    let id = q_periapt_host_store::filesystem::private_file_identity(file)
        .map_err(|_| DurableError::PrivateFile)?;
    Ok((u64::from(id.volume_serial()), id.file_index()))
}
