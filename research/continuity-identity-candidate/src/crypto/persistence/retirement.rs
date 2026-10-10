// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Logical removal of an acknowledged original device signer's sealed seed.
use super::*;
use crate::{AnchorRetiredReportAcknowledgement, AnchorRetiredReportProposal, VerifiedDevice};
#[cfg(unix)]
use q_periapt_host_store::filesystem::{LockedFileBackend, OwnedPrivateDirectory};
#[cfg(unix)]
use redb::StorageBackend;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
const TAG: &[u8; 8] = b"QPSRET01";
#[cfg(unix)]
const ORIGINAL: &[u8; 8] = b"QPSIGN01";

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
        out.extend_from_slice(b"QPSRPL01");
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.device.to_be_bytes());
        out.extend_from_slice(&self.inode.to_be_bytes());
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.report.to_bytes());
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        if d.array::<8>()? != *b"QPSRPL01" {
            return Err(Error::Encoding);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let device = d.u64()?;
        let inode = d.u64()?;
        if inode == 0 {
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
        path: &Path,
        key: &JournalKey,
        identity: SigningKeyId,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<Self, DurableError> {
        #[cfg(not(unix))]
        {
            let _ = (path, key, identity, original, ack);
            Err(DurableError::PrivateFile)
        }
        #[cfg(unix)]
        {
            let file = Admitted::open(path)?;
            check_file(&file.file, FILE_BYTES)?;
            let mut wire = vec![0; FILE_BYTES];
            file.backend.read(0, &mut wire)?;
            if unseal(key, identity, 2, &wire)?.public != original.key {
                return Err(DurableError::Conflict);
            }
            let metadata = file.file.metadata()?;
            let plan = Self {
                identity,
                device: metadata.dev(),
                inode: metadata.ino(),
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
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<bool, DurableError> {
        self.check_ack(original, ack)?;
        #[cfg(not(unix))]
        {
            let _ = (path, key);
            Err(DurableError::PrivateFile)
        }
        #[cfg(unix)]
        {
            let file = Admitted::open(path)?;
            let erased = self.inspect(&file, key, original)?;
            // A recovered terminal is not durable evidence until its exact inode is synced.
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
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<(), DurableError> {
        self.check_ack(original, ack)?;
        #[cfg(not(unix))]
        {
            let _ = (path, key);
            Err(DurableError::PrivateFile)
        }
        #[cfg(unix)]
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
    #[cfg(unix)]
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
#[cfg(unix)]
struct Admitted {
    file: File,
    backend: LockedFileBackend,
    parent: OwnedPrivateDirectory,
    leaf: std::ffi::OsString,
}
#[cfg(unix)]
impl Admitted {
    fn open(path: &Path) -> Result<Self, DurableError> {
        let (parent, leaf) = open_private_parent(path).map_err(|_| DurableError::PrivateFile)?;
        let file = parent
            .open_state_file(leaf)
            .map_err(|_| DurableError::PrivateFile)?;
        let backend = LockedFileBackend::new(file.try_clone()?).map_err(crate::durable::storage)?;
        if file.metadata()?.nlink() != 1 {
            return Err(DurableError::PrivateFile);
        }
        Ok(Self {
            file,
            backend,
            parent,
            leaf: leaf.to_owned(),
        })
    }
    fn check_identity(&self, plan: &SigningFilePlan) -> Result<(), DurableError> {
        let metadata = self.file.metadata()?;
        if metadata.nlink() != 1 || metadata.dev() != plan.device || metadata.ino() != plan.inode {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn check_name(&self, plan: &SigningFilePlan) -> Result<(), DurableError> {
        self.check_identity(plan)?;
        let current = self
            .parent
            .open_state_file(&self.leaf)
            .map_err(|_| DurableError::PrivateFile)?
            .metadata()?;
        if current.dev() != plan.device || current.ino() != plan.inode || current.nlink() != 1 {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoStage {
    HeaderWrite,
    HeaderSync,
    Truncate,
    TerminalSync,
    DirectorySync,
}
#[cfg(all(test, unix))]
#[derive(Clone, Copy)]
pub(crate) enum IoFault {
    Prefix(usize),
    Boundary(IoStage, bool),
}
#[cfg(all(test, unix))]
thread_local! {
    static IO_FAULT: std::cell::RefCell<Option<(IoFault, std::rc::Rc<std::cell::Cell<bool>>)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(all(test, unix))]
pub(crate) struct IoFaultGuard {
    fired: std::rc::Rc<std::cell::Cell<bool>>,
}
#[cfg(all(test, unix))]
impl IoFaultGuard {
    pub(crate) fn fired(&self) -> bool {
        self.fired.get()
    }
}
#[cfg(all(test, unix))]
impl Drop for IoFaultGuard {
    fn drop(&mut self) {
        IO_FAULT.with(|s| {
            s.borrow_mut().take();
        });
    }
}
#[cfg(all(test, unix))]
pub(crate) fn inject(fault: IoFault) -> IoFaultGuard {
    if let IoFault::Prefix(n) = fault {
        assert!(n <= 8);
    }
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    IO_FAULT.with(|s| {
        assert!(s.borrow().is_none());
        *s.borrow_mut() = Some((fault, fired.clone()));
    });
    IoFaultGuard { fired }
}
#[cfg(all(test, unix))]
fn test_boundary(stage: IoStage, after: bool, file: &Admitted) -> Result<(), DurableError> {
    let cut = IO_FAULT.with(|s| {
        let mut slot = s.borrow_mut();
        let matches = slot.as_ref().is_some_and(|(fault, _)| match fault {
            IoFault::Prefix(_) => stage == IoStage::HeaderWrite && !after,
            IoFault::Boundary(at, side) => *at == stage && *side == after,
        });
        if matches {
            slot.take()
        } else {
            None
        }
    });
    if let Some((fault, fired)) = cut {
        fired.set(true);
        if let IoFault::Prefix(n) = fault {
            file.backend
                .write(0, TAG.get(..n).expect("bounded injected prefix"))?;
        }
        return Err(std::io::Error::other("injected original signing-file I/O failure").into());
    }
    if let Some(root) = std::env::var_os("QPERIAPT_SIGNER_CUT_ROOT") {
        let label = format!("{stage:?}-{}", if after { "after" } else { "before" });
        if std::env::var("QPERIAPT_SIGNER_CUT_STAGE").ok().as_deref() == Some(label.as_str()) {
            use std::io::Write;
            let root = Path::new(&root);
            let mut ready =
                std::fs::File::create_new(root.join("signer-ready.pending")).expect("ready marker");
            ready.write_all(label.as_bytes()).expect("stage");
            ready.sync_all().expect("ready durable");
            std::fs::rename(root.join("signer-ready.pending"), root.join("signer-ready"))
                .expect("ready name");
            std::fs::File::open(root)
                .expect("parent")
                .sync_all()
                .expect("ready name durable");
            while !root.join("signer-resume").exists() {
                std::thread::park_timeout(std::time::Duration::from_millis(10));
            }
        }
    }
    Ok(())
}
