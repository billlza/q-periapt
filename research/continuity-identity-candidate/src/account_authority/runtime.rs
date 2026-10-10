// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    RwLock,
};

struct Entry {
    checkpoint: AccountAuthorityCheckpoint,
    enabled: AtomicBool,
}
pub(super) struct Runtime {
    binding: [u8; 32],
    open: AtomicBool,
    entries: RwLock<BTreeMap<ApplicationAccountId, Arc<Entry>>>,
}
impl Runtime {
    pub(super) fn new(binding: [u8; 32]) -> Self {
        Self {
            binding,
            open: AtomicBool::new(true),
            entries: RwLock::new(BTreeMap::new()),
        }
    }
    pub(super) fn close(&self) {
        self.open.store(false, Ordering::Release);
    }
    pub(super) fn invalidate(&self, application: ApplicationAccountId) -> Result<(), DurableError> {
        let entries = self.entries.read().map_err(|_| DurableError::Closed)?;
        if let Some(entry) = entries.get(&application) {
            entry.enabled.store(false, Ordering::Release);
        }
        Ok(())
    }
    pub(super) fn publish(
        &self,
        current: &BTreeMap<ApplicationAccountId, Current>,
    ) -> Result<(), DurableError> {
        let mut entries = self.entries.write().map_err(|_| DurableError::Closed)?;
        let mut next = BTreeMap::new();
        for (application, selected) in current {
            let entry = match entries.get(application) {
                Some(previous)
                    if !selected.pending
                        && previous.checkpoint == selected.checkpoint
                        && previous.enabled.load(Ordering::Acquire) =>
                {
                    Arc::clone(previous)
                }
                _ => Arc::new(Entry {
                    checkpoint: selected.checkpoint,
                    enabled: AtomicBool::new(!selected.pending),
                }),
            };
            next.insert(*application, entry);
        }
        *entries = next;
        Ok(())
    }
}

/// Read access tied to one live original authority-store owner.
/// It cannot persist or choose a successor, and does not keep a dropped database owner alive.
#[derive(Clone)]
pub struct AccountAuthorityAccess(pub(super) Arc<Runtime>);
impl AccountAuthorityAccess {
    /// Original key/path/identity-bound registry scope for a managed installation.
    pub fn binding(&self) -> [u8; 32] {
        self.0.binding
    }
    /// Observe the current mapping; pending replacement is explicitly suspended.
    pub fn current(
        &self,
        application: ApplicationAccountId,
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        if !self.0.open.load(Ordering::Acquire) {
            return Err(DurableError::Closed);
        }
        let entry = self
            .0
            .entries
            .read()
            .map_err(|_| DurableError::Closed)?
            .get(&application)
            .cloned()
            .ok_or(DurableError::Absent)?;
        let lease = AccountAuthorityLease {
            runtime: Arc::clone(&self.0),
            entry,
        };
        lease.check()?;
        Ok(lease.checkpoint())
    }
    /// Admit an exact original mapping. Recheck the returned lease at operational release.
    pub fn admit(
        &self,
        expected: AccountAuthorityCheckpoint,
    ) -> Result<AccountAuthorityLease, DurableError> {
        if !self.0.open.load(Ordering::Acquire) {
            return Err(DurableError::Closed);
        }
        let entry = self
            .0
            .entries
            .read()
            .map_err(|_| DurableError::Closed)?
            .get(&expected.application)
            .cloned()
            .ok_or(DurableError::Absent)?;
        if entry.checkpoint != expected {
            return Err(DurableError::Conflict);
        }
        let lease = AccountAuthorityLease {
            runtime: Arc::clone(&self.0),
            entry,
        };
        lease.check()?;
        Ok(lease)
    }
    /// Find an already associated cryptographic account. Absence never permits implicit first use.
    pub fn admit_account(&self, account: [u8; 32]) -> Result<AccountAuthorityLease, DurableError> {
        if !self.0.open.load(Ordering::Acquire) {
            return Err(DurableError::Closed);
        }
        let entry = self
            .0
            .entries
            .read()
            .map_err(|_| DurableError::Closed)?
            .values()
            .find(|e| e.checkpoint.account == account)
            .cloned()
            .ok_or(DurableError::Absent)?;
        let lease = AccountAuthorityLease {
            runtime: Arc::clone(&self.0),
            entry,
        };
        lease.check()?;
        Ok(lease)
    }
}

/// Revocable authority admission, not a key, verified device or session owner.
/// An unrelated application's update preserves this lease; changing this entry
/// or closing the original parent makes subsequent release checks fail.
pub struct AccountAuthorityLease {
    runtime: Arc<Runtime>,
    entry: Arc<Entry>,
}
impl AccountAuthorityLease {
    /// Exact originally admitted public mapping; observing it does not revalidate it.
    pub fn checkpoint(&self) -> AccountAuthorityCheckpoint {
        self.entry.checkpoint
    }
    /// Recheck immediately before releasing an operational result after I/O.
    pub fn check(&self) -> Result<(), DurableError> {
        if !self.runtime.open.load(Ordering::Acquire) {
            return Err(DurableError::Closed);
        }
        if !self.entry.enabled.load(Ordering::Acquire) {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
}
