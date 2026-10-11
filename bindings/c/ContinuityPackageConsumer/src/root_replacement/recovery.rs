// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One original-storage admission for all managed root recovery variants.
use super::*;

pub(super) struct Recovery {
    pub(super) paths: p::EnrollmentPaths,
    pub(super) intent: p::EnrollmentIntent,
    pub(super) scope: Approval,
}
impl Recovery {
    pub(super) unsafe fn read(
        path: *const u8,
        length: usize,
        intent: *const enrollment::Intent,
        scope: *const Scope,
    ) -> Result<Self> {
        let path = unsafe { text(path, length, 4096) }?;
        Ok(Self {
            paths: enrollment::paths(Path::new(&path))?,
            intent: unsafe { enrollment::Approved::read(intent) }?.into_native(),
            scope: unsafe { Approval::read(scope) }?,
        })
    }
    pub(super) fn resume(
        self,
        registry: u64,
        deadline: Instant,
        action: impl FnOnce(p::AccountAuthorityStore, Self) -> Result<p::ManagedAccountRootReplacement>,
    ) -> Result<()> {
        with_entry(registry, deadline, |slot, entry| {
            opening::check(&entry.cancel, deadline)?;
            let store = take_registry(slot)?;
            let access = store.access()?;
            let pin = self.scope.pin.clone();
            let native = action(store, self)?;
            let owner = Box::new(Owner {
                native,
                pin,
                access,
                report: None,
            });
            opening::check(&entry.cancel, deadline)?;
            *slot = Some(Owned::RootReplacement(owner));
            Ok(())
        })
    }
}
