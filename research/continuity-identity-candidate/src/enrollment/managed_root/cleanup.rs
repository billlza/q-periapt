// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Historical cleanup while the same controller continues to own successor authority.
use super::*;
use crate::RetiredDeviceEnrollment;

impl ManagedAccountRootReplacement {
    /// Borrow the original restricted cleanup owner for a reporting/ACK/erasure step.
    /// Requires a committed original registry decision and retained parent retirement.
    /// The controller retains the registry throughout; successful old-signer erasure
    /// reopens only the same historical parent and cannot revoke the successor by itself.
    ///
    /// Use the existing `RetiredDeviceEnrollment` installation/report/host-ACK sequence.
    /// This callback does not make external host effects atomic or infer their outcome.
    /// A callback/storage error or unwind closes this controller and revokes its
    /// delegated owners. Panics propagate unchanged;
    /// reopen the original registry/operation after an unknown result. Missing originals
    /// fail. No enrollment, key, root or report identity is regenerated.
    pub fn with_retired_cleanup<T>(
        &mut self,
        action: impl FnOnce(&mut RetiredDeviceEnrollment) -> Result<T, DurableError>,
    ) -> Result<T, DurableError> {
        if self.active.as_ref().ok_or(DurableError::Closed)?.state()? != State::Committed {
            return Err(DurableError::Suspended);
        }
        self.run(|owners| {
            let proposal = owners
                .registry
                .replacement(owners.operation.id())?
                .2
                .clone();
            owners.start_cleanup(&proposal)?;
            #[cfg(all(test, unix))]
            account_root::managed_boundary("cleanup-parent");
            let result = action(owners.cleanup()?)?;
            #[cfg(all(test, unix))]
            if owners.cleanup()?.is_closed() {
                account_root::managed_boundary("cleanup-owner-closed");
            }
            owners.finish_cleanup_step(&proposal)?;
            #[cfg(all(test, unix))]
            account_root::managed_boundary("cleanup-return");
            Ok(result)
        })
    }
}
