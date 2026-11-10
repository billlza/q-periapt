// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Keep next-attempt recovery out of the original foreign-caller admission frame.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    #[inline(never)]
    pub(super) async fn admit_transferred_next(
        &self,
        enrollment: DeviceEnrollment,
        transition: &crate::TransferredAccountRootJournalTransition,
    ) -> Result<Original, DurableError> {
        Ok(Original::Fenced(
            AccountRootEnrollmentRecovery::prepare_transferred_transition(enrollment, transition)
                .await?,
        ))
    }
}
