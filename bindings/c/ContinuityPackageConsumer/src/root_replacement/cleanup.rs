// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reuse the restricted retirement API without releasing successor authority.
use super::*;

pub(crate) fn step<T>(
    slot: &mut Option<Owned>,
    entry: &Entry,
    deadline: Instant,
    action: impl FnOnce(&mut retirement::View<'_>) -> Result<T>,
) -> Result<T> {
    opening::check(&entry.cancel, deadline)?;
    let owner = match slot.as_mut() {
        Some(Owned::RootReplacement(owner)) => owner,
        Some(_) => return Err(failure(6)),
        None => return Err(failure(2)),
    };
    // A premature cleanup request is not an admitted callback failure.
    if owner.native.state()? != p::AccountAuthorityReplacementState::Committed {
        return Err(p::DurableError::Suspended.into());
    }
    let Some(Owned::RootReplacement(mut owner)) = slot.take() else {
        return Err(failure(5));
    };
    let mut foreign_error = None;
    let result = owner.native.with_retired_cleanup(|native| {
        match action(&mut retirement::View {
            native,
            pin: &owner.pin,
            report: &mut owner.report,
        }) {
            Ok(value) => Ok(value),
            Err(error) => {
                // Preserve the precise foreign diagnostic while triggering the
                // native controller's close-on-callback-error contract.
                foreign_error = Some(error);
                Err(p::DurableError::Rejected)
            }
        }
    });
    if let Some(error) = foreign_error {
        return Err(error);
    }
    let value = result?;
    opening::check(&entry.cancel, deadline)?;
    // Successful old-signer erasure keeps this same registry/controller alive.
    *slot = Some(Owned::RootReplacement(owner));
    Ok(value)
}
