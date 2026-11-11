// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Nonblocking paired admission with one cancellation token and deadline.
use super::*;
use std::sync::MutexGuard;

fn lock(entry: &Entry) -> Result<MutexGuard<'_, Option<Owned>>> {
    match entry.owner.try_lock() {
        Ok(value) => Ok(value),
        Err(TryLockError::WouldBlock) => Err(failure(3)),
        Err(TryLockError::Poisoned(error)) => {
            error.into_inner().take();
            entry.cancel.cancel();
            Err(failure(5))
        }
    }
}
pub(super) fn with<T>(
    left: u64,
    right: u64,
    deadline: Instant,
    action: impl FnOnce(&mut Option<Owned>, &Entry, &mut Option<Owned>, &Entry) -> Result<T>,
) -> Result<T> {
    if left == right {
        return Err(Failure::argument());
    }
    let a = entry(left)?;
    let b = entry(right)?;
    let (first, second) = if left < right { (&a, &b) } else { (&b, &a) };
    let mut low = lock(first)?;
    let mut high = lock(second)?;
    opening::check(&a.cancel, deadline)?;
    opening::check(&b.cancel, deadline)?;
    // Cancellation of either handle reaches the same active witness transport.
    // The token is call-local; future idle owners retain their own cancellation.
    let cancel = Cancellation::default();
    let _first = first.invocation.enter(deadline, &cancel)?;
    let _second = second.invocation.enter(deadline, &cancel)?;
    opening::check(&a.cancel, deadline)?;
    opening::check(&b.cancel, deadline)?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if left < right {
            action(&mut low, &a, &mut high, &b)
        } else {
            action(&mut high, &a, &mut low, &b)
        }
    }));
    match result {
        Ok(Ok(value)) => {
            let checked = opening::check(&cancel, deadline)
                .and_then(|_| opening::check(&a.cancel, deadline))
                .and_then(|_| opening::check(&b.cancel, deadline));
            if let Err(error) = checked {
                low.take();
                high.take();
                return Err(error);
            }
            Ok(value)
        }
        Ok(Err(error)) => Err(error),
        Err(_) => {
            a.cancel.cancel();
            b.cancel.cancel();
            low.take();
            high.take();
            Err(failure(5))
        }
    }
}
