// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One explicit owner-local deadline shared with its deeply owned witness client.
use crate::{failure, p, Cancellation, Result};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) const TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(p::connection_transport::Error::Deadline.into())
    } else {
        Ok(())
    }
}

struct Invocation {
    deadline: Instant,
    cancel: Cancellation,
}
#[derive(Clone, Default)]
pub(crate) struct Scope(Arc<Mutex<Option<Invocation>>>);

impl Scope {
    /// Signal only the current borrowed call. Parent cancellation separately
    /// fences future admission; this does not poison an unrelated idle peer.
    pub(crate) fn cancel_active(&self) -> Result<()> {
        let active = self.0.lock().map_err(|_| failure(5))?;
        if let Some(active) = active.as_ref() {
            active.cancel.cancel();
        }
        Ok(())
    }
    pub(crate) fn enter(&self, deadline: Instant, cancel: &Cancellation) -> Result<Active> {
        let mut current = self.0.lock().map_err(|_| failure(5))?;
        if current.is_some() {
            return Err(failure(3));
        }
        check(deadline)?;
        *current = Some(Invocation {
            deadline,
            cancel: cancel.clone(),
        });
        Ok(Active(self.clone()))
    }

    pub(crate) fn constrain(&self, attempt: Instant) -> io::Result<Instant> {
        self.transport_context(attempt)
            .map(|(deadline, _)| deadline)
    }

    /// Snapshot the same call's deadline and cancellation owner together. A
    /// retained witness transport must not keep another peer's previous token.
    pub(crate) fn transport_context(
        &self,
        attempt: Instant,
    ) -> io::Result<(Instant, Cancellation)> {
        let current = self
            .0
            .lock()
            .map_err(|_| io::Error::other("C invocation scope poisoned"))?;
        let current = current
            .as_ref()
            .ok_or_else(|| io::Error::other("witness requires an active C invocation"))?;
        let deadline = current.deadline.min(attempt);
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "C invocation deadline expired",
            ));
        }
        Ok((deadline, current.cancel.clone()))
    }
}

pub(crate) struct Active(Scope);
impl Drop for Active {
    fn drop(&mut self) {
        // Cleanup cannot grant another call authority: a poisoned scope remains
        // poisoned and future admission fails even after its deadline is removed.
        self.0
             .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enclosing_deadline_is_shared_without_refresh_and_cannot_be_reentered() {
        let scope = Scope::default();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        let active = scope.enter(deadline, &cancel).expect("first invocation");
        let witness = scope.clone();
        assert_eq!(
            witness.constrain(deadline + TIMEOUT).expect("active"),
            deadline
        );
        assert!(matches!(scope.enter(deadline + TIMEOUT, &cancel), Err(error) if error.code == 3));
        assert_eq!(
            witness.constrain(deadline + TIMEOUT).expect("unchanged"),
            deadline
        );
        drop(active);
        assert!(witness.constrain(deadline + TIMEOUT).is_err());
        let later = deadline + TIMEOUT;
        let _next = scope.enter(later, &cancel).expect("next invocation");
        assert_eq!(
            witness.constrain(later + TIMEOUT).expect("new scope"),
            later
        );
    }

    #[test]
    fn expired_admission_and_independent_owners_do_not_change_active_scope() {
        let scope = Scope::default();
        let cancel = Cancellation::default();
        let expired = Instant::now();
        assert!(matches!(scope.enter(expired, &cancel), Err(error) if error.code == 303));
        let deadline = Instant::now() + TIMEOUT;
        let _active = scope.enter(deadline, &cancel).expect("valid invocation");
        let other = Scope::default();
        let _other = other
            .enter(deadline + TIMEOUT, &cancel)
            .expect("independent owner");
        assert_eq!(
            scope.constrain(deadline + TIMEOUT).expect("original scope"),
            deadline
        );
        assert_eq!(
            scope
                .constrain(expired)
                .expect_err("earlier attempt expired")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn sequential_calls_keep_their_own_cancellation_without_retaining_idle_authority() {
        let scope = Scope::default();
        let first = Cancellation::default();
        let second = Cancellation::default();
        let deadline = Instant::now() + TIMEOUT;
        let active = scope.enter(deadline, &first).expect("first call");
        let (_, retained) = scope.transport_context(deadline).expect("first snapshot");
        scope.cancel_active().expect("cancel current call");
        assert!(retained.is_cancelled());
        assert!(!second.is_cancelled());
        drop(active);
        scope
            .cancel_active()
            .expect("idle cancellation has no child");
        assert!(scope.transport_context(deadline).is_err());
        let _active = scope.enter(deadline, &second).expect("second call");
        let (_, current) = scope.transport_context(deadline).expect("second snapshot");
        assert!(!current.is_cancelled());
        assert!(retained.is_cancelled());
        scope.cancel_active().expect("cancel second call");
        assert!(second.is_cancelled());
    }
}
