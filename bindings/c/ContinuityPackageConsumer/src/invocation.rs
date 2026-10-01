// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One explicit owner-local deadline shared with its deeply owned witness client.
use crate::{failure, p, Result};
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

#[derive(Clone, Default)]
pub(crate) struct Scope(Arc<Mutex<Option<Instant>>>);

impl Scope {
    pub(crate) fn enter(&self, deadline: Instant) -> Result<Active> {
        let mut current = self.0.lock().map_err(|_| failure(5))?;
        if current.is_some() {
            return Err(failure(3));
        }
        check(deadline)?;
        *current = Some(deadline);
        Ok(Active(self.clone()))
    }

    pub(crate) fn constrain(&self, attempt: Instant) -> io::Result<Instant> {
        let deadline = self
            .0
            .lock()
            .map_err(|_| io::Error::other("C invocation scope poisoned"))?
            .ok_or_else(|| io::Error::other("witness requires an active C invocation"))?
            .min(attempt);
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "C invocation deadline expired",
            ));
        }
        Ok(deadline)
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
        let deadline = Instant::now() + Duration::from_secs(1);
        let active = scope.enter(deadline).expect("first invocation");
        let witness = scope.clone();
        assert_eq!(
            witness.constrain(deadline + TIMEOUT).expect("active"),
            deadline
        );
        assert!(matches!(scope.enter(deadline + TIMEOUT), Err(error) if error.code == 3));
        assert_eq!(
            witness.constrain(deadline + TIMEOUT).expect("unchanged"),
            deadline
        );
        drop(active);
        assert!(witness.constrain(deadline + TIMEOUT).is_err());
        let later = deadline + TIMEOUT;
        let _next = scope.enter(later).expect("next invocation");
        assert_eq!(
            witness.constrain(later + TIMEOUT).expect("new scope"),
            later
        );
    }

    #[test]
    fn expired_admission_and_independent_owners_do_not_change_active_scope() {
        let scope = Scope::default();
        let expired = Instant::now();
        assert!(matches!(scope.enter(expired), Err(error) if error.code == 303));
        let deadline = Instant::now() + TIMEOUT;
        let _active = scope.enter(deadline).expect("valid invocation");
        let other = Scope::default();
        let _other = other.enter(deadline + TIMEOUT).expect("independent owner");
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
}
