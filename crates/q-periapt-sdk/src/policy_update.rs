// SPDX-License-Identifier: Apache-2.0 OR MIT
//! In-process prepare/persist/activate transition, never a persistent authority.
use crate::{Error, Runtime, State};
use q_periapt_policy::TrustedPolicyState;
use std::sync::{atomic::Ordering, Arc};

/// A verified future policy, with no key-operation API. The host must atomically
/// compare/persist the state pair before activation, in storage scoped to its root.
/// Closing/dropping a candidate before activation leaves the old runtime active.
pub struct PolicyUpdate {
    previous: Arc<State>,
    next: Option<Arc<Runtime>>,
}
impl PolicyUpdate {
    /// Expected previous state and verified next state for the host's atomic CAS.
    pub fn states(&self) -> Result<(TrustedPolicyState, TrustedPolicyState), Error> {
        self.previous.ensure_open()?;
        let next = self.next.as_ref().ok_or(Error::Closed)?;
        Ok((
            self.previous.configuration.trusted_state(),
            next.trusted_state(),
        ))
    }

    /// Activate only after the host has atomically persisted the state pair.
    /// Exactly one candidate can replace the old runtime. The atomic successful
    /// close is the revocation point: prior admitted calls may finish, future
    /// old-key/secret/derived-key operations fail. No allocation/crypto is needed.
    ///
    /// This method cannot verify external persistence. If persistence committed
    /// but activation fails, stop using the old runtime and reconstruct from the
    /// signed policy and persisted state; never fall back to older stored state.
    pub fn activate_after_persist(mut self) -> Result<Arc<Runtime>, Error> {
        let next = self.next.take().ok_or(Error::Closed)?;
        self.previous
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Closed)?;
        Ok(next)
    }

    /// Cancel a preparation without revoking the old runtime. After persistence
    /// has committed, cancellation requires the host's explicit recovery path.
    pub fn close(&mut self) {
        self.next = None;
    }
}

impl Runtime {
    /// Verify a strictly newer policy using this runtime's pinned root and exact
    /// trusted state. Same-version reapplication is not an epoch transition.
    /// Rejected, closed or abandoned preparations never revoke the old runtime.
    pub fn prepare_policy_update(
        &self,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<PolicyUpdate, Error> {
        let _operation = self.state.begin_control()?;
        let next = Self::from_signed_policy(
            policy,
            signature,
            self.state.trust_root.as_slice(),
            Some(&self.trusted_state()),
            self.state.limits,
        )?;
        if next.trusted_state().version() <= self.trusted_state().version() {
            return Err(Error::PolicyDenied);
        }
        self.state.ensure_open()?;
        Ok(PolicyUpdate {
            previous: Arc::clone(&self.state),
            next: Some(Arc::new(next)),
        })
    }
}
