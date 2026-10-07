// SPDX-License-Identifier: Apache-2.0 OR MIT
//! In-process prepare/persist/activate transition, never a persistent authority.
use crate::{Error, Limits, Runtime, State, UpdateMode};
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
    /// Runtimes borrowed from a [`PolicyOwner`] return [`Error::UpdateOwnerRequired`]:
    /// their update capability stays with that owner, across every successor.
    pub fn prepare_policy_update(
        &self,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<PolicyUpdate, Error> {
        self.state.ensure_open()?;
        if self.state.update_mode == UpdateMode::OwnerManaged {
            return Err(Error::UpdateOwnerRequired);
        }
        self.prepare_policy_update_inner(policy, signature)
    }

    fn prepare_policy_update_inner(
        &self,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<PolicyUpdate, Error> {
        let _operation = self.state.begin_control()?;
        let next = Self::from_signed_policy_with_mode(
            policy,
            signature,
            self.state.trust_root.as_slice(),
            Some(&self.trusted_state()),
            self.state.limits,
            self.state.update_mode,
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

/// Sole policy-update capability for a host persistence owner.
///
/// Keep this value private inside the storage implementation and lend only
/// [`Self::runtime`] aliases to consumers. Those aliases cannot prepare updates.
/// Creation and activation do not perform I/O: this owner must persist the signed
/// policy and exact state before exposing an initial or replacement runtime.
/// This separates API capabilities; it does not isolate malicious same-process
/// code or prevent a trusted host from explicitly bootstrapping another runtime.
/// Closing/dropping this owner revokes its operational aliases.
///
/// There is no conversion from a borrowed runtime into update authority:
/// ```compile_fail
/// use q_periapt_sdk::{PolicyOwner, Runtime};
/// use std::sync::Arc;
/// fn elevate(alias: Arc<Runtime>) -> PolicyOwner { PolicyOwner::from(alias) }
/// ```
pub struct PolicyOwner {
    runtime: Arc<Runtime>,
}

impl PolicyOwner {
    /// Verify an initial or reopened signed policy and retain its update capability.
    /// `last_trusted` must come from the host's original protected storage.
    /// Persist a newly bootstrapped policy before lending its runtime.
    pub fn from_signed_policy(
        policy: &[u8],
        signature: &[u8],
        root: &[u8],
        last_trusted: Option<&TrustedPolicyState>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            runtime: Arc::new(Runtime::from_signed_policy_with_mode(
                policy,
                signature,
                root,
                last_trusted,
                limits,
                UpdateMode::OwnerManaged,
            )?),
        })
    }

    /// Exact state for the host's durable image and compare-and-persist operation.
    pub fn trusted_state(&self) -> TrustedPolicyState {
        self.runtime.trusted_state()
    }

    /// Lend an operational alias without policy-update authority.
    pub fn runtime(&self) -> Result<Arc<Runtime>, Error> {
        self.runtime.state.ensure_open()?;
        Ok(Arc::clone(&self.runtime))
    }

    /// Verify the next policy under this owner's exact root/state. The candidate
    /// exposes only its state pair until the host has completed persistence.
    pub fn prepare_policy_update(
        &self,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<OwnedPolicyUpdate, Error> {
        Ok(OwnedPolicyUpdate {
            update: self
                .runtime
                .prepare_policy_update_inner(policy, signature)?,
        })
    }

    /// Revoke operational aliases and outstanding preparations for this epoch.
    pub fn close(&self) {
        self.runtime.close();
    }
}
impl Drop for PolicyOwner {
    fn drop(&mut self) {
        self.close();
    }
}

/// Verified successor of a [`PolicyOwner`], with no operational runtime access.
/// The host must atomically persist its complete signed image and state pair.
pub struct OwnedPolicyUpdate {
    update: PolicyUpdate,
}
impl OwnedPolicyUpdate {
    /// Exact previous and successor states for the host's durable compare-and-swap.
    pub fn states(&self) -> Result<(TrustedPolicyState, TrustedPolicyState), Error> {
        self.update.states()
    }

    /// After successful persistence, revoke the original epoch and return the
    /// successor's sole update owner. Only one competing preparation can win.
    /// On failure after persistence, close the store and reopen its committed
    /// image; never resume an older policy. No persistence is performed here.
    pub fn activate_after_persist(self) -> Result<PolicyOwner, Error> {
        Ok(PolicyOwner {
            runtime: self.update.activate_after_persist()?,
        })
    }

    /// Cancel preparation before persistence, leaving the old epoch unchanged.
    pub fn close(&mut self) {
        self.update.close();
    }
}
