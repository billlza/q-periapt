// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Own the registry and original enrollment through an approved root cutover.
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityReplacementState as State, AccountAuthorityStore,
    AnchorAccountReplacementPlan as Plan, AnchorAccountReplacementProposal as Proposal,
    JournalAccountAuthority,
};
mod adoption;
pub use adoption::ManagedAccountRootAdoption;
mod operation;
mod original;
use original::Original;
mod cleanup;
use operation::Operation;
mod transition;
pub use transition::ManagedAccountRootTransition;

struct Owners {
    original: Option<Original>,
    registry: AccountAuthorityStore,
    expected: AccountAuthorityCheckpoint,
    operation: Operation,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    pin: AnchorPin,
}
impl Drop for Owners {
    fn drop(&mut self) {
        // Revoke every delegated successor before parent/child database disposal.
        self.registry.close();
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    fn state(&self) -> Result<State, DurableError> {
        self.operation.state(&self.registry, self.expected)
    }
    async fn successor(&mut self) -> Result<(AccountAuthorityCheckpoint, Proposal), DurableError> {
        if self.state()? != State::Committed {
            return Err(DurableError::Suspended);
        }
        let proposal = self.registry.replacement(self.operation.id())?.2.clone();
        self.check_parent(&proposal, true).await?;
        let checkpoint = self
            .registry
            .access()?
            .current(self.expected.application())?;
        if checkpoint.account() != proposal.successor_account()
            || Some(checkpoint.revision()) != self.expected.revision().checked_add(1)
        {
            return Err(DurableError::Conflict);
        }
        Ok((checkpoint, proposal))
    }
}

/// Coordinates one independently approved account-root replacement using the
/// original registry, enrollment and journal. No new storage format is introduced.
/// Witness freeze/replacement approval and target issuance remain independent
/// control-plane actions. This owner verifies their receipts; it cannot approve them.
///
/// Keep this owner alive while a returned successor operates. Close/drop and
/// failures during storage/recovery revoke registry access and release all leases.
/// Dedicated witness-receipt methods reject invalid bytes before mutation and
/// preserve the owner. Cleanup callback errors follow that method's close contract.
/// A storage/recovery error can follow a commit: reopen the original registry and use
/// `resume_original` with the same retained inputs, then replay the same receipt.
pub struct ManagedAccountRootReplacement {
    active: Option<Box<Owners>>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl ManagedAccountRootReplacement {
    fn check_inputs(owners: &Owners) -> Result<(), DurableError> {
        if owners.operation.expectation().previous_account() != owners.expected.account()
            || crate::identity::account_id(&owners.intent.root) != owners.expected.account()
            || owners.intent.description.family
                != owners.operation.expectation().authority_transition().2
            || owners.pin.binding() != owners.operation.expectation().witness_binding()
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Consume the current managed device and registry, durably retain the exact
    /// approved plan, and revoke old traffic before a witness freeze is requested.
    /// The original device must select this registry/checkpoint. Failure consumes
    /// both owners without deleting or recreating any persistent state.
    pub async fn begin(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: Plan,
        mut original: EnrolledDevice,
        pin: AnchorPin,
    ) -> Result<Self, DurableError> {
        let enrollment = &original
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .enrollment;
        let authority = JournalAccountAuthority::new(registry.access()?, expected)?;
        if !enrollment
            .account_authority
            .as_ref()
            .is_some_and(|selected| selected.same_scope(&authority))
        {
            return Err(DurableError::Conflict);
        }
        let mut owners = Owners {
            original: None,
            registry,
            expected,
            operation: Operation::Prepared(Box::new(plan)),
            paths: enrollment.paths.clone(),
            intent: enrollment.intent.clone(),
            pin,
        };
        Self::check_inputs(&owners)?;
        owners
            .registry
            .begin_preparation(expected, owners.operation.plan()?.clone())?;
        let original = *original.active.take().ok_or(DurableError::Closed)?;
        drop(original.service);
        drop(original.signer);
        owners.original = Some(Original::Preparing(Box::new(original.enrollment)));
        #[cfg(all(test, unix))]
        account_root::managed_boundary("preparation");
        owners.reconcile().await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    /// Resume an existing original registry operation. Absence is an error, never
    /// permission to create a new plan, enrollment, key or journal. A retained bound
    /// proposal reconciles the original parent/child fences before returning.
    pub async fn resume_original(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: Plan,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            original: None,
            registry,
            expected,
            operation: Operation::Prepared(Box::new(plan)),
            paths,
            intent,
            pin,
        };
        Self::check_inputs(&owners)?;
        owners.reconcile().await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    fn run<T>(
        &mut self,
        action: impl FnOnce(&mut Owners) -> Result<T, DurableError>,
    ) -> Result<T, DurableError> {
        // Own the controller across the operation. Errors and unwinding drop it
        // before control escapes; only a successful result restores live access.
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        let result = action(&mut owners)?;
        self.active = Some(owners);
        Ok(result)
    }

    /// Durable registry progress, not current traffic permission or proof of a
    /// remote non-commit. Preparing/Pending remain suspended after transport loss.
    pub fn state(&mut self) -> Result<State, DurableError> {
        self.run(|owners| owners.state())
    }
    /// Verify the original signed freeze, bind it in the registry, and retain the
    /// exact parent/journal fences before returning the approved witness proposal.
    pub async fn bind_witness_freeze(&mut self, receipt: &[u8]) -> Result<Proposal, DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        if owners.state()? == State::Closed {
            return Err(Error::Retired.into());
        }
        let frozen = owners
            .pin
            .verify_account_freeze(owners.operation.plan()?.request(), receipt)?;
        owners.operation.plan()?.bind(&frozen)?;
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        owners
            .registry
            .bind_preparation(owners.operation.id(), &frozen)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("binding");
        owners.reconcile().await?;
        let proposal = owners
            .registry
            .replacement(owners.operation.id())?
            .2
            .clone();
        owners.check_parent(&proposal, false).await?;
        self.active = Some(owners);
        Ok(proposal)
    }
    /// Retain the exact signed retirement in child and parent before selecting
    /// the successor in the registry. Lost returns retry this same receipt and
    /// cannot advance the registry revision twice. No operational owner is returned.
    pub async fn retain_witness_retirement(
        &mut self,
        receipt: &[u8],
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        if owners.state()? == State::Closed {
            return Err(Error::Retired.into());
        }
        let proposal = owners.registry.replacement(owners.operation.id())?.2;
        let retired = owners.pin.verify_retired_account(proposal, receipt)?;
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        owners
            .retain_parent_retirement(retired.proposal(), receipt)
            .await?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("retirement");
        owners.registry.commit_replacement(&retired)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("registry");
        let checkpoint = owners.successor().await?.0;
        self.active = Some(owners);
        Ok(checkpoint)
    }
    /// Activate only the exact independently enrolled successor after retained
    /// retirement. Current credential/policy, fresh witness admission and durable
    /// registry binding remain required. Retain this controller for its lifetime.
    pub async fn activate_successor(
        &mut self,
        enrollment: DeviceEnrollment,
        policy: &VerifiedSessionPolicy,
        now: u64,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<EnrolledDevice, DurableError> {
        // As in run(), the operation owns the controller until success. Future
        // drop also revokes every delegated owner through Owners::drop.
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        let result = Self::activate_successor_owned(
            &mut owners,
            enrollment,
            policy,
            now,
            transport,
            timeout,
        )
        .await?;
        self.active = Some(owners);
        Ok(result)
    }
    async fn activate_successor_owned(
        owners: &mut Owners,
        mut enrollment: DeviceEnrollment,
        policy: &VerifiedSessionPolicy,
        now: u64,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<EnrolledDevice, DurableError> {
        let (checkpoint, proposal) = owners.successor().await?;
        let image = enrollment.image_without_policy_renewal()?;
        let device = enrollment.admitted(&image, policy, now).await?;
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Suspended);
        };
        if device.account_id() != proposal.successor_account()
            || proposal.successor().journal_parts()
                != (
                    *admission.journal.as_bytes(),
                    crate::bootstrap::storage_owner(&device),
                    admission.policy,
                )
        {
            return Err(DurableError::Conflict);
        }
        enrollment.select_account_authority(JournalAccountAuthority::new(
            owners.registry.access()?,
            checkpoint,
        )?)?;
        let client = enrollment
            .anchor_client(policy, now, owners.pin.clone(), transport, timeout)
            .await?;
        enrollment.activate(policy, now, Some(client)).await
    }
    /// Obtain the committed successor's original registry admission for ordinary
    /// enrollment reopening and later credential/policy maintenance. This read
    /// descriptor does not own the registry and is revoked when this owner closes.
    pub async fn successor_authority(&mut self) -> Result<JournalAccountAuthority, DurableError> {
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        let (checkpoint, _) = owners.successor().await?;
        let authority = JournalAccountAuthority::new(owners.registry.access()?, checkpoint)?;
        self.active = Some(owners);
        Ok(authority)
    }
    /// Revoke returned successor owners and release all original leases. Durable
    /// progress remains available through the original registry and recovery inputs.
    pub fn close(&mut self) {
        self.active = None;
    }
}
