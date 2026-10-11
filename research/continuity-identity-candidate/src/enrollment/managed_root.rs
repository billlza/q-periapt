// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Own the registry and original enrollment through an approved root cutover.
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityReplacementState as State, AccountAuthorityStore,
    AnchorAccountReplacementPlan as Plan, AnchorAccountReplacementProposal as Proposal,
    JournalAccountAuthority,
};

struct Owners {
    recovery: Option<AccountRootEnrollmentRecovery>,
    enrollment: Option<DeviceEnrollment>,
    registry: AccountAuthorityStore,
    expected: AccountAuthorityCheckpoint,
    plan: Plan,
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
impl Owners {
    fn state(&self) -> Result<State, DurableError> {
        let (application, state, plan) = self.registry.preparation(self.plan.operation())?;
        if application != self.expected.application()
            || plan != &self.plan
            || self.registry.operation_checkpoint(self.plan.operation())? != self.expected
        {
            return Err(DurableError::Conflict);
        }
        Ok(state)
    }
    fn reconcile(&mut self) -> Result<(), DurableError> {
        match self.state()? {
            State::Preparing => {
                if self.enrollment.is_none() {
                    self.enrollment = Some(DeviceEnrollment::open(
                        self.paths.clone(),
                        self.intent.clone(),
                    )?);
                }
                Ok(())
            }
            State::Closed => Err(Error::Retired.into()),
            State::Pending | State::Committed => {
                let proposal = self.registry.replacement(self.plan.operation())?.2.clone();
                self.recovery = Some(match self.enrollment.take() {
                    Some(enrollment) => AccountRootEnrollmentRecovery::prepare(
                        enrollment,
                        self.pin.clone(),
                        proposal,
                    )?,
                    None => AccountRootEnrollmentRecovery::resume_original(
                        self.paths.clone(),
                        self.intent.clone(),
                        self.pin.clone(),
                        proposal,
                    )?,
                });
                Ok(())
            }
        }
    }
    fn successor(&mut self) -> Result<(AccountAuthorityCheckpoint, Proposal), DurableError> {
        if self.state()? != State::Committed
            || self
                .recovery
                .as_mut()
                .ok_or(DurableError::Suspended)?
                .status()?
                != AccountRootEnrollmentState::WitnessCommitted
        {
            return Err(DurableError::Suspended);
        }
        let proposal = self.registry.replacement(self.plan.operation())?.2.clone();
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
/// Keep this owner alive while a returned successor operates. Close, drop or any
/// method error revokes its registry access and releases all original leases.
/// An error can follow a commit: reopen the original registry and use
/// `resume_original` with the same retained inputs, then replay the same receipt.
pub struct ManagedAccountRootReplacement {
    active: Option<Box<Owners>>,
}
impl ManagedAccountRootReplacement {
    fn check_inputs(owners: &Owners) -> Result<(), DurableError> {
        if owners.plan.target().previous_account() != owners.expected.account()
            || crate::identity::account_id(&owners.intent.root) != owners.expected.account()
            || owners.intent.description.family != owners.plan.target().authority_transition().2
            || owners.pin.binding() != owners.plan.target().witness_binding()
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Consume the current managed device and registry, durably retain the exact
    /// approved plan, and revoke old traffic before a witness freeze is requested.
    /// The original device must select this registry/checkpoint. Failure consumes
    /// both owners without deleting or recreating any persistent state.
    pub fn begin(
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
            recovery: None,
            enrollment: None,
            registry,
            expected,
            plan,
            paths: enrollment.paths.clone(),
            intent: enrollment.intent.clone(),
            pin,
        };
        Self::check_inputs(&owners)?;
        owners
            .registry
            .begin_preparation(expected, owners.plan.clone())?;
        let original = *original.active.take().ok_or(DurableError::Closed)?;
        drop(original.service);
        drop(original.signer);
        owners.enrollment = Some(original.enrollment);
        #[cfg(all(test, unix))]
        account_root::managed_boundary("preparation");
        owners.reconcile()?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    /// Resume an existing original registry operation. Absence is an error, never
    /// permission to create a new plan, enrollment, key or journal. A retained bound
    /// proposal reconciles the original parent/child fences before returning.
    pub fn resume_original(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: Plan,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            recovery: None,
            enrollment: None,
            registry,
            expected,
            plan,
            paths,
            intent,
            pin,
        };
        Self::check_inputs(&owners)?;
        owners.reconcile()?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    fn run<T>(
        &mut self,
        action: impl FnOnce(&mut Owners) -> Result<T, DurableError>,
    ) -> Result<T, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|owners| action(owners));
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Durable registry progress, not current traffic permission or proof of a
    /// remote non-commit. Preparing/Pending remain suspended after transport loss.
    pub fn state(&mut self) -> Result<State, DurableError> {
        self.run(|owners| owners.state())
    }
    /// Verify the original signed freeze, bind it in the registry, and retain the
    /// exact parent/journal fences before returning the approved witness proposal.
    pub fn bind_witness_freeze(&mut self, receipt: &[u8]) -> Result<Proposal, DurableError> {
        self.run(|owners| {
            let frozen = owners
                .pin
                .verify_account_freeze(owners.plan.request(), receipt)?;
            owners
                .registry
                .bind_preparation(owners.plan.operation(), &frozen)?;
            #[cfg(all(test, unix))]
            account_root::managed_boundary("binding");
            if owners.recovery.is_none() {
                owners.reconcile()?;
            }
            owners
                .recovery
                .as_mut()
                .ok_or(DurableError::Suspended)?
                .proposal()
        })
    }
    /// Retain the exact signed retirement in child and parent before selecting
    /// the successor in the registry. Lost returns retry this same receipt and
    /// cannot advance the registry revision twice. No operational owner is returned.
    pub fn retain_witness_retirement(
        &mut self,
        receipt: &[u8],
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        self.run(|owners| {
            let proposal = owners
                .registry
                .replacement(owners.plan.operation())?
                .2
                .clone();
            let retired = owners.pin.verify_retired_account(&proposal, receipt)?;
            owners
                .recovery
                .as_mut()
                .ok_or(DurableError::Suspended)?
                .retain_witness_retirement(receipt)?;
            #[cfg(all(test, unix))]
            account_root::managed_boundary("retirement");
            owners.registry.commit_replacement(&retired)?;
            #[cfg(all(test, unix))]
            account_root::managed_boundary("registry");
            Ok(owners.successor()?.0)
        })
    }
    /// Activate only the exact independently enrolled successor after retained
    /// retirement. Current credential/policy, fresh witness admission and durable
    /// registry binding remain required. Retain this controller for its lifetime.
    pub fn activate_successor(
        &mut self,
        mut enrollment: DeviceEnrollment,
        policy: &VerifiedSessionPolicy,
        now: u64,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<EnrolledDevice, DurableError> {
        self.run(|owners| {
            let (checkpoint, proposal) = owners.successor()?;
            let image = enrollment.image_without_policy_renewal()?;
            let device = enrollment.admitted(&image, policy, now)?;
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
            let client =
                enrollment.anchor_client(policy, now, owners.pin.clone(), transport, timeout)?;
            enrollment.activate(policy, now, Some(client))
        })
    }
    /// Obtain the committed successor's original registry admission for ordinary
    /// enrollment reopening and later credential/policy maintenance. This read
    /// descriptor does not own the registry and is revoked when this owner closes.
    pub fn successor_authority(&mut self) -> Result<JournalAccountAuthority, DurableError> {
        self.run(|owners| {
            let (checkpoint, _) = owners.successor()?;
            JournalAccountAuthority::new(owners.registry.access()?, checkpoint)
        })
    }
    /// Revoke returned successor owners and release all original leases. Durable
    /// progress remains available through the original registry and recovery inputs.
    pub fn close(&mut self) {
        self.active = None;
    }
}
