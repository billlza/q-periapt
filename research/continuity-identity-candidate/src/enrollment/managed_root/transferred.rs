// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same controller, original storage and exact current-Witness account decision.
use super::*;
mod next_attempt;
use crate::{
    AnchorFrozenAccount, AnchorTransferredAccountReplacementApproval,
    TransferredAccountRootPreparation,
};

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    // Keep the transferred approval/cleanup frame out of ordinary root recovery.
    // The two admission paths are exclusive but both perform deep verification.
    #[inline(never)]
    pub(super) async fn admit_transferred_original(
        &self,
        enrollment: DeviceEnrollment,
        proposal: &Proposal,
        plan: &TransferredAccountRootPreparation,
    ) -> Result<Original, DurableError> {
        let approval = self.registry.transferred_approval(self.operation.id())?;
        if approval.proposal() != proposal {
            return Err(DurableError::Conflict);
        }
        plan.check_approval(approval)?;
        if self.state()? == State::Committed {
            let decision = self
                .registry
                .transferred_account_decision(self.operation.id())?;
            if let Some(context) = enrollment.retained_transferred_cleanup(
                plan.bind(approval.clone())?,
                decision.as_bytes(),
                self.cleanup_history
                    .clone()
                    .unwrap_or_else(|| plan.history.clone()),
            )? {
                let retired = crate::RetiredDeviceEnrollment::from_transferred_enrollment(
                    enrollment, context,
                )
                .await?;
                retired.check_transferred_managed_checkpoint(
                    plan,
                    self.registry
                        .managed_transferred_checkpoint(self.operation.id())?,
                )?;
                return Ok(Original::Retired(Box::new(retired)));
            }
        }
        self.check_transferred_checkpoint(&enrollment, false)
            .await?;
        if let Some(transition) = plan.transition() {
            return self.admit_transferred_next(enrollment, transition).await;
        }
        Ok(Original::Fenced(
            AccountRootEnrollmentRecovery::prepare_transferred(
                enrollment,
                plan.bind(approval.clone())?,
            )
            .await?,
        ))
    }

    pub(super) async fn check_preparing_original(
        &self,
        enrollment: &DeviceEnrollment,
    ) -> Result<(), DurableError> {
        if matches!(self.operation, Operation::Transferred(_)) {
            self.check_transferred_checkpoint(enrollment, true).await?;
        }
        Ok(())
    }
    pub(super) async fn check_transferred_checkpoint(
        &self,
        enrollment: &DeviceEnrollment,
        preparing: bool,
    ) -> Result<(), DurableError> {
        let expected = self
            .registry
            .managed_transferred_checkpoint(self.operation.id())?;
        if self.original_checkpoint(enrollment, preparing).await? != expected {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    async fn original_checkpoint(
        &self,
        enrollment: &DeviceEnrollment,
        preparing: bool,
    ) -> Result<[u8; 32], DurableError> {
        let Operation::Transferred(plan) = &self.operation else {
            return Err(DurableError::Conflict);
        };
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
        if (preparing && snapshot.root_replacement.is_some() && plan.transition().is_none())
            || snapshot.retirement.is_some()
        {
            return Err(DurableError::Conflict);
        }
        if let Some(transition) = plan.transition() {
            AccountRootEnrollmentRecovery::check_transferred_transition(enrollment, transition)
                .await?;
        }
        enrollment.validate_roster_resolution(&snapshot.image)?;
        enrollment.validate_witness_roster(&snapshot.image)?;
        enrollment.validate_policy_pending(&snapshot.image)?;
        let Phase::Accepted {
            admission, stage, ..
        } = &snapshot.image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if *stage == AdmissionPhase::Accepted {
            return Err(DurableError::Suspended);
        }
        if let Some(selected) = &snapshot.witness_handoff {
            selected.check_plan(plan.selection.as_ref().ok_or(DurableError::Conflict)?)?;
        }
        let original = enrollment.original_device_metadata(&snapshot.image)?;
        let child = plan.check_original(
            enrollment.paths.installation.files()[1],
            &enrollment.key().await?,
            &original,
            (admission.journal, admission.policy),
            (self.registry.access()?.binding(), self.expected),
            !preparing || plan.transition().is_some(),
        )?;
        plan.original_checkpoint(account_root::original_digest(enrollment)?, child)
    }
    pub(super) fn reconcile_transferred_decision(&mut self) -> Result<(), DurableError> {
        if !matches!(self.operation, Operation::Transferred(_)) {
            return Ok(());
        }
        let state = self.state()?;
        if state == State::Preparing {
            return Ok(());
        }
        if let Some(Original::Retired(parent)) = self.original.as_ref() {
            if state != State::Committed {
                return Err(DurableError::Conflict);
            }
            let decision = self
                .registry
                .transferred_account_decision(self.operation.id())?;
            return parent.check_transferred_decision(decision.as_bytes());
        }
        let Some(Original::Fenced(parent)) = self.original.as_mut() else {
            return Err(DurableError::Conflict);
        };
        if matches!(state, State::Committed | State::Closed) {
            let decision = self
                .registry
                .transferred_account_decision(self.operation.id())?;
            parent.retain_account_decision(decision.as_bytes())?;
        } else if parent.status()? != AccountRootEnrollmentState::IntentRetained {
            let decision = parent.account_decision()?;
            self.registry
                .retain_transferred_account_decision(self.operation.id(), decision.as_bytes())?;
        }
        Ok(())
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl ManagedAccountRootReplacement {
    fn transferred_owners(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: TransferredAccountRootPreparation,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Owners, DurableError> {
        let pin = plan.current_pin()?.clone();
        let owners = Owners {
            original: None,
            registry,
            expected,
            operation: Operation::Transferred(Box::new(plan)),
            paths,
            intent,
            pin,
            cleanup_history: None,
        };
        Self::check_inputs(&owners)?;
        Ok(owners)
    }
    /// Retain the approved current-Witness target in the same original registry
    /// before a remote account freeze. Only original authenticated storage is
    /// inspected: a live old service or signer is not required. Existing G/P/R
    /// intent, sealed keys, journal head and command IDs are never rewritten.
    /// Failure consumes the registry; an unknown commit resumes this exact plan.
    pub async fn begin_transferred(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: TransferredAccountRootPreparation,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        let mut owners = Self::transferred_owners(registry, expected, plan, paths, intent)?;
        match owners
            .registry
            .transferred_preparation(owners.operation.id())
        {
            Ok(_) => {
                owners.reconcile().await?;
                return Ok(Self {
                    active: Some(Box::new(owners)),
                });
            }
            Err(DurableError::Absent) => {}
            Err(error) => return Err(error),
        }
        let enrollment =
            DeviceEnrollment::open_original_storage(owners.paths.clone(), owners.intent.clone())
                .await?;
        let checkpoint = owners.original_checkpoint(&enrollment, true).await?;
        let Operation::Transferred(plan) = &owners.operation else {
            return Err(DurableError::Conflict);
        };
        owners.registry.begin_managed_transferred_preparation(
            expected,
            plan.target.clone(),
            &plan.history,
            checkpoint,
        )?;
        owners.original = Some(Original::Preparing(Box::new(enrollment)));
        #[cfg(all(test, unix))]
        account_root::managed_boundary("preparation");
        owners.reconcile().await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    /// Reconcile the existing original operation, including child/parent outcome
    /// commits whose registry acknowledgement was lost. Missing state is an error;
    /// no registry, enrollment, key, approval or operation is created on recovery.
    pub async fn resume_transferred_original(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: TransferredAccountRootPreparation,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        let mut owners = Self::transferred_owners(registry, expected, plan, paths, intent)?;
        owners.reconcile().await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    /// Reopen the same committed operation for cleanup under independently verified
    /// later Witness history. Root-operation authority remains the original one;
    /// this history selects only historical accounting and never successor traffic.
    /// Existing parent checkpoints are required after journal or signer erasure.
    pub async fn resume_transferred_cleanup_original(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        plan: TransferredAccountRootPreparation,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        history: crate::AnchorHandoffHistory,
    ) -> Result<Self, DurableError> {
        if history.checkpoint() != plan.history.checkpoint() {
            history.require_extension_of(&plan.history)?;
        }
        let mut owners = Self::transferred_owners(registry, expected, plan, paths, intent)?;
        if owners.state()? != State::Committed {
            return Err(DurableError::Suspended);
        }
        owners.cleanup_history = Some(history);
        owners.reconcile().await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    /// Bind the verified whole-account freeze and independently approved complete
    /// replacement, then retain the original parent and child fences. This cannot
    /// approve a network-selected target or authorize either account's traffic.
    pub async fn bind_transferred_freeze(
        &mut self,
        frozen: &AnchorFrozenAccount,
        approval: AnchorTransferredAccountReplacementApproval,
    ) -> Result<Proposal, DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let Operation::Transferred(plan) = &owners.operation else {
            return Err(DurableError::Conflict);
        };
        let proposal = plan.target.bind(frozen, &plan.history)?;
        approval.check_retained_history(&plan.history)?;
        if approval.proposal() != &proposal {
            return Err(DurableError::Conflict);
        }
        // A next-attempt context already fixes the entire independent approval,
        // including its operator decision and validity. Reject a different one
        // before it can become the registry's immutable bound intent.
        plan.check_approval(&approval)?;
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        owners
            .registry
            .bind_transferred_preparation(owners.operation.id(), frozen, approval)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("binding");
        owners.reconcile().await?;
        owners.check_parent(&proposal, false).await?;
        self.active = Some(owners);
        Ok(proposal)
    }
    /// Retain exact purpose-37 bytes in child, parent, then registry. A committed
    /// result selects the approved successor once; Closed never revives old traffic.
    /// Invalid proofs fail before mutation. Storage errors close the controller and
    /// may follow commit; resume the same original preparation and receipt.
    pub async fn retain_transferred_decision(
        &mut self,
        wire: &[u8],
    ) -> Result<State, DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let Operation::Transferred(plan) = &owners.operation else {
            return Err(DurableError::Conflict);
        };
        owners
            .registry
            .transferred_approval(owners.operation.id())?
            .verify_decision(&plan.history, wire)?;
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        match owners.original.as_mut() {
            Some(Original::Fenced(parent)) => {
                parent.retain_account_decision(wire)?;
            }
            Some(Original::Retired(parent)) => parent.check_transferred_decision(wire)?,
            _ => return Err(DurableError::Conflict),
        }
        #[cfg(all(test, unix))]
        account_root::managed_boundary("decision");
        let state = owners
            .registry
            .retain_transferred_account_decision(owners.operation.id(), wire)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("registry");
        owners.reconcile_transferred_decision()?;
        if state == State::Committed {
            owners.successor().await?;
        }
        self.active = Some(owners);
        Ok(state)
    }
}
