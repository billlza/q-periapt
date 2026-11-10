// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exactly one original parent lease across preparation, fencing and cleanup.
use super::*;
use crate::{AccountRootJournalTransition, RetiredDeviceEnrollment};

pub(super) enum Original {
    Preparing(Box<DeviceEnrollment>),
    Fenced(AccountRootEnrollmentRecovery),
    Retired(Box<RetiredDeviceEnrollment>),
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    fn registry_committed(&self, proposal: &Proposal) -> Result<bool, DurableError> {
        let (application, state, retained) = match self.registry.replacement(proposal.operation()) {
            Ok(record) => record,
            Err(DurableError::Absent | DurableError::Suspended) => return Ok(false),
            Err(error) => return Err(error),
        };
        if application != self.expected.application()
            || retained != proposal
            || self.registry.operation_checkpoint(proposal.operation())? != self.expected
        {
            return Err(DurableError::Conflict);
        }
        Ok(state == State::Committed)
    }
    async fn admit_original(
        &self,
        enrollment: DeviceEnrollment,
        proposal: &Proposal,
        transition: Option<&AccountRootJournalTransition>,
    ) -> Result<Original, DurableError> {
        if let Operation::Transferred(plan) = &self.operation {
            if transition.is_some() {
                return Err(DurableError::Conflict);
            }
            return self
                .admit_transferred_original(enrollment, proposal, plan)
                .await;
        }
        if let Some(retired) = enrollment.retained_root_cleanup(&self.pin, proposal)? {
            if !self.registry_committed(proposal)? {
                return Err(DurableError::Conflict);
            }
            return Ok(Original::Retired(Box::new(
                RetiredDeviceEnrollment::from_enrollment(enrollment, self.pin.clone(), retired)
                    .await?,
            )));
        }
        let recovery = match transition {
            Some(transition) => {
                AccountRootEnrollmentRecovery::prepare_managed_transition(
                    enrollment,
                    self.pin.clone(),
                    transition,
                )
                .await?
            }
            None => {
                AccountRootEnrollmentRecovery::prepare(
                    enrollment,
                    self.pin.clone(),
                    proposal.clone(),
                )
                .await?
            }
        };
        Ok(Original::Fenced(recovery))
    }
    pub(super) async fn reconcile(&mut self) -> Result<(), DurableError> {
        let proposal = match self.state()? {
            State::Preparing => None,
            State::Closed => match self.registry.replacement(self.operation.id()) {
                Ok((_, _, proposal)) => Some(proposal.clone()),
                Err(DurableError::Suspended) => None,
                Err(error) => return Err(error),
            },
            State::Pending | State::Committed => {
                Some(self.registry.replacement(self.operation.id())?.2.clone())
            }
        };
        let original = match (proposal, self.original.take()) {
            (None, None) => {
                let enrollment = if matches!(self.operation, Operation::Transferred(_)) {
                    DeviceEnrollment::open_original_storage(self.paths.clone(), self.intent.clone())
                        .await?
                } else {
                    DeviceEnrollment::open(self.paths.clone(), self.intent.clone()).await?
                };
                self.check_preparing_original(&enrollment).await?;
                Original::Preparing(Box::new(enrollment))
            }
            (None, Some(original @ Original::Preparing(_))) => original,
            (None, Some(_)) => return Err(DurableError::Conflict),
            (Some(proposal), None) => {
                self.admit_original(
                    DeviceEnrollment::open_original_storage(
                        self.paths.clone(),
                        self.intent.clone(),
                    )
                    .await?,
                    &proposal,
                    None,
                )
                .await?
            }
            (Some(proposal), Some(Original::Preparing(enrollment))) => {
                self.admit_original(*enrollment, &proposal, None).await?
            }
            (Some(proposal), Some(mut original)) => {
                self.check_original(&mut original, &proposal, false).await?;
                original
            }
        };
        self.original = Some(original);
        self.reconcile_transferred_decision()?;
        Ok(())
    }
    async fn check_original(
        &self,
        original: &mut Original,
        proposal: &Proposal,
        committed: bool,
    ) -> Result<(), DurableError> {
        match original {
            Original::Preparing(_) => Err(DurableError::Suspended),
            Original::Fenced(recovery) => {
                if recovery.proposal()? != *proposal
                    || (committed
                        && recovery.status()? != AccountRootEnrollmentState::WitnessCommitted)
                {
                    return Err(DurableError::Suspended);
                }
                Ok(())
            }
            Original::Retired(retired) => {
                if let Operation::Transferred(plan) = &self.operation {
                    retired.check_transferred_managed_checkpoint(
                        plan,
                        self.registry
                            .managed_transferred_checkpoint(self.operation.id())?,
                    )?;
                }
                retired
                    .check_managed_scope(&self.paths, &self.intent, &self.pin, proposal)
                    .await
            }
        }
    }
    pub(super) async fn check_parent(
        &mut self,
        proposal: &Proposal,
        committed: bool,
    ) -> Result<(), DurableError> {
        let mut original = self.original.take().ok_or(DurableError::Closed)?;
        self.check_original(&mut original, proposal, committed)
            .await?;
        self.original = Some(original);
        Ok(())
    }
    pub(super) async fn validate_parent_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<(), DurableError> {
        match self.original.as_mut() {
            Some(Original::Fenced(recovery)) => {
                recovery.validate_managed_transition(transition).await
            }
            Some(Original::Retired(_)) => self.check_parent(transition.next_proposal(), true).await,
            Some(Original::Preparing(_)) | None => Ok(()),
        }
    }
    pub(super) async fn advance_parent(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<(), DurableError> {
        let proposal = transition.next_proposal();
        let original = match self.original.take() {
            Some(Original::Fenced(mut recovery)) => {
                recovery.apply_managed_transition(transition).await?;
                Original::Fenced(recovery)
            }
            Some(Original::Preparing(enrollment)) => {
                self.admit_original(*enrollment, proposal, Some(transition))
                    .await?
            }
            Some(mut original @ Original::Retired(_)) => {
                if !self.registry_committed(proposal)? {
                    return Err(DurableError::Conflict);
                }
                self.check_original(&mut original, proposal, true).await?;
                original
            }
            None => {
                self.admit_original(
                    DeviceEnrollment::open_original_storage(
                        self.paths.clone(),
                        self.intent.clone(),
                    )
                    .await?,
                    proposal,
                    Some(transition),
                )
                .await?
            }
        };
        self.original = Some(original);
        Ok(())
    }
    pub(super) async fn retain_parent_retirement(
        &mut self,
        proposal: &Proposal,
        receipt: &[u8],
    ) -> Result<(), DurableError> {
        self.check_parent(proposal, false).await?;
        match self.original.as_mut().ok_or(DurableError::Closed)? {
            Original::Fenced(recovery) => {
                recovery.retain_witness_retirement(receipt)?;
            }
            Original::Retired(_) => self.check_parent(proposal, true).await?,
            Original::Preparing(_) => return Err(DurableError::Suspended),
        }
        Ok(())
    }
    pub(super) async fn start_cleanup(&mut self, proposal: &Proposal) -> Result<(), DurableError> {
        self.check_parent(proposal, true).await?;
        let original = match self.original.take().ok_or(DurableError::Closed)? {
            Original::Fenced(recovery) => {
                Original::Retired(Box::new(if let Some(history) = &self.cleanup_history {
                    recovery
                        .into_retired_with_accounting_history(history.clone())
                        .await?
                } else {
                    recovery.into_retired().await?
                }))
            }
            original @ Original::Retired(_) => original,
            Original::Preparing(_) => return Err(DurableError::Suspended),
        };
        self.original = Some(original);
        self.check_parent(proposal, true).await
    }
    pub(super) fn cleanup(&mut self) -> Result<&mut RetiredDeviceEnrollment, DurableError> {
        match self.original.as_mut() {
            Some(Original::Retired(retired)) => Ok(retired),
            _ => Err(DurableError::Suspended),
        }
    }
    pub(super) async fn finish_cleanup_step(
        &mut self,
        proposal: &Proposal,
    ) -> Result<(), DurableError> {
        // Logical signer erasure deliberately closes its restricted owner. Only
        // that explicit closed state permits reopening these same existing paths.
        if self.cleanup()?.is_closed() {
            self.original = None;
            let original = self
                .admit_original(
                    DeviceEnrollment::open_original_storage(
                        self.paths.clone(),
                        self.intent.clone(),
                    )
                    .await?,
                    proposal,
                    None,
                )
                .await?;
            if !matches!(original, Original::Retired(_)) {
                return Err(DurableError::Conflict);
            }
            self.original = Some(original);
        }
        self.check_parent(proposal, true).await
    }
}
