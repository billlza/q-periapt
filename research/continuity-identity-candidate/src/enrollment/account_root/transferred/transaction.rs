// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Preflight and retain the child lease across parent intent publication.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Consume the original service/signer and retain one approved root operation.
    /// Original parent, child and selection state remain; failures can follow
    /// commit and must resume the same independent plan without old traffic.
    pub async fn begin_transferred_account_root_replacement(
        mut self,
        plan: TransferredAccountRootJournalPlan,
    ) -> Result<AccountRootEnrollmentRecovery, DurableError> {
        let owners = *self.active.take().ok_or(DurableError::Closed)?;
        drop(owners.service);
        drop(owners.signer);
        AccountRootEnrollmentRecovery::prepare_transferred(owners.enrollment, plan).await
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl AccountRootEnrollmentRecovery {
    /// Reconcile the existing original enrollment and exact independently retained
    /// plan, without opening its device signer. Existing parent checkpoints bind
    /// the original child image, pending and selection; stale backups are refused.
    /// A verified child result whose parent ACK was lost is retained automatically.
    pub async fn resume_transferred_original(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        plan: TransferredAccountRootJournalPlan,
    ) -> Result<Self, DurableError> {
        Self::prepare_transferred(
            DeviceEnrollment::open_original_storage(paths, intent).await?,
            plan,
        )
        .await
    }
    pub(in crate::enrollment) async fn prepare_transferred(
        enrollment: DeviceEnrollment,
        plan: TransferredAccountRootJournalPlan,
    ) -> Result<Self, DurableError> {
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
        if snapshot.retirement.is_some() {
            return Err(DurableError::Conflict);
        }
        let pin = plan.witness_pin()?.clone();
        let original = validate(&enrollment, &snapshot.image, &pin, plan.proposal())?;
        let Phase::Accepted { admission, .. } = &snapshot.image.phase else {
            return Err(DurableError::Suspended);
        };
        plan.check_parent(&original, admission.journal, admission.policy)?;
        let fresh = snapshot.root_replacement.is_none();
        if fresh && !plan.attempts().is_empty() {
            return Err(DurableError::Absent);
        }
        if let Some(state) = &snapshot.root_replacement {
            if state.proposal != *plan.proposal()
                || state.authority.as_ref() != Some(&plan.binding()?)
                || &state.attempts != plan.attempts()
                || state.child.is_none()
            {
                return Err(DurableError::Conflict);
            }
            check_selection(&plan, snapshot.witness_handoff.as_ref())?;
        }
        let child = AccountRootJournalRecovery::prepare_transferred_parent(
            enrollment.paths.installation.files()[1],
            enrollment.key().await?,
            &original,
            admission.journal,
            plan.clone(),
            snapshot
                .root_replacement
                .as_ref()
                .and_then(|state| state.child),
        )?;
        if fresh {
            match (plan.selection(), child.selection()) {
                (None, None) if snapshot.witness_handoff.is_none() => {}
                (Some(selected), Some(progress)) => {
                    enrollment.retain_witness_progress(
                        &snapshot.image,
                        selected,
                        snapshot.witness_handoff.as_ref(),
                        progress.clone(),
                    )?;
                }
                _ => return Err(DurableError::Suspended),
            }
        }
        let state = match snapshot.root_replacement {
            Some(state) => *state,
            None => {
                let state = State {
                    identity: snapshot.image.identity,
                    image: original_digest(&enrollment)?,
                    journal: admission.journal,
                    proposal: plan.proposal().clone(),
                    receipt: None,
                    history: Vec::new(),
                    child: Some(child.checkpoint()),
                    authority: Some(plan.binding()?),
                    selection: selected_binding(&enrollment)?,
                    attempts: plan.attempts().clone(),
                };
                save(&enrollment, None, &state, "intent")?;
                state
            }
        };
        let journal = child.commit()?;
        let mut owners = Owners {
            journal: Some(journal),
            enrollment,
            pin,
            state,
            transferred: Some(Box::new(plan)),
        };
        owners.read()?;
        owners.reconcile_current_outcome()?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
