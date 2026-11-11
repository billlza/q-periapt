// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Full independent context follows the original parent, without recreating a signer.
use super::*;

pub(super) fn check_snapshot(
    enrollment: &DeviceEnrollment,
    snapshot: &EnrollmentSnapshot,
    context: &TransferredRetirementContext,
) -> Result<(), DurableError> {
    snapshot
        .root_replacement
        .as_ref()
        .ok_or(DurableError::Conflict)?
        .check_retirement_context(context)?;
    let original = enrollment.original_device_metadata(&snapshot.image)?;
    let Phase::Accepted { admission, .. } = &snapshot.image.phase else {
        return Err(DurableError::Conflict);
    };
    context
        .plan()
        .check_parent(&original, admission.journal, admission.policy)?;
    match (
        context.plan().selection(),
        snapshot.witness_handoff.as_ref(),
    ) {
        (None, None) => {}
        (Some(plan), Some(selected)) => selected.check_plan(plan)?,
        _ => return Err(DurableError::Conflict),
    }
    Ok(())
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
pub(super) async fn installation(
    enrollment: &DeviceEnrollment,
    retired: AnchorRetiredSubject,
    context: Option<&TransferredRetirementContext>,
) -> Result<RetiredInstallationRecovery, DurableError> {
    if let Some(context) = context {
        RetiredInstallationRecovery::open_transferred_with_storage(
            enrollment.storage.clone(),
            enrollment.paths.installation.clone(),
            enrollment.key().await?,
            context.clone(),
        )
        .await
    } else {
        RetiredInstallationRecovery::open_with_storage(
            enrollment.storage.clone(),
            enrollment.paths.installation.clone(),
            enrollment.key().await?,
            retired,
        )
        .await
    }
}
impl Owners {
    pub(super) fn verify_plan_receipt(
        &self,
        plan: &SignerPlan,
        incoming: Option<&[u8]>,
    ) -> Result<AnchorRetiredReportAcknowledgement, DurableError> {
        match (self.context.as_deref(), &plan.proof) {
            (None, SignerProof::Legacy(saved)) => {
                Ok(self.pin.verify_retired_report_acknowledgement(
                    self.retired,
                    plan.file.report(),
                    incoming.unwrap_or(saved),
                )?)
            }
            (Some(context), SignerProof::Transferred(saved)) => {
                let key = &self
                    .enrollment
                    .active
                    .as_ref()
                    .ok_or(DurableError::Closed)?
                    .key;
                let report = plan.file.report();
                let control = Control::decode(
                    key,
                    context,
                    &self.state.inventory,
                    Some(report),
                    Some(report),
                    saved,
                )?;
                let receipt =
                    control.verified(crate::AnchorTransferredCleanupStage::Acknowledged)?;
                control.acknowledgement(context, report, incoming.unwrap_or(receipt.as_bytes()))
            }
            _ => Err(DurableError::Conflict),
        }
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredDeviceEnrollment {
    #[cfg(all(test, unix))]
    pub(crate) fn open_transferred_database(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        context: TransferredRetirementContext,
        database: Database,
    ) -> Result<Self, DurableError> {
        let pin = context.accounting_pin().clone();
        let retired = context.retired_subject();
        Self::open_context_in_database(
            paths,
            intent,
            pin,
            retired,
            Some(Box::new(context)),
            database,
        )
    }
    pub(in crate::enrollment) fn check_transferred_decision(
        &self,
        wire: &[u8],
    ) -> Result<(), DurableError> {
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        owner.read()?;
        if owner
            .context
            .as_ref()
            .ok_or(DurableError::Conflict)?
            .decision()
            != wire
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn check_transferred_managed_checkpoint(
        &self,
        preparation: &crate::TransferredAccountRootPreparation,
        expected: [u8; 32],
    ) -> Result<(), DurableError> {
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        owner.read()?;
        let context = owner.context.as_ref().ok_or(DurableError::Conflict)?;
        let independently_bound = TransferredRetirementContext::new(
            preparation.bind(context.plan().approval().clone())?,
            context.decision(),
            context.retired_subject().subject(),
            preparation.history.clone(),
        )?;
        let saved = owner.state.context.as_ref().ok_or(DurableError::Conflict)?;
        if independently_bound.binding() != context.binding()
            || preparation.original_checkpoint(
                account_root::original_digest(&owner.enrollment)?,
                saved.original_child,
            )? != expected
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Recover the original historical parent under its complete independently
    /// retained plan, Committed decision, selection and accounting history. This
    /// opens no signer and grants no traffic. A later accounting history must be
    /// supplied independently; it is never inferred from stored or peer receipts.
    pub async fn open_transferred(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        context: TransferredRetirementContext,
    ) -> Result<Self, DurableError> {
        Self::from_transferred_enrollment(
            DeviceEnrollment::open_original_storage(paths, intent).await?,
            context,
        )
        .await
    }
    pub(in crate::enrollment) async fn from_transferred_enrollment(
        enrollment: DeviceEnrollment,
        context: TransferredRetirementContext,
    ) -> Result<Self, DurableError> {
        let pin = context.accounting_pin().clone();
        let retired = context.retired_subject();
        Self::from_enrollment_context(enrollment, pin, retired, Some(Box::new(context))).await
    }
}
