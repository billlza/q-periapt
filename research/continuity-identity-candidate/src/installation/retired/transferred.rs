// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original installation records the independent decision before network dispatch.
use super::*;
use crate::{AnchorTransferredCleanupApproval, AnchorTransferredCleanupReceipt};
impl Owners {
    pub(super) fn control(&self, saved: &Configuration) -> Result<Option<Control>, DurableError> {
        match (
            &self.context,
            saved.retired_context,
            saved.retired_control.as_deref(),
        ) {
            (None, None, None) => Ok(None),
            (Some(ctx), Some(binding), Some(wire)) if ctx.binding() == binding => {
                Ok(Some(Control::decode(
                    &self.key,
                    ctx,
                    &self.proposal,
                    saved.retired_report.as_ref(),
                    saved.retired_ack.as_ref(),
                    wire,
                )?))
            }
            _ => Err(DurableError::Conflict),
        }
    }
    pub(super) fn proof_authority<'a>(
        &'a self,
        pin: &'a AnchorPin,
        control: Option<&'a Control>,
    ) -> Result<ReceiptAuthority<'a>, DurableError> {
        match (&self.context, control) {
            (None, None) => Ok(ReceiptAuthority::Legacy(pin)),
            (Some(ctx), Some(control)) => {
                ctx.check_pin(pin)?;
                Ok(ReceiptAuthority::Transferred(ctx, control))
            }
            _ => Err(DurableError::Conflict),
        }
    }
}
fn save_control(
    owners: &Owners,
    saved: &Configuration,
    next: &Control,
) -> Result<(), DurableError> {
    let before = saved
        .retired_control
        .as_deref()
        .ok_or(DurableError::Conflict)?;
    let wire = next.encode(&owners.key)?;
    if wire == before {
        return Ok(());
    }
    let tx = transaction(&owners.configuration)?;
    let expected_report = saved.retired_report.as_ref().map(|r| r.to_bytes());
    let expected_ack = saved.retired_ack.as_ref().map(|r| {
        let mut bytes = b"QPCIAK01".to_vec();
        bytes.extend_from_slice(&r.to_bytes());
        bytes
    });
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if table
            .get("retired-authority")
            .map_err(storage)?
            .as_ref()
            .map(|v| v.value())
            != Some(before)
            || table
                .get("retired-cleanup")
                .map_err(storage)?
                .as_ref()
                .map(|v| v.value())
                != Some(request_wire(&owners.proposal, saved.retired_context).as_slice())
            || table
                .get("retired-report")
                .map_err(storage)?
                .as_ref()
                .map(|v| v.value())
                != expected_report.as_deref()
            || table
                .get("retired-ack")
                .map_err(storage)?
                .as_ref()
                .map(|v| v.value())
                != expected_ack.as_deref()
            || table.len().map_err(storage)?
                != 3 + u64::from(saved.retired_report.is_some())
                    + u64::from(saved.retired_ack.is_some())
        {
            return Err(DurableError::Conflict);
        }
        table
            .insert("retired-authority", wire.as_slice())
            .map_err(storage)?;
    }
    #[cfg(all(test, unix))]
    super::super::tests::at_boundary("retired-authority-before-commit");
    tx.commit().map_err(DurableError::CommitUncertain)?;
    #[cfg(all(test, unix))]
    super::super::tests::at_boundary("retired-authority-after-commit");
    Ok(())
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredInstallationRecovery {
    pub(crate) fn retained_transferred_control(&mut self) -> Result<Option<Vec<u8>>, DurableError> {
        let result = (|| {
            self.proposal()?;
            let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
            let saved = read_configuration(&owner.configuration)?;
            if let Some(control) = owner.control(&saved)? {
                control.verified(CleanupStage::Acknowledged)?;
                Ok(Some(saved.retired_control.ok_or(DurableError::Conflict)?))
            } else {
                Ok(None)
            }
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    #[cfg(all(test, unix))]
    pub(crate) fn open_transferred_database(
        configuration: Database,
        paths: InstallationPaths,
        key: JournalKey,
        context: TransferredRetirementContext,
    ) -> Result<Self, DurableError> {
        let retired = context.retired_subject();
        Self::open_database_with_storage(
            configuration,
            crate::storage::Storage::native()?,
            paths,
            key,
            retired,
            Some(Box::new(context)),
        )
    }
    /// Capture the original inventory under a complete independently verified
    /// transferred retirement. Old image/pending/selection bytes are never changed.
    pub async fn open_transferred(
        paths: InstallationPaths,
        key: JournalKey,
        context: TransferredRetirementContext,
    ) -> Result<Self, DurableError> {
        Self::open_transferred_with_storage(crate::storage::Storage::native()?, paths, key, context)
            .await
    }
    pub(crate) async fn open_transferred_with_storage(
        storage: crate::storage::Storage,
        paths: InstallationPaths,
        key: JournalKey,
        context: TransferredRetirementContext,
    ) -> Result<Self, DurableError> {
        let configuration = storage.open_database(&paths.configuration).await?;
        let retired = context.retired_subject();
        Self::open_database_with_storage(
            configuration,
            storage,
            paths,
            key,
            retired,
            Some(Box::new(context)),
        )
        .await
    }
    /// Durably retain an independently authorized exact stage before dispatch.
    /// The next stage requires its predecessor's verified receipt; ACK additionally
    /// requires the original complete host-accounted intent. No effect is executed.
    /// Unknown commit reopens and retries this same approval, never selects another.
    pub fn prepare_transferred_stage(
        &mut self,
        approval: &AnchorTransferredCleanupApproval,
    ) -> Result<Vec<u8>, DurableError> {
        let result = (|| {
            self.proposal()?;
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let saved = read_configuration(&owners.configuration)?;
            let control = owners.control(&saved)?.ok_or(DurableError::Suspended)?;
            let context = owners.context.as_ref().ok_or(DurableError::Suspended)?;
            let next = control.prepare(
                context,
                &owners.proposal,
                saved.retired_report.as_ref(),
                approval,
            )?;
            save_control(owners, &saved, &next)?;
            Ok(approval.to_bytes())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Recover the exact prepared independent stage, including after transport loss.
    /// Absence is not a statement that a remote invocation did not commit.
    pub fn transferred_stage_approval(
        &mut self,
        stage: CleanupStage,
    ) -> Result<AnchorTransferredCleanupApproval, DurableError> {
        let result = (|| {
            self.proposal()?;
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let saved = read_configuration(&owners.configuration)?;
            Ok(owners
                .control(&saved)?
                .ok_or(DurableError::Suspended)?
                .prepared(stage)?
                .clone())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Exact already verified receipt from the original installation, not a query
    /// against the network or permission to regenerate a missing approval.
    pub fn transferred_stage_receipt(
        &mut self,
        stage: CleanupStage,
    ) -> Result<AnchorTransferredCleanupReceipt, DurableError> {
        let result = (|| {
            self.proposal()?;
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let saved = read_configuration(&owners.configuration)?;
            Ok(owners
                .control(&saved)?
                .ok_or(DurableError::Suspended)?
                .verified(stage)?
                .clone())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(super) fn retain_transferred_receipt(
        &mut self,
        pin: &AnchorPin,
        stage: CleanupStage,
        wire: &[u8],
    ) -> Result<AnchorTransferredCleanupReceipt, DurableError> {
        self.proposal()?;
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let context = owners.context.as_ref().ok_or(DurableError::Suspended)?;
        context.check_pin(pin)?;
        let control = owners.control(&saved)?.ok_or(DurableError::Suspended)?;
        let next = control.retain(context, stage, wire)?;
        save_control(owners, &saved, &next)?;
        Ok(next.verified(stage)?.clone())
    }
}
