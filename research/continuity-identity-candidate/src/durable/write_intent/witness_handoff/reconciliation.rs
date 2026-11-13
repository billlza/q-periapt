// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh current-witness evidence reconciles the original sealed operation.
use super::*;
use crate::{AnchorTransport, DeviceSigningKey};
use std::time::Duration;
mod operation;
use operation::Expected;

/// Fresh transferred-witness classification of original local work. It does not
/// grant current traffic permission or silently discard pending/terminal records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessPendingRecovery {
    /// No local intent, and a fresh current-witness head matches the original image.
    Current,
    /// The ordinary intent's predecessor is current; no permanent non-commit claim.
    AdvancePending,
    /// The original exact ordinary command is applied; its sealed target is local.
    AdvanceApplied,
    /// Exact original credential/head operation, including explicit Unavailable.
    Credential(crate::AnchorCredentialRenewalState),
    /// Exact original policy/head operation, including explicit Unavailable.
    Policy(crate::AnchorPolicyRenewalState),
    /// Exact original roster/head operation, including explicit Unavailable.
    Roster(crate::AnchorRosterRefreshState),
    /// Exact original grant-only cancellation, without a fabricated target image.
    Cancellation(crate::AnchorCredentialCancellationState),
}
impl WitnessJournalAdoption {
    /// Attach a finite-budget carrier and the original device signer only after
    /// reading this journal's durable adopted decision. Carrier bytes never pick
    /// the witness history or logical command authority. Failure closes this owner.
    pub fn attach_current_witness(
        &mut self,
        signer: DeviceSigningKey,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<(), DurableError> {
        let result = (|| {
            let owner = self.active.as_mut().ok_or(DurableError::Closed)?;
            let fence = owner.read()?;
            let receipt = fence.receipt.ok_or(DurableError::Suspended)?;
            if signer.public_key()? != owner.plan.device {
                return Err(Error::Scope.into());
            }
            let authority = crate::anchor::transferred::Authority::verified(
                &owner.plan.approved,
                &owner.plan.history,
                &receipt,
                &owner.plan.request,
            )?;
            owner.client = Some(crate::AnchorClient::from_handoff(
                authority,
                fence.lineage.checkpoint(fence.prepared_at)?,
                signer,
                transport,
                timeout,
            )?);
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Consume this journal lease and transfer its already attached current
    /// witness client to the original installation or renewal coordinator.
    /// The durable selection remains required on every subsequent journal read
    /// and transaction. This does not grant traffic permission, clear pending
    /// work, or acknowledge a coordinator result.
    pub fn into_current_witness(mut self) -> Result<crate::AnchorClient, DurableError> {
        let mut owner = self.active.take().ok_or(DurableError::Closed)?;
        let fence = owner.read()?;
        let receipt = fence.receipt.ok_or(DurableError::Suspended)?;
        let client = owner.client.take().ok_or(DurableError::AnchorRequired)?;
        client.check_journal_selection(
            &fence.request,
            &receipt,
            fence.lineage.checkpoint(fence.prepared_at)?,
        )?;
        Ok(client)
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl WitnessJournalAdoption {
    /// Query the exact retained operation through the currently adopted witness.
    /// Only an authenticated exact Applied result installs its already sealed
    /// target, atomically with the control row. Original pending bytes remain for
    /// coordinator acknowledgement. This sends no Commit, Close, ACK or new work.
    /// A dropped polled future or error consumes this lease and signing owner;
    /// recover this same journal, plan and operation after any unknown result.
    pub async fn recover_original_pending(
        &mut self,
    ) -> Result<WitnessPendingRecovery, DurableError> {
        let mut owner = self.active.take().ok_or(DurableError::Closed)?;
        let fence = owner.read()?;
        if fence.receipt.is_none() {
            return Err(DurableError::Suspended);
        }
        let (image, pending) = owner.snapshot()?;
        let expected =
            Expected::from_snapshot(&image, pending.as_ref(), owner.plan.scope().subject())?;
        let reply = owner
            .client
            .as_mut()
            .ok_or(DurableError::AnchorRequired)?
            .exchange(owner.plan.scope().subject(), expected.operation())
            .await?;
        let (state, applied) = expected.classify(&reply)?;
        if applied {
            let Some(PendingIntent::Write(pending)) = &pending else {
                return Err(DurableError::Conflict);
            };
            install(&owner, &fence, &image, pending)?;
        }
        owner.read()?;
        self.active = Some(owner);
        Ok(state)
    }
}
fn install(
    owner: &Owners,
    fence: &Fence,
    image: &Image,
    pending: &PendingWrite,
) -> Result<(), DurableError> {
    let target = pending.authenticated_target(&owner.key, image.owner)?;
    pending.check_retained_target(&target)?;
    owner.plan.check_image(&target)?;
    if image.digest == pending.next_digest {
        pending.check_retained_target(image)?;
        return Ok(());
    }
    pending.check_current(image)?;
    let before = fence.encode(&owner.key)?;
    let mut next = fence.clone();
    next.image = pending.next_digest;
    let control = next.encode(&owner.key)?;
    let tx = transaction(&owner.db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if table.len().map_err(storage)? != 3 {
            return Err(DurableError::Corrupt);
        }
        let saved = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if image_hash(saved.value()) != image.digest {
            return Err(DurableError::Conflict);
        }
        drop(saved);
        if table
            .get("pending")
            .map_err(storage)?
            .as_ref()
            .map(|r| r.value())
            != Some(pending.wire.as_slice())
            || table.get(ROW).map_err(storage)?.as_ref().map(|r| r.value())
                != Some(before.as_slice())
        {
            return Err(DurableError::Conflict);
        }
        table
            .insert("image", pending.target.as_slice())
            .map_err(storage)?;
        table.insert(ROW, control.as_slice()).map_err(storage)?;
    }
    #[cfg(all(test, unix))]
    tests::boundary("reconcile", false);
    tx.commit().map_err(DurableError::CommitUncertain)?;
    #[cfg(all(test, unix))]
    tests::boundary("reconcile", true);
    if owner.read()?.encode(&owner.key)? != control {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}
