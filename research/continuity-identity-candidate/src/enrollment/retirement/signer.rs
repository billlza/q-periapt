// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original signing-file plan, observation and logical erasure.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredDeviceEnrollment {
    /// Retain an exact original signer-file plan after authenticated journal erasure
    /// and a verified legacy purpose-21 or transferred purpose-38 host acknowledgement. This authenticates the original device
    /// role, public key, file identity and encrypted bytes without returning a signer.
    /// Exact retries retain the first plan and perform no file mutation.
    pub async fn prepare_signer_erasure(&mut self, receipt: &[u8]) -> Result<(), DurableError> {
        let result = self.prepare_signer_erasure_attempt(receipt).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn prepare_signer_erasure_attempt(&mut self, receipt: &[u8]) -> Result<(), DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        let (image, state, original) = owners.read()?;
        if let Some(plan) = &state.signer {
            owners.verify_plan_receipt(plan, Some(receipt))?;
            return Ok(());
        }
        let pin = owners.pin.clone();
        let child = owners.installation().await?;
        if child.journal_erasure_status(&pin).await? != JournalErasureState::Erased {
            return Err(DurableError::Suspended);
        }
        let ack = child.verify_host_acknowledgement(&pin, receipt)?;
        let proof = match child.retained_transferred_control()? {
            Some(control) => SignerProof::Transferred(control),
            None => SignerProof::Legacy(receipt.to_vec()),
        };
        let active = owners
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        let file = SigningFilePlan::capture(
            &owners.enrollment.storage,
            &owners.enrollment.paths.signer,
            &active.key,
            image.identity,
            &original,
            &ack,
        )
        .await?;
        let mut next = state.clone();
        next.signer = Some(Box::new(SignerPlan { file, proof }));
        save(&owners.enrollment, Some(&state), &next)?;
        owners.state = next;
        Ok(())
    }

    /// Query the original prepared file. Missing, foreign or corrupt state is an
    /// error. A full-length partially marked file still retains encrypted seeds.
    /// This requires the independently stored complete host ACK, never just a tag.
    pub async fn signer_erasure_status(&mut self) -> Result<SigningFileErasureState, DurableError> {
        let result = self.signer_erasure_status_attempt().await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn signer_erasure_status_attempt(
        &mut self,
    ) -> Result<SigningFileErasureState, DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let (_, state, original) = owners.read()?;
        let plan = state.signer.as_ref().ok_or(DurableError::Suspended)?;
        let ack = owners.verify_plan(plan)?;
        let active = owners
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        Ok(
            if plan
                .file
                .erased(
                    &owners.enrollment.storage,
                    &owners.enrollment.paths.signer,
                    &active.key,
                    &original,
                    &ack,
                )
                .await?
            {
                SigningFileErasureState::Erased
            } else {
                SigningFileErasureState::Retained
            },
        )
    }
    /// Logically erase only the exact prepared original signing file. Sync the fixed
    /// retirement header before truncating its encrypted body, then sync again.
    /// Always closes this owner; reopen and retry the original plan after I/O failure.
    /// Wrapping key, historical configuration, old pages/backups and previously copied
    /// signing owners remain outside this logical erasure claim.
    pub async fn erase_signer(&mut self) -> Result<(), DurableError> {
        let result = self.erase_signer_attempt().await;
        self.close();
        result
    }
    async fn erase_signer_attempt(&mut self) -> Result<(), DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let (_, state, original) = owners.read()?;
        let plan = state.signer.as_ref().ok_or(DurableError::Suspended)?;
        let ack = owners.verify_plan(plan)?;
        let active = owners
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        plan.file
            .erase(
                &owners.enrollment.storage,
                &owners.enrollment.paths.signer,
                &active.key,
                &original,
                &ack,
            )
            .await
    }
}
