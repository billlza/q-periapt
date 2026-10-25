// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retained source retirement: prepare privately, admit commit, then release.
use super::*;

#[derive(Clone)]
pub(super) struct Retirement {
    pub(super) approval: AnchorHandoffTargetApproval,
    pub(super) acknowledgement: Vec<u8>,
    pub(super) receipt: AnchorHandoffReceipt,
}

impl AnchorHandoffTargetApproval {
    fn retirement_body(
        &self,
        freeze: &[u8],
        acknowledgement: &[u8],
        admitted_at: u64,
    ) -> Result<Vec<u8>, Error> {
        self.admit(admitted_at)?;
        self.verify_import_receipt(freeze, acknowledgement)?;
        let mut body = b"QPAHRT01".to_vec();
        body.extend_from_slice(&self.plan.to_bytes());
        let approval = self.to_bytes();
        for (domain, bytes) in [
            (
                b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-TARGET-APPROVAL/v1".as_slice(),
                approval.as_slice(),
            ),
            (
                b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-FREEZE/v1".as_slice(),
                freeze,
            ),
            (
                b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-IMPORT/v1".as_slice(),
                acknowledgement,
            ),
        ] {
            body.extend_from_slice(&digest(domain, bytes));
        }
        body.extend_from_slice(&admitted_at.to_be_bytes());
        Ok(body)
    }

    /// Verify the exact source retirement against this independently retained
    /// approval and original committed freeze/import bytes. Admission expiry
    /// does not invalidate an already committed historical decision. This does
    /// not activate a target, renew client grants or authorize client adoption.
    pub fn verify_retirement_receipt(
        &self,
        freeze: &[u8],
        acknowledgement: &[u8],
        wire: &[u8],
    ) -> Result<AnchorHandoffReceipt, Error> {
        let receipt = self.plan.verify_receipt(wire)?;
        if receipt.state != AnchorHandoffState::Retired {
            return Err(Error::Scope);
        }
        let (body, _) = open_envelope(wire)?;
        let mut d = Decoder::new(body);
        d.take(8 + self.plan.to_bytes().len() + 3 * 32)?;
        let admitted_at = d.u64()?;
        d.finish()?;
        if body != self.retirement_body(freeze, acknowledgement, admitted_at)? {
            return Err(Error::Scope);
        }
        Ok(receipt)
    }
}

impl Retirement {
    pub(super) fn verify(&self, freeze: &AnchorHandoffReceipt) -> Result<(), DurableError> {
        if self.approval.plan.to_bytes() != freeze.plan.to_bytes()
            || self.receipt.plan.to_bytes() != freeze.plan.to_bytes()
            || self.receipt.state != AnchorHandoffState::Retired
        {
            return Err(DurableError::Corrupt);
        }
        self.approval.verify_retirement_receipt(
            freeze.as_bytes(),
            &self.acknowledgement,
            self.receipt.as_bytes(),
        )?;
        Ok(())
    }
}

pub(super) fn sign_retirement(
    approval: &AnchorHandoffTargetApproval,
    freeze: &[u8],
    acknowledgement: &[u8],
    admitted_at: u64,
    signer: &AnchorSigningKey,
) -> Result<AnchorHandoffReceipt, Error> {
    let body = approval.retirement_body(freeze, acknowledgement, admitted_at)?;
    let wire = envelope(
        &body,
        &signer.sign(Purpose::AnchorHandoffRetirement, &body)?,
    )?;
    approval.verify_retirement_receipt(freeze, acknowledgement, &wire)
}

impl AnchorStore {
    /// Irreversibly retire the exact frozen source after authenticating the
    /// target's committed import acknowledgement and independently retained
    /// target approval. Neither a freeze nor an unapproved acknowledgement is
    /// sufficient. No ordinary source operation can resume after this commit.
    ///
    /// The trusted fallible clock is read before signing and again immediately
    /// before committing the database transaction. Both operator intervals must
    /// still admit that second time, which cannot precede the first. A clock,
    /// capacity or signing failure never releases a certificate. Storage/commit
    /// failures close the owner; reopen the original store to observe its actual
    /// state rather than infer noncommit or cancel an unknown retirement.
    ///
    /// Exact retired retries return retained bytes without reading the clock or
    /// signing. The observer can recover the same bytes after old-key removal.
    /// This candidate operation does not implement target activation or client
    /// account-root/policy-root adoption.
    pub fn retire_handoff(
        &mut self,
        approval: &AnchorHandoffTargetApproval,
        acknowledgement: &[u8],
        mut clock: impl FnMut() -> std::io::Result<u64>,
    ) -> Result<AnchorHandoffReceipt, DurableError> {
        let mut image = self.handoff_image()?;
        let journal = image.handoff.as_ref().ok_or(DurableError::Absent)?;
        let observed = journal.observe(&approval.plan)?;
        if let Some(retired) = &journal.retired {
            if retired.approval.to_bytes() != approval.to_bytes()
                || retired.acknowledgement != acknowledgement
            {
                return Err(DurableError::Conflict);
            }
            return Ok(retired.receipt.clone());
        }
        if observed.state != AnchorHandoffState::Frozen {
            return Err(Error::Retired.into());
        }
        // An authenticated target acknowledgement is not evidence that a
        // foreign implementation enforced our retained-key separation rules.
        // Check independently before signing or making retirement irreversible.
        // Historical exact retries above must retain their original decision.
        image.check_witness_key(&approval.plan.target.key)?;
        let admitted_at = clock().map_err(DurableError::Io)?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let receipt = sign_retirement(
            approval,
            observed.as_bytes(),
            acknowledgement,
            admitted_at,
            &owner.signer,
        )?;
        let source = self.frozen_handoff_state(&approval.plan)?;
        let original = import::validate_retirement_source(
            &self.active.as_ref().ok_or(DurableError::Closed)?.wrapping,
            approval,
            source.as_bytes(),
            observed.as_bytes(),
        )?;
        let mut history = original.history.clone();
        history.append_verified(
            approval,
            observed.as_bytes(),
            acknowledgement,
            receipt.as_bytes(),
        )?;
        let content = image_codec::encode_content(&original.history, &image)?;
        if content != image_codec::encode_content(&original.history, &original.image)? {
            return Err(DurableError::Conflict);
        }
        preflight_activation(
            approval,
            source.as_bytes(),
            observed.as_bytes().len(),
            acknowledgement.len(),
            receipt.as_bytes().len(),
            content.len(),
        )?;
        image.handoff.as_mut().ok_or(DurableError::Absent)?.retired = Some(Retirement {
            approval: approval.clone(),
            acknowledgement: acknowledgement.to_vec(),
            receipt: receipt.clone(),
        });
        // The unchanged complete state and all three exact certificates must fit
        // before irreversible work. Capacity failure leaves Frozen cancellable.
        self.preflight_handoff_image(&image)?;
        self.persist_image_checked(&mut image, false, || {
            let now = clock().map_err(DurableError::Io)?;
            if now < admitted_at {
                return Err(Error::Validity.into());
            }
            approval.admit(now)?;
            Ok(())
        })?;
        Ok(receipt)
    }
}
