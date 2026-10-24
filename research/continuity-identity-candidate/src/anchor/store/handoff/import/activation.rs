// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Target activation commits before returning a service owner or certificate.
use super::*;
mod adoption;
pub(in crate::anchor::store::handoff::import) mod authorization;
pub use authorization::AnchorHandoffClientAuthorizationReceipt;
mod inherited;

const BODY_BYTES: usize = 8 + 5 * 32;
pub(super) const RECEIPT_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;

pub(super) struct Activation {
    pub(super) retirement: Vec<u8>,
    pub(super) receipt: Vec<u8>,
    pub(super) content: Vec<u8>,
}

/// Exact durable target activation. It does not adopt an inherited client or
/// constitute an ordinary request reply, policy grant or account approval.
#[derive(Clone)]
pub struct AnchorHandoffActivationReceipt {
    wire: Vec<u8>,
    checkpoint: [u8; 32],
}
impl AnchorHandoffActivationReceipt {
    /// Retain these original signed bytes; recovery never re-signs activation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Verified history checkpoint, for independent control-plane retention.
    pub fn history_checkpoint(&self) -> [u8; 32] {
        self.checkpoint
    }
}

fn history(
    approval: &AnchorHandoffTargetApproval,
    freeze: &[u8],
    acknowledgement: &[u8],
    retirement: &[u8],
) -> Result<AnchorHandoffHistory, DurableError> {
    let mut history = AnchorHandoffHistory::from_trusted_origin(approval.plan.source.clone());
    history.append_verified(approval, freeze, acknowledgement, retirement)?;
    Ok(history)
}
fn receipt_body(
    approval: &AnchorHandoffTargetApproval,
    freeze: &[u8],
    acknowledgement: &[u8],
    retirement: &[u8],
    history: &AnchorHandoffHistory,
) -> Vec<u8> {
    let mut body = b"QPAHAC01".to_vec();
    for (domain, bytes) in [
        (
            b"Q-PERIAPT-CONTINUITY-ANCHOR-ACTIVATION-APPROVAL/v1".as_slice(),
            approval.to_bytes().as_slice(),
        ),
        (
            b"Q-PERIAPT-CONTINUITY-ANCHOR-ACTIVATION-FREEZE/v1".as_slice(),
            freeze,
        ),
        (
            b"Q-PERIAPT-CONTINUITY-ANCHOR-ACTIVATION-IMPORT/v1".as_slice(),
            acknowledgement,
        ),
        (
            b"Q-PERIAPT-CONTINUITY-ANCHOR-ACTIVATION-RETIREMENT/v1".as_slice(),
            retirement,
        ),
    ] {
        body.extend_from_slice(&digest(domain, bytes));
    }
    body.extend_from_slice(&history.checkpoint());
    body
}

fn verify(
    approval: &AnchorHandoffTargetApproval,
    freeze: &[u8],
    acknowledgement: &[u8],
    retirement: &[u8],
    wire: &[u8],
) -> Result<(AnchorHandoffActivationReceipt, AnchorHandoffHistory), DurableError> {
    let history = history(approval, freeze, acknowledgement, retirement)?;
    let expected = receipt_body(approval, freeze, acknowledgement, retirement, &history);
    let (actual, signature) = open_envelope(wire)?;
    if expected.len() != BODY_BYTES || actual != expected {
        return Err(Error::Scope.into());
    }
    approval
        .plan
        .target
        .key
        .verify(Purpose::AnchorHandoffActivation, actual, signature)?;
    Ok((
        AnchorHandoffActivationReceipt {
            wire: wire.to_vec(),
            checkpoint: history.checkpoint(),
        },
        history,
    ))
}
impl AnchorHandoffTargetApproval {
    /// Independently verify exact target activation under the originally retained
    /// approval, freeze, import and committed source retirement. This historical
    /// certificate grants no inherited client permission or operating reply.
    pub fn verify_activation_receipt(
        &self,
        freeze: &[u8],
        acknowledgement: &[u8],
        retirement: &[u8],
        wire: &[u8],
    ) -> Result<AnchorHandoffActivationReceipt, DurableError> {
        Ok(verify(self, freeze, acknowledgement, retirement, wire)?.0)
    }
}

fn stored_inheritance_error(error: DurableError) -> DurableError {
    match error {
        DurableError::Suspended => DurableError::Corrupt,
        other => other,
    }
}

pub(super) fn validate(
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
    original: &Image,
) -> Result<(), DurableError> {
    let Some(activation) = &image.activation else {
        return Ok(());
    };
    if image.cancellation.is_some() {
        return Err(DurableError::Corrupt);
    }
    let (_, history) = verify(
        approval,
        &image.freeze,
        &image.acknowledgement,
        &activation.retirement,
        &activation.receipt,
    )?;
    let current = image_codec::decode_content(&history, &activation.content)?;
    inherited::check(original, &current, &history, &image.client_index)
        .map_err(stored_inheritance_error)
}

// Verified immutable proofs are cached by this controlled owner. Each load still
// authenticates the complete row and checks its exact immutable commitment and
// current content. No incoming state can select new history keys/checkpoints.
pub(in crate::anchor::store) struct Transferred {
    client_index: BTreeMap<[u8; 32], [u8; 32]>,
    client_contexts: BTreeMap<[u8; 32], crate::AnchorHandoffReplyContext>,
    approval: AnchorHandoffTargetApproval,
    immutable: [u8; 32],
    history: AnchorHandoffHistory,
    original: Image,
}
fn immutable(image: &ImportedImage) -> Result<[u8; 32], DurableError> {
    let activation = image.activation.as_ref().ok_or(DurableError::Corrupt)?;
    if image.cancellation.is_some() {
        return Err(DurableError::Corrupt);
    }
    let mut body = b"QPAHAC-IMMUTABLE/v1".to_vec();
    for value in [
        &image.source,
        &image.freeze,
        &image.acknowledgement,
        &activation.retirement,
        &activation.receipt,
    ] {
        super::super::codec::put(value, &mut body)?;
    }
    Ok(digest(
        b"Q-PERIAPT-CONTINUITY-ANCHOR-ACTIVATED-IMMUTABLE/v1",
        &body,
    ))
}
impl Transferred {
    fn new(
        db: &Database,
        key: &JournalKey,
        approval: AnchorHandoffTargetApproval,
        image: &ImportedImage,
    ) -> Result<Self, DurableError> {
        let original = storage::validate_source(key, &approval, &image.source, &image.freeze)?;
        validate(&approval, image, &original)?;
        let client_contexts = authorization::verified_contexts(db, &approval, image, &original)?;
        let activation = image.activation.as_ref().ok_or(DurableError::Absent)?;
        Ok(Self {
            client_index: image.client_index.clone(),
            client_contexts,
            immutable: immutable(image)?,
            history: history(
                &approval,
                &image.freeze,
                &image.acknowledgement,
                &activation.retirement,
            )?,
            approval,
            original,
        })
    }
    pub(in crate::anchor::store) fn namespace(&self) -> [u8; 32] {
        self.history.namespace_binding()
    }
    pub(in crate::anchor::store) fn client_context(
        &self,
        subject: AnchorSubject,
    ) -> Result<crate::AnchorHandoffReplyContext, DurableError> {
        self.client_contexts
            .get(&subject.id(&self.namespace()))
            .copied()
            .ok_or(DurableError::Suspended)
    }
    fn admit(&self, image: &ImportedImage) -> Result<(), DurableError> {
        if immutable(image)? != self.immutable || image.client_index != self.client_index {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(in crate::anchor::store) fn load(
        &self,
        db: &Database,
        key: &JournalKey,
    ) -> Result<Image, DurableError> {
        let saved = storage::load_authenticated(db, key, &self.approval)?;
        self.admit(&saved)?;
        let activation = saved.activation.as_ref().ok_or(DurableError::Corrupt)?;
        let mut image = image_codec::decode_content(&self.history, &activation.content)?;
        inherited::check(&self.original, &image, &self.history, &self.client_index)
            .map_err(stored_inheritance_error)?;
        image.inherited = self.original.entries.keys().copied().collect();
        image.digest = saved.digest;
        Ok(image)
    }
    pub(in crate::anchor::store) fn persist(
        &self,
        db: &Database,
        key: &JournalKey,
        image: &mut Image,
        admit_commit: impl FnOnce() -> Result<(), DurableError>,
    ) -> Result<(), DurableError> {
        inherited::check(&self.original, image, &self.history, &self.client_index)?;
        let mut saved = storage::load_authenticated(db, key, &self.approval)?;
        self.admit(&saved)?;
        if saved.digest != image.digest {
            return Err(DurableError::Conflict);
        }
        saved
            .activation
            .as_mut()
            .ok_or(DurableError::Corrupt)?
            .content = image_codec::encode_content(&self.history, image)?;
        let bytes = storage::seal(key, &self.approval, &saved)?;
        let tx = transaction(db)?;
        {
            let mut table = tx.open_table(IMPORT_TABLE).map_err(storage)?;
            if table.len().map_err(storage)? != 1 {
                return Err(DurableError::Corrupt);
            }
            let current = table
                .get("image")
                .map_err(storage)?
                .ok_or(DurableError::Corrupt)?;
            if storage::image_digest(current.value()) != image.digest {
                return Err(DurableError::Conflict);
            }
            drop(current);
            table.insert("image", bytes.as_slice()).map_err(storage)?;
        }
        admit_commit()?;
        tx.commit().map_err(DurableError::CommitUncertain)?;
        image.digest = storage::image_digest(&bytes);
        Ok(())
    }
}

impl AnchorHandoffTarget {
    /// Complete an already committed source retirement in this original import.
    /// Persist the exact retirement, activation certificate and complete current
    /// content atomically before returning a service owner. Expiry does not erase
    /// an admitted/committed transaction. Inherited clients remain suspended until
    /// independently approved adoption; new trusted enrollment uses current pins.
    ///
    /// Retain the original approval, retirement, target key and path. An error
    /// may follow commit: reopen this same target, inspect its activation receipt
    /// and retry these exact inputs. A different retirement cannot replace it.
    /// Further handoff and inherited-client adoption remain separate candidate
    /// integration gates; this owner must not bypass them through legacy methods.
    pub fn activate(
        &mut self,
        retirement: &[u8],
        signer: AnchorSigningKey,
    ) -> Result<(AnchorStore, AnchorHandoffActivationReceipt), DurableError> {
        let mut image = self.image()?;
        if image.cancellation.is_some() {
            return Err(Error::Retired.into());
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        if signer.public_key()? != owner.approval.plan.target.key {
            return Err(Error::Scope.into());
        }
        let history = history(
            &owner.approval,
            &image.freeze,
            &image.acknowledgement,
            retirement,
        )?;
        if let Some(activation) = &image.activation {
            if activation.retirement != retirement {
                return Err(DurableError::Conflict);
            }
        } else {
            let original = storage::validate_source(
                &owner.wrapping,
                &owner.approval,
                &image.source,
                &image.freeze,
            )?;
            original.check_witness_key(&owner.approval.plan.target.key)?;
            let content = image_codec::encode_content(&history, &original)?;
            storage::preflight_activation(
                &owner.approval,
                image.source.len(),
                image.freeze.len(),
                image.acknowledgement.len(),
                retirement.len(),
                content.len(),
            )?;
            let body = receipt_body(
                &owner.approval,
                &image.freeze,
                &image.acknowledgement,
                retirement,
                &history,
            );
            if body.len() != BODY_BYTES {
                return Err(DurableError::Corrupt);
            }
            let receipt = envelope(
                &body,
                &signer.sign(Purpose::AnchorHandoffActivation, &body)?,
            )?;
            image.activation = Some(Activation {
                retirement: retirement.to_vec(),
                receipt,
                content,
            });
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            testing::after_commit("activate");
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let transferred =
            Transferred::new(&owner.db, &owner.wrapping, owner.approval.clone(), &image)?;
        let pin = owner.approval.plan.target.clone();
        let receipt = AnchorHandoffActivationReceipt {
            wire: image
                .activation
                .as_ref()
                .ok_or(DurableError::Corrupt)?
                .receipt
                .clone(),
            checkpoint: history.checkpoint(),
        };
        let owner = self.active.take().ok_or(DurableError::Closed)?;
        Ok((
            AnchorStore {
                active: Some(Active {
                    db: owner.db,
                    wrapping: owner.wrapping,
                    signer,
                    pin,
                    transferred: Some(transferred),
                }),
            },
            receipt,
        ))
    }
    /// Recover the exact already committed activation without either signing key.
    pub fn activation_receipt(&mut self) -> Result<AnchorHandoffActivationReceipt, DurableError> {
        let image = self.image()?;
        let activation = image.activation.as_ref().ok_or(DurableError::Absent)?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let history = history(
            &owner.approval,
            &image.freeze,
            &image.acknowledgement,
            &activation.retirement,
        )?;
        Ok(AnchorHandoffActivationReceipt {
            wire: activation.receipt.clone(),
            checkpoint: history.checkpoint(),
        })
    }
}
