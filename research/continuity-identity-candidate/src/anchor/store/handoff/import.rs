// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently approved, durable inactive import. No ordinary witness API.
use super::*;
mod approval;
mod archive;
pub use approval::{AnchorHandoffImportReceipt, AnchorHandoffTargetApproval};
pub(in crate::anchor::store) mod activation;
mod source_control;
mod storage;
pub use activation::{AnchorHandoffActivationReceipt, AnchorHandoffClientAuthorizationReceipt};
pub(in crate::anchor::store::handoff) use storage::preflight_activation;
#[cfg(all(test, unix))]
mod testing;

const IMPORT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_import_v1");
// Preserve the entire original 1 MiB content allowance, with a separately
// bounded envelope for the two approvals and exact lifecycle certificates.
const MAX_IMPORT_IMAGE: usize = MAX_IMAGE + 32 * 1024;

#[derive(Clone)]
struct ImportedImage {
    source_archived: bool,
    source_control: Option<[u8; 32]>,
    client_index: BTreeMap<[u8; 32], [u8; 32]>,
    activation: Option<activation::Activation>,
    source: Vec<u8>,
    freeze: Vec<u8>,
    acknowledgement: Vec<u8>,
    cancellation: Option<Vec<u8>>,
    digest: [u8; 32],
}
struct ImportedOwner {
    db: Database,
    wrapping: JournalKey,
    approval: AnchorHandoffTargetApproval,
}

/// Durable target observation. Only explicit activation returns a service owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorHandoffTargetState {
    /// Complete original state is retained while source retirement is unresolved.
    ImportedInactive,
    /// Target activation is committed; inherited clients still need adoption.
    Activated,
    /// Exact source cancellation is retained; this import cannot be activated.
    Cancelled,
}

/// Owner of independently approved imported metadata under a new storage key.
/// It has no ordinary request handler. Target activation and client adoption
/// require separate transactions, never a freeze or import acknowledgement.
pub struct AnchorHandoffTarget {
    active: Option<ImportedOwner>,
}
impl AnchorHandoffTarget {
    /// Publish a new complete inactive import without replacing any existing
    /// destination. Validate source signature, exact full commitment and every
    /// original image record before local authentication with the target key.
    /// The source storage key and source private signer are never inputs.
    ///
    /// Retain the independently approved configuration before calling. A failed
    /// publication may already have committed: reopen the same destination with
    /// that exact approval. Never reset an existing/unknown import or infer a
    /// fresh first use from absence after an earlier successful publication.
    pub fn provision_import(
        path: &Path,
        wrapping: JournalKey,
        signer: &AnchorSigningKey,
        approval: AnchorHandoffTargetApproval,
        source: &[u8],
        freeze: &[u8],
        now: u64,
    ) -> Result<Self, DurableError> {
        approval.admit(now)?;
        storage::validate_source(&wrapping, &approval, source, freeze)?
            .check_witness_key(&approval.plan.target.key)?;
        let receipt = approval.sign_import(freeze, signer)?;
        let image = ImportedImage {
            source_archived: archive::is_capture(source),
            source_control: None,
            client_index: BTreeMap::new(),
            activation: None,
            source: source.to_vec(),
            freeze: freeze.to_vec(),
            acknowledgement: receipt.as_bytes().to_vec(),
            cancellation: None,
            digest: [0; 32],
        };
        let bytes = storage::encode(&wrapping, &approval, &image)?;
        let db = provision_private_database(path, |db| {
            let tx = transaction(db)?;
            if image.source_archived {
                archive::publish(&tx, &approval, &image.source)?;
            }
            tx.open_table(IMPORT_TABLE)
                .map_err(storage)?
                .insert("image", bytes.as_slice())
                .map_err(storage)?;
            tx.commit().map_err(DurableError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            testing::after_commit("import-unpublished");
            Ok::<_, DurableError>(())
        })?;
        #[cfg(all(test, unix))]
        testing::after_commit("import");
        Self::from_database(db, wrapping, approval)
    }

    /// Reopen the exact retained import, including after admission expires or
    /// a reply is lost. No signing key is needed to recover retained receipts.
    /// Missing, corrupt or differently approved storage is never reprovisioned.
    pub fn open(
        path: &Path,
        wrapping: JournalKey,
        approval: AnchorHandoffTargetApproval,
    ) -> Result<Self, DurableError> {
        Self::from_database(open_private_database(path)?, wrapping, approval)
    }

    pub(in crate::anchor::store) fn from_database(
        db: Database,
        wrapping: JournalKey,
        approval: AnchorHandoffTargetApproval,
    ) -> Result<Self, DurableError> {
        storage::load(&db, &wrapping, &approval)?;
        Ok(Self {
            active: Some(ImportedOwner {
                db,
                wrapping,
                approval,
            }),
        })
    }

    /// Release the database lease and the target's storage-key owner.
    pub fn close(&mut self) {
        self.active = None;
    }

    /// Reauthenticate current durable state; expiry never discards an import.
    pub fn status(&mut self) -> Result<AnchorHandoffTargetState, DurableError> {
        let image = self.image()?;
        Ok(if image.cancellation.is_some() {
            AnchorHandoffTargetState::Cancelled
        } else if image.activation.is_some() {
            AnchorHandoffTargetState::Activated
        } else {
            AnchorHandoffTargetState::ImportedInactive
        })
    }

    /// Recover the exact original import acknowledgement without re-signing.
    /// Cancelled imports return Retired, not a fresh inactive acknowledgement.
    pub fn import_receipt(&mut self) -> Result<AnchorHandoffImportReceipt, DurableError> {
        let image = self.image()?;
        if image.cancellation.is_some() {
            return Err(Error::Retired.into());
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        Ok(owner
            .approval
            .verify_import_receipt(&image.freeze, &image.acknowledgement)?)
    }

    /// Retained complete original metadata, including after exact cancellation.
    /// These bytes alone grant no authority or permission to serve requests.
    pub fn retained_source_state(&mut self) -> Result<Vec<u8>, DurableError> {
        Ok(self.image()?.source)
    }

    /// Verify the exact source retirement against the retained import
    /// and construct its historical namespace/authority proof. This is read-only:
    /// it does not retain the new certificate, activate the target, change a
    /// client policy, or authorize ordinary service. After activation, only the
    /// exact committed retirement may select this owner's history. The source image
    /// admits only an original authority; transferred-image support is separate.
    pub fn verify_source_retirement(
        &mut self,
        retirement: &[u8],
    ) -> Result<AnchorHandoffHistory, DurableError> {
        let image = self.image()?;
        if image.cancellation.is_some() {
            return Err(Error::Retired.into());
        }
        if image.source_archived {
            return Err(DurableError::Suspended);
        }
        if image
            .activation
            .as_ref()
            .is_some_and(|activation| activation.retirement != retirement)
        {
            return Err(DurableError::Conflict);
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let mut history =
            AnchorHandoffHistory::from_trusted_origin(owner.approval.plan.source.clone());
        history.append_verified(
            &owner.approval,
            &image.freeze,
            &image.acknowledgement,
            retirement,
        )?;
        let original = storage::validate_source(
            &owner.wrapping,
            &owner.approval,
            &image.source,
            &image.freeze,
        )?;
        // Reuse the complete image validator with the verified historical
        // resolver. Namespace and every retained operation remain byte-exact;
        // recognizing their former authority grants no current client rights.
        let content = image_codec::encode_content(&owner.approval.plan.source, &original)?;
        let transferred = image_codec::decode_content(&history, &content)?;
        if image_codec::encode_content(&history, &transferred)? != content {
            return Err(DurableError::Corrupt);
        }
        Ok(history)
    }

    /// Close only from the exact original source's committed cancellation.
    /// A timeout, expiry, freeze/import receipt or missing reply cannot close it.
    /// Retain the complete original state and terminal bytes for reconciliation.
    pub fn close_cancelled(
        &mut self,
        cancellation: &[u8],
    ) -> Result<AnchorHandoffTargetState, DurableError> {
        let mut image = self.image()?;
        if image.activation.is_some() {
            return Err(Error::Retired.into());
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let verified = owner.approval.plan.verify_receipt(cancellation)?;
        if verified.state() != AnchorHandoffState::Cancelled {
            return Err(Error::Scope.into());
        }
        if let Some(retained) = &image.cancellation {
            if retained != cancellation {
                return Err(DurableError::Conflict);
            }
            return Ok(AnchorHandoffTargetState::Cancelled);
        }
        image.cancellation = Some(cancellation.to_vec());
        self.persist(&mut image)?;
        Ok(AnchorHandoffTargetState::Cancelled)
    }

    /// Exact terminal source certificate retained by the closed target.
    pub fn cancellation_receipt(&mut self) -> Result<Vec<u8>, DurableError> {
        self.image()?.cancellation.ok_or(DurableError::Absent)
    }

    fn image(&mut self) -> Result<ImportedImage, DurableError> {
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let result = storage::load(&owner.db, &owner.wrapping, &owner.approval);
        if result.is_err() {
            self.close();
        }
        result
    }

    fn persist(&mut self, image: &mut ImportedImage) -> Result<(), DurableError> {
        let result = (|| {
            let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
            let bytes = storage::encode(&owner.wrapping, &owner.approval, image)?;
            let tx = transaction(&owner.db)?;
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
            tx.commit().map_err(DurableError::CommitUncertain)?;
            image.digest = storage::image_digest(&bytes);
            #[cfg(all(test, unix))]
            testing::after_commit("cancel");
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
