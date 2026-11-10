// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A separate durable server authorization; it never asserts client adoption.
use super::*;
use crate::{session_policy::RetainedAdoptionRequest, HistoricalAnchorHandoffAdoption};
mod record;
mod transaction;
use record::Record;

pub(in crate::anchor::store::handoff::import) const TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_clients_v1");
pub(in crate::anchor::store::handoff::import) const MAX_RECORD_BYTES: usize = 16 * 1024;
const RECEIPT_BYTES: usize = 4 + 80 + crate::crypto::SIGNATURE_BYTES;

/// Exact target authorization of one original client's dual-approved transfer.
/// This is not proof that its original journal adopted the new witness, nor an
/// ordinary request reply or credential/policy renewal.
#[derive(Clone)]
pub struct AnchorHandoffClientAuthorizationReceipt {
    wire: Vec<u8>,
    scope: crate::AnchorHandoffAdoptionScope,
    admitted_at: u64,
}
fn receipt_body(approved: &HistoricalAnchorHandoffAdoption, at: u64) -> Vec<u8> {
    let mut body = b"QPAHCA01".to_vec();
    body.extend_from_slice(&approved.scope().statement_digest());
    body.extend_from_slice(&digest(
        b"Q-PERIAPT-WITNESS-CLIENT-APPROVALS/v1",
        approved.as_bytes(),
    ));
    body.extend_from_slice(&at.to_be_bytes());
    body
}
impl AnchorHandoffClientAuthorizationReceipt {
    /// Exact bytes retained by the target's completed transaction.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Original independently approved scope, not an installed-state claim.
    pub fn scope(&self) -> &crate::AnchorHandoffAdoptionScope {
        &self.scope
    }
    /// Historical time admitted by the target before its transaction.
    pub fn admitted_at(&self) -> u64 {
        self.admitted_at
    }
    /// Verify the current target's exact receipt against both independently
    /// verified issuer approvals and the independently pinned history.
    pub fn verify(
        wire: &[u8],
        approved: &HistoricalAnchorHandoffAdoption,
        history: &AnchorHandoffHistory,
    ) -> Result<Self, Error> {
        if wire.len() != RECEIPT_BYTES
            || approved.scope().history != history.checkpoint()
            || approved.scope().successor != history.current_pin().binding()
        {
            return Err(Error::Scope);
        }
        let (body, signature) = open_envelope(wire)?;
        let mut d = Decoder::new(body);
        d.take(72)?;
        let at = d.u64()?;
        d.finish()?;
        approved.check_admission(at)?;
        if body != receipt_body(approved, at) {
            return Err(Error::Scope);
        }
        history.current_pin().public_key().verify(
            Purpose::AnchorHandoffClientAuthorization,
            body,
            signature,
        )?;
        Ok(Self {
            wire: wire.to_vec(),
            scope: approved.scope().clone(),
            admitted_at: at,
        })
    }
    fn sign(
        signer: &AnchorSigningKey,
        approved: &HistoricalAnchorHandoffAdoption,
        history: &AnchorHandoffHistory,
        at: u64,
    ) -> Result<Self, Error> {
        if signer.public_key()? != *history.current_pin().public_key() {
            return Err(Error::Scope);
        }
        let body = receipt_body(approved, at);
        let wire = envelope(
            &body,
            &signer.sign(Purpose::AnchorHandoffClientAuthorization, &body)?,
        )?;
        Self::verify(&wire, approved, history)
    }
}
pub(in crate::anchor::store::handoff::import) fn record_digest(bytes: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-WITNESS-CLIENT-AUTHORIZATION-ROW/v1", bytes)
}
pub(in crate::anchor::store::handoff::import) fn check_row_hashes(
    read: &redb::ReadTransaction,
    index: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<(), DurableError> {
    if index.is_empty() {
        return Ok(());
    }
    let table = read.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)?
        != u64::try_from(index.len()).map_err(|_| DurableError::Capacity)?
    {
        return Err(DurableError::Corrupt);
    }
    for (id, commitment) in index {
        let bytes = table
            .get(id.as_slice())
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if bytes.value().len() > MAX_RECORD_BYTES || record_digest(bytes.value()) != *commitment {
            return Err(DurableError::Corrupt);
        }
    }
    Ok(())
}
pub(in crate::anchor::store::handoff::import) fn load_records(
    db: &Database,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
    original: &storage::SourceState,
) -> Result<BTreeMap<[u8; 32], Record>, DurableError> {
    if image.client_index.is_empty() {
        return Ok(BTreeMap::new());
    }
    decode_records(
        &capture_rows(db, &image.client_index)?,
        approval,
        image,
        original,
    )
}

pub(in crate::anchor::store::handoff::import) fn capture_rows(
    db: &Database,
    index: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<BTreeMap<[u8; 32], Vec<u8>>, DurableError> {
    if index.is_empty() {
        return Ok(BTreeMap::new());
    }
    let read = db.begin_read().map_err(storage)?;
    check_row_hashes(&read, index)?;
    let table = read.open_table(TABLE).map_err(storage)?;
    let mut bytes = BTreeMap::new();
    for id in index.keys() {
        let value = table
            .get(id.as_slice())
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        bytes.insert(*id, value.value().to_vec());
    }
    Ok(bytes)
}

// Used by both the database reader and a complete public source capture. No
// unindexed row, absent row or valid signature from another subject is accepted.
pub(in crate::anchor::store::handoff::import) fn decode_records(
    bytes: &BTreeMap<[u8; 32], Vec<u8>>,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
    original: &storage::SourceState,
) -> Result<BTreeMap<[u8; 32], Record>, DurableError> {
    if bytes.len() != image.client_index.len() || bytes.len() > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let (receipt, history) = verified_activation(approval, image, original)?;
    let mut operations = std::collections::BTreeSet::new();
    let mut records = BTreeMap::new();
    for (id, commitment) in &image.client_index {
        let value = bytes.get(id).ok_or(DurableError::Corrupt)?;
        if value.len() > MAX_RECORD_BYTES || record_digest(value) != *commitment {
            return Err(DurableError::Corrupt);
        }
        let record = Record::decode(value, *id, &original.image, approval, &history, &receipt)?;
        if !operations.insert(*record.request.scope().operation().as_bytes()) {
            return Err(DurableError::Corrupt);
        }
        records.insert(*id, record);
    }
    Ok(records)
}

fn entry_digest(entry: &Entry, history: &AnchorHandoffHistory) -> Result<[u8; 32], DurableError> {
    let mut bytes = Vec::new();
    encode_entry(entry, history, EntryFormat::COMPLETE, &mut bytes)?;
    Ok(digest(
        b"Q-PERIAPT-WITNESS-ADOPTION-IMPORTED-ENTRY/v1",
        &bytes,
    ))
}
pub(super) fn verified_contexts(
    db: &Database,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
    original: &storage::SourceState,
) -> Result<BTreeMap<[u8; 32], crate::AnchorHandoffReplyContext>, DurableError> {
    if image.client_index.is_empty() {
        return Ok(BTreeMap::new());
    }
    let (_, history) = verified_activation(approval, image, original)?;
    load_records(db, approval, image, original)?
        .into_iter()
        .map(|(id, record)| {
            Ok((
                id,
                crate::AnchorHandoffReplyContext::verified(
                    &record.request.approved,
                    &history,
                    record.receipt.as_bytes(),
                )?,
            ))
        })
        .collect()
}
fn check_request(
    request: &RetainedAdoptionRequest,
    id: [u8; 32],
    original: &Image,
    approval: &AnchorHandoffTargetApproval,
    history: &AnchorHandoffHistory,
) -> Result<(), DurableError> {
    let s = request.scope();
    let entry = original.entries.get(&id).ok_or(DurableError::Absent)?;
    let identity = OriginalIdentity {
        account: request.account,
        description: request.original.clone(),
    };
    let policy = entry
        .policy_authorization
        .or_else(|| entry.independent_policy.as_ref().and_then(|p| p.current));
    if s.subject != entry.subject
        || s.subject.id(&original.namespace) != id
        || s.namespace != original.namespace
        || s.predecessor != approval.plan.source.binding()
        || s.entry != entry_digest(entry, history)?
        || s.credential_owner != entry.credential_owner
        || s.authority != entry.authority
        || entry
            .original_identity
            .as_ref()
            .is_some_and(|old| old != &identity)
        || policy.map_or(s.policy.digest() != entry.subject.policy, |p| {
            s.policy != p.checkpoint
        })
    {
        return Err(Error::Scope.into());
    }
    identity.check(entry)?;
    Ok(())
}

impl AnchorHandoffTarget {
    /// Recover exact server authorization without a signing key. Absence is
    /// local target metadata, never proof that an old G/P/R did not commit.
    pub fn client_authorization_receipt(
        &mut self,
        subject: AnchorSubject,
    ) -> Result<AnchorHandoffClientAuthorizationReceipt, DurableError> {
        let image = self.image()?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let original = storage::source_state(&owner.db, &owner.wrapping, &owner.approval, &image)?;
        load_records(&owner.db, &owner.approval, &image, &original)?
            .remove(&subject.id(&original.image.namespace))
            .map(|r| r.receipt)
            .ok_or(DurableError::Absent)
    }
}
