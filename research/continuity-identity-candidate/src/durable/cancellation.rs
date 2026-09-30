// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Irreversible local cancellation before application message activation.
use super::*;
use crate::{AnchorClient, BootstrapRole, LeafKind};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const METADATA_BYTES: usize = 170;

/// Exact bootstrap record identity, not an authorization or a commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapOperationId([u8; 32]);
impl BootstrapOperationId {
    /// Derive the existing journal identity for a retained initiation request.
    pub fn for_initiation(request: InitiationId) -> Self {
        Self(initiator::operation_id(request))
    }
    /// Derive the response identity without granting validity to the input.
    pub fn for_response(context: [u8; 32], initial: &[u8]) -> Result<Self, Error> {
        crate::codec::nonzero(&context)?;
        if initial.len() != 5817 {
            return Err(Error::Encoding);
        }
        Ok(Self(operation_id(&context, initial)))
    }
    /// Restore independently retained correlation bytes.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public correlation bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public entry in an authenticated, bounded bootstrap journal inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapEntry {
    /// Exact operation to reconcile.
    pub operation: BootstrapOperationId,
    /// Original context digest; never a reconstructed operational context.
    pub context: [u8; 32],
    /// Original local handshake role.
    pub role: BootstrapRole,
    /// Current durable local phase.
    pub status: DurableStatus,
}
/// Historical inventory disposition at the instant of cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapPrekeyDisposition {
    /// Claimed one-time key permanently abandoned before response release.
    AbandonedByCancellation,
    /// Response commit had already consumed this one-time key.
    AlreadyConsumed,
    /// Reusable key was not changed; later explicit retirement is independent.
    ReusableUnchanged,
}
/// Public inventory reference retained by a cancelled response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPrekeyUse {
    /// Original host inventory request.
    pub request: PrekeyId,
    /// Selected leaf kind.
    pub kind: LeafKind,
    /// Historical disposition, not current usability.
    pub disposition: BootstrapPrekeyDisposition,
}
/// Immutable local cancellation receipt. Hashes identify durable local flights;
/// they do not prove dispatch, remote receipt or remote cancellation. The report
/// ID is authenticated inside this journal, not a transferable signature. Private
/// state is logically removed, without a claim about old pages or backups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapCancellation {
    /// Cancelled record, always with status BootstrapCancelled.
    pub entry: BootstrapEntry,
    /// Last durable local phase before cancellation.
    pub previous: DurableStatus,
    /// Stable key-separated authenticator of the original local record.
    pub report: [u8; 32],
    /// Known initial flight, if it was durably materialized.
    pub initial_hash: Option<[u8; 32]>,
    /// Known response; ProcessingReply does not yet imply KEM confirmation.
    pub reply_hash: Option<[u8; 32]>,
    /// Known final confirmation, without a delivery claim.
    pub final_hash: Option<[u8; 32]>,
    /// Known transcript identity, without application activation authority.
    pub session: Option<[u8; 32]>,
    /// Permanently retained one-time claims, including externally owned keys.
    pub one_time_claims: Vec<[u8; 32]>,
    /// Selected local inventory entries; external owners are not erased here.
    pub inventory: Vec<BootstrapPrekeyUse>,
}

#[derive(Clone)]
pub(super) struct Metadata {
    pub(super) previous: DurableStatus,
    pub(super) report: [u8; 32],
    values: [Option<[u8; 32]>; 4],
}
fn role(kind: RecordKind) -> Result<BootstrapRole, DurableError> {
    match kind {
        RecordKind::Initiator => Ok(BootstrapRole::Initiator),
        RecordKind::Responder => Ok(BootstrapRole::Responder),
        _ => Err(DurableError::Conflict),
    }
}
fn mask(kind: RecordKind, phase: DurableStatus) -> Result<u8, DurableError> {
    use DurableStatus::*;
    match (kind, phase) {
        (
            RecordKind::Initiator,
            InitialKeyReserved | InitialKemReserved | InitialSignatureReserved,
        ) => Ok(0),
        (RecordKind::Initiator, Prepared | AwaitingReply) => Ok(1),
        (RecordKind::Initiator, ProcessingReply) => Ok(3),
        (RecordKind::Initiator, FinalPrepared | FinalCommitted) => Ok(15),
        (RecordKind::Responder, Executing | ResponseKemReserved | ResponseSignatureReserved) => {
            Ok(1)
        }
        (RecordKind::Responder, Prepared | AwaitingFinal) => Ok(3),
        (RecordKind::Responder, Complete) => Ok(15),
        _ => Err(DurableError::Corrupt),
    }
}
pub(super) fn encode(metadata: &Option<Metadata>, bytes: &mut Vec<u8>) {
    if let Some(m) = metadata {
        bytes.extend_from_slice(b"QPBCTR01");
        bytes.push(m.previous as u8);
        bytes.extend_from_slice(&m.report);
        bytes.push(
            m.values
                .iter()
                .enumerate()
                .fold(0, |bits, (i, v)| bits | (u8::from(v.is_some()) << i)),
        );
        for v in &m.values {
            bytes.extend_from_slice(&v.unwrap_or([0; 32]));
        }
    } else {
        bytes.extend_from_slice(&[0; METADATA_BYTES]);
    }
}
pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Option<Metadata>, DurableError> {
    let raw = d.take(METADATA_BYTES)?;
    if raw == [0; METADATA_BYTES] {
        return Ok(None);
    }
    let mut d = Decoder::new(raw);
    if d.array::<8>()? != *b"QPBCTR01" {
        return Err(DurableError::Corrupt);
    }
    let previous = DurableStatus::decode(d.array::<1>()?[0])?;
    let report = d.array()?;
    let bits = d.array::<1>()?[0];
    if bits & !15 != 0 || report == [0; 32] {
        return Err(DurableError::Corrupt);
    }
    let mut values = [None; 4];
    for (i, v) in values.iter_mut().enumerate() {
        let raw = d.array()?;
        if bits & (1 << i) != 0 {
            if raw == [0; 32] {
                return Err(DurableError::Corrupt);
            }
            *v = Some(raw);
        } else if raw != [0; 32] {
            return Err(DurableError::Corrupt);
        }
    }
    d.finish()?;
    Ok(Some(Metadata {
        previous,
        report,
        values,
    }))
}
pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    for (op, record) in &image.records {
        if record.phase == DurableStatus::BootstrapCancelled {
            let m = record.cancellation.as_ref().ok_or(DurableError::Corrupt)?;
            let bits = mask(record.kind, m.previous)?;
            if m.report == [0; 32] {
                return Err(DurableError::Corrupt);
            }
            for (i, v) in m.values.iter().enumerate() {
                if v.is_some() != (bits & (1 << i) != 0) || *v == Some([0; 32]) {
                    return Err(DurableError::Corrupt);
                }
            }
            match record.kind {
                RecordKind::Initiator => initiator::validate_record(
                    &image.id,
                    op,
                    &record.context,
                    record.phase,
                    &record.payload,
                )?,
                RecordKind::Responder => {
                    responder::validate_record(
                        &image.id,
                        op,
                        &record.context,
                        record.phase,
                        &record.payload,
                    )?;
                    if m.values[0] != Some(bootstrap::hash(b"initial-wire", &record.payload)) {
                        return Err(DurableError::Corrupt);
                    }
                }
                _ => return Err(DurableError::Corrupt),
            }
        } else if record.cancellation.is_some() {
            return Err(DurableError::Corrupt);
        }
    }
    Ok(())
}
fn entry(op: [u8; 32], r: &Record) -> Result<BootstrapEntry, DurableError> {
    Ok(BootstrapEntry {
        operation: BootstrapOperationId(op),
        context: r.context,
        role: role(r.kind)?,
        status: r.phase,
    })
}
fn report(image: &Image, op: [u8; 32]) -> Result<BootstrapCancellation, DurableError> {
    let r = image.records.get(&op).ok_or(DurableError::Absent)?;
    let m = r.cancellation.as_ref().ok_or(DurableError::Suspended)?;
    Ok(BootstrapCancellation {
        entry: entry(op, r)?,
        previous: m.previous,
        report: m.report,
        initial_hash: m.values[0],
        reply_hash: m.values[1],
        final_hash: m.values[2],
        session: m.values[3],
        one_time_claims: r.keys.clone(),
        inventory: prekeys::cancellation_inventory(image, &op)?,
    })
}
pub(super) fn metadata(
    key: &JournalKey,
    image: &Image,
    op: [u8; 32],
) -> Result<Metadata, DurableError> {
    let r = image.records.get(&op).ok_or(DurableError::Absent)?;
    let bits = mask(r.kind, r.phase)?;
    let mut values = [None; 4];
    if bits & 1 != 0 {
        let wire = if r.kind == RecordKind::Initiator {
            initiator::initial(r)?
        } else {
            responder::initial_bytes(r.phase, &r.payload)?
        };
        values[0] = Some(bootstrap::hash(b"initial-wire", wire));
    }
    if bits & 2 != 0 {
        let wire = if r.kind == RecordKind::Initiator {
            initiator::selected_reply(r)?
        } else {
            r.payload
                .get(40 + 5817..40 + 5817 + 4633)
                .ok_or(DurableError::Corrupt)?
        };
        values[1] = Some(bootstrap::hash(b"reply-wire", wire));
    }
    if bits & 4 != 0 {
        let checkpoint = if r.kind == RecordKind::Initiator {
            initiator::checkpoint(r)?
        } else {
            &r.payload
        };
        let wire = checkpoint
            .get(
                checkpoint
                    .len()
                    .checked_sub(136)
                    .ok_or(DurableError::Corrupt)?..,
            )
            .ok_or(DurableError::Corrupt)?;
        values[2] = Some(bootstrap::hash(b"final-wire", wire));
        values[3] = Some(bootstrap::hash(
            b"session-id",
            wire.get(..104).ok_or(DurableError::Corrupt)?,
        ));
    }
    let mut derived = ZeroizingBytes::<32>::zeroed();
    hkdf::Hkdf::<Sha256>::new(None, key.0.as_bytes())
        .expand(
            b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANCELLATION-KEY/v1",
            derived.as_mut_bytes(),
        )
        .map_err(|_| Error::Provider)?;
    let mut auth = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider)?;
    for value in [image.id, image.owner, op, r.context] {
        auth.update(&value);
    }
    auth.update(&[r.kind as u8, r.phase as u8]);
    for list in [&r.authorities, &r.keys, &r.prekeys] {
        auth.update(&[list.len() as u8]);
        for value in list {
            auth.update(value);
        }
    }
    auth.update(&(r.payload.len() as u32).to_be_bytes());
    auth.update(&r.payload);
    Ok(Metadata {
        previous: r.phase,
        report: auth.finalize().into_bytes().into(),
        values,
    })
}
impl DeviceJournal {
    /// Permanently cancel an existing initiation, including after policy close.
    /// Established message sessions require their separate closure protocol.
    pub fn cancel_initiation(
        &mut self,
        context: &BootstrapContext,
        request: InitiationId,
    ) -> Result<BootstrapCancellation, DurableError> {
        let op = self.initiation_query(context, request)?;
        let image = self.image()?;
        initiator::check_request(
            image.records.get(&op).ok_or(DurableError::Absent)?,
            context,
            request,
        )?;
        self.cancel_bootstrap(image, op, context.digest())
    }
    /// Permanently cancel an existing response without refunding one-time claims.
    pub fn cancel_response(
        &mut self,
        context: &BootstrapContext,
        initial: &[u8],
    ) -> Result<BootstrapCancellation, DurableError> {
        let op = self.query_id(context, initial)?;
        let image = self.image()?;
        image
            .records
            .get(&op)
            .ok_or(DurableError::Absent)?
            .check_request(context, initial)?;
        self.cancel_bootstrap(image, op, context.digest())
    }
    fn cancel_bootstrap(
        &mut self,
        mut image: Image,
        op: [u8; 32],
        context: [u8; 32],
    ) -> Result<BootstrapCancellation, DurableError> {
        let r = image.records.get(&op).ok_or(DurableError::Absent)?;
        role(r.kind)?;
        if r.context != context {
            return Err(DurableError::Conflict);
        }
        match r.phase {
            DurableStatus::BootstrapCancelled => return report(&image, op),
            DurableStatus::Messages => return Err(DurableError::Suspended),
            DurableStatus::Rejected => return Err(DurableError::Rejected),
            _ => {}
        }
        let m = metadata(
            &self.active.as_ref().ok_or(DurableError::Closed)?.key,
            &image,
            op,
        )?;
        let public = if r.kind == RecordKind::Initiator {
            r.payload.get(..32).ok_or(DurableError::Corrupt)?
        } else {
            responder::initial_bytes(r.phase, &r.payload)?
        }
        .to_vec();
        prekeys::cancel_claims(&mut image, &op)?;
        let r = image.records.get_mut(&op).ok_or(DurableError::Corrupt)?;
        r.payload = Zeroizing::new(public);
        r.phase = DurableStatus::BootstrapCancelled;
        r.cancellation = Some(m);
        self.persist(&mut image)?;
        report(&image, op)
    }
}

/// Cleanup-only owner of an existing authenticated journal. It has no bootstrap,
/// application, key-generation, provisioning or public-flight release methods.
/// Opening requires an independently retained store ID and the original key.
pub struct BootstrapCancellationJournal {
    journal: DeviceJournal,
}
impl BootstrapCancellationJournal {
    /// Open local-only storage. Missing/corrupt/required-witness storage fails.
    pub fn open(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, None)
    }
    /// Reopen with the original pinned witness. The witness must authenticate the
    /// original enrolled signer; expiry/refusal never enables a local fallback.
    pub fn open_anchored(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        client: AnchorClient,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, Some(client))
    }
    fn open_inner(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        client: Option<AnchorClient>,
    ) -> Result<Self, DurableError> {
        let db = open_private_database(path)?;
        let (image, pending) = write_intent::load_cleanup_snapshot(&db, &key, expected)?;
        let owner = image.owner;
        match (image.protection, client.is_some()) {
            (Protection::Local, false) | (Protection::Required { .. }, true) => {}
            (Protection::Required { .. }, false) => return Err(DurableError::AnchorRequired),
            _ => return Err(DurableError::Conflict),
        }
        let mut active = Active {
            db,
            key,
            owner,
            id: image.id,
            protection: image.protection,
            anchor: None,
        };
        if let Some(client) = client {
            active.attach_retained_cleanup_subject(client)?;
        }
        if let Some(pending) = pending {
            write_intent::reconcile(&mut active, &pending)?;
        }
        let current = load(&active.db, &active.key, owner)?;
        active.check_current(&current)?;
        Ok(Self {
            journal: DeviceJournal {
                active: Some(active),
            },
        })
    }
    /// List only public bootstrap correlation and phase metadata.
    pub fn entries(&mut self) -> Result<Vec<BootstrapEntry>, DurableError> {
        let image = self.journal.image()?;
        image
            .records
            .iter()
            .filter(|(_, r)| matches!(r.kind, RecordKind::Initiator | RecordKind::Responder))
            .map(|(op, r)| entry(*op, r))
            .collect()
    }
    /// Cancel one exact retained context and operation, or return its exact receipt.
    /// A sealed prior activation may reconcile during open; it then requires session closure.
    pub fn cancel(
        &mut self,
        context: [u8; 32],
        operation: BootstrapOperationId,
    ) -> Result<BootstrapCancellation, DurableError> {
        let image = self.journal.image()?;
        self.journal.cancel_bootstrap(image, operation.0, context)
    }
    /// Drop the wrapping-key owner, database lease and witness client.
    pub fn close(&mut self) {
        self.journal.close();
    }
}

#[cfg(all(test, unix))]
mod tests;
