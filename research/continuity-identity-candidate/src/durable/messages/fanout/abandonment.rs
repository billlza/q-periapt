// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit local abandonment closes whole sessions; it never rewinds a send slot.
use super::*;
use hmac::{Hmac, Mac};

/// Private-keyed identifier of an immutable, metadata-only loss report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FanoutAbandonmentId([u8; 32]);
impl FanoutAbandonmentId {
    /// Restore a retained ID. Its exact batch and journal binding is still checked.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Correlation bytes; not a public plaintext commitment or an authorization.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Uncommitted input whose session will be permanently closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedAbandonment {
    /// Original reservation; no ciphertext was durably committed for this ID.
    pub message: MessageId,
    /// Bytes being discarded, with no content or content hash released.
    pub plaintext_bytes: usize,
    /// Associated-data length, with no content released.
    pub associated_data_bytes: usize,
}
/// Metadata for an unconsumed delivery that will be lost on acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbandonedDelivery {
    /// Original delivery correlation ID.
    pub message: MessageId,
    /// Position within this receiving epoch.
    pub index: u64,
    /// Bytes to account for as lost; this report never returns their plaintext.
    pub plaintext_bytes: usize,
}
/// Complete retained epoch accounting before destructive session closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbandonedEpoch {
    /// Original epoch number.
    pub epoch: u64,
    /// Authenticated peer-consumed prefix; closure does not advance it.
    pub acknowledged_before: u64,
    /// Committed send count, excluding the uncommitted reservation.
    pub sent: u64,
    /// Contiguous locally consumed prefix.
    pub consumed_before: u64,
    /// Observed receive-chain position, not proof of honest peer activity.
    pub received: u64,
    /// Previously authenticated peer close count, when one exists.
    pub peer_sent: Option<u64>,
    /// Prior explicit closed-epoch accounting, preserved without inventing ACKs.
    pub resolution: EpochResolutionStatus,
    /// Exact outstanding ciphertext identities; each outcome remains unknown.
    pub unconfirmed: Vec<UnconfirmedMessage>,
    /// Unconsumed inbox metadata; all these deliveries will be lost locally.
    pub deliveries: Vec<AbandonedDelivery>,
    /// Observed skipped indices, not proof that corresponding messages existed.
    pub skipped: Vec<u64>,
}
/// One complete frozen session, including work older than this batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbandonedSession {
    /// Original credential-bound peer.
    pub device: [u8; 16],
    /// Original peer generation.
    pub generation: u64,
    /// Exact admitted context digest.
    pub context: [u8; 32],
    /// Session that will never be reactivated.
    pub session: [u8; 32],
    /// Local bootstrap role, 1 for initiator and 2 for responder.
    pub role: u8,
    /// Last observed rekey progress, without a recovery claim.
    pub progress: RekeyProgress,
    /// Exact reserved input to abandon.
    pub reserved: ReservedAbandonment,
    /// Every retained epoch; earlier history was already separately retired.
    pub epochs: Vec<AbandonedEpoch>,
}
/// Immutable metadata-only report returned after all sessions are durably frozen.
/// The application must durably record every unknown/lost outcome before ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FanoutAbandonment {
    /// Exact batch; no replacement recipients or inputs are implied.
    pub batch: FanoutId,
    /// Retain with the host's durable, deduplicated accounting transaction.
    pub report: FanoutAbandonmentId,
    /// Complete original recipient set in device order.
    pub sessions: Vec<AbandonedSession>,
}

fn report_mac(
    image: &Image,
    batch: &Batch,
    key: &ZeroizingBytes<32>,
) -> Result<Hmac<Sha256>, DurableError> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_bytes())
        .map_err(|_| Error::Provider)?;
    mac.update(&label(b"fanout-abandonment/v1"));
    mac.update(&image.id);
    mac.update(&image.owner);
    mac.update(&batch.metadata());
    for member in &batch.members {
        let record = image
            .records
            .get(&record_id(&member.session))
            .ok_or(DurableError::Corrupt)?;
        mac.update(&record.context);
        mac.update(&(record.payload.len() as u64).to_be_bytes());
        // The private state is immutable once frozen. Never export this transcript
        // or replace this private-keyed MAC with a public plaintext-derived hash.
        mac.update(&record.payload);
    }
    Ok(mac)
}
pub(super) fn validate_report(image: &Image, batch: &Batch) -> Result<(), DurableError> {
    let BatchState::Abandoning { report, key } = &batch.state else {
        return Err(DurableError::Corrupt);
    };
    report_mac(image, batch, key)?
        .verify_slice(&report.0)
        .map_err(|_| DurableError::Corrupt)
}
pub(in crate::durable::messages) fn progress(state: &State) -> Result<RekeyProgress, Error> {
    Ok(RekeyProgress {
        confirmed_epoch: state.control.confirmed_epoch(),
        sending_epoch: state.send_epoch,
        receiving_epoch: state.receive_epoch,
        pending_epoch: state.control.pending_epoch()?,
    })
}
pub(in crate::durable::messages) fn epoch_accounting(state: &State) -> Vec<AbandonedEpoch> {
    let mut epochs = Vec::with_capacity(state.epochs.len());
    for traffic in state.epochs.values() {
        epochs.push(AbandonedEpoch {
            epoch: traffic.epoch,
            acknowledged_before: traffic.send_floor,
            sent: traffic.sent,
            consumed_before: traffic.receive_floor,
            received: traffic.received,
            peer_sent: traffic.receive_limit,
            resolution: traffic.resolution,
            unconfirmed: traffic
                .outgoing
                .iter()
                .map(|(id, saved)| UnconfirmedMessage::new(*id, &saved.wire))
                .collect(),
            deliveries: traffic
                .incoming
                .iter()
                .filter(|(_, s)| !s.consumed)
                .map(|(id, s)| AbandonedDelivery {
                    message: *id,
                    index: s.index,
                    plaintext_bytes: s.plaintext.len(),
                })
                .collect(),
            skipped: traffic.skipped.keys().copied().collect(),
        });
    }
    epochs
}
fn report(image: &Image, batch: &Batch) -> Result<FanoutAbandonment, DurableError> {
    validate_report(image, batch)?;
    let BatchState::Abandoning { report, .. } = batch.state else {
        return Err(DurableError::Corrupt);
    };
    let mut sessions = Vec::with_capacity(batch.members.len());
    for member in &batch.members {
        let record = image
            .records
            .get(&record_id(&member.session))
            .ok_or(DurableError::Corrupt)?;
        let state = State::decode(&record.payload)?;
        let plan = state
            .traffic(member.message.epoch()?)?
            .pending
            .as_ref()
            .ok_or(DurableError::Corrupt)?;
        let epochs = epoch_accounting(&state);
        sessions.push(AbandonedSession {
            device: member.device,
            generation: member.generation,
            context: member.context,
            session: member.session,
            role: member.role,
            progress: progress(&state)?,
            reserved: ReservedAbandonment {
                message: plan.id,
                plaintext_bytes: plan.plaintext.len(),
                associated_data_bytes: plan.ad.len(),
            },
            epochs,
        });
    }
    Ok(FanoutAbandonment {
        batch: batch.id,
        report,
        sessions,
    })
}

impl DeviceJournal {
    // Cleanup uses exact previously admitted context/owner bindings. It does not
    // require continued peer authorization, and can only destroy local authority.
    pub(in crate::durable::messages::fanout) fn check_fanout_cleanup(
        &self,
        image: &Image,
        batch: &Batch,
        targets: &[FanoutTarget<'_>],
    ) -> Result<(), DurableError> {
        if targets.len() != batch.members.len() {
            return Err(DurableError::Conflict);
        }
        let mut seen = BTreeSet::new();
        for target in targets {
            self.check_policy(target.context.policy())?;
            let member = batch
                .members
                .iter()
                .find(|m| m.session == target.session)
                .ok_or(DurableError::Conflict)?;
            let owner = if member.role == 1 {
                target.context.initiator_storage_owner()
            } else {
                target.context.storage_owner()
            };
            let devices = target.context.devices();
            let peer = if member.role == 1 {
                devices[1]
            } else {
                devices[0]
            };
            if !seen.insert(target.session)
                || owner != image.owner
                || member.context != target.context.digest()
                || peer.account_id() != batch.account
                || peer.device_id() != member.device
                || peer.generation() != member.generation
                || peer.credential_digest() != member.credential
            {
                return Err(DurableError::Conflict);
            }
        }
        Ok(())
    }
    /// Freeze every member session of a reserved batch for explicit loss accounting.
    /// This is irreversible. No application/control/bootstrap bytes can subsequently
    /// be released from those sessions, even before the final acknowledgement.
    /// Revoked or expired contexts may be used only for this metadata-only cleanup.
    /// Existing required-witness policy is enforced at commit and report release.
    pub fn begin_fanout_abandonment(
        &mut self,
        id: FanoutId,
        targets: &[FanoutTarget<'_>],
    ) -> Result<FanoutAbandonment, DurableError> {
        let mut image = self.image()?;
        let mut batch = codec::get(&image, id)?;
        self.check_fanout_cleanup(&image, &batch, targets)?;
        match batch.state {
            BatchState::Reserved(_) => {
                let mut key = ZeroizingBytes::<32>::zeroed();
                getrandom::fill(key.as_mut_bytes()).map_err(|_| Error::Entropy)?;
                let report = FanoutAbandonmentId::from_trusted_state(
                    report_mac(&image, &batch, &key)?
                        .finalize()
                        .into_bytes()
                        .into(),
                )?;
                for member in &batch.members {
                    let record = image
                        .records
                        .get_mut(&record_id(&member.session))
                        .ok_or(DurableError::Corrupt)?;
                    if record.phase != DurableStatus::Messages {
                        return Err(DurableError::Corrupt);
                    }
                    record.phase = DurableStatus::MessagesAbandoning;
                }
                batch.state = BatchState::Abandoning { report, key };
                image
                    .records
                    .insert(batch_key(id), batch.record(image.local_account));
                self.persist(&mut image)?;
                #[cfg(all(test, unix))]
                tests::after_stage("fanout-abandoning");
            }
            BatchState::Abandoning { .. } => {}
            BatchState::Abandoned(_) => return Err(Error::Retired.into()),
            BatchState::Committed(_) => return Err(DurableError::Conflict),
        }
        let report = report(&image, &batch)?;
        self.check_release(&image)?;
        Ok(report)
    }
    /// After the host durably accounts for the exact report, replace all member
    /// sessions with keyless terminal records in one transaction. This erases
    /// logical owners, not historical disk blocks, backups or caller copies.
    /// Repeating the exact acknowledgement is idempotent; outcomes never become ACKs.
    pub fn acknowledge_fanout_abandonment(
        &mut self,
        id: FanoutId,
        report: FanoutAbandonmentId,
        targets: &[FanoutTarget<'_>],
    ) -> Result<(), DurableError> {
        let mut image = self.image()?;
        let mut batch = codec::get(&image, id)?;
        self.check_fanout_cleanup(&image, &batch, targets)?;
        match batch.state {
            BatchState::Abandoned(saved) if saved == report => {}
            BatchState::Abandoning { report: saved, .. } if saved == report => {
                validate_report(&image, &batch)?;
                for member in &batch.members {
                    let record = image
                        .records
                        .get_mut(&record_id(&member.session))
                        .ok_or(DurableError::Corrupt)?;
                    let state = State::decode(&record.payload)?;
                    let payload = Retired::new(&state, id, report, member.message)?.encode();
                    if payload.len() > record.payload.len() {
                        return Err(DurableError::Corrupt);
                    }
                    record.payload = payload;
                    record.phase = DurableStatus::MessagesAbandoned;
                }
                batch.state = BatchState::Abandoned(report);
                image
                    .records
                    .insert(batch_key(id), batch.record(image.local_account));
                self.persist(&mut image)?;
                #[cfg(all(test, unix))]
                tests::after_stage("fanout-abandoned");
            }
            _ => return Err(DurableError::Conflict),
        }
        self.check_release(&image)
    }
}

pub(in crate::durable::messages) fn require_live_source(
    image: &Image,
    source: &[u8; 32],
) -> Result<(), DurableError> {
    for record in image
        .records
        .values()
        .filter(|r| r.kind == RecordKind::Messages)
    {
        match record.phase {
            DurableStatus::MessagesAbandoning | DurableStatus::MessagesClosing
                if State::decode(&record.payload)?.source == *source =>
            {
                return Err(DurableError::Suspended)
            }
            DurableStatus::MessagesAbandoned | DurableStatus::MessagesClosed
                if Retired::decode(&record.payload)?.source == *source =>
            {
                return Err(Error::Retired.into())
            }
            _ => {}
        }
    }
    Ok(())
}
pub(in crate::durable::messages) fn validate_message_record(
    image: &Image,
    record: &Record,
) -> Result<([u8; 32], [u8; 32], u8), DurableError> {
    let retired = Retired::decode(&record.payload)?;
    let id = retired.batch.ok_or(DurableError::Corrupt)?;
    if id.check(&image.id)? >= image.next_fanout {
        return Err(DurableError::Corrupt);
    }
    // Metadata can be retired; the session tombstone remains independently bound.
    if let Some(record) = image.records.get(&batch_key(id)) {
        let batch = Batch::decode(image, &batch_key(id), record)?;
        if !matches!(batch.state, BatchState::Abandoned(report) if *report.as_bytes() == retired.report)
            || !batch.members.iter().any(|m| {
                m.session == retired.session
                    && m.role == retired.role
                    && Some(m.message) == retired.pending
            })
        {
            return Err(DurableError::Corrupt);
        }
    }
    Ok((retired.source, retired.session, retired.role))
}
