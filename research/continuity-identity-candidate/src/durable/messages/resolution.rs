// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit application accounting for closed-epoch outcomes, never delivery success.
use super::*;
use hmac::{Hmac, Mac};

/// Commitment to one immutable closed-epoch report, not an authority capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochResolutionId([u8; 32]);
impl EpochResolutionId {
    /// Restore a previously retained report ID; journal admission verifies its scope.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Bytes the host retains with its durable application decision.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Local application resolution state; no variant asserts peer delivery success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochResolutionStatus {
    /// Normal message/ACK processing; no resolution was requested.
    Unrequested,
    /// The epoch is frozen and its committed report awaits application accounting.
    Pending(EpochResolutionId),
    /// The caller acknowledged recording the report; old secret/data owners are erased.
    Acknowledged(EpochResolutionId),
}
impl EpochResolutionStatus {
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        match self {
            Self::Unrequested => bytes.push(0),
            Self::Pending(id) => {
                bytes.push(1);
                bytes.extend_from_slice(&id.0);
            }
            Self::Acknowledged(id) => {
                bytes.push(2);
                bytes.extend_from_slice(&id.0);
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        match d.array::<1>()? {
            [0] => Ok(Self::Unrequested),
            [1] => Ok(Self::Pending(EpochResolutionId::from_trusted_state(
                d.array()?,
            )?)),
            [2] => Ok(Self::Acknowledged(EpochResolutionId::from_trusted_state(
                d.array()?,
            )?)),
            _ => Err(Error::Encoding),
        }
    }
    pub(super) fn acknowledged(self) -> bool {
        matches!(self, Self::Acknowledged(_))
    }
}

/// Exact committed send with no accepted consumption acknowledgement.
pub struct UnconfirmedMessage {
    id: MessageId,
    wire_digest: [u8; 32],
}
impl UnconfirmedMessage {
    /// Original ID for application reconciliation; it cannot become a new send.
    pub fn message_id(&self) -> MessageId {
        self.id
    }
    /// Domain-separated SHA3-256 commitment to the exact ciphertext frame.
    pub fn ciphertext_digest(&self) -> &[u8; 32] {
        &self.wire_digest
    }
}

/// Owned, unconsumed delivery from the closed epoch. Old-key compromise can have
/// invalidated its authenticity; this result does not undo earlier application effects.
pub struct UnconsumedDelivery {
    id: MessageId,
    index: u64,
    bytes: Zeroizing<Vec<u8>>,
}
impl UnconsumedDelivery {
    /// Original ID, also used for prior application deduplication.
    pub fn message_id(&self) -> MessageId {
        self.id
    }
    /// Index within the closed receiving epoch, possibly beyond its signed close count.
    pub fn index(&self) -> u64 {
        self.index
    }
    /// Retained plaintext, erased when this owned result is dropped.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Immutable report returned only after the epoch freeze and report ID are committed.
/// The host must durably account for these outcomes before acknowledging this ID.
pub struct ClosedEpochResolution {
    id: EpochResolutionId,
    epoch: u64,
    acknowledged_before: u64,
    sent: u64,
    consumed_before: u64,
    received: u64,
    peer_sent: u64,
    outgoing: Vec<UnconfirmedMessage>,
    incoming: Vec<UnconsumedDelivery>,
    skipped: Vec<u64>,
}
impl ClosedEpochResolution {
    /// Exact ID to retain with the host's durable application transaction.
    pub fn resolution_id(&self) -> EpochResolutionId {
        self.id
    }
    /// Closed key epoch; no logical session or message ID is reset.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Previously peer-acknowledged send prefix, unchanged by resolution.
    pub fn acknowledged_before(&self) -> u64 {
        self.acknowledged_before
    }
    /// Total committed local sends in this epoch.
    pub fn sent_count(&self) -> u64 {
        self.sent
    }
    /// Previously contiguous local consumption prefix, unchanged by resolution.
    pub fn consumed_before(&self) -> u64 {
        self.consumed_before
    }
    /// Observed old receive-chain position; disclosure may have poisoned it.
    pub fn observed_receive_count(&self) -> u64 {
        self.received
    }
    /// Identity-signed peer close count from the committed rekey transcript.
    pub fn peer_sent_count(&self) -> u64 {
        self.peer_sent
    }
    /// Committed sends whose delivery outcome remains unknown.
    pub fn unconfirmed_messages(&self) -> &[UnconfirmedMessage] {
        &self.outgoing
    }
    /// Retained plaintext not yet consumed by the application, including entries
    /// beyond the signed close count. The host must account for every entry.
    pub fn unconsumed_deliveries(&self) -> &[UnconsumedDelivery] {
        &self.incoming
    }
    /// Observed skipped indices, not evidence that honest messages ever existed.
    /// A further unseen range exists when observed_receive_count < peer_sent_count.
    pub fn skipped_indices(&self) -> &[u64] {
        &self.skipped
    }
}

fn wire_digest(wire: &[u8]) -> [u8; 32] {
    digest(&label(b"resolution-ciphertext/v1"), wire)
}
impl Traffic {
    pub(super) fn require_unresolved(&self) -> Result<(), Error> {
        if self.resolution != EpochResolutionStatus::Unrequested {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn resolution_mac(&self) -> Result<Hmac<Sha256>, Error> {
        if !self.send_closed || self.pending.is_some() {
            return Err(Error::State);
        }
        let close = self.receive_limit.ok_or(Error::State)?;
        // This buffer contains plaintext-derived commitments; it is private even
        // though the final per-report HMAC identifier may be used for correlation.
        let mut body = Zeroizing::new(self.session.to_vec());
        body.push(self.role);
        for value in [
            self.epoch,
            self.send_floor,
            self.sent,
            self.receive_floor,
            self.received,
            close,
        ] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.extend_from_slice(&(self.outgoing.len() as u16).to_be_bytes());
        for (id, saved) in &self.outgoing {
            body.extend_from_slice(&id.0);
            body.extend_from_slice(saved.intent.as_ref());
            body.extend_from_slice(&wire_digest(&saved.wire));
        }
        body.extend_from_slice(&(self.incoming.len() as u16).to_be_bytes());
        for (id, saved) in &self.incoming {
            body.extend_from_slice(&id.0);
            body.extend_from_slice(&saved.index.to_be_bytes());
            body.extend_from_slice(saved.intent.as_ref());
            body.push(u8::from(saved.consumed));
            body.extend_from_slice(&(saved.plaintext.len() as u32).to_be_bytes());
            let plaintext_digest =
                Zeroizing::new(digest(&label(b"resolution-plaintext/v1"), &saved.plaintext));
            body.extend_from_slice(plaintext_digest.as_ref());
        }
        body.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        for index in self.skipped.keys() {
            body.extend_from_slice(&index.to_be_bytes());
        }
        let key = self.resolution_key.as_ref().ok_or(Error::State)?;
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Provider)?;
        mac.update(&label(b"closed-epoch-resolution/v1"));
        mac.update(&body);
        Ok(mac)
    }
    fn resolution_id(&self) -> Result<EpochResolutionId, Error> {
        EpochResolutionId::from_trusted_state(self.resolution_mac()?.finalize().into_bytes().into())
    }
    pub(super) fn validate_resolution(&self) -> Result<(), Error> {
        match self.resolution {
            EpochResolutionStatus::Unrequested => {
                if self.resolution_key.is_some() {
                    return Err(Error::Encoding);
                }
                Ok(())
            }
            EpochResolutionStatus::Pending(id) => self
                .resolution_mac()?
                .verify_slice(&id.0)
                .map_err(|_| Error::Encoding),
            EpochResolutionStatus::Acknowledged(_) => {
                if !self.send_closed
                    || self.receive_limit.is_none()
                    || self.pending.is_some()
                    || self.resolution_key.is_some()
                    || !self.outgoing.is_empty()
                    || !self.incoming.is_empty()
                    || !self.skipped.is_empty()
                    || self.send_floor > self.sent
                    || self.receive_floor > self.received
                    || [&self.send, &self.receive, &self.send_ack, &self.receive_ack]
                        .iter()
                        .any(|key| key.as_bytes() != &[0; 32])
                {
                    return Err(Error::Encoding);
                }
                Ok(())
            }
        }
    }
    fn resolution_report(&self) -> Result<ClosedEpochResolution, Error> {
        let EpochResolutionStatus::Pending(id) = self.resolution else {
            return Err(Error::State);
        };
        self.validate_resolution()?;
        Ok(ClosedEpochResolution {
            id,
            epoch: self.epoch,
            acknowledged_before: self.send_floor,
            sent: self.sent,
            consumed_before: self.receive_floor,
            received: self.received,
            peer_sent: self.receive_limit.ok_or(Error::State)?,
            outgoing: self
                .outgoing
                .iter()
                .map(|(id, saved)| UnconfirmedMessage {
                    id: *id,
                    wire_digest: wire_digest(&saved.wire),
                })
                .collect(),
            incoming: self
                .incoming
                .iter()
                .filter(|(_, saved)| !saved.consumed)
                .map(|(id, saved)| UnconsumedDelivery {
                    id: *id,
                    index: saved.index,
                    bytes: saved.plaintext.clone(),
                })
                .collect(),
            skipped: self.skipped.keys().copied().collect(),
        })
    }
}

impl DeviceJournal {
    /// Irreversibly freeze a closed old epoch and commit its exact unresolved-outcome
    /// report before release. Repeated calls recover that report after restart.
    /// Call only when the application chooses explicit resolution over old delivery.
    pub fn begin_closed_epoch_resolution(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        epoch: u64,
        now: u64,
    ) -> Result<ClosedEpochResolution, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if epoch >= state.send_epoch || epoch >= state.receive_epoch {
            return Err(Error::State.into());
        }
        // Read an existing frozen report even if later control work is pending.
        // Starting a new resolution must not invalidate an already signed assertion.
        if state.traffic(epoch)?.resolution == EpochResolutionStatus::Unrequested {
            if state.control.has_pending() {
                return Err(DurableError::Suspended);
            }
            let traffic = state.traffic_mut(epoch)?;
            let mut report_key = ZeroizingBytes::<32>::zeroed();
            getrandom::fill(report_key.as_mut_bytes()).map_err(|_| Error::Entropy)?;
            traffic.resolution_key = Some(report_key);
            traffic.resolution = EpochResolutionStatus::Pending(traffic.resolution_id()?);
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("epoch-resolution-frozen");
        }
        if state.traffic(epoch)?.resolution.acknowledged() {
            return Err(Error::Retired.into());
        }
        self.check_context_release(&image, context, now)?;
        Ok(state.traffic(epoch)?.resolution_report()?)
    }

    /// Record the application's durable accounting of this exact report and erase
    /// its old secret/data owners. This reports no successful delivery. The host's
    /// external transaction must already be durable and deduplicated by report ID.
    pub fn acknowledge_closed_epoch_resolution(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        epoch: u64,
        id: EpochResolutionId,
        now: u64,
    ) -> Result<(), DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        let traffic = state.traffic_mut(epoch)?;
        match traffic.resolution {
            EpochResolutionStatus::Unrequested => return Err(Error::State.into()),
            EpochResolutionStatus::Pending(saved) | EpochResolutionStatus::Acknowledged(saved)
                if saved != id =>
            {
                return Err(DurableError::Conflict)
            }
            EpochResolutionStatus::Acknowledged(_) => {}
            EpochResolutionStatus::Pending(_) => {
                traffic.validate_resolution()?;
                traffic.outgoing.clear();
                traffic.incoming.clear();
                traffic.skipped.clear();
                traffic.send = ZeroizingBytes::zeroed();
                traffic.receive = ZeroizingBytes::zeroed();
                traffic.send_ack = ZeroizingBytes::zeroed();
                traffic.receive_ack = ZeroizingBytes::zeroed();
                traffic.resolution_key = None;
                traffic.resolution = EpochResolutionStatus::Acknowledged(id);
                self.store_message_state(&mut image, &state)?;
                #[cfg(all(test, unix))]
                super::tests::after_stage("epoch-resolution-acknowledged");
            }
        }
        self.check_context_release(&image, context, now)?;
        Ok(())
    }

    /// Query authenticated local accounting state without releasing plaintext or
    /// granting authority after policy close, expiry or revocation.
    pub fn closed_epoch_resolution_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        epoch: u64,
    ) -> Result<EpochResolutionStatus, DurableError> {
        let state = self.message_state_for_status(context, session)?;
        Ok(state.traffic(epoch)?.resolution)
    }
}
