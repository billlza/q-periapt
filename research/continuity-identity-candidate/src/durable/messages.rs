// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Epoch-scoped message protection owned exclusively by the device transaction.
use super::*;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

mod acknowledgement;
mod closure;
pub use closure::{
    SessionClosure, SessionClosureArchive, SessionClosureId, SessionClosureJournal,
    SessionClosureStatus,
};
mod terminal;
use terminal::Retired;
#[cfg(feature = "connection-tls")]
mod delivery;
#[cfg(feature = "connection-tls")]
pub(crate) use delivery::{acknowledgement_epoch, message_epoch, message_route, Delivery};
mod fanout;
pub use fanout::{
    AbandonedDelivery, AbandonedEpoch, AbandonedSession, FanoutAbandonment, FanoutAbandonmentId,
    FanoutId, FanoutInput, FanoutMember, FanoutOutput, FanoutStatus, FanoutTarget,
    ReservedAbandonment,
};
mod progress;
pub use progress::SendProgress;
mod resolution;
pub use resolution::{
    ClosedEpochResolution, EpochResolutionId, EpochResolutionStatus, UnconfirmedMessage,
    UnconsumedDelivery,
};
mod traffic;
use traffic::Traffic;
mod rekey;
pub use rekey::{
    RekeyControlMessage, RekeyControlStep, RekeyFlight, RekeyOfferStatus, RekeyProgress,
    RekeyRequestStatus, RekeyResponseStatus,
};

const MAX_PLAINTEXT: usize = 16 * 1024;
const MAX_AD: usize = 1024;
const MAX_SKIPPED: usize = 128;
const MAX_RECEIPTS: usize = 64;
const MESSAGE_HEADER: usize = 8 + 32 + 1 + 8 + 8 + 32 + 4;
const MESSAGE_TAG: &[u8; 8] = b"QPCMSG03";
const MAX_TRAFFIC_EPOCHS: usize = 4;
const STATE_TAG: &[u8; 8] = b"QPMST011";
const DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/";

fn first_retained_epoch(newest: u64) -> u64 {
    newest.saturating_sub((MAX_TRAFFIC_EPOCHS - 1) as u64)
}

/// Journal-issued session/direction/epoch/sequence ID, retained for retries.
/// Reusing an active ID with different input fails; retired IDs cannot be reused.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageId([u8; 32]);
impl MessageId {
    fn for_epoch(session: &[u8; 32], role: u8, epoch: u64, index: u64) -> Result<Self, Error> {
        if !matches!(role, 1 | 2) || epoch == u64::MAX || index == u64::MAX {
            return Err(Error::Capacity);
        }
        let mut bound = session.to_vec();
        bound.push(role);
        bound.extend_from_slice(&epoch.to_be_bytes());
        bound.extend_from_slice(&index.to_be_bytes());
        let binding = digest(&label(b"epoch-message-id"), &bound);
        let mut bytes = [0; 32];
        bytes
            .get_mut(..8)
            .ok_or(Error::Encoding)?
            .copy_from_slice(&epoch.to_be_bytes());
        bytes
            .get_mut(8..16)
            .ok_or(Error::Encoding)?
            .copy_from_slice(&index.to_be_bytes());
        bytes
            .get_mut(16..)
            .ok_or(Error::Encoding)?
            .copy_from_slice(binding.get(..16).ok_or(Error::Encoding)?);
        Ok(Self(bytes))
    }
    fn index(self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.0
                .get(8..16)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        ))
    }
    fn epoch(self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.0
                .get(..8)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        ))
    }
    fn check(self, session: &[u8; 32], role: u8) -> Result<u64, Error> {
        let index = self.index()?;
        if self != Self::for_epoch(session, role, self.epoch()?, index)? {
            return Err(Error::Scope);
        }
        Ok(index)
    }
    /// Recover an application's retained ID, not an authorization capability.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public correlation bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Read-only reconciliation state for one exact outgoing message ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageStatus {
    /// No reservation or outbox exists for this ID in the authenticated session.
    Absent,
    /// Exact input is durable; no ciphertext outbox has been committed.
    Reserved,
    /// Exact ciphertext and its chain advancement are durably committed.
    Committed,
    /// The peer authenticated application consumption; its outbox was retired.
    Acknowledged,
    /// This committed send is in a frozen report awaiting application accounting.
    ResolutionPending,
    /// The application acknowledged recording this unresolved delivery outcome.
    /// No successful delivery or permission to reuse this ID is implied.
    DeliveryUnknown,
    /// Reserved input was explicitly abandoned and its entire session is terminal.
    ReservationAbandoned,
}

/// Authenticated plaintext returned only after the inbox and chain commit.
/// Exact duplicates return the retained delivery until consumption; afterwards
/// they return `Retired`. External application effects need separate deduplication.
pub struct CommittedPlaintext {
    id: MessageId,
    bytes: Zeroizing<Vec<u8>>,
}
impl CommittedPlaintext {
    /// Peer-selected message ID, unique within this session direction.
    pub fn message_id(&self) -> MessageId {
        self.id
    }
    /// Plaintext owned by this result and erased on drop; caller copies are separate.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct SendPlan {
    id: MessageId,
    fanout: Option<FanoutId>,
    plaintext: Zeroizing<Vec<u8>>,
    ad: Vec<u8>,
}
struct Outgoing {
    intent: Zeroizing<[u8; 32]>,
    wire: Vec<u8>,
}
struct Incoming {
    index: u64,
    intent: Zeroizing<[u8; 32]>,
    plaintext: Zeroizing<Vec<u8>>,
    consumed: bool,
}
struct State {
    source: [u8; 32],
    session: [u8; 32],
    role: u8,
    rekey: ZeroizingBytes<32>,
    control: rekey::Control,
    send_epoch: u64,
    receive_epoch: u64,
    epochs: BTreeMap<u64, Traffic>,
    closure: Option<closure::Pending>,
}
fn key(bytes: &[u8]) -> Result<ZeroizingBytes<32>, Error> {
    let bytes: &[u8; 32] = bytes.try_into().map_err(|_| Error::Encoding)?;
    let mut value = ZeroizingBytes::zeroed();
    value.as_mut_bytes().copy_from_slice(bytes);
    Ok(value)
}
fn label(name: &[u8]) -> Vec<u8> {
    let mut value = DOMAIN.to_vec();
    value.extend_from_slice(name);
    value
}
fn record_id(session: &[u8; 32]) -> [u8; 32] {
    digest(&label(b"record"), session)
}
fn intent(name: &[u8], first: &[u8], second: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut value = Zeroizing::new(Vec::with_capacity(8 + first.len() + second.len()));
    value.extend_from_slice(&(first.len() as u64).to_be_bytes());
    value.extend_from_slice(first);
    value.extend_from_slice(second);
    Zeroizing::new(digest(&label(name), &value))
}
fn step(
    seed: &ZeroizingBytes<32>,
    index: u64,
) -> Result<(ZeroizingBytes<32>, ZeroizingBytes<32>), Error> {
    if index == u64::MAX {
        return Err(Error::Capacity);
    }
    let mut info = label(b"chain");
    info.extend_from_slice(&index.to_be_bytes());
    let mut output = ZeroizingBytes::<64>::zeroed();
    Hkdf::<Sha256>::new(None, seed.as_bytes())
        .expand(&info, output.as_mut_bytes())
        .map_err(|_| Error::Provider)?;
    Ok((
        key(output.as_bytes().get(..32).ok_or(Error::Encoding)?)?,
        key(output.as_bytes().get(32..).ok_or(Error::Encoding)?)?,
    ))
}
fn associated(header: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut value = label(b"aead");
    value.extend_from_slice(header);
    value.extend_from_slice(&(ad.len() as u16).to_be_bytes());
    value.extend_from_slice(ad);
    value
}
struct Header {
    session: [u8; 32],
    role: u8,
    epoch: u64,
    index: u64,
    id: MessageId,
    length: usize,
}
impl Header {
    fn decode(wire: &[u8]) -> Result<Self, Error> {
        if !(MESSAGE_HEADER + 16..=MESSAGE_HEADER + 16 + MAX_PLAINTEXT).contains(&wire.len()) {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(wire.get(..MESSAGE_HEADER).ok_or(Error::Encoding)?);
        if d.array::<8>()? != *MESSAGE_TAG {
            return Err(Error::Encoding);
        }
        let session = d.array()?;
        let [role] = d.array()?;
        let epoch = d.u64()?;
        if !matches!(role, 1 | 2) || epoch == u64::MAX {
            return Err(Error::Encoding);
        }
        let index = d.u64()?;
        if index == u64::MAX {
            return Err(Error::Capacity);
        }
        let id = MessageId::from_trusted_state(d.array()?)?;
        if id.check(&session, role)? != index || id.epoch()? != epoch {
            return Err(Error::Encoding);
        }
        let length = u32::from_be_bytes(d.array()?) as usize;
        d.finish()?;
        if length > MAX_PLAINTEXT || length + MESSAGE_HEADER + 16 != wire.len() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            session,
            role,
            epoch,
            index,
            id,
            length,
        })
    }
    fn encode(&self) -> Vec<u8> {
        let mut wire = MESSAGE_TAG.to_vec();
        wire.extend_from_slice(&self.session);
        wire.push(self.role);
        wire.extend_from_slice(&self.epoch.to_be_bytes());
        wire.extend_from_slice(&self.index.to_be_bytes());
        wire.extend_from_slice(&self.id.0);
        wire.extend_from_slice(&(self.length as u32).to_be_bytes());
        wire
    }
}
impl State {
    fn new(
        source: [u8; 32],
        session: [u8; 32],
        role: u8,
        root: ZeroizingBytes<32>,
        context: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut info = label(b"initial/HKDF-SHA256/ChaCha20Poly1305");
        info.extend_from_slice(context);
        let mut output = ZeroizingBytes::<160>::zeroed();
        Hkdf::<Sha256>::new(Some(&session), root.as_bytes())
            .expand(&info, output.as_mut_bytes())
            .map_err(|_| Error::Provider)?;
        let rekey = key(output.as_bytes().get(..32).ok_or(Error::Encoding)?)?;
        let traffic = Traffic::from_material(
            session,
            role,
            0,
            output.as_bytes().get(32..).ok_or(Error::Encoding)?,
        )?;
        Ok(Self {
            source,
            session,
            role,
            rekey,
            control: rekey::Control::genesis(&session, context),
            send_epoch: 0,
            receive_epoch: 0,
            epochs: BTreeMap::from([(0, traffic)]),
            closure: None,
        })
    }
    fn traffic(&self, epoch: u64) -> Result<&Traffic, Error> {
        if epoch < first_retained_epoch(self.send_epoch.max(self.receive_epoch)) {
            return Err(Error::Retired);
        }
        self.epochs.get(&epoch).ok_or(Error::State)
    }
    fn traffic_mut(&mut self, epoch: u64) -> Result<&mut Traffic, Error> {
        if epoch < first_retained_epoch(self.send_epoch.max(self.receive_epoch)) {
            return Err(Error::Retired);
        }
        self.epochs.get_mut(&epoch).ok_or(Error::State)
    }
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(STATE_TAG.to_vec());
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.session);
        bytes.push(self.role);
        bytes.extend_from_slice(self.rekey.as_bytes());
        bytes.extend_from_slice(&self.send_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.receive_epoch.to_be_bytes());
        bytes.push(self.epochs.len() as u8);
        for value in self.epochs.values() {
            let encoded = value.encode();
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        self.control.encode(&mut bytes);
        closure::encode_pending(&self.closure, &mut bytes);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *STATE_TAG {
            return Err(Error::Encoding);
        }
        let source = d.array()?;
        let session = d.array()?;
        let [role] = d.array()?;
        if !matches!(role, 1 | 2) {
            return Err(Error::Encoding);
        }
        let rekey = key(d.take(32)?)?;
        let send_epoch = d.u64()?;
        let receive_epoch = d.u64()?;
        let [count] = d.array()?;
        if count == 0 || usize::from(count) > MAX_TRAFFIC_EPOCHS {
            return Err(Error::Capacity);
        }
        let newest = send_epoch.max(receive_epoch);
        let first = first_retained_epoch(newest);
        if newest == u64::MAX || u64::from(count) != newest - first + 1 {
            return Err(Error::Encoding);
        }
        let mut epochs = BTreeMap::new();
        for ordinal in 0..u64::from(count) {
            let length = u32::from_be_bytes(d.array()?) as usize;
            let traffic = Traffic::decode(d.take(length)?, session, role)?;
            if traffic.epoch != first + ordinal {
                return Err(Error::Encoding);
            }
            epochs.insert(traffic.epoch, traffic);
        }
        if !epochs.contains_key(&send_epoch) || !epochs.contains_key(&receive_epoch) {
            return Err(Error::Encoding);
        }
        for (epoch, traffic) in &epochs {
            if traffic.send_closed != (*epoch < send_epoch)
                || traffic.receive_limit.is_some() != (*epoch < receive_epoch)
                || (*epoch > send_epoch && (traffic.sent != 0 || traffic.pending.is_some()))
                || (*epoch > receive_epoch && traffic.received != 0)
            {
                return Err(Error::Encoding);
            }
        }
        let control = rekey::Control::decode(&mut d)?;
        let closure = closure::decode_pending(&mut d)?;
        d.finish()?;
        Ok(Self {
            source,
            session,
            role,
            rekey,
            control,
            send_epoch,
            receive_epoch,
            epochs,
            closure,
        })
    }
}

impl DeviceJournal {
    fn store_message_state(
        &mut self,
        image: &mut Image,
        state: &State,
    ) -> Result<(), DurableError> {
        image
            .records
            .get_mut(&record_id(&state.session))
            .ok_or(DurableError::Corrupt)?
            .payload = state.encode();
        self.persist(image)
    }
    /// Transfer a committed initiator bootstrap root into durable message chains.
    /// Dispatch its already committed final flight before application frames.
    pub fn activate_initiator_messages(
        &mut self,
        context: Arc<BootstrapContext>,
        request: InitiationId,
        now: u64,
    ) -> Result<[u8; 32], DurableError> {
        context.check_session_identity(now)?;
        let op = self.initiation_query(&context, request)?;
        let mut image = self.image()?;
        require_live_source(&image, &op)?;
        rosters::authorize_context(&image, &context, now)?;
        let record = image.records.get(&op).ok_or(DurableError::Absent)?;
        initiator::check_request(record, &context, request)?;
        if record.phase == DurableStatus::Messages {
            return self.existing_messages(&image, &op, &context, now);
        }
        if record.phase != DurableStatus::FinalCommitted {
            return Err(DurableError::Suspended);
        }
        let mut operation =
            self.restore_initiator(Arc::clone(&context), initiator::checkpoint(record)?)?;
        let (session, root) = operation.retire_session_root()?;
        let state = State::new(op, session, 1, root, &context.digest())?;
        let record = image.records.get_mut(&op).ok_or(DurableError::Corrupt)?;
        record.payload = initiator::pack(request, &operation.checkpoint()?);
        record.phase = DurableStatus::Messages;
        self.install_messages(&mut image, state, &context, now)
    }
    /// Transfer a responder root only after its final confirmation is committed.
    pub fn activate_responder_messages(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        now: u64,
    ) -> Result<[u8; 32], DurableError> {
        context.check_session_identity(now)?;
        let op = self.query_id(&context, initial)?;
        let mut image = self.image()?;
        require_live_source(&image, &op)?;
        rosters::authorize_context(&image, &context, now)?;
        let record = image.records.get(&op).ok_or(DurableError::Absent)?;
        record.check_request(&context, initial)?;
        if record.phase == DurableStatus::Messages {
            return self.existing_messages(&image, &op, &context, now);
        }
        if record.phase != DurableStatus::Complete {
            return Err(DurableError::Suspended);
        }
        let mut operation = self.restore_record(Arc::clone(&context), &record.payload)?;
        let (session, root) = operation.retire_session_root()?;
        let state = State::new(op, session, 2, root, &context.digest())?;
        let record = image.records.get_mut(&op).ok_or(DurableError::Corrupt)?;
        record.payload = operation.checkpoint()?;
        record.phase = DurableStatus::Messages;
        self.install_messages(&mut image, state, &context, now)
    }
    fn existing_messages(
        &mut self,
        image: &Image,
        op: &[u8; 32],
        context: &BootstrapContext,
        now: u64,
    ) -> Result<[u8; 32], DurableError> {
        for record in image
            .records
            .values()
            .filter(|r| r.kind == RecordKind::Messages && r.phase == DurableStatus::Messages)
        {
            let state = State::decode(&record.payload)?;
            if state.source == *op {
                context.check_session_identity(now)?;
                self.check_context_release(image, context, now)?;
                return Ok(state.session);
            }
        }
        Err(DurableError::Corrupt)
    }
    fn install_messages(
        &mut self,
        image: &mut Image,
        state: State,
        context: &BootstrapContext,
        now: u64,
    ) -> Result<[u8; 32], DurableError> {
        if image.operation_count() >= MAX_RECORDS {
            return Err(DurableError::Capacity);
        }
        let id = record_id(&state.session);
        if image.records.contains_key(&id) {
            return Err(DurableError::Conflict);
        }
        image.records.insert(
            id,
            Record {
                kind: RecordKind::Messages,
                context: context.digest(),
                phase: DurableStatus::Messages,
                authorities: rosters::context_accounts(context),
                keys: Vec::new(),
                prekeys: Vec::new(),
                payload: state.encode(),
            },
        );
        self.persist(image)?;
        #[cfg(all(test, unix))]
        tests::after_stage("activation");
        context.check_session_identity(now)?;
        self.check_context_release(image, context, now)?;
        Ok(state.session)
    }
    fn message_state(
        &mut self,
        image: &Image,
        context: &BootstrapContext,
        session: &[u8; 32],
        now: u64,
    ) -> Result<State, DurableError> {
        rosters::authorize_context(image, context, now)?;
        self.check_policy(context.policy())?;
        let record = image
            .records
            .get(&record_id(session))
            .ok_or(DurableError::Absent)?;
        if record.kind != RecordKind::Messages
            || record.context != context.digest()
            || record.authorities != rosters::context_accounts(context)
        {
            return Err(DurableError::Conflict);
        }
        match record.phase {
            DurableStatus::Messages => {}
            DurableStatus::MessagesAbandoning | DurableStatus::MessagesClosing => {
                return Err(DurableError::Suspended)
            }
            DurableStatus::MessagesAbandoned | DurableStatus::MessagesClosed => {
                return Err(Error::Retired.into())
            }
            _ => return Err(DurableError::Corrupt),
        }
        let state = State::decode(&record.payload)?;
        let owner = if state.role == 1 {
            context.initiator_storage_owner()
        } else {
            context.storage_owner()
        };
        if owner != image.owner {
            return Err(DurableError::Conflict);
        }
        state.send_progress(context.policy().application_send_budget())?;
        Ok(state)
    }
    /// Read the current send slot before submitting input. Retain this ID across
    /// retries. Concurrent readers may see the same slot; differing inputs conflict.
    pub fn next_message_id(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        now: u64,
    ) -> Result<MessageId, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        if state.control.send_fenced() {
            return Err(DurableError::Suspended);
        }
        let progress = state.send_progress(context.policy().application_send_budget())?;
        if progress.remaining == 0 && !progress.reserved {
            return Err(Error::RekeyRequired.into());
        }
        let id = MessageId::for_epoch(
            &session,
            state.role,
            state.send_epoch,
            state.traffic(state.send_epoch)?.sent,
        )?;
        fanout::require_individual(&image, session, id)?;
        context.check_session_identity(now)?;
        self.check_context_release(&image, context, now)?;
        Ok(id)
    }
    /// Commit the next chain state and exact ciphertext outbox together before
    /// returning dispatchable bytes. An exact repeated ID/input replays its outbox.
    pub fn send_message(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        id: MessageId,
        plaintext: &[u8],
        associated_data: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        fanout::require_individual(&image, session, id)?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if plaintext.len() > MAX_PLAINTEXT || associated_data.len() > MAX_AD {
            return Err(DurableError::Capacity);
        }
        let index = id.check(&session, state.role)?;
        let epoch = id.epoch()?;
        let active_epoch = state.send_epoch;
        let fenced = state.control.send_fenced();
        let progress = state.send_progress(context.policy().application_send_budget())?;
        let traffic = state.traffic_mut(epoch)?;
        traffic.require_unresolved()?;
        if index < traffic.send_floor {
            return Err(Error::Retired.into());
        }
        let already = traffic.outgoing.contains_key(&id);
        if !already && (epoch != active_epoch || fenced) {
            return Err(DurableError::Suspended);
        }
        if !already && index != traffic.sent {
            return Err(Error::Conflict.into());
        }
        if !already {
            if let Some(plan) = &traffic.pending {
                if plan.id != id
                    || plan.plaintext.as_slice() != plaintext
                    || plan.ad != associated_data
                {
                    return Err(DurableError::Conflict);
                }
            } else {
                if progress.remaining == 0 {
                    return Err(Error::RekeyRequired.into());
                }
                if traffic.outgoing.len() >= MAX_RECEIPTS {
                    return Err(DurableError::Capacity);
                }
                traffic.pending = Some(SendPlan {
                    id,
                    fanout: None,
                    plaintext: Zeroizing::new(plaintext.to_vec()),
                    ad: associated_data.to_vec(),
                });
                image
                    .records
                    .get_mut(&record_id(&session))
                    .ok_or(DurableError::Corrupt)?
                    .payload = state.encode();
                self.persist(&mut image)?;
                #[cfg(all(test, unix))]
                tests::after_stage("reserved");
            }
            context.check_session_identity(now)?;
        }
        let wire = state
            .traffic_mut(epoch)?
            .send(id, plaintext, associated_data)?;
        if !already {
            image
                .records
                .get_mut(&record_id(&session))
                .ok_or(DurableError::Corrupt)?
                .payload = state.encode();
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            tests::after_stage("sent");
        }
        context.check_session_identity(now)?;
        self.check_context_release(&image, context, now)?;
        Ok(wire)
    }
    /// Inspect an authenticated outgoing record without executing or releasing it.
    /// Policy close/expiry does not turn a read-only query into message permission.
    pub fn message_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        id: MessageId,
    ) -> Result<MessageStatus, DurableError> {
        let image = self.image()?;
        let record = self.message_record_for_status(&image, context, session)?;
        if matches!(
            record.phase,
            DurableStatus::MessagesAbandoned | DurableStatus::MessagesClosed
        ) {
            let retired = Retired::decode(&record.payload)?;
            check_message_owner(&image, context, retired.role)?;
            return Ok(retired.status(id)?);
        }
        let state = State::decode(&record.payload)?;
        check_message_owner(&image, context, state.role)?;
        state.send_progress(context.policy().application_send_budget())?;
        let index = id.check(&session, state.role)?;
        let traffic = state.traffic(id.epoch()?)?;
        Ok(if index < traffic.send_floor {
            MessageStatus::Acknowledged
        } else if index < traffic.sent && traffic.resolution.acknowledged() {
            MessageStatus::DeliveryUnknown
        } else if index < traffic.sent
            && (matches!(traffic.resolution, EpochResolutionStatus::Pending(_))
                || record.phase == DurableStatus::MessagesClosing)
        {
            MessageStatus::ResolutionPending
        } else if traffic.outgoing.contains_key(&id) {
            MessageStatus::Committed
        } else if traffic.pending.as_ref().is_some_and(|p| p.id == id) {
            MessageStatus::Reserved
        } else {
            MessageStatus::Absent
        })
    }
    fn message_record_for_status<'a>(
        &self,
        image: &'a Image,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<&'a Record, DurableError> {
        self.check_policy(context.policy())?;
        let record = image
            .records
            .get(&record_id(&session))
            .ok_or(DurableError::Absent)?;
        if record.kind != RecordKind::Messages
            || record.context != context.digest()
            || record.authorities != rosters::context_accounts(context)
        {
            return Err(DurableError::Conflict);
        }
        Ok(record)
    }
    fn message_state_for_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<State, DurableError> {
        let image = self.image()?;
        let record = self.message_record_for_status(&image, context, session)?;
        if matches!(
            record.phase,
            DurableStatus::MessagesAbandoned | DurableStatus::MessagesClosed
        ) {
            return Err(Error::Retired.into());
        }
        let state = State::decode(&record.payload)?;
        check_message_owner(&image, context, state.role)?;
        state.send_progress(context.policy().application_send_budget())?;
        Ok(state)
    }
    /// Continue only the sealed pending input or replay its committed outbox.
    /// No replacement plaintext or fresh message ID is accepted by this method.
    pub fn resume_message(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        id: MessageId,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        fanout::require_individual(&image, session, id)?;
        let mut state = self.message_state(&image, context, &session, now)?;
        let index = id.check(&session, state.role)?;
        let traffic = state.traffic_mut(id.epoch()?)?;
        traffic.require_unresolved()?;
        if index < traffic.send_floor {
            return Err(Error::Retired.into());
        }
        if let Some(saved) = traffic.outgoing.get(&id) {
            context.check_session_identity(now)?;
            self.check_context_release(&image, context, now)?;
            return Ok(saved.wire.clone());
        }
        let plan = traffic
            .pending
            .take()
            .filter(|plan| plan.id == id)
            .ok_or(DurableError::Absent)?;
        drop(image);
        self.send_message(context, session, id, &plan.plaintext, &plan.ad, now)
    }
    /// Authenticate on transaction-private state, then commit the consumed key,
    /// skipped keys and sealed inbox together before returning plaintext.
    pub fn receive_message(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        wire: &[u8],
        associated_data: &[u8],
        now: u64,
    ) -> Result<CommittedPlaintext, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        let header = Header::decode(wire)?;
        if header.index >= u64::from(context.policy().application_send_budget().messages()) {
            return Err(Error::PolicyDenied.into());
        }
        let id = header.id;
        let epoch = id.epoch()?;
        if epoch > state.receive_epoch {
            return Err(DurableError::Suspended);
        }
        let traffic = state.traffic_mut(epoch)?;
        let already = traffic.incoming.contains_key(&id);
        let plaintext = traffic.receive(wire, associated_data)?;
        if !already {
            image
                .records
                .get_mut(&record_id(&session))
                .ok_or(DurableError::Corrupt)?
                .payload = state.encode();
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            tests::after_stage("received");
        }
        context.check_session_identity(now)?;
        self.check_context_release(&image, context, now)?;
        Ok(plaintext)
    }
}

fn check_message_owner(
    image: &Image,
    context: &BootstrapContext,
    role: u8,
) -> Result<(), DurableError> {
    let owner = if role == 1 {
        context.initiator_storage_owner()
    } else {
        context.storage_owner()
    };
    if image.owner != owner {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

pub(super) fn require_live_source(image: &Image, source: &[u8; 32]) -> Result<(), DurableError> {
    fanout::require_live_source(image, source)
}

pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    let mut sources = BTreeSet::new();
    for (id, record) in &image.records {
        if record.kind != RecordKind::Messages {
            continue;
        }
        if !record.keys.is_empty() || !record.prekeys.is_empty() {
            return Err(DurableError::Corrupt);
        }
        let (source_id, session, role) = match record.phase {
            DurableStatus::Messages
            | DurableStatus::MessagesAbandoning
            | DurableStatus::MessagesClosing => {
                let state = State::decode(&record.payload).map_err(|_| DurableError::Corrupt)?;
                closure::validate_record(image, record, &state)?;
                fanout::validate_pending(image, &state, record.phase)
                    .map_err(|_| DurableError::Corrupt)?;
                state
                    .control
                    .validate(&state.session, state.role, &record.context, &state.rekey)
                    .map_err(|_| DurableError::Corrupt)?;
                state
                    .control
                    .validate_epochs(state.send_epoch, state.receive_epoch, state.epochs.len())
                    .map_err(|_| DurableError::Corrupt)?;
                state
                    .control
                    .validate_cutovers(&state, &record.context)
                    .map_err(|_| DurableError::Corrupt)?;
                (state.source, state.session, state.role)
            }
            DurableStatus::MessagesAbandoned => fanout::validate_message_record(image, record)?,
            DurableStatus::MessagesClosed => {
                let retired = Retired::decode(&record.payload)?;
                if retired.batch.is_some() {
                    return Err(DurableError::Corrupt);
                }
                (retired.source, retired.session, retired.role)
            }
            _ => return Err(DurableError::Corrupt),
        };
        if *id != record_id(&session) || !sources.insert(source_id) {
            return Err(DurableError::Corrupt);
        }
        let source = image.records.get(&source_id).ok_or(DurableError::Corrupt)?;
        let expected = if role == 1 {
            RecordKind::Initiator
        } else {
            RecordKind::Responder
        };
        if source.kind != expected
            || source.phase != DurableStatus::Messages
            || source.context != record.context
            || source.authorities != record.authorities
        {
            return Err(DurableError::Corrupt);
        }
        let payload = if role == 1 {
            source.payload.get(32..).ok_or(DurableError::Corrupt)?
        } else {
            &source.payload
        };
        let final_wire = payload
            .get(
                payload
                    .len()
                    .checked_sub(136)
                    .ok_or(DurableError::Corrupt)?..,
            )
            .ok_or(DurableError::Corrupt)?;
        let prefix = final_wire.get(..104).ok_or(DurableError::Corrupt)?;
        if digest(
            b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/session-id",
            prefix,
        ) != session
        {
            return Err(DurableError::Corrupt);
        }
    }
    for (id, record) in &image.records {
        if record.phase == DurableStatus::Messages
            && record.kind != RecordKind::Messages
            && !sources.contains(id)
        {
            return Err(DurableError::Corrupt);
        }
    }
    fanout::validate_image(image).map_err(|_| DurableError::Corrupt)
}

#[cfg(all(test, unix))]
mod tests;
