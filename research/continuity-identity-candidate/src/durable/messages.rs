// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initial-epoch message protection owned exclusively by the device transaction.
use super::*;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

mod acknowledgement;

const MAX_PLAINTEXT: usize = 16 * 1024;
const MAX_AD: usize = 1024;
const MAX_SKIPPED: usize = 128;
const MAX_RECEIPTS: usize = 64;
const MESSAGE_HEADER: usize = 8 + 32 + 1 + 8 + 8 + 32 + 4;
const MESSAGE_TAG: &[u8; 8] = b"QPCMSG02";
const STATE_TAG: &[u8; 8] = b"QPMST002";
const DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/";

/// Journal-issued session/direction/sequence ID, retained by the host for retries.
/// Reusing an active ID with different input fails; retired IDs cannot be reused.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageId([u8; 32]);
impl MessageId {
    fn for_index(session: &[u8; 32], role: u8, index: u64) -> Result<Self, Error> {
        if !matches!(role, 1 | 2) || index == u64::MAX {
            return Err(Error::Capacity);
        }
        let mut bound = session.to_vec();
        bound.push(role);
        bound.extend_from_slice(&index.to_be_bytes());
        let binding = digest(&label(b"message-id"), &bound);
        let mut bytes = [0; 32];
        bytes
            .get_mut(..8)
            .ok_or(Error::Encoding)?
            .copy_from_slice(&index.to_be_bytes());
        bytes
            .get_mut(8..)
            .ok_or(Error::Encoding)?
            .copy_from_slice(binding.get(..24).ok_or(Error::Encoding)?);
        Ok(Self(bytes))
    }
    fn index(self) -> Result<u64, Error> {
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
        if self != Self::for_index(session, role, index)? {
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
    plaintext: Zeroizing<Vec<u8>>,
    ad: Vec<u8>,
}
struct Outgoing {
    intent: [u8; 32],
    wire: Vec<u8>,
}
struct Incoming {
    index: u64,
    intent: [u8; 32],
    plaintext: Zeroizing<Vec<u8>>,
    consumed: bool,
}
struct State {
    source: [u8; 32],
    session: [u8; 32],
    role: u8,
    rekey: ZeroizingBytes<32>,
    send: ZeroizingBytes<32>,
    receive: ZeroizingBytes<32>,
    send_ack: ZeroizingBytes<32>,
    receive_ack: ZeroizingBytes<32>,
    send_floor: u64,
    receive_floor: u64,
    sent: u64,
    received: u64,
    skipped: BTreeMap<u64, ZeroizingBytes<32>>,
    pending: Option<SendPlan>,
    outgoing: BTreeMap<MessageId, Outgoing>,
    incoming: BTreeMap<MessageId, Incoming>,
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
fn intent(name: &[u8], first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut value = Zeroizing::new(Vec::with_capacity(8 + first.len() + second.len()));
    value.extend_from_slice(&(first.len() as u64).to_be_bytes());
    value.extend_from_slice(first);
    value.extend_from_slice(second);
    digest(&label(name), &value)
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
        if !matches!(role, 1 | 2) || d.u64()? != 0 {
            return Err(Error::Encoding);
        }
        let index = d.u64()?;
        if index == u64::MAX {
            return Err(Error::Capacity);
        }
        let id = MessageId::from_trusted_state(d.array()?)?;
        if id.check(&session, role)? != index {
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
            index,
            id,
            length,
        })
    }
    fn encode(&self) -> Vec<u8> {
        let mut wire = MESSAGE_TAG.to_vec();
        wire.extend_from_slice(&self.session);
        wire.push(self.role);
        wire.extend_from_slice(&0u64.to_be_bytes());
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
        let a = key(output.as_bytes().get(32..64).ok_or(Error::Encoding)?)?;
        let b = key(output.as_bytes().get(64..96).ok_or(Error::Encoding)?)?;
        let ack_a = key(output.as_bytes().get(96..128).ok_or(Error::Encoding)?)?;
        let ack_b = key(output.as_bytes().get(128..).ok_or(Error::Encoding)?)?;
        let (send_ack, receive_ack) = if role == 1 {
            (ack_a, ack_b)
        } else {
            (ack_b, ack_a)
        };
        let (send, receive) = if role == 1 { (a, b) } else { (b, a) };
        Ok(Self {
            source,
            session,
            role,
            rekey,
            send,
            receive,
            send_ack,
            receive_ack,
            send_floor: 0,
            receive_floor: 0,
            sent: 0,
            received: 0,
            skipped: BTreeMap::new(),
            pending: None,
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
        })
    }
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(STATE_TAG.to_vec());
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.session);
        bytes.push(self.role);
        for k in [
            &self.rekey,
            &self.send,
            &self.receive,
            &self.send_ack,
            &self.receive_ack,
        ] {
            bytes.extend_from_slice(k.as_bytes());
        }
        bytes.extend_from_slice(&self.send_floor.to_be_bytes());
        bytes.extend_from_slice(&self.receive_floor.to_be_bytes());
        bytes.extend_from_slice(&self.sent.to_be_bytes());
        bytes.extend_from_slice(&self.received.to_be_bytes());
        bytes.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        for (index, k) in &self.skipped {
            bytes.extend_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(k.as_bytes());
        }
        bytes.push(u8::from(self.pending.is_some()));
        if let Some(plan) = &self.pending {
            bytes.extend_from_slice(&plan.id.0);
            bytes.extend_from_slice(&(plan.plaintext.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&plan.plaintext);
            bytes.extend_from_slice(&(plan.ad.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&plan.ad);
        }
        bytes.extend_from_slice(&(self.outgoing.len() as u16).to_be_bytes());
        for (id, saved) in &self.outgoing {
            bytes.extend_from_slice(&id.0);
            bytes.extend_from_slice(&saved.intent);
            bytes.extend_from_slice(&(saved.wire.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&saved.wire);
        }
        bytes.extend_from_slice(&(self.incoming.len() as u16).to_be_bytes());
        for (id, saved) in &self.incoming {
            bytes.extend_from_slice(&id.0);
            bytes.extend_from_slice(&saved.index.to_be_bytes());
            bytes.extend_from_slice(&saved.intent);
            bytes.push(u8::from(saved.consumed));
            bytes.extend_from_slice(&(saved.plaintext.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&saved.plaintext);
        }
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
        let send = key(d.take(32)?)?;
        let receive = key(d.take(32)?)?;
        let send_ack = key(d.take(32)?)?;
        let receive_ack = key(d.take(32)?)?;
        let send_floor = d.u64()?;
        let receive_floor = d.u64()?;
        let sent = d.u64()?;
        let received = d.u64()?;
        let mut skipped = BTreeMap::new();
        let count = usize::from(d.u16()?);
        if count > MAX_SKIPPED {
            return Err(Error::Capacity);
        }
        for _ in 0..count {
            let index = d.u64()?;
            if index < receive_floor
                || index >= received
                || skipped
                    .last_key_value()
                    .is_some_and(|(last, _)| *last >= index)
            {
                return Err(Error::Encoding);
            }
            skipped.insert(index, key(d.take(32)?)?);
        }
        let pending = match d.array::<1>()? {
            [0] => None,
            [1] => {
                let id = MessageId::from_trusted_state(d.array()?)?;
                let length = u32::from_be_bytes(d.array()?) as usize;
                if length > MAX_PLAINTEXT {
                    return Err(Error::Capacity);
                }
                let plaintext = Zeroizing::new(d.take(length)?.to_vec());
                let length = usize::from(d.u16()?);
                if length > MAX_AD {
                    return Err(Error::Capacity);
                }
                Some(SendPlan {
                    id,
                    plaintext,
                    ad: d.take(length)?.to_vec(),
                })
            }
            _ => return Err(Error::Encoding),
        };
        let mut outgoing = BTreeMap::new();
        let mut send_indices = BTreeSet::new();
        let count = usize::from(d.u16()?);
        if count > MAX_RECEIPTS || sent.checked_sub(send_floor) != Some(count as u64) {
            return Err(Error::Capacity);
        }
        for _ in 0..count {
            let id = MessageId::from_trusted_state(d.array()?)?;
            let intent = d.array()?;
            let length = u32::from_be_bytes(d.array()?) as usize;
            if length > MESSAGE_HEADER + 16 + MAX_PLAINTEXT {
                return Err(Error::Encoding);
            }
            let wire = d.take(length)?.to_vec();
            let header = Header::decode(&wire)?;
            if header.id != id
                || header.session != session
                || header.role != role
                || header.index < send_floor
                || header.index >= sent
                || !send_indices.insert(header.index)
                || outgoing
                    .last_key_value()
                    .is_some_and(|(last, _)| *last >= id)
            {
                return Err(Error::Encoding);
            }
            outgoing.insert(id, Outgoing { intent, wire });
        }
        if pending.as_ref().is_some_and(|p| {
            p.id.check(&session, role) != Ok(sent)
                || outgoing.contains_key(&p.id)
                || outgoing.len() >= MAX_RECEIPTS
        }) {
            return Err(Error::Encoding);
        }
        let mut incoming = BTreeMap::new();
        let mut receive_indices = BTreeSet::new();
        let count = usize::from(d.u16()?);
        if count > MAX_RECEIPTS
            || received.checked_sub(receive_floor) != Some((count + skipped.len()) as u64)
        {
            return Err(Error::Capacity);
        }
        for _ in 0..count {
            let id = MessageId::from_trusted_state(d.array()?)?;
            let index = d.u64()?;
            if id.check(&session, 3 - role)? != index {
                return Err(Error::Encoding);
            }
            let intent = d.array()?;
            let consumed = match d.array::<1>()? {
                [0] => false,
                [1] => true,
                _ => return Err(Error::Encoding),
            };
            let length = u32::from_be_bytes(d.array()?) as usize;
            if length > MAX_PLAINTEXT
                || (consumed && (length != 0 || index == receive_floor))
                || index < receive_floor
                || index >= received
                || skipped.contains_key(&index)
                || !receive_indices.insert(index)
                || incoming
                    .last_key_value()
                    .is_some_and(|(last, _)| *last >= id)
            {
                return Err(Error::Encoding);
            }
            let plaintext = Zeroizing::new(d.take(length)?.to_vec());
            incoming.insert(
                id,
                Incoming {
                    index,
                    intent,
                    plaintext,
                    consumed,
                },
            );
        }
        d.finish()?;
        Ok(Self {
            source,
            session,
            role,
            rekey,
            send,
            receive,
            send_ack,
            receive_ack,
            send_floor,
            receive_floor,
            sent,
            received,
            skipped,
            pending,
            outgoing,
            incoming,
        })
    }
    fn send(&mut self, id: MessageId, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.len() > MAX_PLAINTEXT || ad.len() > MAX_AD {
            return Err(Error::Capacity);
        }
        let index = id.check(&self.session, self.role)?;
        if index < self.send_floor {
            return Err(Error::Retired);
        }
        let intent = intent(b"send-intent", plaintext, ad);
        if let Some(saved) = self.outgoing.get(&id) {
            return if saved.intent == intent {
                Ok(saved.wire.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        if index != self.sent {
            return Err(Error::Conflict);
        }
        if self.outgoing.len() >= MAX_RECEIPTS {
            return Err(Error::Capacity);
        }
        let plan = self.pending.as_ref().ok_or(Error::State)?;
        if plan.id != id || plan.plaintext.as_slice() != plaintext || plan.ad != ad {
            return Err(Error::Conflict);
        }
        let (next, message) = step(&self.send, self.sent)?;
        let mut wire = Header {
            session: self.session,
            role: self.role,
            index: self.sent,
            id,
            length: plaintext.len(),
        }
        .encode();
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        let cipher =
            ChaCha20Poly1305::new_from_slice(message.as_bytes()).map_err(|_| Error::Provider)?;
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::from([0; 12]),
                &associated(&wire, ad),
                ciphertext.as_mut_slice().into(),
            )
            .map_err(|_| Error::Provider)?;
        wire.extend_from_slice(&ciphertext);
        wire.extend_from_slice(&tag);
        self.pending = None;
        self.send = next;
        self.sent += 1;
        self.outgoing.insert(
            id,
            Outgoing {
                intent,
                wire: wire.clone(),
            },
        );
        Ok(wire)
    }
    fn receive(&mut self, wire: &[u8], ad: &[u8]) -> Result<CommittedPlaintext, Error> {
        if ad.len() > MAX_AD {
            return Err(Error::Capacity);
        }
        let header = Header::decode(wire)?;
        if header.session != self.session || header.role == self.role {
            return Err(Error::Scope);
        }
        if header.index < self.receive_floor {
            return Err(Error::Retired);
        }
        let intent = intent(b"receive-intent", wire, ad);
        if let Some(saved) = self.incoming.get(&header.id) {
            return if saved.intent == intent {
                if saved.consumed {
                    return Err(Error::Retired);
                }
                Ok(CommittedPlaintext {
                    id: header.id,
                    bytes: saved.plaintext.clone(),
                })
            } else {
                Err(Error::Authentication)
            };
        }
        if self.incoming.len() >= MAX_RECEIPTS {
            return Err(Error::Capacity);
        }
        // Candidate state is transaction-private and dropped on any error. Even a
        // failed skipped-key authentication cannot consume the persisted key.
        let message = if header.index < self.received {
            self.skipped
                .remove(&header.index)
                .ok_or(Error::Authentication)?
        } else {
            let distance = header.index - self.received;
            if distance > MAX_SKIPPED as u64 || self.skipped.len() + distance as usize > MAX_SKIPPED
            {
                return Err(Error::Capacity);
            }
            while self.received < header.index {
                let (next, message) = step(&self.receive, self.received)?;
                self.skipped.insert(self.received, message);
                self.receive = next;
                self.received += 1;
            }
            let (next, message) = step(&self.receive, self.received)?;
            self.receive = next;
            self.received += 1;
            message
        };
        let mut plaintext = Zeroizing::new(
            wire.get(MESSAGE_HEADER..MESSAGE_HEADER + header.length)
                .ok_or(Error::Encoding)?
                .to_vec(),
        );
        let tag = Tag::from(
            <[u8; 16]>::try_from(
                wire.get(MESSAGE_HEADER + header.length..)
                    .ok_or(Error::Encoding)?,
            )
            .map_err(|_| Error::Encoding)?,
        );
        let cipher =
            ChaCha20Poly1305::new_from_slice(message.as_bytes()).map_err(|_| Error::Provider)?;
        cipher
            .decrypt_inout_detached(
                &Nonce::from([0; 12]),
                &associated(wire.get(..MESSAGE_HEADER).ok_or(Error::Encoding)?, ad),
                plaintext.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| Error::Authentication)?;
        self.incoming.insert(
            header.id,
            Incoming {
                index: header.index,
                intent,
                plaintext: plaintext.clone(),
                consumed: false,
            },
        );
        Ok(CommittedPlaintext {
            id: header.id,
            bytes: plaintext,
        })
    }
}

impl DeviceJournal {
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
            .filter(|r| r.kind == RecordKind::Messages)
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
        let state = State::decode(&record.payload)?;
        let owner = if state.role == 1 {
            context.initiator_storage_owner()
        } else {
            context.storage_owner()
        };
        if owner != image.owner {
            return Err(DurableError::Conflict);
        }
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
        let id = MessageId::for_index(&session, state.role, state.sent)?;
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
        let mut state = self.message_state(&image, context, &session, now)?;
        if plaintext.len() > MAX_PLAINTEXT || associated_data.len() > MAX_AD {
            return Err(DurableError::Capacity);
        }
        let index = id.check(&session, state.role)?;
        if index < state.send_floor {
            return Err(Error::Retired.into());
        }
        let already = state.outgoing.contains_key(&id);
        if !already && index != state.sent {
            return Err(Error::Conflict.into());
        }
        if !already {
            if let Some(plan) = &state.pending {
                if plan.id != id
                    || plan.plaintext.as_slice() != plaintext
                    || plan.ad != associated_data
                {
                    return Err(DurableError::Conflict);
                }
            } else {
                if state.outgoing.len() >= MAX_RECEIPTS {
                    return Err(DurableError::Capacity);
                }
                state.pending = Some(SendPlan {
                    id,
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
        let wire = state.send(id, plaintext, associated_data)?;
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
        self.check_policy(context.policy())?;
        let image = self.image()?;
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
        let state = State::decode(&record.payload)?;
        let owner = if state.role == 1 {
            context.initiator_storage_owner()
        } else {
            context.storage_owner()
        };
        if image.owner != owner {
            return Err(DurableError::Conflict);
        }
        let index = id.check(&session, state.role)?;
        Ok(if index < state.send_floor {
            MessageStatus::Acknowledged
        } else if state.outgoing.contains_key(&id) {
            MessageStatus::Committed
        } else if state.pending.as_ref().is_some_and(|p| p.id == id) {
            MessageStatus::Reserved
        } else {
            MessageStatus::Absent
        })
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
        let mut state = self.message_state(&image, context, &session, now)?;
        if id.check(&session, state.role)? < state.send_floor {
            return Err(Error::Retired.into());
        }
        if let Some(saved) = state.outgoing.get(&id) {
            context.check_session_identity(now)?;
            self.check_context_release(&image, context, now)?;
            return Ok(saved.wire.clone());
        }
        let plan = state
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
        let id = Header::decode(wire)?.id;
        let already = state.incoming.contains_key(&id);
        let plaintext = state.receive(wire, associated_data)?;
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

pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    let mut sources = BTreeSet::new();
    for (id, record) in &image.records {
        if record.kind != RecordKind::Messages {
            continue;
        }
        if record.phase != DurableStatus::Messages
            || !record.keys.is_empty()
            || !record.prekeys.is_empty()
        {
            return Err(DurableError::Corrupt);
        }
        let state = State::decode(&record.payload).map_err(|_| DurableError::Corrupt)?;
        if *id != record_id(&state.session) || !sources.insert(state.source) {
            return Err(DurableError::Corrupt);
        }
        let source = image
            .records
            .get(&state.source)
            .ok_or(DurableError::Corrupt)?;
        let expected = if state.role == 1 {
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
        let payload = if state.role == 1 {
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
        ) != state.session
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
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
