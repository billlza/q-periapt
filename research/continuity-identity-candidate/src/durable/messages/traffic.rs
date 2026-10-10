// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Traffic, receipt and ACK authority isolated to one authenticated key epoch.
use super::*;

enum SendInput<'a> {
    Submitted(&'a [u8], &'a [u8]),
    Reserved,
}

pub(super) struct Traffic {
    pub(super) session: [u8; 32],
    pub(super) role: u8,
    pub(super) epoch: u64,
    pub(super) send_closed: bool,
    pub(super) receive_limit: Option<u64>,
    pub(super) resolution: EpochResolutionStatus,
    pub(super) resolution_key: Option<ZeroizingBytes<32>>,
    pub(super) send: ZeroizingBytes<32>,
    pub(super) receive: ZeroizingBytes<32>,
    pub(super) send_ack: ZeroizingBytes<32>,
    pub(super) receive_ack: ZeroizingBytes<32>,
    pub(super) send_floor: u64,
    pub(super) receive_floor: u64,
    pub(super) sent: u64,
    pub(super) received: u64,
    pub(super) skipped: BTreeMap<u64, ZeroizingBytes<32>>,
    pub(super) pending: Option<SendPlan>,
    pub(super) outgoing: BTreeMap<MessageId, Outgoing>,
    pub(super) incoming: BTreeMap<MessageId, Incoming>,
}
impl Traffic {
    // Signed rekey flights attest to this local condition before a later cutover
    // can remove the epoch. Without explicit application resolution, do not destroy
    // an unsent reservation, unacknowledged outbox, or unconsumed plaintext. A
    // disclosed old key can invent indices beyond the identity-signed close count; only skipped keys
    // and already-consumed metadata for those impossible honest slots may expire.
    pub(super) fn can_retire(&self) -> bool {
        if self.resolution.acknowledged() {
            // The distinct terminal invariant is checked at every image admission.
            return self.send_closed
                && self.receive_limit.is_some()
                && self.pending.is_none()
                && self.outgoing.is_empty()
                && self.incoming.is_empty()
                && self.skipped.is_empty();
        }
        if self.resolution != EpochResolutionStatus::Unrequested {
            return false;
        }
        self.send_closed
            && self.pending.is_none()
            && self.send_floor == self.sent
            && self.outgoing.is_empty()
            && self.receive_limit.is_some_and(|limit| {
                self.receive_floor >= limit
                    && self.skipped.keys().all(|index| *index >= limit)
                    && self.incoming.values().all(|saved| saved.consumed)
            })
    }

    pub(super) fn from_material(
        session: [u8; 32],
        role: u8,
        epoch: u64,
        material: &[u8],
    ) -> Result<Self, Error> {
        if material.len() != 128 || epoch == u64::MAX || !matches!(role, 1 | 2) {
            return Err(Error::Encoding);
        }
        let a = key(material.get(..32).ok_or(Error::Encoding)?)?;
        let b = key(material.get(32..64).ok_or(Error::Encoding)?)?;
        let ack_a = key(material.get(64..96).ok_or(Error::Encoding)?)?;
        let ack_b = key(material.get(96..).ok_or(Error::Encoding)?)?;
        let (send, receive, send_ack, receive_ack) = if role == 1 {
            (a, b, ack_a, ack_b)
        } else {
            (b, a, ack_b, ack_a)
        };
        Ok(Self {
            session,
            role,
            epoch,
            send_closed: false,
            receive_limit: None,
            resolution: EpochResolutionStatus::Unrequested,
            resolution_key: None,
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
    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"QPTEPO04".to_vec());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.push(u8::from(self.send_closed));
        bytes.push(u8::from(self.receive_limit.is_some()));
        if let Some(limit) = self.receive_limit {
            bytes.extend_from_slice(&limit.to_be_bytes());
        }
        self.resolution.encode(&mut bytes);
        bytes.push(u8::from(self.resolution_key.is_some()));
        if let Some(key) = &self.resolution_key {
            bytes.extend_from_slice(key.as_bytes());
        }
        for k in [&self.send, &self.receive, &self.send_ack, &self.receive_ack] {
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
            bytes.push(u8::from(plan.fanout.is_some()));
            if let Some(fanout) = plan.fanout {
                bytes.extend_from_slice(fanout.as_bytes());
            }
            bytes.extend_from_slice(&(plan.plaintext.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&plan.plaintext);
            bytes.extend_from_slice(&(plan.ad.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&plan.ad);
        }
        bytes.extend_from_slice(&(self.outgoing.len() as u16).to_be_bytes());
        for (id, saved) in &self.outgoing {
            bytes.extend_from_slice(&id.0);
            bytes.extend_from_slice(saved.intent.as_ref());
            bytes.extend_from_slice(&(saved.wire.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&saved.wire);
        }
        bytes.extend_from_slice(&(self.incoming.len() as u16).to_be_bytes());
        for (id, saved) in &self.incoming {
            bytes.extend_from_slice(&id.0);
            bytes.extend_from_slice(&saved.index.to_be_bytes());
            bytes.extend_from_slice(saved.intent.as_ref());
            bytes.push(u8::from(saved.consumed));
            bytes.extend_from_slice(&(saved.plaintext.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&saved.plaintext);
        }
        bytes
    }
    pub(super) fn decode(bytes: &[u8], session: [u8; 32], role: u8) -> Result<Self, Error> {
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPTEPO04" {
            return Err(Error::Encoding);
        }
        let epoch = d.u64()?;
        if epoch == u64::MAX {
            return Err(Error::Encoding);
        }
        let send_closed = match d.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(Error::Encoding),
        };
        let receive_limit = match d.array::<1>()? {
            [0] => None,
            [1] => Some(d.u64()?),
            _ => return Err(Error::Encoding),
        };
        if !matches!(role, 1 | 2) {
            return Err(Error::Encoding);
        }
        let resolution = EpochResolutionStatus::decode(&mut d)?;
        let resolution_key = match d.array::<1>()? {
            [0] => None,
            [1] => Some(key(d.take(32)?)?),
            _ => return Err(Error::Encoding),
        };
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
        if count > MAX_SKIPPED || (resolution.acknowledged() && count != 0) {
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
                let fanout = match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(FanoutId::from_trusted_state(d.array()?)?),
                    _ => return Err(Error::Encoding),
                };
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
                    fanout,
                    plaintext,
                    ad: d.take(length)?.to_vec(),
                })
            }
            _ => return Err(Error::Encoding),
        };
        let mut outgoing = BTreeMap::new();
        let mut send_indices = BTreeSet::new();
        let count = usize::from(d.u16()?);
        if count > MAX_RECEIPTS
            || if resolution.acknowledged() {
                count != 0 || send_floor > sent
            } else {
                sent.checked_sub(send_floor) != Some(count as u64)
            }
        {
            return Err(Error::Capacity);
        }
        for _ in 0..count {
            let id = MessageId::from_trusted_state(d.array()?)?;
            let intent = Zeroizing::new(d.array()?);
            let length = u32::from_be_bytes(d.array()?) as usize;
            if length > MESSAGE_HEADER + 16 + MAX_PLAINTEXT {
                return Err(Error::Encoding);
            }
            let wire = d.take(length)?.to_vec();
            let header = Header::decode(&wire)?;
            if header.id != id
                || header.session != session
                || header.role != role
                || header.epoch != epoch
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
                || p.id.epoch() != Ok(epoch)
                || send_closed
                || outgoing.contains_key(&p.id)
                || outgoing.len() >= MAX_RECEIPTS
        }) {
            return Err(Error::Encoding);
        }
        let mut incoming = BTreeMap::new();
        let mut receive_indices = BTreeSet::new();
        let count = usize::from(d.u16()?);
        if count > MAX_RECEIPTS
            || if resolution.acknowledged() {
                count != 0 || receive_floor > received
            } else {
                received.checked_sub(receive_floor) != Some((count + skipped.len()) as u64)
            }
        {
            return Err(Error::Capacity);
        }
        for _ in 0..count {
            let id = MessageId::from_trusted_state(d.array()?)?;
            let index = d.u64()?;
            if id.check(&session, 3 - role)? != index || id.epoch()? != epoch {
                return Err(Error::Encoding);
            }
            let intent = Zeroizing::new(d.array()?);
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
        if (send_closed && send.as_bytes() != &[0; 32])
            || receive_limit
                .is_some_and(|limit| received >= limit && receive.as_bytes() != &[0; 32])
        {
            return Err(Error::Encoding);
        }
        let traffic = Self {
            session,
            role,
            epoch,
            send_closed,
            receive_limit,
            resolution,
            resolution_key,
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
        };
        traffic.validate_resolution()?;
        Ok(traffic)
    }
    pub(super) fn send(
        &mut self,
        id: MessageId,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.send_input(id, SendInput::Submitted(plaintext, ad))
            .map(<[u8]>::to_vec)
    }
    // The aggregate caller has checked this reservation against its original
    // member and intent. Borrow its retained bytes through the same send path;
    // no temporary plaintext/AD copies or alternate encryption implementation.
    pub(super) fn send_reserved(&mut self, id: MessageId) -> Result<&[u8], Error> {
        self.send_input(id, SendInput::Reserved)
    }
    fn send_input(&mut self, id: MessageId, input: SendInput<'_>) -> Result<&[u8], Error> {
        self.require_unresolved()?;
        let (plaintext, ad) = match input {
            SendInput::Submitted(plaintext, ad) => (plaintext, ad),
            SendInput::Reserved => {
                let plan = self.pending.as_ref().ok_or(Error::State)?;
                (plan.plaintext.as_slice(), plan.ad.as_slice())
            }
        };
        if plaintext.len() > MAX_PLAINTEXT || ad.len() > MAX_AD {
            return Err(Error::Capacity);
        }
        let index = id.check(&self.session, self.role)?;
        if id.epoch()? != self.epoch {
            return Err(Error::Scope);
        }
        if index < self.send_floor {
            return Err(Error::Retired);
        }
        let intent = intent(b"send-intent", plaintext, ad);
        let at_capacity = self.outgoing.len() >= MAX_RECEIPTS;
        let entry = match self.outgoing.entry(id) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let saved = entry.into_mut();
                return if saved.intent == intent {
                    Ok(saved.wire.as_slice())
                } else {
                    Err(Error::Conflict)
                };
            }
            std::collections::btree_map::Entry::Vacant(entry) => entry,
        };
        if self.send_closed {
            return Err(Error::Retired);
        }
        if index != self.sent {
            return Err(Error::Conflict);
        }
        if at_capacity {
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
            epoch: self.epoch,
            index: self.sent,
            id,
            length: plaintext.len(),
        }
        .encode();
        // Reserve ciphertext and tag together so retaining the original buffer
        // does not retain spare capacity from a second growth for the tag.
        wire.reserve_exact(plaintext.len() + 16);
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
        Ok(entry.insert(Outgoing { intent, wire }).wire.as_slice())
    }
    pub(super) fn receive(&mut self, wire: &[u8], ad: &[u8]) -> Result<CommittedPlaintext, Error> {
        self.require_unresolved()?;
        if ad.len() > MAX_AD {
            return Err(Error::Capacity);
        }
        let header = Header::decode(wire)?;
        if header.session != self.session || header.role == self.role || header.epoch != self.epoch
        {
            return Err(Error::Scope);
        }
        if self
            .receive_limit
            .is_some_and(|limit| header.index >= limit)
        {
            return Err(Error::Retired);
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
        if self
            .receive_limit
            .is_some_and(|limit| self.received >= limit)
        {
            self.receive = ZeroizingBytes::zeroed();
        }
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
