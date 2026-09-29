// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[derive(Clone)]
pub(super) struct Member {
    pub device: [u8; 16],
    pub generation: u64,
    pub credential: [u8; 32],
    pub context: [u8; 32],
    pub session: [u8; 32],
    pub role: u8,
    pub message: MessageId,
}
pub(super) struct Batch {
    pub id: FanoutId,
    pub account: [u8; 32],
    pub roster: RosterCheckpoint,
    pub reserved: bool,
    pub intent: Zeroizing<[u8; 32]>,
    pub members: Vec<Member>,
}
pub(super) fn batch_key(id: FanoutId) -> [u8; 32] {
    digest(&label(b"account-fanout-record/v1"), id.as_bytes())
}
impl Batch {
    fn metadata(&self) -> Vec<u8> {
        let mut bytes = b"QPFANO01".to_vec();
        bytes.extend_from_slice(&self.id.0);
        bytes.extend_from_slice(&self.account);
        bytes.extend_from_slice(&self.roster.version().to_be_bytes());
        bytes.extend_from_slice(&self.roster.digest());
        bytes.push(self.members.len() as u8);
        for member in &self.members {
            bytes.extend_from_slice(&member.device);
            bytes.extend_from_slice(&member.generation.to_be_bytes());
            bytes.extend_from_slice(&member.credential);
            bytes.extend_from_slice(&member.context);
            bytes.extend_from_slice(&member.session);
            bytes.push(member.role);
            bytes.extend_from_slice(&member.message.0);
        }
        bytes
    }
    pub(super) fn record(&self, local: [u8; 32]) -> Record {
        let metadata = self.metadata();
        let context = digest(&label(b"account-fanout-metadata/v1"), &metadata);
        let mut payload = Zeroizing::new(metadata);
        payload.extend_from_slice(self.intent.as_ref());
        let mut authorities = vec![local, self.account];
        authorities.sort_unstable();
        authorities.dedup();
        Record {
            kind: RecordKind::Fanout,
            context,
            phase: if self.reserved {
                DurableStatus::FanoutReserved
            } else {
                DurableStatus::FanoutCommitted
            },
            authorities,
            keys: Vec::new(),
            prekeys: Vec::new(),
            payload,
        }
    }
    pub(super) fn decode(
        image: &Image,
        key: &[u8; 32],
        record: &Record,
    ) -> Result<Self, DurableError> {
        if record.kind != RecordKind::Fanout
            || !record.keys.is_empty()
            || !record.prekeys.is_empty()
        {
            return Err(DurableError::Corrupt);
        }
        let reserved = match record.phase {
            DurableStatus::FanoutReserved => true,
            DurableStatus::FanoutCommitted => false,
            _ => return Err(DurableError::Corrupt),
        };
        let mut d = Decoder::new(&record.payload);
        if d.array::<8>()? != *b"QPFANO01" {
            return Err(DurableError::Corrupt);
        }
        let id = FanoutId::from_trusted_state(d.array()?)?;
        if batch_key(id) != *key || id.check(&image.id)? >= image.next_fanout {
            return Err(DurableError::Corrupt);
        }
        let account = d.array()?;
        crate::codec::nonzero(&account)?;
        let roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let [count] = d.array()?;
        if !(1..=MAX_DEVICES).contains(&usize::from(count)) {
            return Err(DurableError::Corrupt);
        }
        let mut members: Vec<Member> = Vec::with_capacity(usize::from(count));
        let mut sessions = BTreeSet::new();
        for _ in 0..count {
            let device = d.array()?;
            let generation = d.u64()?;
            let credential = d.array()?;
            let context = d.array()?;
            let session = d.array()?;
            let [role] = d.array()?;
            let message = MessageId::from_trusted_state(d.array()?)?;
            if device == [0; 16]
                || generation == 0
                || generation == u64::MAX
                || credential == [0; 32]
                || context == [0; 32]
                || session == [0; 32]
                || !matches!(role, 1 | 2)
                || !sessions.insert(session)
                || members.last().is_some_and(|m| m.device >= device)
            {
                return Err(DurableError::Corrupt);
            }
            message.check(&session, role)?;
            members.push(Member {
                device,
                generation,
                credential,
                context,
                session,
                role,
                message,
            });
        }
        let intent = Zeroizing::new(d.array()?);
        d.finish()?;
        let batch = Self {
            id,
            account,
            roster,
            reserved,
            intent,
            members,
        };
        let expected = batch.record(image.local_account);
        if record.context != expected.context || record.authorities != expected.authorities {
            return Err(DurableError::Corrupt);
        }
        Ok(batch)
    }
    pub(super) fn match_targets(&self, selected: &[Selected<'_>]) -> Result<(), DurableError> {
        if self.members.len() != selected.len()
            || self.members.iter().zip(selected).any(|(member, selected)| {
                let other = &selected.member;
                member.device != other.device
                    || member.generation != other.generation
                    || member.credential != other.credential
                    || member.context != other.context
                    || member.session != other.session
                    || member.role != other.role
            })
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
pub(super) fn get(image: &Image, id: FanoutId) -> Result<Batch, DurableError> {
    let ordinal = id.check(&image.id)?;
    let key = batch_key(id);
    match image.records.get(&key) {
        Some(record) => Batch::decode(image, &key, record),
        None if ordinal < image.next_fanout => Err(Error::Retired.into()),
        None if ordinal == image.next_fanout => Err(DurableError::Absent),
        None => Err(DurableError::Conflict),
    }
}
pub(super) fn output(
    state: &State,
    member: &Member,
    intent: &Zeroizing<[u8; 32]>,
) -> Result<FanoutOutput, DurableError> {
    if state.session != member.session || state.role != member.role {
        return Err(DurableError::Corrupt);
    }
    let index = member.message.check(&state.session, state.role)?;
    let traffic = match state.traffic(member.message.epoch()?) {
        Err(Error::Retired) => return Ok(FanoutOutput::HistoryRetired),
        result => result?,
    };
    if index >= traffic.sent {
        return Err(DurableError::Corrupt);
    }
    if index < traffic.send_floor {
        return Ok(FanoutOutput::Acknowledged);
    }
    if traffic.resolution.acknowledged() {
        return Ok(FanoutOutput::DeliveryUnknown);
    }
    if matches!(traffic.resolution, EpochResolutionStatus::Pending(_)) {
        return Ok(FanoutOutput::ResolutionPending);
    }
    let saved = traffic
        .outgoing
        .get(&member.message)
        .ok_or(DurableError::Corrupt)?;
    if saved.intent != *intent {
        return Err(DurableError::Corrupt);
    }
    Ok(FanoutOutput::Committed(saved.wire.clone()))
}
pub(in crate::durable::messages) fn validate_image(image: &Image) -> Result<(), DurableError> {
    if image.next_fanout == u64::MAX {
        return Err(DurableError::Corrupt);
    }
    let mut count = 0;
    let mut reserved = BTreeSet::new();
    for (key, record) in &image.records {
        if record.kind != RecordKind::Fanout {
            if matches!(
                record.phase,
                DurableStatus::FanoutReserved | DurableStatus::FanoutCommitted
            ) {
                return Err(DurableError::Corrupt);
            }
            continue;
        }
        count += 1;
        if count > MAX_FANOUTS {
            return Err(DurableError::Capacity);
        }
        let batch = Batch::decode(image, key, record)?;
        let authorities = &record.authorities;
        for member in &batch.members {
            let record = image
                .records
                .get(&record_id(&member.session))
                .ok_or(DurableError::Corrupt)?;
            if record.kind != RecordKind::Messages
                || record.context != member.context
                || &record.authorities != authorities
            {
                return Err(DurableError::Corrupt);
            }
            let state = State::decode(&record.payload)?;
            if state.session != member.session || state.role != member.role {
                return Err(DurableError::Corrupt);
            }
            if batch.reserved {
                let traffic = state.traffic(member.message.epoch()?)?;
                let plan = traffic.pending.as_ref().ok_or(DurableError::Corrupt)?;
                if member.message.epoch()? != state.send_epoch
                    || plan.id != member.message
                    || plan.fanout != Some(batch.id)
                    || !reserved.insert((member.session, member.message))
                    || intent(b"send-intent", &plan.plaintext, &plan.ad) != batch.intent
                {
                    return Err(DurableError::Corrupt);
                }
            } else {
                output(&state, member, &batch.intent)?;
            }
        }
    }
    Ok(())
}

// The message validator already owns a decoded state. Check its reverse links
// there rather than decoding every ordinary session a second time on each read.
pub(in crate::durable::messages) fn validate_pending(
    image: &Image,
    state: &State,
) -> Result<(), DurableError> {
    for traffic in state.epochs.values() {
        if let Some(plan) = &traffic.pending {
            if let Some(id) = plan.fanout {
                let batch = get(image, id)?;
                if !batch.reserved
                    || !batch
                        .members
                        .iter()
                        .any(|m| m.session == state.session && m.message == plan.id)
                {
                    return Err(DurableError::Corrupt);
                }
            }
        }
    }
    Ok(())
}
