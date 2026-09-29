// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete-roster sends under one device journal and its aggregate witness.
use super::*;
use crate::{RosterCheckpoint, MAX_DEVICES};

mod codec;
use codec::{batch_key, Batch, BatchState, Member};
mod abandonment;
pub(super) use abandonment::{
    epoch_accounting, progress as abandoned_progress, require_live_source, validate_message_record,
};
pub use abandonment::{
    AbandonedDelivery, AbandonedEpoch, AbandonedSession, FanoutAbandonment, FanoutAbandonmentId,
    ReservedAbandonment,
};
const MAX_FANOUTS: usize = 16;

/// Journal-bound monotonic correlation ID. It contains no plaintext commitment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FanoutId([u8; 32]);
impl FanoutId {
    fn at(journal: &[u8; 32], ordinal: u64) -> Result<Self, Error> {
        if ordinal == u64::MAX {
            return Err(Error::Capacity);
        }
        let mut input = journal.to_vec();
        input.extend_from_slice(&ordinal.to_be_bytes());
        let binding = digest(&label(b"account-fanout-id/v1"), &input);
        let mut bytes = [0; 32];
        bytes
            .get_mut(..8)
            .ok_or(Error::Encoding)?
            .copy_from_slice(&ordinal.to_be_bytes());
        bytes
            .get_mut(8..)
            .ok_or(Error::Encoding)?
            .copy_from_slice(binding.get(..24).ok_or(Error::Encoding)?);
        Ok(Self(bytes))
    }
    fn check(self, journal: &[u8; 32]) -> Result<u64, Error> {
        let ordinal = u64::from_be_bytes(
            self.0
                .get(..8)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        );
        if self != Self::at(journal, ordinal)? {
            return Err(Error::Scope);
        }
        Ok(ordinal)
    }
    /// Restore a retained correlation ID; journal admission still verifies it.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public ID bytes, independent of the message plaintext.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One existing pairwise session; the journal derives its exact peer identity.
pub struct FanoutTarget<'a> {
    /// Authenticated context for this exact session.
    pub context: &'a BootstrapContext,
    /// Previously admitted session; fanout never provisions missing sessions.
    pub session: [u8; 32],
}
/// Exact submission retained across retries. All current account devices are
/// mandatory, except this sending device when sending to its own account.
pub struct FanoutInput<'a> {
    /// Previously read next ID, retained even if commit returns an error.
    pub id: FanoutId,
    /// Recipient account whose installed signed roster supplies the complete set.
    pub account: [u8; 32],
    /// One session per required device, with no duplicates or exclusions.
    pub targets: &'a [FanoutTarget<'a>],
    /// Shared plaintext, at most the ordinary message limit.
    pub plaintext: &'a [u8],
    /// Shared associated data, at most the ordinary message limit.
    pub associated_data: &'a [u8],
}
/// Local aggregate reconciliation only; committed does not mean remotely received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanoutStatus {
    /// This next ID has not been reserved. Future or wrong-journal IDs are errors.
    Absent,
    /// Every input slot is reserved, and no member has dispatchable ciphertext.
    Reserved,
    /// All required chain advances and ciphertexts committed together.
    Committed,
    /// Every member session is frozen; the exact report awaits host accounting.
    Abandoning(FanoutAbandonmentId),
    /// All member sessions are permanently closed after host accounting.
    Abandoned(FanoutAbandonmentId),
    /// This older ID was explicitly retired and can never identify new work.
    Retired,
}
/// Per-recipient outcome when replaying a locally committed aggregate.
pub enum FanoutOutput {
    /// Exact committed bytes, released only after whole-aggregate admission.
    Committed(Vec<u8>),
    /// Authenticated peer consumption retired this outbox.
    Acknowledged,
    /// A frozen closed-epoch report awaits durable application accounting.
    ResolutionPending,
    /// Application accounting recorded an unknown outcome, not delivery success.
    DeliveryUnknown,
    /// Earlier epoch history was retired after its separate settlement/accounting.
    /// This does not distinguish acknowledgement from recorded unknown delivery.
    HistoryRetired,
    /// Input was reserved but never committed; the whole session is now terminal.
    ReservationAbandoned,
}
/// One explicitly identified member of a complete aggregate result.
pub struct FanoutMember {
    /// Credential-bound recipient device identifier.
    pub device: [u8; 16],
    /// Original pairwise session.
    pub session: [u8; 32],
    /// Original per-session message ID; never replaced on retry.
    pub message: MessageId,
    /// Explicit current outcome. Missing bytes never masquerade as success.
    pub output: FanoutOutput,
}

struct Selected<'a> {
    member: Member,
    state: State,
    context: &'a BootstrapContext,
    local: &'a VerifiedDevice,
}
impl DeviceJournal {
    /// Read the next aggregate ID. Concurrent readers can see the same ID;
    /// only the first exact reservation wins, and different input conflicts.
    pub fn next_fanout_id(&mut self) -> Result<FanoutId, DurableError> {
        let image = self.image()?;
        self.check_release(&image)?;
        Ok(FanoutId::at(&image.id, image.next_fanout)?)
    }
    /// Query local commit state without releasing bytes or granting authority.
    pub fn fanout_status(&mut self, id: FanoutId) -> Result<FanoutStatus, DurableError> {
        let image = self.image()?;
        let ordinal = id.check(&image.id)?;
        if ordinal > image.next_fanout {
            return Err(DurableError::Conflict);
        }
        match image.records.get(&batch_key(id)) {
            Some(record) => Ok(Batch::decode(&image, &batch_key(id), record)?.status()),
            None if ordinal == image.next_fanout => Ok(FanoutStatus::Absent),
            None => Ok(FanoutStatus::Retired),
        }
    }
    fn select_fanout<'a>(
        &mut self,
        image: &Image,
        account: [u8; 32],
        targets: &'a [FanoutTarget<'a>],
        now: Option<u64>,
    ) -> Result<Vec<Selected<'a>>, DurableError> {
        if targets.is_empty() || targets.len() > MAX_DEVICES {
            return Err(DurableError::Capacity);
        }
        let mut selected = Vec::with_capacity(targets.len());
        let mut sessions = BTreeSet::new();
        for target in targets {
            let state = match now {
                Some(now) => self.message_state(image, target.context, &target.session, now)?,
                None => self.message_state_for_status(target.context, target.session)?,
            };
            let devices = target.context.devices();
            let (local, peer) = match state.role {
                1 => (devices[0], devices[1]),
                2 => (devices[1], devices[0]),
                _ => return Err(DurableError::Corrupt),
            };
            if peer.account_id() != account || !sessions.insert(target.session) {
                return Err(DurableError::Conflict);
            }
            let member = Member {
                device: peer.device_id(),
                generation: peer.generation(),
                credential: peer.credential_digest(),
                context: target.context.digest(),
                session: target.session,
                role: state.role,
                message: MessageId::for_epoch(
                    &target.session,
                    state.role,
                    state.send_epoch,
                    state.traffic(state.send_epoch)?.sent,
                )?,
            };
            selected.push(Selected {
                member,
                state,
                context: target.context,
                local,
            });
        }
        selected.sort_by_key(|s| s.member.device);
        if selected.windows(2).any(|pair| {
            pair.first().map(|s| s.member.device) == pair.last().map(|s| s.member.device)
        }) {
            return Err(DurableError::Conflict);
        }
        Ok(selected)
    }
    fn authorize_fanout(
        &mut self,
        image: &Image,
        account: [u8; 32],
        selected: &[Selected<'_>],
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        let roster = rosters::current(image, &account)?;
        roster.check_time(now)?;
        let local = selected.first().ok_or(DurableError::Capacity)?.local;
        let expected: Vec<_> = roster
            .members()
            .filter(|(device, _, _)| account != image.local_account || *device != local.device_id())
            .collect();
        let actual: Vec<_> = selected
            .iter()
            .map(|s| (s.member.device, s.member.generation, s.member.credential))
            .collect();
        if actual != expected {
            return Err(Error::PolicyDenied.into());
        }
        for selected in selected {
            rosters::authorize_context(image, selected.context, now)?;
        }
        self.check_release(image)?;
        Ok(roster.checkpoint())
    }
    /// Atomically reserve every required input, then atomically commit every
    /// chain/outbox before releasing any bytes. Cancellation stops dispatch; it
    /// cannot clear or replace an uncertain aggregate reservation.
    pub fn send_account_message(
        &mut self,
        input: FanoutInput<'_>,
        now: u64,
    ) -> Result<Vec<FanoutMember>, DurableError> {
        if input.plaintext.len() > MAX_PLAINTEXT || input.associated_data.len() > MAX_AD {
            return Err(DurableError::Capacity);
        }
        let mut image = self.image()?;
        let ordinal = input.id.check(&image.id)?;
        if let Some(record) = image.records.get(&batch_key(input.id)) {
            let batch = Batch::decode(&image, &batch_key(input.id), record)?;
            if batch.account != input.account
                || *batch.intent()?
                    != intent(b"send-intent", input.plaintext, input.associated_data)
            {
                return Err(DurableError::Conflict);
            }
            return self.resume_account_message(input.id, input.targets, now);
        }
        if ordinal < image.next_fanout {
            return Err(Error::Retired.into());
        }
        if ordinal != image.next_fanout {
            return Err(DurableError::Conflict);
        }
        if image.operation_count() >= MAX_RECORDS
            || image
                .records
                .values()
                .filter(|r| r.kind == RecordKind::Fanout)
                .count()
                >= MAX_FANOUTS
        {
            return Err(DurableError::Capacity);
        }
        let mut selected = self.select_fanout(&image, input.account, input.targets, Some(now))?;
        let roster = self.authorize_fanout(&image, input.account, &selected, now)?;
        for item in &mut selected {
            if item.state.control.send_fenced() {
                return Err(DurableError::Suspended);
            }
            let progress = item
                .state
                .send_progress(item.context.policy().application_send_budget())?;
            let traffic = item.state.traffic_mut(item.state.send_epoch)?;
            traffic.require_unresolved()?;
            if traffic.pending.is_some() {
                return Err(DurableError::Suspended);
            }
            if progress.remaining == 0 {
                return Err(Error::RekeyRequired.into());
            }
            if traffic.outgoing.len() >= MAX_RECEIPTS {
                return Err(DurableError::Capacity);
            }
            traffic.pending = Some(SendPlan {
                id: item.member.message,
                fanout: Some(input.id),
                plaintext: Zeroizing::new(input.plaintext.to_vec()),
                ad: input.associated_data.to_vec(),
            });
        }
        let batch = Batch {
            id: input.id,
            account: input.account,
            roster,
            state: BatchState::Reserved(intent(
                b"send-intent",
                input.plaintext,
                input.associated_data,
            )),
            members: selected.iter().map(|s| s.member.clone()).collect(),
        };
        for item in &selected {
            image
                .records
                .get_mut(&record_id(&item.member.session))
                .ok_or(DurableError::Corrupt)?
                .payload = item.state.encode();
        }
        image.next_fanout = image
            .next_fanout
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(DurableError::Capacity)?;
        image
            .records
            .insert(batch_key(input.id), batch.record(image.local_account));
        self.persist(&mut image)?;
        #[cfg(all(test, unix))]
        tests::after_stage("fanout-reserved");
        self.resume_account_message(input.id, input.targets, now)
    }
    /// Resume only the complete saved recipient set and exact reserved inputs.
    /// A changed installed roster suspends this aggregate instead of dropping or
    /// adding a recipient. Existing ordinary message/epoch accounting is retained.
    pub fn resume_account_message(
        &mut self,
        id: FanoutId,
        targets: &[FanoutTarget<'_>],
        now: u64,
    ) -> Result<Vec<FanoutMember>, DurableError> {
        let mut image = self.image()?;
        let mut batch = codec::get(&image, id)?;
        batch.intent()?;
        let mut selected = self.select_fanout(&image, batch.account, targets, Some(now))?;
        batch.match_targets(&selected)?;
        if self.authorize_fanout(&image, batch.account, &selected, now)? != batch.roster {
            return Err(Error::Checkpoint.into());
        }
        if batch.reserved() {
            for (member, item) in batch.members.iter().zip(&mut selected) {
                let traffic = item.state.traffic_mut(member.message.epoch()?)?;
                let plan = traffic.pending.take().ok_or(DurableError::Corrupt)?;
                if plan.id != member.message
                    || plan.fanout != Some(id)
                    || intent(b"send-intent", &plan.plaintext, &plan.ad) != *batch.intent()?
                {
                    return Err(DurableError::Corrupt);
                }
                let plaintext = Zeroizing::new(plan.plaintext.to_vec());
                let ad = plan.ad.clone();
                traffic.pending = Some(plan);
                // No per-member persistence or release. Only the aggregate below
                // installs any ciphertext or advances a durable chain.
                let wire = traffic.send(member.message, &plaintext, &ad)?;
                #[cfg(all(test, unix))]
                tests::after_fanout_computation(&wire);
                drop(wire);
            }
            for item in &selected {
                image
                    .records
                    .get_mut(&record_id(&item.member.session))
                    .ok_or(DurableError::Corrupt)?
                    .payload = item.state.encode();
            }
            batch.state = BatchState::Committed(batch.intent()?.clone());
            image
                .records
                .insert(batch_key(id), batch.record(image.local_account));
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            tests::after_stage("fanout-committed");
        }
        if self.authorize_fanout(&image, batch.account, &selected, now)? != batch.roster {
            return Err(Error::Checkpoint.into());
        }
        batch
            .members
            .iter()
            .zip(&selected)
            .map(|(member, item)| {
                Ok(FanoutMember {
                    device: member.device,
                    session: member.session,
                    message: member.message,
                    output: codec::output(&item.state, member, batch.intent()?)?,
                })
            })
            .collect()
    }
    /// Retire aggregate metadata only when every member has separate authenticated
    /// acknowledgement or completed epoch accounting. The monotonic ID is never
    /// reused. A reserved aggregate cannot be abandoned through this method.
    pub fn retire_fanout(
        &mut self,
        id: FanoutId,
        targets: &[FanoutTarget<'_>],
    ) -> Result<(), DurableError> {
        let mut image = self.image()?;
        let batch = codec::get(&image, id)?;
        if matches!(
            batch.state,
            BatchState::Reserved(_) | BatchState::Abandoning { .. }
        ) {
            return Err(DurableError::Suspended);
        }
        self.check_fanout_cleanup(&image, &batch, targets)?;
        for member in &batch.members {
            if matches!(
                codec::record_output(&image, &batch, member)?,
                FanoutOutput::Committed(_) | FanoutOutput::ResolutionPending
            ) {
                return Err(DurableError::Suspended);
            }
        }
        image
            .records
            .remove(&batch_key(id))
            .ok_or(DurableError::Corrupt)?;
        self.persist(&mut image)?;
        self.check_release(&image)
    }
}

pub(super) fn require_individual(
    image: &Image,
    session: [u8; 32],
    id: MessageId,
) -> Result<(), DurableError> {
    for (key, record) in image
        .records
        .iter()
        .filter(|(_, r)| r.kind == RecordKind::Fanout)
    {
        let batch = Batch::decode(image, key, record)?;
        if matches!(
            batch.state,
            BatchState::Reserved(_) | BatchState::Abandoning { .. }
        ) && batch
            .members
            .iter()
            .any(|m| m.session == session && m.message == id)
        {
            return Err(DurableError::Suspended);
        }
    }
    Ok(())
}
pub(super) use codec::{validate_image, validate_pending};
