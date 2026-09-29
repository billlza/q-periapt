// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Monotonic account authority in the same encrypted journal transaction.
use super::*;
use crate::{RosterCheckpoint, VerifiedRoster};

pub(super) const MAX_ROSTERS: usize = 64;

fn id(account: &[u8; 32]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-JOURNAL-ROSTER/v1", account)
}
const MAX_DEVICE_HISTORY: usize = 256;

#[cfg(all(test, unix))]
pub(crate) mod tests;

struct Stored {
    roster: VerifiedRoster,
    history: BTreeMap<[u8; 16], (u64, [u8; 32])>,
}
impl Stored {
    fn initial(roster: &VerifiedRoster) -> Self {
        Self {
            roster: roster.clone(),
            history: roster
                .members()
                .map(|(id, generation, certificate)| (id, (generation, certificate)))
                .collect(),
        }
    }
    fn record(&self) -> Record {
        let roster = self.roster.journal_bytes();
        let mut payload = Zeroizing::new(b"QPRHST01".to_vec());
        payload.extend_from_slice(&(roster.len() as u32).to_be_bytes());
        payload.extend_from_slice(&roster);
        payload.extend_from_slice(&(self.history.len() as u16).to_be_bytes());
        for (id, (generation, certificate)) in &self.history {
            payload.extend_from_slice(id);
            payload.extend_from_slice(&generation.to_be_bytes());
            payload.extend_from_slice(certificate);
        }
        Record {
            kind: RecordKind::Roster,
            context: self.roster.checkpoint().digest(),
            phase: DurableStatus::Roster,
            authorities: Vec::new(),
            keys: Vec::new(),
            prekeys: Vec::new(),
            payload,
        }
    }
    fn advance(self, roster: &VerifiedRoster) -> Result<Self, DurableError> {
        let mut history = self.history;
        for (id, generation, certificate) in roster.members() {
            if let Some((floor, original)) = history.get(&id) {
                if generation < *floor
                    || (generation == *floor
                        && (*original != certificate
                            || !self.roster.contains_member(id, generation, certificate)))
                {
                    return Err(Error::Checkpoint.into());
                }
            } else if history.len() >= MAX_DEVICE_HISTORY {
                return Err(DurableError::Capacity);
            }
            history.insert(id, (generation, certificate));
        }
        Ok(Self {
            roster: roster.clone(),
            history,
        })
    }
}
fn decode(key: &[u8; 32], record: &Record) -> Result<Stored, DurableError> {
    if record.kind != RecordKind::Roster
        || record.phase != DurableStatus::Roster
        || !record.authorities.is_empty()
        || !record.keys.is_empty()
        || !record.prekeys.is_empty()
    {
        return Err(DurableError::Corrupt);
    }
    let mut decoder = Decoder::new(&record.payload);
    if decoder.array::<8>()? != *b"QPRHST01" {
        return Err(DurableError::Corrupt);
    }
    let size = u32::from_be_bytes(decoder.array()?) as usize;
    let roster = VerifiedRoster::from_journal(decoder.take(size)?)
        .map_err(DurableError::InvalidCheckpoint)?;
    if id(&roster.account_id()) != *key || record.context != roster.checkpoint().digest() {
        return Err(DurableError::Corrupt);
    }
    let count = usize::from(decoder.u16()?);
    if count > MAX_DEVICE_HISTORY {
        return Err(DurableError::Corrupt);
    }
    let mut history = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = decoder.array::<16>()?;
        let generation = decoder.u64()?;
        let certificate = decoder.array::<32>()?;
        if id == [0; 16]
            || generation == 0
            || generation == u64::MAX
            || certificate == [0; 32]
            || previous.is_some_and(|old| old >= id)
        {
            return Err(DurableError::Corrupt);
        }
        previous = Some(id);
        history.insert(id, (generation, certificate));
    }
    decoder.finish()?;
    if roster
        .members()
        .any(|(id, generation, certificate)| history.get(&id) != Some(&(generation, certificate)))
    {
        return Err(DurableError::Corrupt);
    }
    Ok(Stored { roster, history })
}
fn get(image: &Image, account: &[u8; 32]) -> Result<Stored, DurableError> {
    let key = id(account);
    decode(&key, image.records.get(&key).ok_or(DurableError::Absent)?)
}
pub(super) fn genesis(device: &VerifiedDevice) -> BTreeMap<[u8; 32], Record> {
    BTreeMap::from([(
        id(&device.account_id()),
        Stored::initial(device.roster()).record(),
    )])
}
pub(super) fn is_genesis(image: &Image, device: &VerifiedDevice) -> Result<bool, DurableError> {
    Ok(image.records.len() == 1
        && image.local_account == device.account_id()
        && get(image, &image.local_account)?.roster.checkpoint() == device.roster().checkpoint())
}
pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    let mut accounts = BTreeSet::new();
    for (key, record) in &image.records {
        if record.kind == RecordKind::Roster {
            accounts.insert(decode(key, record)?.roster.account_id());
        }
    }
    if accounts.is_empty()
        || accounts.len() > MAX_ROSTERS
        || !accounts.contains(&image.local_account)
    {
        return Err(DurableError::Corrupt);
    }
    for record in image.records.values() {
        if record.kind != RecordKind::Roster {
            if !(1..=2).contains(&record.authorities.len())
                || !record.authorities.contains(&image.local_account)
                || record
                    .authorities
                    .iter()
                    .zip(record.authorities.iter().skip(1))
                    .any(|(left, right)| left >= right)
                || (record.kind == RecordKind::Prekey
                    && record.authorities != [image.local_account])
            {
                return Err(DurableError::Corrupt);
            }
            for account in &record.authorities {
                if *account == [0; 32] || !accounts.contains(account) {
                    return Err(DurableError::Corrupt);
                }
            }
        }
    }
    Ok(())
}
pub(super) fn context_accounts(context: &BootstrapContext) -> Vec<[u8; 32]> {
    let mut accounts = context.devices().map(VerifiedDevice::account_id).to_vec();
    accounts.sort_unstable();
    accounts.dedup();
    accounts
}
pub(super) fn authorize_device(
    image: &Image,
    device: &VerifiedDevice,
    now: u64,
) -> Result<(), DurableError> {
    get(image, &device.account_id())
        .map_err(|error| {
            if matches!(error, DurableError::Absent) {
                DurableError::Corrupt
            } else {
                error
            }
        })?
        .roster
        .authorize_device(device, now)?;
    Ok(())
}
pub(super) fn authorize_context(
    image: &Image,
    context: &BootstrapContext,
    now: u64,
) -> Result<(), DurableError> {
    context.check_session_identity(now)?;
    for device in context.devices() {
        authorize_device(image, device, now)?;
    }
    Ok(())
}
/// Only a new bootstrap may introduce an account's initial independently
/// verified snapshot. The caller commits it with the first operation reservation.
/// Existing heads never advance implicitly from a cached context.
pub(super) fn admit_context(
    image: &mut Image,
    context: &BootstrapContext,
    new_operation: bool,
    now: u64,
) -> Result<(), DurableError> {
    for device in context.devices() {
        let key = id(&device.account_id());
        if !image.records.contains_key(&key) {
            if !new_operation {
                return Err(DurableError::Corrupt);
            }
            if image
                .records
                .values()
                .filter(|r| r.kind == RecordKind::Roster)
                .count()
                >= MAX_ROSTERS
            {
                return Err(DurableError::Capacity);
            }
            device.roster().authorize_device(device, now)?;
            image
                .records
                .insert(key, Stored::initial(device.roster()).record());
        }
    }
    authorize_context(image, context, now)
}

impl DeviceJournal {
    /// Commit an independently authenticated account head. Older and forked heads
    /// fail; the same canonical head does not rewrite its retained signature bytes.
    /// Unknown outcomes close the journal and require exact write-intent recovery.
    pub fn install_roster(
        &mut self,
        roster: &VerifiedRoster,
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        roster.check_time(now)?;
        let mut image = self.image()?;
        let key = id(&roster.account_id());
        let updated = if let Some(saved) = image.records.get(&key) {
            let saved = decode(&key, saved)?;
            if !saved.roster.same_authority(roster) {
                return Err(DurableError::Conflict);
            }
            let old = saved.roster.checkpoint();
            let new = roster.checkpoint();
            if new.version() < old.version()
                || (new.version() == old.version() && new.digest() != old.digest())
            {
                return Err(Error::Checkpoint.into());
            }
            if new == old {
                self.check_release(&image)?;
                return Ok(old);
            }
            saved.advance(roster)?
        } else {
            if image
                .records
                .values()
                .filter(|r| r.kind == RecordKind::Roster)
                .count()
                >= MAX_ROSTERS
            {
                return Err(DurableError::Capacity);
            }
            Stored::initial(roster)
        };
        image.records.insert(key, updated.record());
        self.persist(&mut image)?;
        self.check_release(&image)?;
        Ok(roster.checkpoint())
    }
    /// Read-only head reconciliation. This grants no message or dispatch authority.
    pub fn roster_checkpoint(
        &mut self,
        account: [u8; 32],
    ) -> Result<RosterCheckpoint, DurableError> {
        let image = self.image()?;
        let checkpoint = get(&image, &account)?.roster.checkpoint();
        self.check_release(&image)?;
        Ok(checkpoint)
    }
    pub(super) fn check_context_release(
        &mut self,
        image: &Image,
        context: &BootstrapContext,
        now: u64,
    ) -> Result<(), DurableError> {
        authorize_context(image, context, now)?;
        self.check_release(image)
    }
    pub(super) fn check_device_release(
        &mut self,
        image: &Image,
        device: &VerifiedDevice,
        now: u64,
    ) -> Result<(), DurableError> {
        authorize_device(image, device, now)?;
        self.check_release(image)
    }
}
