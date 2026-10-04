// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Monotonic account authority in the same encrypted journal transaction.
use super::*;
use crate::{CredentialRenewalId, RosterCheckpoint, VerifiedCredentialRenewal, VerifiedRoster};

pub(super) use crate::contract::MAX_ACCOUNT_ROSTER_RECORDS as MAX_ROSTERS;

fn id(account: &[u8; 32]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-JOURNAL-ROSTER/v1", account)
}
use crate::contract::MAX_DEVICE_HISTORY_PER_ACCOUNT as MAX_DEVICE_HISTORY;
mod local_renewal;
pub(crate) use local_renewal::{LocalRenewalCommit, LocalRenewalResolution};

#[cfg(all(test, unix))]
pub(crate) mod tests;

struct Stored {
    roster: VerifiedRoster,
    history: BTreeMap<[u8; 16], (u64, [u8; 32])>,
    renewals: BTreeMap<[u8; 16], VerifiedCredentialRenewal>,
    local_commit: Option<LocalRenewalCommit>,
}
impl Stored {
    fn initial(roster: &VerifiedRoster) -> Self {
        Self {
            roster: roster.clone(),
            history: roster
                .members()
                .map(|(id, generation, certificate)| (id, (generation, certificate)))
                .collect(),
            renewals: BTreeMap::new(),
            local_commit: None,
        }
    }
    fn record(&self) -> Result<Record, DurableError> {
        if self.history.len() > MAX_DEVICE_HISTORY || self.renewals.len() > MAX_DEVICE_HISTORY {
            return Err(DurableError::Capacity);
        }
        let roster = self.roster.journal_bytes();
        let tag = if self.local_commit.is_some() {
            b"QPRHST03"
        } else if self.renewals.is_empty() {
            b"QPRHST01"
        } else {
            b"QPRHST02"
        };
        let mut payload = Zeroizing::new(tag.to_vec());
        payload.extend_from_slice(&(roster.len() as u32).to_be_bytes());
        payload.extend_from_slice(&roster);
        payload.extend_from_slice(&(self.history.len() as u16).to_be_bytes());
        for (id, (generation, certificate)) in &self.history {
            payload.extend_from_slice(id);
            payload.extend_from_slice(&generation.to_be_bytes());
            payload.extend_from_slice(certificate);
        }
        if !self.renewals.is_empty() || self.local_commit.is_some() {
            payload.extend_from_slice(&(self.renewals.len() as u16).to_be_bytes());
            for (id, renewal) in &self.renewals {
                payload.extend_from_slice(id);
                let size =
                    u32::try_from(renewal.as_bytes().len()).map_err(|_| DurableError::Capacity)?;
                payload.extend_from_slice(&size.to_be_bytes());
                payload.extend_from_slice(renewal.as_bytes());
            }
        }
        if let Some(commit) = &self.local_commit {
            commit.encode(&mut payload);
        }
        Ok(Record {
            kind: RecordKind::Roster,
            context: self.roster.checkpoint().digest(),
            phase: DurableStatus::Roster,
            authorities: Vec::new(),
            keys: Vec::new(),
            prekeys: Vec::new(),
            cancellation: None,
            payload,
        })
    }
    fn advance(self, roster: &VerifiedRoster) -> Result<Self, DurableError> {
        self.advance_with_renewal(roster, None)
    }
    fn advance_with_renewal(
        self,
        roster: &VerifiedRoster,
        renewal: Option<&VerifiedCredentialRenewal>,
    ) -> Result<Self, DurableError> {
        if let Some(renewal) = renewal {
            let predecessor = renewal.previous_device();
            let successor = renewal.successor_device();
            if !self.roster.same_authority(roster)
                || self.roster.checkpoint() != predecessor.roster().checkpoint()
                || roster.checkpoint() != successor.roster().checkpoint()
                || !self.roster.contains_member(
                    predecessor.device_id(),
                    predecessor.generation(),
                    predecessor.credential_digest(),
                )
                || self.history.get(&predecessor.device_id())
                    != Some(&(predecessor.generation(), predecessor.credential_digest()))
            {
                return Err(DurableError::Conflict);
            }
            if let Some(saved) = self.renewals.get(&successor.device_id()) {
                if saved.original_credential_digest() != renewal.original_credential_digest()
                    || saved.policy_digest() != renewal.policy_digest()
                {
                    return Err(DurableError::Conflict);
                }
            }
        }
        let mut history = self.history;
        for (id, generation, certificate) in roster.members() {
            if let Some((floor, original)) = history.get(&id) {
                let permitted = renewal.is_some_and(|renewal| {
                    let previous = renewal.previous_device();
                    let next = renewal.successor_device();
                    id == next.device_id()
                        && generation == next.generation()
                        && generation == *floor
                        && certificate == next.credential_digest()
                        && *original == previous.credential_digest()
                        && self.roster.contains_member(id, generation, *original)
                });
                if generation < *floor
                    || (generation == *floor
                        && (*original != certificate
                            || !self.roster.contains_member(id, generation, certificate))
                        && !permitted)
                {
                    return Err(Error::Checkpoint.into());
                }
            } else if history.len() >= MAX_DEVICE_HISTORY {
                return Err(DurableError::Capacity);
            }
            history.insert(id, (generation, certificate));
        }
        let mut renewals = self.renewals;
        renewals.retain(|id, grant| {
            let next = grant.successor_device();
            history.get(id) == Some(&(next.generation(), next.credential_digest()))
        });
        if let Some(renewal) = renewal {
            renewals.insert(
                renewal.successor_device().device_id(),
                VerifiedCredentialRenewal::from_journal(renewal.as_bytes(), roster)?,
            );
        }
        Ok(Self {
            roster: roster.clone(),
            history,
            renewals,
            local_commit: self.local_commit,
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
    let tag = decoder.array::<8>()?;
    if tag != *b"QPRHST01" && tag != *b"QPRHST02" && tag != *b"QPRHST03" {
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
    let mut renewals = BTreeMap::new();
    if tag == *b"QPRHST02" || tag == *b"QPRHST03" {
        let count = usize::from(decoder.u16()?);
        if (count == 0 && tag == *b"QPRHST02") || count > MAX_DEVICE_HISTORY {
            return Err(DurableError::Corrupt);
        }
        let mut previous = None;
        for _ in 0..count {
            let id = decoder.array::<16>()?;
            let size = u32::from_be_bytes(decoder.array()?) as usize;
            if previous.is_some_and(|old| old >= id) || size > crate::MAX_CREDENTIAL_RENEWAL_BYTES {
                return Err(DurableError::Corrupt);
            }
            let renewal = VerifiedCredentialRenewal::from_journal(decoder.take(size)?, &roster)
                .map_err(DurableError::InvalidCheckpoint)?;
            let next = renewal.successor_device();
            let checkpoint = next.roster().checkpoint();
            if id != next.device_id()
                || history.get(&id) != Some(&(next.generation(), next.credential_digest()))
                || checkpoint.version() > roster.checkpoint().version()
                || (checkpoint.version() == roster.checkpoint().version()
                    && checkpoint != roster.checkpoint())
            {
                return Err(DurableError::Corrupt);
            }
            previous = Some(id);
            renewals.insert(id, renewal);
        }
    }
    let local_commit = if tag == *b"QPRHST03" {
        let commit = LocalRenewalCommit::decode(&mut decoder)?;
        if commit.target.version() > roster.checkpoint().version()
            || (commit.target.version() == roster.checkpoint().version()
                && commit.target != roster.checkpoint())
        {
            return Err(DurableError::Corrupt);
        }
        Some(commit)
    } else {
        None
    };
    decoder.finish()?;
    if roster
        .members()
        .any(|(id, generation, certificate)| history.get(&id) != Some(&(generation, certificate)))
    {
        return Err(DurableError::Corrupt);
    }
    Ok(Stored {
        roster,
        history,
        renewals,
        local_commit,
    })
}
fn get(image: &Image, account: &[u8; 32]) -> Result<Stored, DurableError> {
    let key = id(account);
    decode(&key, image.records.get(&key).ok_or(DurableError::Absent)?)
}
pub(super) fn current(image: &Image, account: &[u8; 32]) -> Result<VerifiedRoster, DurableError> {
    Ok(get(image, account)?.roster)
}
pub(super) fn genesis(device: &VerifiedDevice) -> Result<BTreeMap<[u8; 32], Record>, DurableError> {
    Ok(BTreeMap::from([(
        id(&device.account_id()),
        Stored::initial(device.roster()).record()?,
    )]))
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
            let saved = decode(key, record)?;
            if let Some(commit) = &saved.local_commit {
                if saved.roster.account_id() != image.local_account || commit.owner != image.owner {
                    return Err(DurableError::Corrupt);
                }
            }
            accounts.insert(saved.roster.account_id());
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
// Structural cleanup binding can survive expiry/revocation. The original
// credential always names its original store; a successor must have a verified
// root grant for this exact owner and policy. This alone releases no key or data.
pub(super) fn check_local_device_scope(
    image: &Image,
    device: &VerifiedDevice,
    policy: &crate::VerifiedSessionPolicy,
) -> Result<(), DurableError> {
    if image.local_account != device.account_id() || policy.family() != device.description.family {
        return Err(DurableError::Conflict);
    }
    if bootstrap::storage_owner(device) == image.owner {
        return Ok(());
    }
    let saved = get(image, &image.local_account)?;
    let grant = saved
        .renewals
        .get(&device.device_id())
        .ok_or(DurableError::Conflict)?;
    if grant.original_storage_owner() != image.owner
        || grant.policy_digest() != policy.checkpoint().digest()
        || grant.successor_device().credential_digest() != device.credential_digest()
    {
        return Err(DurableError::Conflict);
    }
    grant.resolve_established(device, policy.checkpoint().digest())?;
    Ok(())
}
pub(super) fn authorize_local_device(
    image: &Image,
    device: &VerifiedDevice,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<(), DurableError> {
    check_local_device_scope(image, device, policy)?;
    authorize_device(image, device, now)
}
pub(super) fn authorize_context(
    image: &Image,
    context: &BootstrapContext,
    now: u64,
) -> Result<(), DurableError> {
    context.require_fresh_identity(now)?;
    context.check_storage_binding(image.id, image.owner, None)?;
    if let Some((_, role, _)) = context.storage_binding() {
        authorize_local_device(image, context.device(role), context.policy(), now)?;
    }
    for device in context.devices() {
        authorize_device(image, device, now)?;
    }
    Ok(())
}

// Resolve only from the authenticated current image, never from a cached view.
pub(super) fn resolve_session_identities(
    image: &Image,
    context: &BootstrapContext,
    now: u64,
) -> Result<[Option<crate::identity::renewal::ResolvedSessionIdentity>; 2], DurableError> {
    let mut result = [None, None];
    for (slot, original) in result.iter_mut().zip(context.devices()) {
        let saved = get(image, &original.account_id())?;
        if let Some(grant) = saved.renewals.get(&original.device_id()) {
            let current = saved.roster.checkpoint();
            let historical = original.roster().checkpoint();
            if current.version() < historical.version()
                || (current.version() == historical.version() && current != historical)
            {
                return Err(Error::Checkpoint.into());
            }
            let resolved =
                grant.resolve_established(original, context.policy().checkpoint().digest())?;
            saved.roster.authorize_device(&resolved.device, now)?;
            *slot = Some(resolved);
        } else {
            saved.roster.authorize_device(original, now)?;
        }
    }
    Ok(result)
}
pub(super) fn authorize_session_context(
    image: &Image,
    context: &BootstrapContext,
    now: u64,
) -> Result<(), DurableError> {
    if context.retained_binding().is_none() {
        return authorize_context(image, context, now);
    }
    messages::check_retained_binding(image, context)?;
    context.check_session_identity(now)?;
    let resolved = resolve_session_identities(image, context, now)?;
    for (role, current) in [
        crate::BootstrapRole::Initiator,
        crate::BootstrapRole::Responder,
    ]
    .into_iter()
    .zip(resolved)
    {
        match (context.renewed_identity(role), current) {
            (None, None) => {}
            (Some(cached), Some(current))
                if cached.statement == current.statement
                    && cached.owner == current.owner
                    && cached.device.credential_digest() == current.device.credential_digest() => {}
            _ => return Err(DurableError::Conflict),
        }
    }
    Ok(())
}

// Preview one independently verified peer without installing its initial roster
// or advancing an existing one. The actual bootstrap must repeat admission and
// commit a new account head together with its first operation reservation.
fn authorize_bootstrap_peer(
    image: &Image,
    device: &VerifiedDevice,
    now: u64,
) -> Result<(), DurableError> {
    match get(image, &device.account_id()) {
        Ok(current) => current.roster.authorize_device(device, now)?,
        Err(DurableError::Absent) => {
            if image.record_count(RecordKind::Roster) >= MAX_ROSTERS {
                return Err(DurableError::Capacity);
            }
            device.roster().authorize_device(device, now)?;
        }
        Err(error) => return Err(error),
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
                .insert(key, Stored::initial(device.roster()).record()?);
        }
    }
    authorize_context(image, context, now)
}

impl DeviceJournal {
    // Only an owning installation may bind this mutation to its exact policy.
    // Local enrollment has a separate durable configuration transaction; the
    // public owning-service entry currently permits only another peer identity.
    pub(crate) fn install_peer_credential_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        renewal: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        self.check_policy(policy)?;
        if operation != renewal.operation()
            || renewal.policy_digest() != policy.checkpoint().digest()
            || authority.policy != policy.checkpoint().digest()
        {
            return Err(DurableError::Conflict);
        }
        crate::installation::admit(renewal.successor_device(), policy, now)?;
        let mut image = self.image()?;
        authority.check(
            image.owner,
            policy
                .anchor_requirement()
                .binding()
                .map(|witness| (policy.checkpoint().digest(), witness)),
        )?;
        let successor = renewal.successor_device();
        let saved = get(&image, &successor.account_id())?;
        let target = successor.roster().checkpoint();
        if saved.roster.checkpoint() == target {
            let original = saved
                .renewals
                .get(&successor.device_id())
                .ok_or(DurableError::Conflict)?;
            if original.operation() != operation
                || original.statement_digest() != renewal.statement_digest()
                || saved.history.get(&successor.device_id())
                    != Some(&(successor.generation(), successor.credential_digest()))
            {
                return Err(DurableError::Conflict);
            }
            saved.roster.authorize_device(successor, now)?;
            self.check_release(&image)?;
            return Ok(target);
        }
        let updated = saved.advance_with_renewal(successor.roster(), Some(renewal))?;
        image
            .records
            .insert(id(&successor.account_id()), updated.record()?);
        self.persist(&mut image)?;
        crate::installation::admit(successor, policy, now)?;
        self.check_release(&image)?;
        Ok(target)
    }
    pub(crate) fn prepare_bootstrap_context(
        &mut self,
        context: std::sync::Arc<BootstrapContext>,
        role: crate::BootstrapRole,
        now: u64,
    ) -> Result<std::sync::Arc<BootstrapContext>, DurableError> {
        context.check(now)?;
        self.check_policy(context.policy())?;
        // One authenticated image and one final release fence cover both the
        // private local mapping and peer preview. Neither preview mutates state.
        let image = self.image()?;
        context.check_storage_binding(image.id, image.owner, Some(role))?;
        authorize_local_device(&image, context.device(role), context.policy(), now)?;
        let context = if bootstrap::storage_owner(context.device(role)) != image.owner {
            std::sync::Arc::new(context.with_current_storage(image.id, role, image.owner)?)
        } else {
            context
        };
        let remote = match role {
            crate::BootstrapRole::Initiator => crate::BootstrapRole::Responder,
            crate::BootstrapRole::Responder => crate::BootstrapRole::Initiator,
        };
        authorize_bootstrap_peer(&image, context.device(remote), now)?;
        self.check_release(&image)?;
        context.check(now)?;
        Ok(context)
    }

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
        image.records.insert(key, updated.record()?);
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
    pub(super) fn check_session_context_release(
        &mut self,
        image: &Image,
        context: &BootstrapContext,
        now: u64,
    ) -> Result<(), DurableError> {
        self.check_policy(context.policy())?;
        authorize_session_context(image, context, now)?;
        self.check_release(image)
    }
}
