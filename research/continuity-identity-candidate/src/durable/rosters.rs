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
mod peer_roster;
pub(crate) use local_renewal::{LocalRenewalCommit, LocalRenewalResolution, LocalRenewalTarget};
mod roster_refresh;
pub use roster_refresh::RosterRefreshMaterials;
pub(super) use roster_refresh::{check_roster_refresh_intent, check_witnessed_roster_terminal};
mod policy_renewal;
use policy_renewal::StoredPolicyRenewal;
pub(super) use policy_renewal::{
    check_enrollment_policy_completion, check_policy_renewal_intent,
    check_witnessed_policy_terminal,
};
pub(crate) use policy_renewal::{
    LocalPolicyRenewalCommit, LocalPolicyRenewalResolution, LocalPolicyRenewalTarget,
    RenewalRequestSnapshot,
};

pub(super) fn check_credential_renewal_intent(
    image: &Image,
    binding: write_intent::RenewalBinding,
) -> Result<(), DurableError> {
    let Protection::Required { policy, .. } = image.protection else {
        return Err(DurableError::AnchorRequired);
    };
    let saved = get(image, &image.local_account)?;
    let receipt = saved.local_commit.as_ref().ok_or(DurableError::Corrupt)?;
    if receipt.operation != binding.operation
        || receipt.statement != binding.transaction_statement()
        || receipt.owner != image.owner
        || receipt.policy != policy
        || receipt.target != saved.roster.checkpoint()
    {
        return Err(DurableError::Conflict);
    }
    let continuation = match (binding.policy, saved.policy_continuation.as_ref()) {
        (None, None) => None,
        (Some(intent), Some(t)) if intent.statement() == t.statement_digest() => {
            if intent.adopts() {
                if t.scope().operation != binding.operation {
                    return Err(DurableError::Conflict);
                }
                Some(t)
            } else {
                if t.scope().operation == binding.operation {
                    return Err(DurableError::Conflict);
                }
                None
            }
        }
        _ => return Err(DurableError::Conflict),
    };
    let mut matches = 0;
    for grant in saved.renewals.values() {
        if grant.operation() == binding.operation && grant.statement_digest() == binding.credential
        {
            let target = LocalRenewalTarget {
                policy_renewal: None,
                grant,
                continuation,
            };
            if target.receipt()? != *receipt {
                return Err(DurableError::Conflict);
            }
            matches += 1;
        }
    }
    if matches != 1 {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

// Historical reservation needs the exact predecessor, including an authenticated
// prior local completion. It neither advances the roster nor admits a runtime.
pub(super) fn check_credential_cancellation(
    image: &Image,
    grant: &crate::HistoricalCredentialRenewal,
    completed: Option<&LocalRenewalCommit>,
) -> Result<(), DurableError> {
    let Protection::Required { policy, .. } = image.protection else {
        return Err(DurableError::AnchorRequired);
    };
    let saved = get(image, &image.local_account)?;
    let previous = grant.previous_device();
    if image.owner != grant.original_storage_owner()
        || image.local_account != previous.account_id()
        || policy != grant.policy_digest()
        || saved.local_commit.as_ref() != completed
        || !saved.roster.same_authority(previous.roster())
        || saved.roster.checkpoint() != previous.roster().checkpoint()
        || !saved.roster.contains_member(
            previous.device_id(),
            previous.generation(),
            previous.credential_digest(),
        )
        || saved.history.get(&previous.device_id())
            != Some(&(previous.generation(), previous.credential_digest()))
        || saved
            .renewals
            .get(&previous.device_id())
            .is_some_and(|current| {
                current.original_credential_digest() != grant.original_credential_digest()
                    || current.policy_digest() != grant.policy_digest()
            })
        || completed.is_some_and(|c| {
            c.operation == grant.operation()
                || c.credential != previous.credential_digest()
                || c.owner != image.owner
                || c.policy != policy
                || c.target.version() > previous.roster().checkpoint().version()
        })
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
pub(super) fn check_policy_cancellation(
    image: &Image,
    grant: &crate::HistoricalCredentialRenewal,
    target: Option<&crate::HistoricalPolicyContinuation>,
    adopts: bool,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    match target {
        None if saved.policy_continuation.is_none() && !adopts => Ok(()),
        Some(t) => {
            if t.scope().journal.as_bytes() != &image.id
                || t.scope().original_owner != image.owner
                || t.scope().original_policy.digest() != grant.policy_digest()
                || t.scope().original_credential != grant.original_credential_digest()
            {
                return Err(DurableError::Conflict);
            }
            if adopts {
                t.check_credential(grant)?;
                match &saved.policy_continuation {
                    None if t.scope().previous_authorization.is_none()
                        && t.scope().previous_policy == t.scope().original_policy =>
                    {
                        Ok(())
                    }
                    Some(previous)
                        if t.scope().previous_authorization
                            == Some(previous.statement_digest())
                            && t.scope().previous_policy == previous.target_policy()
                            && t.scope().original_policy == previous.scope().original_policy =>
                    {
                        Ok(())
                    }
                    _ => Err(DurableError::Conflict),
                }
            } else if saved
                .policy_continuation
                .as_ref()
                .is_some_and(|p| p.journal_bytes() == t.journal_bytes())
                && t.scope().operation != grant.operation()
            {
                Ok(())
            } else {
                Err(DurableError::Conflict)
            }
        }
        _ => Err(DurableError::Conflict),
    }
}

#[cfg(all(test, unix))]
mod policy_continuation_tests;
#[cfg(all(test, unix))]
pub(crate) mod tests;

struct Stored {
    roster: VerifiedRoster,
    history: BTreeMap<[u8; 16], (u64, [u8; 32])>,
    renewals: BTreeMap<[u8; 16], VerifiedCredentialRenewal>,
    local_commit: Option<LocalRenewalCommit>,
    policy_continuation: Option<crate::HistoricalPolicyContinuation>,
    policy_renewal: Option<StoredPolicyRenewal>,
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
            policy_continuation: None,
            policy_renewal: None,
        }
    }
    fn record(&self) -> Result<Record, DurableError> {
        if self.history.len() > MAX_DEVICE_HISTORY || self.renewals.len() > MAX_DEVICE_HISTORY {
            return Err(DurableError::Capacity);
        }
        let roster = self.roster.journal_bytes();
        let tag = if self.policy_continuation.is_some() {
            b"QPRHST04"
        } else if self.local_commit.is_some() {
            b"QPRHST03"
        } else if self.renewals.is_empty() {
            b"QPRHST01"
        } else {
            b"QPRHST02"
        };
        let mut payload = Zeroizing::new(if let Some(policy) = &self.policy_renewal {
            let mut prefix = if policy.carried_grant.is_some() {
                b"QPRHST06"
            } else {
                b"QPRHST05"
            }
            .to_vec();
            prefix.extend_from_slice(tag);
            prefix
        } else {
            tag.to_vec()
        });
        payload.extend_from_slice(&(roster.len() as u32).to_be_bytes());
        payload.extend_from_slice(&roster);
        payload.extend_from_slice(&(self.history.len() as u16).to_be_bytes());
        for (id, (generation, certificate)) in &self.history {
            payload.extend_from_slice(id);
            payload.extend_from_slice(&generation.to_be_bytes());
            payload.extend_from_slice(certificate);
        }
        if !self.renewals.is_empty()
            || self.local_commit.is_some()
            || self.policy_continuation.is_some()
        {
            payload.extend_from_slice(&(self.renewals.len() as u16).to_be_bytes());
            for (id, renewal) in &self.renewals {
                payload.extend_from_slice(id);
                let size =
                    u32::try_from(renewal.as_bytes().len()).map_err(|_| DurableError::Capacity)?;
                payload.extend_from_slice(&size.to_be_bytes());
                payload.extend_from_slice(renewal.as_bytes());
            }
        }
        if self.policy_continuation.is_some() {
            payload.push(u8::from(self.local_commit.is_some()));
        }
        if let Some(commit) = &self.local_commit {
            commit.encode(&mut payload);
        }
        if let Some(continuation) = &self.policy_continuation {
            let wire = continuation.journal_bytes();
            let length = u32::try_from(wire.len()).map_err(|_| DurableError::Capacity)?;
            payload.extend_from_slice(&length.to_be_bytes());
            payload.extend_from_slice(&wire);
        }
        if let Some(renewal) = &self.policy_renewal {
            renewal.encode(&mut payload)?;
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
            policy_continuation: self.policy_continuation,
            policy_renewal: self.policy_renewal,
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
    let credential_renewed = tag == *b"QPRHST06";
    let policy_only = tag == *b"QPRHST05" || credential_renewed;
    let tag = if policy_only {
        decoder.array::<8>()?
    } else {
        tag
    };
    if tag != *b"QPRHST01" && tag != *b"QPRHST02" && tag != *b"QPRHST03" && tag != *b"QPRHST04" {
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
    if tag == *b"QPRHST02" || tag == *b"QPRHST03" || tag == *b"QPRHST04" {
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
    let has_commit = if tag == *b"QPRHST04" {
        match decoder.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(DurableError::Corrupt),
        }
    } else {
        tag == *b"QPRHST03"
    };
    let local_commit = if has_commit {
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
    let policy_continuation = if tag == *b"QPRHST04" {
        let size = u32::from_be_bytes(decoder.array()?) as usize;
        if size != crate::PUBLIC_KEY_BYTES + crate::MAX_POLICY_CONTINUATION_BYTES {
            return Err(DurableError::Corrupt);
        }
        Some(
            crate::HistoricalPolicyContinuation::from_journal(decoder.take(size)?, &roster)
                .map_err(DurableError::InvalidCheckpoint)?,
        )
    } else {
        None
    };
    let policy_renewal = if policy_only {
        Some(StoredPolicyRenewal::decode(
            &mut decoder,
            &roster,
            credential_renewed,
        )?)
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
        policy_continuation,
        policy_renewal,
    })
}
fn get(image: &Image, account: &[u8; 32]) -> Result<Stored, DurableError> {
    let key = id(account);
    let saved = decode(&key, image.records.get(&key).ok_or(DurableError::Absent)?)?;
    check_policy_continuation_scope(image, &saved)?;
    policy_renewal::check_scope(image, &saved)?;
    Ok(saved)
}
fn check_policy_continuation_scope(image: &Image, saved: &Stored) -> Result<(), DurableError> {
    let Some(continuation) = &saved.policy_continuation else {
        return Ok(());
    };
    let scope = continuation.scope();
    if saved.roster.account_id() != image.local_account
        || scope.journal.as_bytes() != &image.id
        || scope.original_owner != image.owner
        || matches!(image.protection, Protection::Required { policy, .. } if policy != scope.original_policy.digest())
        || saved
            .local_commit
            .as_ref()
            .is_some_and(|commit| commit.policy != scope.original_policy.digest())
        || saved.renewals.values().any(|grant| {
            grant.original_storage_owner() == image.owner
                && (grant.policy_digest() != scope.original_policy.digest()
                    || grant.original_credential_digest() != scope.original_credential)
        })
    {
        return Err(DurableError::Conflict);
    }
    // Local-only journals do not carry a policy checkpoint in their header.
    // Operational admission must additionally match the original installation
    // or context P0; historical decoding cannot create that missing authority.
    Ok(())
}
pub(super) fn current(image: &Image, account: &[u8; 32]) -> Result<VerifiedRoster, DurableError> {
    Ok(get(image, account)?.roster)
}
// Durable enrollment readback must agree with the actual local journal before
// releasing the independent witness slot, for both Applied and Closed. Closed
// retains the predecessor T, not the rejected proposal's new T.
pub(super) fn check_terminal_completion(
    image: &Image,
    expected: Option<[u8; 32]>,
    completed: Option<&LocalRenewalCommit>,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    if saved
        .policy_continuation
        .as_ref()
        .map(|t| t.statement_digest())
        != expected
        || saved.local_commit.as_ref() != completed
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
pub(super) fn genesis(device: &VerifiedDevice) -> Result<BTreeMap<[u8; 32], Record>, DurableError> {
    Ok(BTreeMap::from([(
        id(&device.account_id()),
        Stored::initial(device.roster()).record()?,
    )]))
}
pub(super) fn is_genesis(image: &Image, device: &VerifiedDevice) -> Result<bool, DurableError> {
    let saved = get(image, &image.local_account)?;
    Ok(image.records.len() == 1
        && image.local_account == device.account_id()
        && saved.policy_renewal.is_none()
        && saved.roster.checkpoint() == device.roster().checkpoint())
}
pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    let mut accounts = BTreeSet::new();
    for (key, record) in &image.records {
        if record.kind == RecordKind::Roster {
            let saved = decode(key, record)?;
            check_policy_continuation_scope(image, &saved)?;
            policy_renewal::check_scope(image, &saved)?;
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
    require_original_operational_policy(image)?;
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
    require_original_operational_policy(image)?;
    context.require_fresh_identity(now)?;
    context.check_storage_binding(image.id, image.owner, None)?;
    if let Some((_, role, _)) = context.storage_binding() {
        authorize_local_device(image, context.device(role), context.current_policy()?, now)?;
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
            let resolved = grant
                .resolve_established(original, context.original_policy().checkpoint().digest())?;
            saved.roster.authorize_device(&resolved.device, now)?;
            *slot = Some(resolved);
        } else {
            saved.roster.authorize_device(original, now)?;
        }
    }
    Ok(result)
}
// Fresh-device and ordinary P0 entry points carry no continued-session
// authority. They must not reuse a cached P0 after T adoption, including by
// presenting a time at which P0 used to be live.
pub(super) fn require_original_operational_policy(image: &Image) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    if saved.policy_continuation.is_some() || saved.policy_renewal.is_some() {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
// Bind independently verified P1 to the exact completed authorization and original
// transcript. The caller must still admit current identities/time/runtime and
// the original existing session/archive before returning an operational view.
fn continued_local_grant<'a>(
    image: &Image,
    saved: &'a Stored,
) -> Result<&'a VerifiedCredentialRenewal, DurableError> {
    let t = saved
        .policy_continuation
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    let mut matching = saved.renewals.values().filter(|g| {
        g.original_storage_owner() == image.owner
            && g.original_credential_digest() == t.scope().original_credential
            && g.policy_digest() == t.scope().original_policy.digest()
    });
    let grant = matching.next().ok_or(DurableError::Conflict)?;
    if matching.next().is_some() {
        return Err(DurableError::Conflict);
    }
    Ok(grant)
}
fn check_continuation_completion(image: &Image, saved: &Stored) -> Result<(), DurableError> {
    if saved.policy_renewal.is_some() {
        return Err(DurableError::Suspended);
    }
    match image.protection {
        Protection::Local if saved.local_commit.is_none() => Ok(()),
        Protection::Local => Err(DurableError::Suspended),
        Protection::Required { .. } => {
            let grant = continued_local_grant(image, saved)?;
            let t = saved
                .policy_continuation
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            let target = LocalRenewalTarget {
                policy_renewal: None,
                grant,
                continuation: (t.scope().operation == grant.operation()).then_some(t),
            };
            if saved.local_commit.as_ref() != Some(&target.receipt()?) {
                return Err(DurableError::Conflict);
            }
            Ok(())
        }
    }
}
// An operational caller still checks its complete context and immutable P0.
// This derives the witness expectation only from authenticated current journal
// authority, never from a caller's stale cached credential or policy statement.
pub(super) fn continued_witness_admission(
    image: &Image,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<Option<(crate::AnchorOperation, VerifiedDevice)>, DurableError> {
    if image.protection == Protection::Local {
        return Ok(None);
    }
    let saved = get(image, &image.local_account)?;
    if saved.policy_renewal.is_some() {
        return Ok(Some(policy_renewal::witness_admission(
            image, &saved, policy, now,
        )?));
    }
    let Some(t) = &saved.policy_continuation else {
        return Ok(None);
    };
    t.check_target(policy)?;
    check_continuation_completion(image, &saved)?;
    let grant = continued_local_grant(image, &saved)?;
    let current = saved.roster.refresh_device(grant.successor_device(), now)?;
    policy.check_device(&current, now)?;
    crate::installation::admit_policy(policy, now)?;
    let operation = crate::AnchorOperation::admit_continuation(
        current.authority_binding(),
        grant.statement_digest(),
        t.statement_digest(),
    )?;
    Ok(Some((operation, current)))
}

pub(super) fn bind_policy_continuation(
    image: &Image,
    context: &BootstrapContext,
    role: crate::BootstrapRole,
    policy: &crate::VerifiedSessionPolicy,
) -> Result<[u8; 32], DurableError> {
    let saved = get(image, &image.local_account)?;
    if saved.policy_renewal.is_some() {
        return policy_renewal::bind_session(image, &saved, context, role, policy);
    }
    let t = saved
        .policy_continuation
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    check_continuation_completion(image, &saved)?;
    let original = context.device(role);
    if image.local_account != original.account_id()
        || image.owner != bootstrap::storage_owner(original)
        || t.scope().original_credential != original.credential_digest()
        || t.scope().original_owner != image.owner
        || t.scope().journal.as_bytes() != &image.id
    {
        return Err(DurableError::Conflict);
    }
    t.check_context_policy(context.original_policy(), policy)?;
    Ok(t.statement_digest())
}

fn check_session_policy_authority(
    image: &Image,
    context: &BootstrapContext,
) -> Result<(), DurableError> {
    match context.continued_policy_statement() {
        Some(statement) => {
            let (journal, _, role) = context.retained_binding().ok_or(DurableError::Conflict)?;
            if journal != image.id
                || bind_policy_continuation(image, context, role, context.current_policy()?)?
                    != statement
            {
                return Err(DurableError::Conflict);
            }
        }
        None => {
            require_original_operational_policy(image)?;
            if context.current_policy()?.checkpoint() != context.original_policy().checkpoint() {
                return Err(DurableError::Conflict);
            }
        }
    }
    Ok(())
}
// Resolve current local authority from the original owning installation and
// authenticated journal, without depending on any peer credential/session. A
// historical approval alone is not permission or a completion acknowledgement.
fn authorize_continued_installation(
    image: &Image,
    scope: &crate::installation::PolicyScope<'_>,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<[u8; 32], DurableError> {
    scope.authority.check(
        image.owner,
        scope
            .original_policy
            .anchor_requirement()
            .binding()
            .map(|w| (scope.original_policy.checkpoint().digest(), w)),
    )?;
    if scope.local_identity().0 != image.local_account
        || scope.authority.policy != scope.original_policy.checkpoint().digest()
    {
        return Err(DurableError::Conflict);
    }
    let saved = get(image, &image.local_account)?;
    if saved.policy_renewal.is_some() {
        return Ok(
            policy_renewal::authorize_installation(image, &saved, scope, policy, now)?
                .credential_digest(),
        );
    }
    let t = saved
        .policy_continuation
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    check_continuation_completion(image, &saved)?;
    t.check_context_policy(scope.original_policy, policy)?;
    let grant = saved
        .renewals
        .get(&scope.local_identity().1)
        .ok_or(DurableError::Conflict)?;
    let current = grant.successor_device();
    if grant.original_storage_owner() != image.owner
        || grant.original_credential_digest() != t.scope().original_credential
        || grant.policy_digest() != scope.authority.policy
        || (current.account_id(), current.device_id()) != scope.local_identity()
    {
        return Err(DurableError::Conflict);
    }
    // The journal's current signed roster, rather than the older roster inside
    // G, decides membership and roster freshness. Credential validity, key
    // separation, permitted modes and actual P1 runtime remain mandatory.
    saved.roster.authorize_device(current, now)?;
    policy.check_device_identity(current, now)?;
    crate::installation::admit_policy(policy, now)?;
    Ok(current.credential_digest())
}
fn authorize_peer_installation(
    image: &Image,
    scope: &crate::installation::PolicyScope<'_>,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<(), DurableError> {
    if scope.authority.policy != scope.original_policy.checkpoint().digest()
        || scope.local_identity().0 != image.local_account
    {
        return Err(DurableError::Conflict);
    }
    scope.authority.check(
        image.owner,
        scope
            .original_policy
            .anchor_requirement()
            .binding()
            .map(|w| (scope.authority.policy, w)),
    )?;
    let saved = get(image, &image.local_account)?;
    if saved.policy_continuation.is_some() || saved.policy_renewal.is_some() {
        authorize_continued_installation(image, scope, policy, now)?;
    } else if policy.checkpoint() != scope.original_policy.checkpoint() {
        return Err(DurableError::Conflict);
    }
    Ok(())
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
    authorize_retained_context_authority(image, context, now)
}
// Operational authorization only; the owning message/fanout path must bind the
// exact actual record and phase first. This also serves committed fanout members
// whose messages have closed, without treating those records as live sessions.
pub(super) fn authorize_retained_context_authority(
    image: &Image,
    context: &BootstrapContext,
    now: u64,
) -> Result<(), DurableError> {
    if context.retained_binding().is_none() {
        return Err(DurableError::Conflict);
    }
    check_session_policy_authority(image, context)?;
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
    pub(crate) fn admit_continued_local_device(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        current: &VerifiedDevice,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
        self.check_policy(scope.original_policy)?;
        let image = self.image()?;
        if authorize_continued_installation(&image, scope, policy, now)?
            != current.credential_digest()
            || (current.account_id(), current.device_id()) != scope.local_identity()
        {
            return Err(DurableError::Conflict);
        }
        let refreshed = get(&image, &image.local_account)?
            .roster
            .refresh_device(current, now)?;
        self.check_operational_release(&image, policy, now)?;
        Ok(refreshed)
    }
    // Only an owning installation may bind this mutation to its exact policy.
    // Local enrollment has a separate durable configuration transaction; the
    // public owning-service entry currently permits only another peer identity.
    pub(crate) fn install_peer_credential_renewal(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        renewal: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        self.check_policy(scope.original_policy)?;
        if operation != renewal.operation()
            || renewal.policy_digest() != scope.authority.policy
            || (
                renewal.successor_device().account_id(),
                renewal.successor_device().device_id(),
            ) == scope.local_identity()
        {
            return Err(DurableError::Conflict);
        }
        crate::installation::admit(renewal.successor_device(), policy, now)?;
        let mut image = self.image()?;
        authorize_peer_installation(&image, scope, policy, now)?;
        self.check_operational_release(&image, policy, now)?;
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
            authorize_peer_installation(&image, scope, policy, now)?;
            self.check_operational_release(&image, policy, now)?;
            return Ok(target);
        }
        let updated = saved.advance_with_renewal(successor.roster(), Some(renewal))?;
        image
            .records
            .insert(id(&successor.account_id()), updated.record()?);
        // A valid root-signed successor roster may revoke this local member.
        // Retain that observed authority change durably, then withhold success
        // if local permission is gone; refusal must not silently undo revocation.
        self.persist(&mut image)?;
        authorize_peer_installation(&image, scope, policy, now)?;
        crate::installation::admit(successor, policy, now)?;
        self.check_operational_release(&image, policy, now)?;
        Ok(target)
    }
    pub(crate) fn prepare_bootstrap_context(
        &mut self,
        context: std::sync::Arc<BootstrapContext>,
        role: crate::BootstrapRole,
        now: u64,
    ) -> Result<std::sync::Arc<BootstrapContext>, DurableError> {
        context.check(now)?;
        self.check_policy(context.original_policy())?;
        // One authenticated image and one final release fence cover both the
        // private local mapping and peer preview. Neither preview mutates state.
        let image = self.image()?;
        context.check_storage_binding(image.id, image.owner, Some(role))?;
        authorize_local_device(&image, context.device(role), context.current_policy()?, now)?;
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
    pub(crate) fn local_roster_for_reconciliation(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
    ) -> Result<VerifiedRoster, DurableError> {
        let image = self.image()?;
        if image.protection != Protection::Local {
            return Err(DurableError::AnchorRequired);
        }
        authority.check(image.owner, None)?;
        let roster = get(&image, &image.local_account)?.roster;
        self.check_release(&image)?;
        Ok(roster)
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
        self.check_policy(context.original_policy())?;
        authorize_session_context(image, context, now)?;
        self.check_operational_release(image, context.current_policy()?, now)
    }
}
