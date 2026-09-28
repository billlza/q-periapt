// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device-local prekey inventory. Only public leaves cross its API boundary.
use super::*;
use crate::{
    AuthenticatedLeaf, LeafKind, PrekeyLeaf, PrekeyQuality, Validity, VerifiedSessionPolicy,
};
use q_periapt_sdk::{
    expert::replay::{RecoveryKey, SealedOperation},
    HybridKey,
};
use zeroize::Zeroize;

pub(super) const MAX_PREKEY_RECORDS: usize = 1024;

#[cfg(all(test, unix))]
mod tests;

/// Public correlation ID retained before a prekey provisioning request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrekeyId([u8; 32]);
impl PrekeyId {
    /// Generate an ID independently of secret KEM randomness.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Restore a retained request ID, never an authority or entropy capability.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public queue/configuration bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact logical inventory status, not a claim of backup or physical-page erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeyStatus {
    /// Authenticated lookup found no such request.
    Absent,
    /// Secret generation is reserved; no public leaf has been released.
    Reserved,
    /// A generated public leaf and sealed recovery command are committed.
    Available,
    /// A response atomically consumed the one-time key and removed its recovery command.
    Consumed,
    /// Explicit retirement removed the logical recovery command.
    Retired,
}

struct Entry {
    request: PrekeyId,
    sdk: [u8; 68],
    kind: LeafKind,
    validity: Validity,
    public: Vec<u8>,
    data: Zeroizing<Vec<u8>>,
}
fn id(request: PrekeyId) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-PREKEY-INVENTORY-ID/v1", &request.0)
}
fn one_time(kind: LeafKind) -> bool {
    matches!(kind, LeafKind::OneTimeClassical | LeafKind::OneTimePq)
}
fn pq(kind: LeafKind) -> bool {
    matches!(kind, LeafKind::LastResortPq | LeafKind::OneTimePq)
}
fn phase_status(phase: DurableStatus) -> Result<PrekeyStatus, DurableError> {
    match phase {
        DurableStatus::PrekeyReserved => Ok(PrekeyStatus::Reserved),
        DurableStatus::PrekeyAvailable => Ok(PrekeyStatus::Available),
        DurableStatus::PrekeyConsumed => Ok(PrekeyStatus::Consumed),
        DurableStatus::PrekeyRetired => Ok(PrekeyStatus::Retired),
        _ => Err(DurableError::Corrupt),
    }
}
impl Entry {
    fn intent(&self) -> [u8; 32] {
        let mut bytes = self.sdk.to_vec();
        bytes.push(self.kind as u8);
        self.validity.encode(&mut bytes);
        digest(b"Q-PERIAPT-CONTINUITY-PREKEY-INVENTORY-INTENT/v1", &bytes)
    }
    fn scope(&self, image: &Image) -> [u8; 32] {
        let mut bytes = image.id.to_vec();
        bytes.extend_from_slice(&image.owner);
        bytes.extend_from_slice(&id(self.request));
        bytes.extend_from_slice(&self.intent());
        digest(
            b"Q-PERIAPT-CONTINUITY-PREKEY-INVENTORY-GENERATION/v1",
            &bytes,
        )
    }
    fn leaf(&self) -> Result<PrekeyLeaf, DurableError> {
        Ok(PrekeyLeaf::new(self.kind, &self.public, self.validity)?)
    }
    fn has_public(&self) -> bool {
        self.public.iter().any(|byte| *byte != 0)
    }
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"QPPKEY01".to_vec());
        bytes.extend_from_slice(&self.request.0);
        bytes.extend_from_slice(&self.sdk);
        bytes.push(self.kind as u8);
        self.validity.encode(&mut bytes);
        bytes.extend_from_slice(&self.public);
        bytes.extend_from_slice(&self.data);
        bytes
    }
    fn decode(record: &Record) -> Result<Self, DurableError> {
        if record.kind != RecordKind::Prekey
            || !record.keys.is_empty()
            || !record.prekeys.is_empty()
        {
            return Err(DurableError::Corrupt);
        }
        let mut d = Decoder::new(&record.payload);
        if d.array::<8>()? != *b"QPPKEY01" {
            return Err(DurableError::Corrupt);
        }
        let request = PrekeyId::from_trusted_state(d.array()?)?;
        let sdk = d.array()?;
        let [kind] = d.array()?;
        let kind = LeafKind::decode(kind)?;
        let validity = Validity::decode(&mut d)?;
        let public = d.take(kind.key_bytes())?.to_vec();
        let length = match phase_status(record.phase)? {
            PrekeyStatus::Reserved | PrekeyStatus::Available => 277,
            PrekeyStatus::Consumed => 32,
            PrekeyStatus::Retired => 0,
            PrekeyStatus::Absent => return Err(DurableError::Corrupt),
        };
        let data = Zeroizing::new(d.take(length)?.to_vec());
        d.finish()?;
        let result = Self {
            request,
            sdk,
            kind,
            validity,
            public,
            data,
        };
        if result.intent() != record.context {
            return Err(DurableError::Corrupt);
        }
        match record.phase {
            DurableStatus::PrekeyReserved if result.has_public() => {
                return Err(DurableError::Corrupt)
            }
            DurableStatus::PrekeyAvailable | DurableStatus::PrekeyConsumed => {
                result.leaf()?;
            }
            DurableStatus::PrekeyRetired if result.has_public() => {
                result.leaf()?;
            }
            _ => {}
        }
        if length == 277 {
            SealedOperation::from_bytes(&result.data).map_err(|_| DurableError::Corrupt)?;
        }
        if record.phase == DurableStatus::PrekeyConsumed
            && (!one_time(kind) || result.data.iter().all(|v| *v == 0))
        {
            return Err(DurableError::Corrupt);
        }
        Ok(result)
    }
}

fn admission(
    policy: &VerifiedSessionPolicy,
    device: &VerifiedDevice,
    kind: LeafKind,
    now: u64,
) -> Result<(), Error> {
    let quality = [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ]
    .into_iter()
    .find(|quality| {
        policy.allowed_modes().permits(*quality)
            && match kind {
                LeafKind::OneTimeClassical => matches!(
                    quality,
                    PrekeyQuality::OneTimeBoth | PrekeyQuality::OneTimeClassicalLastResortPq
                ),
                LeafKind::OneTimePq => matches!(
                    quality,
                    PrekeyQuality::OneTimeBoth | PrekeyQuality::SignedClassicalOneTimePq
                ),
                _ => true,
            }
    })
    .ok_or(Error::PolicyDenied)?;
    policy.check_mode(quality, now)?;
    policy.check_device(device, now)
}
fn public_component(key: &HybridKey, kind: LeafKind) -> Result<Vec<u8>, Error> {
    let bytes = key.public_key()?.to_bytes();
    let bytes = if pq(kind) {
        bytes.get(..q_periapt_backends::ML_KEM_768_PK_LEN)
    } else {
        bytes.get(q_periapt_backends::ML_KEM_768_PK_LEN..)
    }
    .ok_or(Error::Encoding)?;
    Ok(bytes.to_vec())
}

impl DeviceJournal {
    fn inventory_owner(
        &self,
        policy: &VerifiedSessionPolicy,
        device: &VerifiedDevice,
    ) -> Result<(), DurableError> {
        self.check_policy(policy)?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        if active.owner != bootstrap::storage_owner(device)
            || policy.family() != device.description.family
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn inventory_entry(
        &self,
        image: &Image,
        policy: &VerifiedSessionPolicy,
        request: PrekeyId,
    ) -> Result<Entry, DurableError> {
        let entry = Entry::decode(
            image
                .records
                .get(&id(request))
                .ok_or(DurableError::Absent)?,
        )?;
        if entry.request != request || entry.sdk != policy.sdk_binding() {
            return Err(DurableError::Conflict);
        }
        Ok(entry)
    }
    fn inventory_recovery_key(&self) -> Result<RecoveryKey, DurableError> {
        RecoveryKey::from_host_key(
            self.active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .key
                .0
                .as_bytes(),
        )
        .map_err(|error| DurableError::Protocol(error.into()))
    }
    /// Reconcile the exact inventory request even after policy close/expiry.
    pub fn prekey_status(
        &mut self,
        policy: &VerifiedSessionPolicy,
        device: &VerifiedDevice,
        request: PrekeyId,
    ) -> Result<PrekeyStatus, DurableError> {
        self.inventory_owner(policy, device)?;
        let image = self.image()?;
        if !image.records.contains_key(&id(request)) {
            return Ok(PrekeyStatus::Absent);
        }
        self.inventory_entry(&image, policy, request)?;
        phase_status(
            image
                .records
                .get(&id(request))
                .ok_or(DurableError::Absent)?
                .phase,
        )
    }
    /// Reserve platform randomness, generate an owned key internally, and commit
    /// its public leaf before returning it. The same request cannot change its role,
    /// SDK policy or validity, and no private key/token leaves this service.
    pub fn generate_prekey(
        &mut self,
        policy: &VerifiedSessionPolicy,
        device: &VerifiedDevice,
        request: PrekeyId,
        kind: LeafKind,
        validity: Validity,
        now: u64,
    ) -> Result<PrekeyLeaf, DurableError> {
        self.inventory_owner(policy, device)?;
        admission(policy, device, kind, now)?;
        validity.check(now)?;
        if !policy.validity().contains(validity)
            || !device.description.validity.contains(validity)
            || !device.roster_validity.contains(validity)
        {
            return Err(Error::Validity.into());
        }
        let mut image = self.image()?;
        let op = id(request);
        let recovery = self.inventory_recovery_key()?;
        let mut entry = if image.records.contains_key(&op) {
            let entry = self.inventory_entry(&image, policy, request)?;
            if entry.kind != kind || entry.validity != validity {
                return Err(DurableError::Conflict);
            }
            entry
        } else {
            if image
                .records
                .values()
                .filter(|r| r.kind == RecordKind::Prekey)
                .count()
                >= MAX_PREKEY_RECORDS
            {
                return Err(DurableError::Capacity);
            }
            let mut entry = Entry {
                request,
                sdk: policy.sdk_binding(),
                kind,
                validity,
                public: vec![0; kind.key_bytes()],
                data: Zeroizing::new(Vec::new()),
            };
            let token = recovery
                .reserve_key(&policy.runtime, &entry.scope(&image))
                .map_err(Error::from)?;
            entry.data.extend_from_slice(token.as_bytes());
            image.records.insert(
                op,
                Record {
                    kind: RecordKind::Prekey,
                    context: entry.intent(),
                    phase: DurableStatus::PrekeyReserved,
                    keys: Vec::new(),
                    prekeys: Vec::new(),
                    payload: entry.encode(),
                },
            );
            self.persist(&mut image)?;
            entry
        };
        match image.records.get(&op).ok_or(DurableError::Absent)?.phase {
            DurableStatus::PrekeyAvailable => {
                self.check_release(&image)?;
                return entry.leaf();
            }
            DurableStatus::PrekeyConsumed => return Err(DurableError::PrekeyClaimed),
            DurableStatus::PrekeyRetired => return Err(DurableError::KeyRetired),
            DurableStatus::PrekeyReserved => {}
            _ => return Err(DurableError::Corrupt),
        }
        let token = SealedOperation::from_bytes(&entry.data).map_err(Error::from)?;
        let key = match recovery.generate_key(&policy.runtime, &entry.scope(&image), &token) {
            Ok(key) => key,
            Err(q_periapt_sdk::Error::InvalidPrivateKey) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(Error::Runtime(
                    q_periapt_sdk::Error::InvalidPrivateKey,
                )));
            }
            Err(error) => return Err(Error::from(error).into()),
        };
        entry.public = public_component(&key, kind)?;
        #[cfg(all(test, unix))]
        tests::after_generation(&entry.public);
        let leaf = entry.leaf()?;
        for (other_id, record) in &image.records {
            if *other_id != op && record.kind == RecordKind::Prekey {
                let other = Entry::decode(record)?;
                if other.has_public() && other.leaf()?.key_fingerprint() == leaf.key_fingerprint() {
                    return Err(DurableError::Conflict);
                }
            }
        }
        admission(policy, device, kind, now)?;
        let record = image.records.get_mut(&op).ok_or(DurableError::Corrupt)?;
        record.phase = DurableStatus::PrekeyAvailable;
        record.payload = entry.encode();
        self.persist(&mut image)?;
        self.check_release(&image)?;
        Ok(leaf)
    }
    /// Retrieve only a currently usable committed public leaf. Reserved, consumed
    /// and retired entries cannot be republished through this method.
    pub fn prekey_leaf(
        &mut self,
        policy: &VerifiedSessionPolicy,
        device: &VerifiedDevice,
        request: PrekeyId,
        now: u64,
    ) -> Result<PrekeyLeaf, DurableError> {
        self.inventory_owner(policy, device)?;
        let image = self.image()?;
        let entry = self.inventory_entry(&image, policy, request)?;
        admission(policy, device, entry.kind, now)?;
        entry.validity.check(now)?;
        match image
            .records
            .get(&id(request))
            .ok_or(DurableError::Absent)?
            .phase
        {
            DurableStatus::PrekeyAvailable => {
                self.check_release(&image)?;
                entry.leaf()
            }
            DurableStatus::PrekeyReserved => Err(DurableError::Suspended),
            DurableStatus::PrekeyConsumed => Err(DurableError::PrekeyClaimed),
            DurableStatus::PrekeyRetired => Err(DurableError::KeyRetired),
            _ => Err(DurableError::Corrupt),
        }
    }
    /// Remove a logical recovery token without reactivating its ID. A pending
    /// response reference blocks retirement. This is not cryptographic erasure of
    /// old pages/backups; consumed entries retain their consumption tombstone.
    pub fn retire_prekey(
        &mut self,
        policy: &VerifiedSessionPolicy,
        device: &VerifiedDevice,
        request: PrekeyId,
    ) -> Result<PrekeyStatus, DurableError> {
        self.inventory_owner(policy, device)?;
        let mut image = self.image()?;
        let mut entry = self.inventory_entry(&image, policy, request)?;
        let op = id(request);
        let status = phase_status(image.records.get(&op).ok_or(DurableError::Absent)?.phase)?;
        if matches!(status, PrekeyStatus::Consumed | PrekeyStatus::Retired) {
            return Ok(status);
        }
        if image.records.values().any(|r| {
            r.prekeys.contains(&op)
                && !matches!(
                    r.phase,
                    DurableStatus::AwaitingFinal
                        | DurableStatus::Complete
                        | DurableStatus::Messages
                )
        }) {
            return Err(DurableError::PrekeyClaimed);
        }
        entry.data.zeroize();
        let record = image.records.get_mut(&op).ok_or(DurableError::Absent)?;
        record.phase = DurableStatus::PrekeyRetired;
        record.payload = entry.encode();
        self.persist(&mut image)?;
        Ok(PrekeyStatus::Retired)
    }
    fn restore_inventory_key(
        &mut self,
        image: &Image,
        policy: &VerifiedSessionPolicy,
        op: &[u8; 32],
    ) -> Result<HybridKey, DurableError> {
        let record = image.records.get(op).ok_or(DurableError::Corrupt)?;
        if record.phase != DurableStatus::PrekeyAvailable {
            return Err(DurableError::PrekeyClaimed);
        }
        let entry = Entry::decode(record)?;
        if entry.sdk != policy.sdk_binding() {
            return Err(DurableError::Conflict);
        }
        let token = SealedOperation::from_bytes(&entry.data).map_err(Error::from)?;
        let result = self.inventory_recovery_key()?.generate_key(
            &policy.runtime,
            &entry.scope(image),
            &token,
        );
        let key = match result {
            Ok(key) => key,
            Err(q_periapt_sdk::Error::InvalidPrivateKey) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(Error::Runtime(
                    q_periapt_sdk::Error::InvalidPrivateKey,
                )));
            }
            Err(error) => return Err(Error::from(error).into()),
        };
        if public_component(&key, entry.kind)? != entry.public {
            self.close();
            return Err(DurableError::InvalidCheckpoint(Error::Scope));
        }
        Ok(key)
    }
    /// Resolve the actual authenticated selection from this journal and restore
    /// only its committed keys. The response reservation references both inventory
    /// entries before restoration, preventing concurrent retirement. One-time
    /// tokens disappear in the same transaction that commits the response outbox.
    pub fn respond_from_inventory(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let op = self.admission(&context, initial, now)?;
        let mut image = self.image()?;
        if let Some(record) = image.records.get(&op) {
            record.check_request(&context, initial)?;
            if record.phase != DurableStatus::Executing {
                return self.resume_response(context, initial, signer, now);
            }
        }
        crate::bootstrap::response_staged::ResponsePlan::check_signer(&context, signer)?;
        let (policy, device, selection) = context.inventory_inputs();
        self.inventory_owner(policy, device)?;
        let refs = [
            find(&image, policy, selection.post_quantum())?,
            find(&image, policy, selection.classical())?,
        ];
        if let Some(record) = image.records.get(&op) {
            if record.prekeys != refs {
                return Err(DurableError::Conflict);
            }
        } else {
            if image.operation_count() >= MAX_RECORDS {
                return Err(DurableError::Capacity);
            }
            let keys = context.one_time_fingerprints();
            if image
                .records
                .values()
                .any(|r| r.keys.iter().any(|key| keys.contains(key)))
            {
                return Err(DurableError::PrekeyClaimed);
            }
            image.records.insert(
                op,
                Record {
                    kind: RecordKind::Responder,
                    context: context.digest(),
                    phase: DurableStatus::Executing,
                    keys,
                    prekeys: refs.to_vec(),
                    payload: Zeroizing::new(initial.to_vec()),
                },
            );
            self.persist(&mut image)?;
        }
        let [pq_ref, classical_ref] = refs;
        let pq = self.restore_inventory_key(&image, policy, &pq_ref)?;
        let classical = self.restore_inventory_key(&image, policy, &classical_ref)?;
        self.respond(
            context,
            initial,
            signer,
            PqKeySource::from_key(&pq),
            TraditionalKeySource::from_key(&classical),
            now,
        )
    }
}

fn find(
    image: &Image,
    policy: &VerifiedSessionPolicy,
    selected: &AuthenticatedLeaf,
) -> Result<[u8; 32], DurableError> {
    for (op, record) in &image.records {
        if record.kind != RecordKind::Prekey {
            continue;
        }
        let entry = Entry::decode(record)?;
        if entry.has_public() && entry.leaf()?.key_fingerprint() == selected.key_fingerprint() {
            if entry.sdk != policy.sdk_binding()
                || entry.kind != selected.kind()
                || !entry.validity.contains(selected.validity())
            {
                return Err(DurableError::Conflict);
            }
            if record.phase != DurableStatus::PrekeyAvailable {
                return Err(DurableError::PrekeyClaimed);
            }
            return Ok(*op);
        }
    }
    Err(DurableError::Absent)
}

pub(super) fn validate_record(op: &[u8; 32], record: &Record) -> Result<(), DurableError> {
    let entry = Entry::decode(record)?;
    if id(entry.request) != *op {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}
pub(super) fn consume(image: &mut Image, operation: &[u8; 32]) -> Result<(), DurableError> {
    let refs = image
        .records
        .get(operation)
        .ok_or(DurableError::Corrupt)?
        .prekeys
        .clone();
    for id in refs {
        let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
        let mut entry = Entry::decode(record)?;
        if one_time(entry.kind) {
            if record.phase != DurableStatus::PrekeyAvailable {
                return Err(DurableError::Corrupt);
            }
            entry.data.zeroize();
            entry.data.extend_from_slice(operation);
            record.phase = DurableStatus::PrekeyConsumed;
            record.payload = entry.encode();
        }
    }
    Ok(())
}

pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    if image.operation_count() > MAX_RECORDS
        || image.records.len() - image.operation_count() > MAX_PREKEY_RECORDS
    {
        return Err(DurableError::Capacity);
    }
    let mut inventory = BTreeMap::new();
    let mut fingerprints = BTreeSet::new();
    for (op, record) in &image.records {
        if record.kind == RecordKind::Prekey {
            validate_record(op, record)?;
            let entry = Entry::decode(record)?;
            if entry.has_public() && !fingerprints.insert(entry.leaf()?.key_fingerprint()) {
                return Err(DurableError::Corrupt);
            }
            inventory.insert(*op, (record.phase, entry));
        }
    }
    for (op, record) in &image.records {
        if record.prekeys.is_empty() {
            continue;
        }
        if record.kind != RecordKind::Responder
            || record.prekeys.len() != 2
            || record.prekeys.first() == record.prekeys.last()
            || record.phase == DurableStatus::Rejected
        {
            return Err(DurableError::Corrupt);
        }
        let mut claims = Vec::new();
        for (index, id) in record.prekeys.iter().enumerate() {
            let (phase, entry) = inventory.get(id).ok_or(DurableError::Corrupt)?;
            if !entry.has_public() || pq(entry.kind) != (index == 0) {
                return Err(DurableError::Corrupt);
            }
            let committed = matches!(
                record.phase,
                DurableStatus::AwaitingFinal | DurableStatus::Complete | DurableStatus::Messages
            );
            if one_time(entry.kind) {
                claims.push(entry.leaf()?.key_fingerprint());
                if committed {
                    if *phase != DurableStatus::PrekeyConsumed || entry.data.as_slice() != op {
                        return Err(DurableError::Corrupt);
                    }
                } else if *phase != DurableStatus::PrekeyAvailable {
                    return Err(DurableError::Corrupt);
                }
            } else if *phase != DurableStatus::PrekeyAvailable
                && !(committed && *phase == DurableStatus::PrekeyRetired)
            {
                return Err(DurableError::Corrupt);
            }
        }
        claims.sort();
        if claims != record.keys {
            return Err(DurableError::Corrupt);
        }
    }
    for (id, (phase, entry)) in inventory {
        if phase == DurableStatus::PrekeyConsumed {
            let owner: [u8; 32] = entry
                .data
                .as_slice()
                .try_into()
                .map_err(|_| DurableError::Corrupt)?;
            let record = image.records.get(&owner).ok_or(DurableError::Corrupt)?;
            if record.kind != RecordKind::Responder
                || !matches!(
                    record.phase,
                    DurableStatus::AwaitingFinal
                        | DurableStatus::Complete
                        | DurableStatus::Messages
                )
                || !record.prekeys.contains(&id)
            {
                return Err(DurableError::Corrupt);
            }
        }
    }
    Ok(())
}
