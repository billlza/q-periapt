// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One recoverable local advertisement; directory distribution remains external.
use super::*;
use crate::{
    Cancellation, IssuedManifest, LeafKind, ManifestContext, PrekeyLeaf, Validity,
    VerifiedSessionPolicy,
};
use std::time::Instant;

mod codec;
use codec::{Entry, Registry};
#[cfg(all(test, unix))]
mod tests;

/// Maximum live publication intents/artifacts. Retired ordinals remain fenced.
pub const MAX_PREKEY_PUBLICATIONS: usize = 16;
// Public artifacts have an independent byte budget. A fresh reservation also
// leaves one quarter of the aggregate image for traffic/authority maintenance.
const MAX_PUBLICATION_REGISTRY_BYTES: usize = MAX_IMAGE / 4;
const MAX_PUBLICATION_ADMISSION_BYTES: usize = MAX_IMAGE - MAX_IMAGE / 4;

/// Journal-bound monotonically allocated publication identity, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PrekeyPublicationId([u8; 32]);
impl PrekeyPublicationId {
    fn at(journal: &[u8; 32], ordinal: u64) -> Result<Self, Error> {
        if ordinal == 0 || ordinal == u64::MAX {
            return Err(Error::Capacity);
        }
        let mut input = journal.to_vec();
        input.extend_from_slice(&ordinal.to_be_bytes());
        let binding = digest(b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ID/v1", &input);
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
        if Self::at(journal, ordinal)? != self {
            return Err(Error::Scope);
        }
        Ok(ordinal)
    }
    /// Restore a retained ID; the owning journal must still admit it.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public correlation bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One original inventory request in a publication plan. No private material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrekeyPublicationKey {
    kind: LeafKind,
    validity: Validity,
    reuse: Option<PrekeyId>,
}
impl PrekeyPublicationKey {
    /// Generate this member under an inventory ID derived from the publication.
    pub fn generate(kind: LeafKind, validity: Validity) -> Self {
        Self {
            kind,
            validity,
            reuse: None,
        }
    }
    /// Reuse an exact available inventory request; roles and validity cannot change.
    pub fn reuse(request: PrekeyId, kind: LeafKind, validity: Validity) -> Self {
        Self {
            kind,
            validity,
            reuse: Some(request),
        }
    }
    /// Original key role.
    pub fn kind(&self) -> LeafKind {
        self.kind
    }
    /// Original key validity.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// Existing inventory identity, or a new publication-owned member.
    pub fn reused_request(&self) -> Option<PrekeyId> {
        self.reuse
    }
}

/// Complete ordered publication intent. It does not assert directory freshness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrekeyPublicationPlan {
    directory: [u8; 32],
    validity: Validity,
    keys: Vec<PrekeyPublicationKey>,
}
impl PrekeyPublicationPlan {
    /// Retain the independently trusted directory expectation and all members.
    /// The closed bootstrap profile requires reusable classical and PQ members.
    pub fn new(
        directory: [u8; 32],
        validity: Validity,
        keys: &[PrekeyPublicationKey],
    ) -> Result<Self, Error> {
        crate::codec::nonzero(&directory)?;
        if keys.is_empty() || keys.len() > crate::MAX_PREKEYS {
            return Err(Error::Capacity);
        }
        let mut reused = BTreeSet::new();
        for key in keys {
            if !validity.contains(key.validity) {
                return Err(Error::Validity);
            }
            if let Some(id) = key.reuse {
                if !reused.insert(*id.as_bytes()) {
                    return Err(Error::Scope);
                }
            }
        }
        if !keys.iter().any(|k| k.kind == LeafKind::SignedClassical)
            || !keys.iter().any(|k| k.kind == LeafKind::LastResortPq)
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            directory,
            validity,
            keys: keys.to_vec(),
        })
    }
    /// Original independently supplied directory expectation.
    pub fn directory_checkpoint(&self) -> [u8; 32] {
        self.directory
    }
    /// Original manifest interval.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// Sufficient capacity for the complete QPPUBA01 public artifact. This is a
    /// shape calculation, not reservation, authority or a remote publication receipt.
    pub fn artifact_size_bound(&self) -> Result<usize, Error> {
        self.keys.iter().try_fold(
            8 + 32 * 3 + 4 + crate::manifest::MANIFEST_WIRE_BYTES + 2,
            |size: usize, key| {
                size.checked_add(32 + 2 + 5 + 25 + key.kind.key_bytes() + 10 * 32)
                    .ok_or(Error::Capacity)
            },
        )
    }
    /// Full ordered member plan; order is bound before any generation.
    pub fn keys(&self) -> &[PrekeyPublicationKey] {
        &self.keys
    }
    fn requests(&self, id: PrekeyPublicationId) -> Result<Vec<PrekeyId>, Error> {
        self.keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                if let Some(id) = key.reuse {
                    return Ok(id);
                }
                let mut bytes = id.0.to_vec();
                bytes.extend_from_slice(
                    &u16::try_from(index)
                        .map_err(|_| Error::Capacity)?
                        .to_be_bytes(),
                );
                PrekeyId::from_trusted_state(digest(
                    b"Q-PERIAPT-CONTINUITY-PUBLICATION-PREKEY/v1",
                    &bytes,
                ))
            })
            .collect()
    }
}

/// Local original state only. Prepared never means remotely published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeyPublicationStatus {
    /// This exact next ordinal has not been reserved.
    Absent,
    /// Complete original intent and generation/output capacity are retained.
    Reserved {
        /// Original intent commitment.
        intent: [u8; 32],
    },
    /// Exact original public artifact is committed; current usability is separate.
    Prepared {
        /// Original intent commitment.
        intent: [u8; 32],
        /// Stable signed-body commitment.
        manifest: [u8; 32],
        /// Complete retained artifact commitment.
        artifact: [u8; 32],
    },
    /// This allocated ordinal was retired locally; its artifact is no longer retained.
    Retired,
}

/// Locally committed public material returned only after current release checks.
pub struct PreparedPrekeyPublication {
    id: PrekeyPublicationId,
    intent: [u8; 32],
    artifact: [u8; 32],
    manifest: IssuedManifest,
    requests: Vec<PrekeyId>,
    public: Vec<u8>,
}
impl PreparedPrekeyPublication {
    /// Complete QPPUBA01 public artifact, encoded before the final current
    /// authority/time/witness checks. It contains no secret or signing capability.
    /// Fields are big-endian: tag, ID/intent/artifact (32 bytes each), manifest
    /// length (u32), manifest, count (u16), inventory IDs in plan order, then
    /// count u16-length-prefixed membership proofs in canonical leaf order.
    /// Parsing these public bytes alone never verifies a signature or freshness.
    pub fn as_bytes(&self) -> &[u8] {
        &self.public
    }
    /// Original journal-bound operation.
    pub fn id(&self) -> PrekeyPublicationId {
        self.id
    }
    /// Original full-intent commitment.
    pub fn intent_digest(&self) -> [u8; 32] {
        self.intent
    }
    /// Exact retained public-artifact commitment, used for local history retirement.
    pub fn artifact_digest(&self) -> [u8; 32] {
        self.artifact
    }
    /// Original signed envelope; no new signature is generated on a retry.
    pub fn manifest(&self) -> &IssuedManifest {
        &self.manifest
    }
    /// Original inventory members in plan order, not canonical proof order.
    pub fn inventory_requests(&self) -> &[PrekeyId] {
        &self.requests
    }
}

/// Held verified inputs; signer matching, durable authority and time are rechecked.
pub struct PrekeyPublicationRequest<'a> {
    /// Previously read next ID, retained before dispatch.
    pub id: PrekeyPublicationId,
    /// Complete unchanged original plan.
    pub plan: &'a PrekeyPublicationPlan,
    /// Current verified protocol/SDK policy.
    pub policy: &'a VerifiedSessionPolicy,
    /// Current verified local device credential and roster.
    pub device: &'a VerifiedDevice,
    /// Controlled local device signer; no general signing capability is returned.
    pub signer: &'a DeviceSigningKey,
}
/// One caller's cancellation/deadline. Neither can undo an already committed stage.
pub struct PrekeyPublicationRun<'a> {
    /// One-way cancellation signal.
    pub cancel: &'a Cancellation,
    /// Absolute invocation deadline, never refreshed between members.
    pub deadline: Instant,
}
impl PrekeyPublicationRun<'_> {
    fn check(&self) -> Result<(), PrekeyPublicationError> {
        if self.cancel.is_cancelled() {
            return Err(PrekeyPublicationError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(PrekeyPublicationError::Deadline);
        }
        Ok(())
    }
}
/// Publication interruption or original durable/authority failure.
#[derive(Debug)]
pub enum PrekeyPublicationError {
    /// Cancellation observed at a stage boundary; reconcile the original ID.
    Cancelled,
    /// Invocation deadline elapsed; reconcile the original ID.
    Deadline,
    /// Original storage, witness, policy or cryptographic failure.
    Durable(DurableError),
}
impl fmt::Display for PrekeyPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("prekey publication cancelled"),
            Self::Deadline => f.write_str("prekey publication deadline"),
            Self::Durable(error) => write!(f, "prekey publication: {error}"),
        }
    }
}
impl std::error::Error for PrekeyPublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Durable(e) => Some(e),
            _ => None,
        }
    }
}
impl From<DurableError> for PrekeyPublicationError {
    fn from(e: DurableError) -> Self {
        Self::Durable(e)
    }
}
impl From<Error> for PrekeyPublicationError {
    fn from(e: Error) -> Self {
        DurableError::from(e).into()
    }
}
impl From<io::Error> for PrekeyPublicationError {
    fn from(e: io::Error) -> Self {
        DurableError::from(e).into()
    }
}

impl DeviceJournal {
    /// Observe the next deterministic publication ID. Only the first exact intent wins.
    pub fn next_prekey_publication_id(&mut self) -> Result<PrekeyPublicationId, DurableError> {
        let image = self.image()?;
        self.check_release(&image)?;
        Ok(PrekeyPublicationId::at(
            &image.id,
            Registry::load(&image)?.next,
        )?)
    }
    /// Read authenticated local history without generating or releasing any key.
    pub fn prekey_publication_status(
        &mut self,
        id: PrekeyPublicationId,
    ) -> Result<PrekeyPublicationStatus, DurableError> {
        let image = self.image()?;
        Registry::load(&image)?.status(id.check(&image.id)?)
    }
    /// Reserve all fresh inventory members and output space in one transaction,
    /// then recover generation and the exact committed signed artifact. `clock`
    /// must return current trusted time on every call, including after blocking I/O.
    /// No local result asserts remote directory publication or physical erasure.
    pub fn prepare_prekey_publication(
        &mut self,
        request: PrekeyPublicationRequest<'_>,
        run: PrekeyPublicationRun<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<PreparedPrekeyPublication, PrekeyPublicationError> {
        run.check()?;
        let at = clock()?;
        let mut image = self.image()?;
        let ordinal = request.id.check(&image.id)?;
        let mut registry = Registry::load(&image)?;
        let expected = Entry::new(&request, ordinal)?;
        self.publication_admit(&image, &request, at)?;
        match registry.entries.get(&ordinal) {
            Some(entry) if entry.intent()? != expected.intent()? => {
                return Err(DurableError::Conflict.into())
            }
            Some(_) => {}
            None => {
                if ordinal != registry.next {
                    return Err(DurableError::Conflict.into());
                }
                if registry.entries.len() >= MAX_PREKEY_PUBLICATIONS {
                    return Err(DurableError::Capacity.into());
                }
                let ids = request.plan.requests(request.id)?;
                for (key, id) in request.plan.keys.iter().zip(ids) {
                    self.reserve_inventory_entry(
                        &mut image,
                        request.policy,
                        request.device,
                        (id, key.kind, key.validity),
                        at,
                    )?;
                    if key.reuse.is_some() {
                        // Reuse must name an already available member, not reserve
                        // an absent arbitrary ID or borrow another unfinished plan.
                        let original = self.image()?;
                        prekeys::require_available(&original, id, request.policy)?;
                    }
                }
                registry.next = registry.next.checked_add(1).ok_or(DurableError::Capacity)?;
                registry.entries.insert(ordinal, expected);
                registry.store(&mut image)?;
                // Capacity refusal precedes any durable mutation. The reserved
                // image already includes all key entries and final artifact space.
                self.publication_capacity(&image)?;
                run.check()?;
                self.publication_admit(&image, &request, clock()?)?;
                self.persist(&mut image)?;
            }
        }
        run.check()?;
        let entry = Registry::load(&self.image()?)?
            .entries
            .remove(&ordinal)
            .ok_or(DurableError::Corrupt)?;
        if !entry.ready {
            let ids = request.plan.requests(request.id)?;
            let mut leaves = Vec::with_capacity(ids.len());
            for (key, id) in request.plan.keys.iter().zip(ids) {
                run.check()?;
                leaves.push(self.generate_prekey(
                    request.policy,
                    request.device,
                    id,
                    key.kind,
                    key.validity,
                    clock()?,
                )?);
            }
            run.check()?;
            let context = entry.context()?;
            let manifest = request
                .signer
                .issue_manifest(request.device, context, &leaves)?;
            let mut image = self.image()?;
            self.publication_admit(&image, &request, clock()?)?;
            let mut registry = Registry::load(&image)?;
            let saved = registry
                .entries
                .get_mut(&ordinal)
                .ok_or(DurableError::Corrupt)?;
            if saved.intent()? != entry.intent()? || saved.ready {
                return Err(DurableError::Conflict.into());
            }
            saved.complete(&manifest, &leaves)?;
            registry.store(&mut image)?;
            run.check()?;
            self.persist(&mut image)?;
        }
        run.check()?;
        let image = self.image()?;
        self.publication_admit(&image, &request, clock()?)?;
        let mut registry = Registry::load(&image)?;
        let saved = registry
            .entries
            .remove(&ordinal)
            .ok_or(DurableError::Corrupt)?;
        let manifest = saved.manifest()?;
        let requests = request.plan.requests(request.id)?;
        let public = public_artifact(request.id, &saved, &manifest, &requests)?;
        for id in request.plan.requests(request.id)? {
            run.check()?;
            self.prekey_leaf(request.policy, request.device, id, clock()?)?;
        }
        self.check_release(&image)?;
        run.check()?;
        self.publication_admit(&image, &request, clock()?)?;
        request
            .device
            .verify_manifest(manifest.as_bytes(), clock()?)?;
        self.publication_admit(&image, &request, clock()?)?;
        run.check()?;
        Ok(PreparedPrekeyPublication {
            id: request.id,
            intent: saved.intent()?,
            artifact: saved.artifact_digest()?,
            manifest,
            requests,
            public,
        })
    }
    fn publication_admit(
        &self,
        image: &Image,
        request: &PrekeyPublicationRequest<'_>,
        now: u64,
    ) -> Result<(), DurableError> {
        self.inventory_owner(image, request.policy, request.device)?;
        rosters::authorize_local_device(image, request.device, request.policy, now)?;
        request.plan.validity.check(now)?;
        if !request.policy.validity().contains(request.plan.validity)
            || !request
                .device
                .description
                .validity
                .contains(request.plan.validity)
            || !request
                .device
                .roster_validity
                .contains(request.plan.validity)
            || request.signer.public_key()? != request.device.key
        {
            return Err(Error::Scope.into());
        }
        let has = |kind| request.plan.keys.iter().any(|key| key.kind == kind);
        let mode = [
            crate::PrekeyQuality::OneTimeBoth,
            crate::PrekeyQuality::ReusableBoth,
            crate::PrekeyQuality::SignedClassicalOneTimePq,
            crate::PrekeyQuality::OneTimeClassicalLastResortPq,
        ]
        .into_iter()
        .find(|mode| {
            request.policy.allowed_modes().permits(*mode)
                && match mode {
                    crate::PrekeyQuality::OneTimeBoth => {
                        has(LeafKind::OneTimeClassical) && has(LeafKind::OneTimePq)
                    }
                    crate::PrekeyQuality::ReusableBoth => true,
                    crate::PrekeyQuality::SignedClassicalOneTimePq => has(LeafKind::OneTimePq),
                    crate::PrekeyQuality::OneTimeClassicalLastResortPq => {
                        has(LeafKind::OneTimeClassical)
                    }
                }
        })
        .ok_or(Error::PolicyDenied)?;
        request.policy.check_mode(mode, now)?;
        for key in &request.plan.keys {
            key.validity.check(now)?;
            prekeys::admission(request.policy, request.device, key.kind, now)?;
        }
        Ok(())
    }
    fn publication_capacity(&self, image: &Image) -> Result<(), DurableError> {
        let key = &self.active.as_ref().ok_or(DurableError::Closed)?.key;
        let wire = seal(key, image)?;
        if wire.len() > HEADER + 16 + MAX_PUBLICATION_ADMISSION_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(())
    }
    /// Retire a prepared public artifact after the host acknowledges its exact
    /// digest. This is local cache retirement, not remote revocation or key erasure.
    pub fn retire_prekey_publication(
        &mut self,
        id: PrekeyPublicationId,
        artifact: [u8; 32],
    ) -> Result<PrekeyPublicationStatus, DurableError> {
        let mut image = self.image()?;
        let ordinal = id.check(&image.id)?;
        let mut registry = Registry::load(&image)?;
        if registry.status(ordinal)? == PrekeyPublicationStatus::Retired {
            return Ok(PrekeyPublicationStatus::Retired);
        }
        let entry = registry.entries.get(&ordinal).ok_or(DurableError::Absent)?;
        if !entry.ready || entry.artifact_digest()? != artifact {
            return Err(DurableError::Conflict);
        }
        registry.entries.remove(&ordinal);
        registry.store(&mut image)?;
        self.persist(&mut image)?;
        Ok(PrekeyPublicationStatus::Retired)
    }
    /// Abandon one still-reserved original intent. Fresh unshared members retire
    /// atomically; reused keys and consumption tombstones remain unchanged.
    pub fn abandon_prekey_publication(
        &mut self,
        id: PrekeyPublicationId,
        intent: [u8; 32],
        policy: &VerifiedSessionPolicy,
    ) -> Result<PrekeyPublicationStatus, DurableError> {
        let mut image = self.image()?;
        let ordinal = id.check(&image.id)?;
        let mut registry = Registry::load(&image)?;
        if registry.status(ordinal)? == PrekeyPublicationStatus::Retired {
            return Ok(PrekeyPublicationStatus::Retired);
        }
        let entry = registry
            .entries
            .remove(&ordinal)
            .ok_or(DurableError::Absent)?;
        if entry.ready || entry.intent()? != intent || entry.sdk != policy.sdk_binding() {
            return Err(DurableError::Conflict);
        }
        let shared: BTreeSet<_> = registry
            .entries
            .iter()
            .map(|(n, e)| e.plan.requests(PrekeyPublicationId::at(&image.id, *n)?))
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .flatten()
            .map(|id| *id.as_bytes())
            .collect();
        for (key, request) in entry.plan.keys.iter().zip(entry.plan.requests(id)?) {
            if key.reuse.is_none() && !shared.contains(request.as_bytes()) {
                self.retire_inventory_in_image(&mut image, policy, request)?;
            }
        }
        registry.store(&mut image)?;
        self.persist(&mut image)?;
        Ok(PrekeyPublicationStatus::Retired)
    }
}

pub(super) fn validate_image(image: &Image) -> Result<(), DurableError> {
    Registry::load(image).map(|_| ())
}
pub(super) fn historical_metadata(
    image: &Image,
) -> Result<retired_report::RecordMetadata, DurableError> {
    let registry = Registry::load(image)?;
    // The registry is entirely public metadata. Reserved output padding contains
    // no seed or token; all key-generation material stays in Prekey records.
    Ok(retired_report::RecordMetadata::PrekeyPublications {
        next_epoch: registry.next,
        public_history: registry.encode()?,
    })
}

fn public_artifact(
    id: PrekeyPublicationId,
    entry: &Entry,
    manifest: &IssuedManifest,
    requests: &[PrekeyId],
) -> Result<Vec<u8>, Error> {
    if requests.len() != manifest.leaf_count() {
        return Err(Error::Encoding);
    }
    let mut out = Vec::with_capacity(entry.plan.artifact_size_bound()?);
    out.extend_from_slice(b"QPPUBA01");
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&entry.intent()?);
    out.extend_from_slice(&entry.artifact_digest()?);
    out.extend_from_slice(
        &u32::try_from(manifest.as_bytes().len())
            .map_err(|_| Error::Capacity)?
            .to_be_bytes(),
    );
    out.extend_from_slice(manifest.as_bytes());
    out.extend_from_slice(
        &u16::try_from(requests.len())
            .map_err(|_| Error::Capacity)?
            .to_be_bytes(),
    );
    for request in requests {
        out.extend_from_slice(request.as_bytes());
    }
    for index in 0..manifest.leaf_count() {
        let proof = manifest.proof(index)?.encode()?;
        out.extend_from_slice(
            &u16::try_from(proof.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&proof);
    }
    if out.len() > entry.plan.artifact_size_bound()? {
        return Err(Error::Capacity);
    }
    Ok(out)
}
