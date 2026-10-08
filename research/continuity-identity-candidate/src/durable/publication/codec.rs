// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn record_id(journal: &[u8; 32]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-PUBLICATION-REGISTRY/v1", journal)
}
fn record_context(image: &Image) -> [u8; 32] {
    digest(
        b"Q-PERIAPT-CONTINUITY-PUBLICATION-REGISTRY-OWNER/v1",
        &[image.id.as_slice(), image.owner.as_slice()].concat(),
    )
}
fn plan_bytes(plan: &PrekeyPublicationPlan) -> Result<Vec<u8>, Error> {
    let mut out = plan.directory.to_vec();
    out.extend_from_slice(&plan.validity.from().to_be_bytes());
    out.extend_from_slice(&plan.validity.until().to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(plan.keys.len())
            .map_err(|_| Error::Capacity)?
            .to_be_bytes(),
    );
    for key in &plan.keys {
        out.push(key.kind as u8);
        out.extend_from_slice(&key.validity.from().to_be_bytes());
        out.extend_from_slice(&key.validity.until().to_be_bytes());
        out.push(u8::from(key.reuse.is_some()));
        out.extend_from_slice(
            key.reuse
                .as_ref()
                .map_or(&[0; 32], |id| id.as_bytes().as_slice()),
        );
    }
    Ok(out)
}
fn decode_plan(d: &mut Decoder<'_>) -> Result<PrekeyPublicationPlan, Error> {
    let directory = d.array()?;
    let validity = Validity::new(d.u64()?, d.u64()?)?;
    let count = usize::from(d.u16()?);
    if count == 0 || count > crate::MAX_PREKEYS {
        return Err(Error::Capacity);
    }
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let [kind] = d.array()?;
        let kind = LeafKind::decode(kind)?;
        let validity = Validity::new(d.u64()?, d.u64()?)?;
        let [present] = d.array()?;
        let id = d.array()?;
        let key = match (present, id) {
            (0, id) if id == [0; 32] => PrekeyPublicationKey::generate(kind, validity),
            (1, id) => {
                PrekeyPublicationKey::reuse(PrekeyId::from_trusted_state(id)?, kind, validity)
            }
            _ => return Err(Error::Encoding),
        };
        keys.push(key);
    }
    PrekeyPublicationPlan::new(directory, validity, &keys)
}

pub(super) struct Entry {
    pub(super) sdk: [u8; 68],
    checkpoint: [u8; 40],
    scope: Vec<u8>,
    pub(super) plan: PrekeyPublicationPlan,
    pub(super) ready: bool,
    artifact: Vec<u8>,
}
impl Entry {
    pub(super) fn new(request: &PrekeyPublicationRequest<'_>, ordinal: u64) -> Result<Self, Error> {
        let sdk = request.policy.sdk_binding();
        let context = ManifestContext::new(
            ordinal,
            request.policy.runtime.trusted_state().digest(),
            crate::bootstrap_suite_digest(),
            request.plan.directory,
            request.plan.validity,
        )?;
        let mut checkpoint = [0; 40];
        checkpoint
            .get_mut(..8)
            .ok_or(Error::Encoding)?
            .copy_from_slice(&request.policy.checkpoint().version().to_be_bytes());
        checkpoint
            .get_mut(8..)
            .ok_or(Error::Encoding)?
            .copy_from_slice(&request.policy.checkpoint().digest());
        let requests = request.plan.requests(request.id)?;
        if requests
            .iter()
            .map(|id| *id.as_bytes())
            .collect::<BTreeSet<_>>()
            .len()
            != requests.len()
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            sdk,
            checkpoint,
            scope: crate::manifest::scope(request.device, context),
            plan: request.plan.clone(),
            ready: false,
            artifact: vec![0; Self::artifact_length(request.plan)?],
        })
    }
    fn artifact_length(plan: &PrekeyPublicationPlan) -> Result<usize, Error> {
        plan.keys
            .iter()
            .try_fold(crate::manifest::MANIFEST_WIRE_BYTES, |size, key| {
                size.checked_add(key.kind.key_bytes())
                    .ok_or(Error::Capacity)
            })
    }
    pub(super) fn context(&self) -> Result<ManifestContext, Error> {
        if self.scope.len() != crate::manifest::MANIFEST_SCOPE_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(self.scope.get(128..).ok_or(Error::Encoding)?);
        let epoch = d.u64()?;
        let policy = d.array()?;
        let suite = d.array()?;
        let directory = d.array()?;
        let validity = Validity::new(d.u64()?, d.u64()?)?;
        d.finish()?;
        ManifestContext::new(epoch, policy, suite, directory, validity)
    }
    fn intent_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.sdk.to_vec();
        bytes.extend_from_slice(&self.checkpoint);
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(&plan_bytes(&self.plan)?);
        Ok(bytes)
    }
    pub(super) fn intent(&self) -> Result<[u8; 32], Error> {
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-INTENT/v1",
            &self.intent_bytes()?,
        ))
    }
    pub(super) fn complete(
        &mut self,
        manifest: &IssuedManifest,
        leaves: &[PrekeyLeaf],
    ) -> Result<(), Error> {
        if self.ready
            || leaves.len() != self.plan.keys.len()
            || manifest.as_bytes().len() != crate::manifest::MANIFEST_WIRE_BYTES
        {
            return Err(Error::State);
        }
        let mut bytes = manifest.as_bytes().to_vec();
        for (key, leaf) in self.plan.keys.iter().zip(leaves) {
            if key.kind != leaf.kind() || key.validity != leaf.validity() {
                return Err(Error::Scope);
            }
            bytes.extend_from_slice(leaf.public_key());
        }
        if bytes.len() != self.artifact.len() {
            return Err(Error::Encoding);
        }
        self.artifact = bytes;
        self.ready = true;
        self.manifest()?;
        Ok(())
    }
    pub(super) fn manifest(&self) -> Result<IssuedManifest, Error> {
        if !self.ready {
            return Err(Error::State);
        }
        let mut d = Decoder::new(&self.artifact);
        let wire = d.take(crate::manifest::MANIFEST_WIRE_BYTES)?;
        let mut leaves = Vec::with_capacity(self.plan.keys.len());
        for key in &self.plan.keys {
            leaves.push(PrekeyLeaf::new(
                key.kind,
                d.take(key.kind.key_bytes())?,
                key.validity,
            )?);
        }
        d.finish()?;
        IssuedManifest::from_retained(wire, &self.scope, &leaves)
    }
    pub(super) fn artifact_digest(&self) -> Result<[u8; 32], Error> {
        if !self.ready {
            return Err(Error::State);
        }
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ARTIFACT/v1",
            &[self.intent()?.as_slice(), self.artifact.as_slice()].concat(),
        ))
    }
    fn status(&self) -> Result<PrekeyPublicationStatus, Error> {
        if !self.ready {
            return Ok(PrekeyPublicationStatus::Reserved {
                intent: self.intent()?,
            });
        }
        let (body, _) = crate::crypto::open_envelope(
            self.artifact
                .get(..crate::manifest::MANIFEST_WIRE_BYTES)
                .ok_or(Error::Encoding)?,
        )?;
        Ok(PrekeyPublicationStatus::Prepared {
            intent: self.intent()?,
            manifest: digest(b"Q-PERIAPT-CONTINUITY-MANIFEST-CANDIDATE/v1", body),
            artifact: self.artifact_digest()?,
        })
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.intent_bytes()?);
        out.push(u8::from(self.ready));
        out.extend_from_slice(&self.artifact);
        Ok(())
    }
    fn decode(d: &mut Decoder<'_>, ordinal: u64, image: &Image) -> Result<Self, Error> {
        let sdk = d.array()?;
        let checkpoint = d.array()?;
        let scope = d.take(crate::manifest::MANIFEST_SCOPE_BYTES)?.to_vec();
        let plan = decode_plan(d)?;
        let [ready] = d.array()?;
        if ready > 1 {
            return Err(Error::Encoding);
        }
        let artifact = d.take(Self::artifact_length(&plan)?)?.to_vec();
        let result = Self {
            sdk,
            checkpoint,
            scope,
            plan,
            ready: ready == 1,
            artifact,
        };
        let context = result.context()?;
        if context.bundle_epoch() != ordinal
            || context.directory_checkpoint() != result.plan.directory
            || context.validity() != result.plan.validity
            || context.suite_digest() != crate::bootstrap_suite_digest()
            || result.scope.get(..32) != Some(image.local_account.as_slice())
        {
            return Err(Error::Scope);
        }
        let id = PrekeyPublicationId::at(&image.id, ordinal)?;
        let ids = result.plan.requests(id)?;
        if ids
            .iter()
            .map(|id| *id.as_bytes())
            .collect::<BTreeSet<_>>()
            .len()
            != ids.len()
        {
            return Err(Error::Scope);
        }
        if result.sdk.get(36..) != Some(context.policy_digest().as_slice()) {
            return Err(Error::Scope);
        }
        let mut checkpoint = Decoder::new(&result.checkpoint);
        crate::codec::generation(checkpoint.u64()?)?;
        crate::codec::nonzero(&checkpoint.array::<32>()?)?;
        checkpoint.finish()?;
        if result.ready {
            result.manifest()?;
        } else if result.artifact.iter().any(|byte| *byte != 0) {
            return Err(Error::Encoding);
        }
        let mut public = Decoder::new(
            result
                .artifact
                .get(crate::manifest::MANIFEST_WIRE_BYTES..)
                .ok_or(Error::Encoding)?,
        );
        for (member, request) in result.plan.keys.iter().zip(ids) {
            let bytes = public.take(member.kind.key_bytes())?;
            prekeys::publication_member(
                image,
                request,
                result.sdk,
                member.kind,
                member.validity,
                result.ready.then_some(bytes),
            )
            .map_err(|_| Error::Encoding)?;
        }
        public.finish()?;
        Ok(result)
    }
}

pub(super) struct Registry {
    pub(super) next: u64,
    pub(super) entries: BTreeMap<u64, Entry>,
}
impl Registry {
    pub(super) fn load(image: &Image) -> Result<Self, DurableError> {
        let key = record_id(&image.id);
        let records: Vec<_> = image
            .records
            .iter()
            .filter(|(_, r)| r.kind == RecordKind::Publication)
            .collect();
        let Some(record) = image.records.get(&key) else {
            return if records.is_empty() {
                Ok(Self {
                    next: 1,
                    entries: BTreeMap::new(),
                })
            } else {
                Err(DurableError::Corrupt)
            };
        };
        if records.len() != 1
            || record.kind != RecordKind::Publication
            || record.phase != DurableStatus::PublicationRegistry
            || record.context != record_context(image)
            || record.authorities != [image.local_account]
            || !record.keys.is_empty()
            || !record.prekeys.is_empty()
            || record.cancellation.is_some()
        {
            return Err(DurableError::Corrupt);
        }
        if record.payload.len() > MAX_PUBLICATION_REGISTRY_BYTES {
            return Err(DurableError::Corrupt);
        }
        let mut d = Decoder::new(&record.payload);
        if d.array::<8>()? != *b"QPPREG01" {
            return Err(DurableError::Corrupt);
        }
        let next = d.u64()?;
        let count = usize::from(d.u16()?);
        if next == 0 || count > MAX_PREKEY_PUBLICATIONS {
            return Err(DurableError::Corrupt);
        }
        let mut entries = BTreeMap::new();
        let mut previous = 0;
        for _ in 0..count {
            let ordinal = d.u64()?;
            if ordinal <= previous || ordinal >= next {
                return Err(DurableError::Corrupt);
            }
            previous = ordinal;
            entries.insert(ordinal, Entry::decode(&mut d, ordinal, image)?);
        }
        d.finish()?;
        Ok(Self { next, entries })
    }
    pub(super) fn status(&self, ordinal: u64) -> Result<PrekeyPublicationStatus, DurableError> {
        if ordinal > self.next {
            return Err(DurableError::Conflict);
        }
        match self.entries.get(&ordinal) {
            Some(entry) => Ok(entry.status()?),
            None if ordinal == self.next => Ok(PrekeyPublicationStatus::Absent),
            None => Ok(PrekeyPublicationStatus::Retired),
        }
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, DurableError> {
        if self.next == 0 || self.entries.len() > MAX_PREKEY_PUBLICATIONS {
            return Err(DurableError::Capacity);
        }
        let mut out = b"QPPREG01".to_vec();
        out.extend_from_slice(&self.next.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(self.entries.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for (ordinal, entry) in &self.entries {
            if *ordinal == 0 || *ordinal >= self.next {
                return Err(DurableError::Corrupt);
            }
            out.extend_from_slice(&ordinal.to_be_bytes());
            entry.encode(&mut out)?;
            if out.len() > MAX_PUBLICATION_REGISTRY_BYTES {
                return Err(DurableError::Capacity);
            }
        }
        Ok(out)
    }
    pub(super) fn store(&self, image: &mut Image) -> Result<(), DurableError> {
        let record = Record {
            kind: RecordKind::Publication,
            phase: DurableStatus::PublicationRegistry,
            context: record_context(image),
            authorities: vec![image.local_account],
            keys: Vec::new(),
            prekeys: Vec::new(),
            cancellation: None,
            payload: Zeroizing::new(self.encode()?),
        };
        image.records.insert(record_id(&image.id), record);
        Ok(())
    }
}
