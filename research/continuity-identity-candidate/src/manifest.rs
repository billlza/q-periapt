// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{
    codec::{generation, nonzero, Decoder},
    crypto::{digest, envelope, open_envelope, Purpose},
    merkle, DeviceSigningKey, Error, Validity, VerifiedDevice,
};
use q_periapt_backends::ML_KEM_768_PK_LEN;
use std::collections::BTreeSet;

/// Maximum leaves in one signed candidate manifest.
pub const MAX_PREKEYS: usize = 1024;
const MANIFEST_TAG: &[u8; 8] = b"QPMANF01";
const LEAF_TAG: &[u8; 8] = b"QPLEAF01";
pub(crate) const MANIFEST_SCOPE_BYTES: usize = 248;
pub(crate) const MANIFEST_WIRE_BYTES: usize =
    4 + 8 + MANIFEST_SCOPE_BYTES + 2 + 32 + crate::crypto::SIGNATURE_BYTES;

/// Signed role fixes the primitive and whether a key is one-time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LeafKind {
    /// Reusable signed X25519 prekey, admitted only by an explicit later policy.
    SignedClassical = 1,
    /// One-time X25519 prekey.
    OneTimeClassical = 2,
    /// Explicit ML-KEM-768 last-resort prekey.
    LastResortPq = 3,
    /// One-time ML-KEM-768 prekey.
    OneTimePq = 4,
}
impl LeafKind {
    pub(crate) fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::SignedClassical),
            2 => Ok(Self::OneTimeClassical),
            3 => Ok(Self::LastResortPq),
            4 => Ok(Self::OneTimePq),
            _ => Err(Error::Encoding),
        }
    }
    fn algorithm(self) -> u8 {
        match self {
            Self::SignedClassical | Self::OneTimeClassical => 1,
            Self::LastResortPq | Self::OneTimePq => 2,
        }
    }
    pub(crate) fn key_bytes(self) -> usize {
        match self {
            Self::SignedClassical | Self::OneTimeClassical => 32,
            Self::LastResortPq | Self::OneTimePq => ML_KEM_768_PK_LEN,
        }
    }
}

/// Public prekey record to be signed; it contains no private key or consumption permission.
/// Primitive public-key validation still belongs to the eventual KEM admission path.
#[derive(Clone, Debug)]
pub struct PrekeyLeaf {
    kind: LeafKind,
    public: Vec<u8>,
    validity: Validity,
}
impl PrekeyLeaf {
    /// Fixed advertised primitive/use role; this is not a consumption receipt.
    pub fn kind(&self) -> LeafKind {
        self.kind
    }
    /// Public bytes for manifest publication, never secret key material.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
    /// The key's permitted publication/use window.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// Check shape and a finite interval before admitting public bytes to a manifest.
    pub fn new(kind: LeafKind, public: &[u8], validity: Validity) -> Result<Self, Error> {
        if public.len() != kind.key_bytes() || public.iter().all(|byte| *byte == 0) {
            return Err(Error::Encoding);
        }
        Ok(Self {
            kind,
            public: public.to_vec(),
            validity,
        })
    }
    /// Algorithm-tagged exact public-byte fingerprint, independent of role, epoch and expiry.
    /// A consumption store must reject reuse across manifests and resolve only canonical,
    /// provider-validated keys; this hash does not establish mathematical key equivalence.
    pub fn key_fingerprint(&self) -> [u8; 32] {
        let mut body = Vec::with_capacity(1 + self.public.len());
        body.push(self.kind.algorithm());
        body.extend_from_slice(&self.public);
        digest(b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLIC-CANDIDATE/v1", &body)
    }
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(25 + self.public.len());
        body.extend_from_slice(LEAF_TAG);
        body.push(self.kind as u8);
        self.validity.encode(&mut body);
        body.extend_from_slice(&self.public);
        body
    }
    fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(body);
        if decoder.array::<8>()? != *LEAF_TAG {
            return Err(Error::Encoding);
        }
        let [kind] = decoder.array()?;
        let kind = LeafKind::decode(kind)?;
        let validity = Validity::decode(&mut decoder)?;
        let leaf = Self::new(kind, decoder.take(kind.key_bytes())?, validity)?;
        decoder.finish()?;
        Ok(leaf)
    }
}

/// Signed manifest context values, not evidence that a session policy or directory was verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestContext {
    bundle_epoch: u64,
    policy: [u8; 32],
    suite: [u8; 32],
    directory: [u8; 32],
    validity: Validity,
}
impl ManifestContext {
    /// Device-signed bundle epoch; monotonic advancement requires a later durable check.
    pub fn bundle_epoch(self) -> u64 {
        self.bundle_epoch
    }
    /// Signed policy digest, requiring separate session-policy authorization.
    pub fn policy_digest(self) -> [u8; 32] {
        self.policy
    }
    /// Signed suite digest, requiring a separate closed profile match.
    pub fn suite_digest(self) -> [u8; 32] {
        self.suite
    }
    /// Signed directory-checkpoint claim, requiring independent consistency validation.
    pub fn directory_checkpoint(self) -> [u8; 32] {
        self.directory
    }
    /// Complete signed validity interval.
    pub fn validity(self) -> Validity {
        self.validity
    }
    /// Construct checked metadata for the candidate signer.
    pub fn new(
        bundle_epoch: u64,
        policy: [u8; 32],
        suite: [u8; 32],
        directory: [u8; 32],
        validity: Validity,
    ) -> Result<Self, Error> {
        generation(bundle_epoch)?;
        nonzero(&policy)?;
        nonzero(&suite)?;
        nonzero(&directory)?;
        Ok(Self {
            bundle_epoch,
            policy,
            suite,
            directory,
            validity,
        })
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bundle_epoch.to_be_bytes());
        out.extend_from_slice(&self.policy);
        out.extend_from_slice(&self.suite);
        out.extend_from_slice(&self.directory);
        self.validity.encode(out);
    }
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Self::new(
            decoder.u64()?,
            decoder.array()?,
            decoder.array()?,
            decoder.array()?,
            Validity::decode(decoder)?,
        )
    }
}

pub(crate) fn scope(device: &VerifiedDevice, context: ManifestContext) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);
    body.extend_from_slice(&device.account);
    body.extend_from_slice(&device.description.id);
    body.extend_from_slice(&device.description.generation.to_be_bytes());
    body.extend_from_slice(&device.certificate);
    body.extend_from_slice(&device.checkpoint.version().to_be_bytes());
    body.extend_from_slice(&device.checkpoint.digest());
    context.encode(&mut body);
    body
}

fn leaf_id(scope: &[u8], leaf: &PrekeyLeaf) -> [u8; 32] {
    let mut body = Vec::with_capacity(scope.len() + 25 + leaf.public.len());
    body.extend_from_slice(scope);
    body.extend_from_slice(&leaf.encode());
    digest(b"Q-PERIAPT-CONTINUITY-PREKEY-LEAF-CANDIDATE/v1", &body)
}

/// Issuer-retained public manifest and leaves, sorted by their complete leaf commitment.
pub struct IssuedManifest {
    wire: Vec<u8>,
    leaves: Vec<PrekeyLeaf>,
    ids: Vec<[u8; 32]>,
}
impl IssuedManifest {
    /// Rebuild public membership material from an authenticated local snapshot.
    /// The caller must still perform current device/policy admission before release.
    pub(crate) fn from_retained(
        wire: &[u8],
        expected_scope: &[u8],
        leaves: &[PrekeyLeaf],
    ) -> Result<Self, Error> {
        if wire.len() != MANIFEST_WIRE_BYTES || expected_scope.len() != MANIFEST_SCOPE_BYTES {
            return Err(Error::Encoding);
        }
        let mut decoder = Decoder::new(expected_scope.get(128..).ok_or(Error::Encoding)?);
        let context = ManifestContext::decode(&mut decoder)?;
        decoder.finish()?;
        let ManifestParts { body, leaves, ids } = manifest_parts(expected_scope, context, leaves)?;
        if open_envelope(wire)?.0 != body {
            return Err(Error::Scope);
        }
        Ok(Self {
            wire: wire.to_vec(),
            leaves,
            ids,
        })
    }
    /// Signed manifest body and both signatures.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Construct a bounded membership proof for one canonical leaf index.
    pub fn proof(&self, index: usize) -> Result<LeafProof, Error> {
        let leaf = self.leaves.get(index).ok_or(Error::Encoding)?.clone();
        Ok(LeafProof {
            leaf,
            index: u16::try_from(index).map_err(|_| Error::Encoding)?,
            siblings: merkle::proof(&self.ids, index)?,
        })
    }
    /// Number of distinct signed public keys in this manifest.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

/// Exact public leaf and its canonical Merkle membership path.
pub struct LeafProof {
    leaf: PrekeyLeaf,
    index: u16,
    siblings: Vec<[u8; 32]>,
}
impl LeafProof {
    // Untrusted hint only; the complete manifest/member verifier must follow.
    pub(crate) fn untrusted_start(&self) -> u64 {
        self.leaf.validity.from
    }
    /// Serialize one bounded proof. Its manifest supplies the tree size and scope.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let leaf = self.leaf.encode();
        let length = u16::try_from(leaf.len()).map_err(|_| Error::Capacity)?;
        let depth = u8::try_from(self.siblings.len()).map_err(|_| Error::Capacity)?;
        let mut wire = Vec::with_capacity(5 + leaf.len() + 32 * self.siblings.len());
        wire.extend_from_slice(&self.index.to_be_bytes());
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(&leaf);
        wire.push(depth);
        for sibling in &self.siblings {
            wire.extend_from_slice(sibling);
        }
        Ok(wire)
    }
    /// Strictly parse a proof without admitting unbounded sibling or key storage.
    pub fn decode(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() > 5 + 25 + ML_KEM_768_PK_LEN + 10 * 32 {
            return Err(Error::Capacity);
        }
        let mut decoder = Decoder::new(wire);
        let index = decoder.u16()?;
        let length = usize::from(decoder.u16()?);
        let leaf = PrekeyLeaf::decode(decoder.take(length)?)?;
        let [depth] = decoder.array()?;
        if depth > 10 {
            return Err(Error::Capacity);
        }
        let mut siblings = Vec::with_capacity(usize::from(depth));
        for _ in 0..depth {
            siblings.push(decoder.array()?);
        }
        decoder.finish()?;
        Ok(Self {
            leaf,
            index,
            siblings,
        })
    }
}

impl DeviceSigningKey {
    /// Sign only for this owner's actually verified account/device credential.
    /// Context policy/directory semantics and later one-time consumption remain separate.
    pub fn issue_manifest(
        &self,
        device: &VerifiedDevice,
        context: ManifestContext,
        leaves: &[PrekeyLeaf],
    ) -> Result<IssuedManifest, Error> {
        if self.public_key()? != device.key {
            return Err(Error::Scope);
        }
        if !device.description.validity.contains(context.validity)
            || !device.roster_validity.contains(context.validity)
        {
            return Err(Error::Validity);
        }
        let ManifestParts { body, leaves, ids } =
            manifest_parts(&scope(device, context), context, leaves)?;
        let wire = envelope(&body, &self.sign(Purpose::Manifest, &body)?)?;
        Ok(IssuedManifest { wire, leaves, ids })
    }
}

struct ManifestParts {
    body: Vec<u8>,
    leaves: Vec<PrekeyLeaf>,
    ids: Vec<[u8; 32]>,
}

fn manifest_parts(
    scope: &[u8],
    context: ManifestContext,
    leaves: &[PrekeyLeaf],
) -> Result<ManifestParts, Error> {
    if leaves.is_empty() || leaves.len() > MAX_PREKEYS {
        return Err(Error::Capacity);
    }
    let mut fingerprints = BTreeSet::new();
    let mut sorted = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        if !context.validity.contains(leaf.validity) {
            return Err(Error::Validity);
        }
        if !fingerprints.insert(leaf.key_fingerprint()) {
            return Err(Error::Scope);
        }
        sorted.push((leaf_id(scope, leaf), leaf.clone()));
    }
    sorted.sort_by_key(|(id, _)| *id);
    let ids: Vec<_> = sorted.iter().map(|(id, _)| *id).collect();
    let mut body = MANIFEST_TAG.to_vec();
    body.extend_from_slice(scope);
    body.extend_from_slice(
        &u16::try_from(ids.len())
            .map_err(|_| Error::Capacity)?
            .to_be_bytes(),
    );
    body.extend_from_slice(&merkle::root(&ids)?);
    Ok(ManifestParts {
        body,
        leaves: sorted.into_iter().map(|(_, leaf)| leaf).collect(),
        ids,
    })
}

/// Signed manifest under an actual verified device and its exact roster binding.
/// This is not a fresh directory view, resolved session policy, or consumption capability.
pub struct VerifiedManifest {
    scope: Vec<u8>,
    context: ManifestContext,
    count: usize,
    root: [u8; 32],
    digest: [u8; 32],
    authority: [u8; 32],
}
impl VerifiedDevice {
    /// Verify signatures and all fixed device/roster fields at the supplied trusted time.
    pub fn verify_manifest(
        &self,
        wire: &[u8],
        trusted_time: u64,
    ) -> Result<VerifiedManifest, Error> {
        self.description.validity.check(trusted_time)?;
        self.roster_validity.check(trusted_time)?;
        let (body, signature) = open_envelope(wire)?;
        self.key.verify(Purpose::Manifest, body, signature)?;
        let mut decoder = Decoder::new(body);
        if decoder.array::<8>()? != *MANIFEST_TAG {
            return Err(Error::Encoding);
        }
        if decoder.array::<32>()? != self.account
            || decoder.array::<16>()? != self.description.id
            || decoder.u64()? != self.description.generation
            || decoder.array::<32>()? != self.certificate
            || decoder.u64()? != self.checkpoint.version()
            || decoder.array::<32>()? != self.checkpoint.digest()
        {
            return Err(Error::Scope);
        }
        let context = ManifestContext::decode(&mut decoder)?;
        context.validity.check(trusted_time)?;
        if !self.description.validity.contains(context.validity)
            || !self.roster_validity.contains(context.validity)
        {
            return Err(Error::Validity);
        }
        let count = usize::from(decoder.u16()?);
        if !(1..=MAX_PREKEYS).contains(&count) {
            return Err(Error::Capacity);
        }
        let root = decoder.array()?;
        nonzero(&root)?;
        decoder.finish()?;
        Ok(VerifiedManifest {
            scope: scope(self, context),
            context,
            count,
            root,
            digest: digest(b"Q-PERIAPT-CONTINUITY-MANIFEST-CANDIDATE/v1", body),
            authority: self.authority_binding(),
        })
    }
}
impl VerifiedManifest {
    pub(crate) fn selection_identity(&self) -> Result<crate::selection::SelectionIdentity, Error> {
        const IDENTITY_BYTES: usize = 32 + 16 + 8 + 32;
        let identity = self.scope.get(..IDENTITY_BYTES).ok_or(Error::Encoding)?;
        let mut decoder = Decoder::new(identity);
        let result = crate::selection::SelectionIdentity {
            account: decoder.array()?,
            device: decoder.array()?,
            generation: decoder.u64()?,
            credential: decoder.array()?,
        };
        decoder.finish()?;
        Ok(result)
    }

    /// Signed metadata to compare against the service's separately resolved policy/directory state.
    pub fn context(&self) -> ManifestContext {
        self.context
    }
    /// Stable canonical body commitment, independent of signing randomness.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Exact root/roster authority binding to recheck in a later consumption transaction.
    pub fn authority_binding(&self) -> [u8; 32] {
        self.authority
    }
    /// Authenticate a public leaf and exact membership path; this neither consumes nor validates a KEM key.
    pub fn verify_leaf(
        &self,
        proof: &LeafProof,
        trusted_time: u64,
    ) -> Result<AuthenticatedLeaf, Error> {
        self.context.validity.check(trusted_time)?;
        proof.leaf.validity.check(trusted_time)?;
        if !self.context.validity.contains(proof.leaf.validity) {
            return Err(Error::Validity);
        }
        let id = leaf_id(&self.scope, &proof.leaf);
        if merkle::reconstruct(id, usize::from(proof.index), self.count, &proof.siblings)?
            != self.root
        {
            return Err(Error::Authentication);
        }
        Ok(AuthenticatedLeaf {
            leaf: proof.leaf.clone(),
            id,
            manifest: self.digest,
            authority: self.authority,
        })
    }
}

/// Signature-covered leaf metadata, distinct from a usable KEM owner or an at-most-once receipt.
pub struct AuthenticatedLeaf {
    leaf: PrekeyLeaf,
    id: [u8; 32],
    manifest: [u8; 32],
    authority: [u8; 32],
}
impl AuthenticatedLeaf {
    /// Signed leaf interval, bounded by its authenticated manifest interval.
    pub fn validity(&self) -> Validity {
        self.leaf.validity
    }

    /// Complete scope-bound leaf commitment.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Signed public-key role and quality.
    pub fn kind(&self) -> LeafKind {
        self.leaf.kind
    }
    /// Signature-covered public bytes; validate at the primitive boundary before use.
    pub fn public_key(&self) -> &[u8] {
        &self.leaf.public
    }
    /// Stable key fingerprint for later cross-manifest alias detection.
    pub fn key_fingerprint(&self) -> [u8; 32] {
        self.leaf.key_fingerprint()
    }
    /// Parent manifest body commitment.
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest
    }
    /// Root/roster authority binding requiring a later transaction recheck.
    pub fn authority_binding(&self) -> [u8; 32] {
        self.authority
    }
}
