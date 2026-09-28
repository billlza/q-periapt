// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{
    codec::nonzero, crypto::digest, AuthenticatedLeaf, Error, LeafKind, LeafProof, Validity,
    VerifiedManifest,
};

/// Exact canonical PrekeySelectionV1 record size, including sixteen LP8 prefixes.
pub const PREKEY_SELECTION_BYTES: usize = 492;
const RECORD_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1";
const DIGEST_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION-DIGEST/v1";

pub(crate) struct SelectionIdentity {
    pub(crate) account: [u8; 32],
    pub(crate) device: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) credential: [u8; 32],
}

/// Explicit classical selection; this choice does not grant session-policy permission.
pub enum ClassicalChoice<'a> {
    /// Authenticate a distinct one-time classical leaf under the same manifest.
    OneTime(&'a LeafProof),
    /// Select the authenticated reusable signed classical leaf.
    SignedOnly,
}

/// Explicit PQ selection; exhaustion cannot silently choose the reusable mode.
pub enum PqChoice<'a> {
    /// Authenticate a distinct one-time PQ leaf under the same manifest.
    OneTime(&'a LeafProof),
    /// Select the authenticated last-resort PQ leaf.
    LastResort,
}

/// Lossless signed role metadata; one-time describes the role, not a consumption receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrekeyQuality {
    /// One-time classical and one-time PQ leaves.
    OneTimeBoth = 1,
    /// Reusable signed classical and last-resort PQ leaves.
    ReusableBoth = 2,
    /// Reusable signed classical and one-time PQ leaves.
    SignedClassicalOneTimePq = 3,
    /// One-time classical and last-resort PQ leaves.
    OneTimeClassicalLastResortPq = 4,
}

/// A canonical selection derived from actual authenticated manifest members.
///
/// No public constructor or decoder can turn a caller-supplied record/digest into
/// this type. It authenticates selected public bytes and roles, but does not
/// validate primitive keys, authorize a mode, establish directory freshness, or
/// consume a prekey. A later service transaction must recheck those boundaries.
pub struct AuthenticatedPrekeySelection {
    encoded: [u8; PREKEY_SELECTION_BYTES],
    digest: [u8; 32],
    quality: PrekeyQuality,
    validity: Validity,
    classical: AuthenticatedLeaf,
    pq: AuthenticatedLeaf,
}

impl AuthenticatedPrekeySelection {
    /// All sixteen canonical fields; the caller cannot substitute their values.
    pub fn as_bytes(&self) -> &[u8; PREKEY_SELECTION_BYTES] {
        &self.encoded
    }
    /// SHA3-256 over the existing 555-byte PrekeySelectionV1 digest preimage.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Exact classical/PQ role combination derived from authenticated leaves.
    pub fn quality(&self) -> PrekeyQuality {
        self.quality
    }
    /// Common signed interval of every referenced baseline and selected leaf.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// Recheck time only; current policy, authority and consumption still require a transaction.
    pub fn check_time(&self, trusted_time: u64) -> Result<(), Error> {
        self.validity.check(trusted_time)
    }
    /// Selected classical public bytes and their authenticated leaf identity.
    pub fn classical(&self) -> &AuthenticatedLeaf {
        &self.classical
    }
    /// Selected PQ public bytes and their authenticated leaf identity.
    pub fn post_quantum(&self) -> &AuthenticatedLeaf {
        &self.pq
    }
    /// Exact signed manifest body commitment shared by all selected proofs.
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.classical.manifest_digest()
    }
    /// Retained account/roster authority to recheck before actual use.
    pub fn authority_binding(&self) -> [u8; 32] {
        self.classical.authority_binding()
    }
}

fn require_role(leaf: &AuthenticatedLeaf, expected: LeafKind) -> Result<(), Error> {
    if leaf.kind() != expected {
        return Err(Error::Scope);
    }
    nonzero(&leaf.id())
}

fn require_distinct(
    selected: &AuthenticatedLeaf,
    reusable: &AuthenticatedLeaf,
) -> Result<(), Error> {
    if selected.id() == reusable.id() || selected.key_fingerprint() == reusable.key_fingerprint() {
        return Err(Error::Scope);
    }
    Ok(())
}

impl VerifiedManifest {
    /// Authenticate a full selection under this one manifest at the supplied time.
    ///
    /// Both reusable baseline leaves are required even when one-time leaves are
    /// chosen. They are part of the canonical selection, not caller-supplied IDs.
    /// Choosing a reusable mode here does not authorize its use in a session.
    pub fn select_prekeys(
        &self,
        signed_classical: &LeafProof,
        last_resort_pq: &LeafProof,
        classical: ClassicalChoice<'_>,
        pq: PqChoice<'_>,
        trusted_time: u64,
    ) -> Result<AuthenticatedPrekeySelection, Error> {
        let signed = self.verify_leaf(signed_classical, trusted_time)?;
        require_role(&signed, LeafKind::SignedClassical)?;
        let last_resort = self.verify_leaf(last_resort_pq, trusted_time)?;
        require_role(&last_resort, LeafKind::LastResortPq)?;
        let signed_id = signed.id();
        let last_resort_id = last_resort.id();
        let baseline = intersect(signed.validity(), last_resort.validity())?;
        let (classical, classical_mode) = match classical {
            ClassicalChoice::OneTime(proof) => {
                let selected = self.verify_leaf(proof, trusted_time)?;
                require_role(&selected, LeafKind::OneTimeClassical)?;
                require_distinct(&selected, &signed)?;
                (selected, 1u8)
            }
            ClassicalChoice::SignedOnly => (signed, 2u8),
        };
        let (pq, pq_mode) = match pq {
            PqChoice::OneTime(proof) => {
                let selected = self.verify_leaf(proof, trusted_time)?;
                require_role(&selected, LeafKind::OneTimePq)?;
                require_distinct(&selected, &last_resort)?;
                (selected, 1u8)
            }
            PqChoice::LastResort => (last_resort, 2u8),
        };
        let quality = match (classical.kind(), pq.kind()) {
            (LeafKind::OneTimeClassical, LeafKind::OneTimePq) => PrekeyQuality::OneTimeBoth,
            (LeafKind::SignedClassical, LeafKind::LastResortPq) => PrekeyQuality::ReusableBoth,
            (LeafKind::SignedClassical, LeafKind::OneTimePq) => {
                PrekeyQuality::SignedClassicalOneTimePq
            }
            (LeafKind::OneTimeClassical, LeafKind::LastResortPq) => {
                PrekeyQuality::OneTimeClassicalLastResortPq
            }
            _ => return Err(Error::Scope),
        };
        let validity = intersect(intersect(baseline, classical.validity())?, pq.validity())?;
        let identity = self.selection_identity()?;
        let context = self.context();
        let mut encoded = Vec::with_capacity(PREKEY_SELECTION_BYTES);
        for field in [
            RECORD_DOMAIN,
            &1u16.to_be_bytes(),
            &context.suite_digest(),
            &identity.account,
            &identity.device,
            &identity.generation.to_be_bytes(),
            &identity.credential,
            &context.bundle_epoch().to_be_bytes(),
            &context.directory_checkpoint(),
            &self.digest(),
            &[classical_mode],
            &signed_id,
            &classical.id(),
            &[pq_mode],
            &last_resort_id,
            &pq.id(),
        ] {
            encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
            encoded.extend_from_slice(field);
        }
        let encoded: [u8; PREKEY_SELECTION_BYTES] =
            encoded.try_into().map_err(|_| Error::Encoding)?;
        let digest = digest(DIGEST_DOMAIN, &encoded);
        nonzero(&digest)?;
        Ok(AuthenticatedPrekeySelection {
            encoded,
            digest,
            quality,
            validity,
            classical,
            pq,
        })
    }
}

fn intersect(left: Validity, right: Validity) -> Result<Validity, Error> {
    Validity::new(
        left.from().max(right.from()),
        left.until().min(right.until()),
    )
}
