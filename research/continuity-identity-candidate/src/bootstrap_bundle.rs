// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Portable untrusted public bootstrap inputs. Trust, policy ownership and exact
//! intended device identities are supplied independently of the input bytes.
use crate::{
    AccountPin, BootstrapContext, ClassicalChoice, DirectoryExpectation, Error, LeafProof,
    PqChoice, PrekeyQuality, VerifiedDevice, VerifiedSessionPolicy,
};
use std::sync::Arc;
mod codec;

/// Maximum complete public bootstrap bundle, including all length prefixes.
pub use crate::contract::MAX_BOOTSTRAP_BUNDLE_BYTES;

/// An exact intended device under an independently retained account pin.
#[derive(Clone, Copy)]
pub struct ExpectedDevice<'a> {
    account: &'a AccountPin,
    device: [u8; 16],
    generation: u64,
}
impl<'a> ExpectedDevice<'a> {
    /// Bind a caller-selected device and generation. Incoming credentials cannot
    /// select another authorized device merely because it shares the same account.
    pub fn new(account: &'a AccountPin, device: [u8; 16], generation: u64) -> Result<Self, Error> {
        crate::codec::nonzero(&device)?;
        crate::codec::generation(generation)?;
        Ok(Self {
            account,
            device,
            generation,
        })
    }
    fn verify(
        self,
        certificate: &[u8],
        roster: &[u8],
        now: u64,
    ) -> Result<Arc<VerifiedDevice>, Error> {
        let device = self.account.verify_device(certificate, roster, now)?;
        if device.device_id() != self.device || device.generation() != self.generation {
            return Err(Error::Scope);
        }
        Ok(Arc::new(device))
    }
}
/// Caller-owned admission expectations. A bundle contains none of these trust pins
/// and cannot update them, replace a policy owner or choose a weaker prekey mode.
pub struct BootstrapRequirements<'a> {
    /// Exact initiator account pin, device and generation.
    pub initiator: ExpectedDevice<'a>,
    /// Exact responder account pin, device and generation.
    pub responder: ExpectedDevice<'a>,
    /// Explicit intended two-leg quality; no network-selected fallback exists.
    pub quality: PrekeyQuality,
    /// Independently retained directory expectation, not a consistency proof.
    pub directory: DirectoryExpectation,
}
/// Borrowed public inputs in their existing canonical signed/proof encodings.
/// These bytes remain untrusted until all verification and independent scope checks.
pub struct BootstrapMaterials<'a> {
    /// Signed initiator device credential.
    pub initiator_credential: &'a [u8],
    /// Signed initiator account roster.
    pub initiator_roster: &'a [u8],
    /// Signed responder device credential.
    pub responder_credential: &'a [u8],
    /// Signed responder account roster.
    pub responder_roster: &'a [u8],
    /// Responder-signed prekey manifest.
    pub responder_manifest: &'a [u8],
    /// Mandatory baseline signed classical membership proof.
    pub signed_classical: &'a [u8],
    /// Mandatory baseline last-resort PQ membership proof.
    pub last_resort_pq: &'a [u8],
    /// Present exactly when the chosen mode uses a one-time classical leaf.
    pub one_time_classical: Option<&'a [u8]>,
    /// Present exactly when the chosen mode uses a one-time PQ leaf.
    pub one_time_pq: Option<&'a [u8]>,
}
/// Bounded canonical container of untrusted public materials. Parsing alone does
/// not create authority, consume prekeys, provision a journal or authenticate a peer.
pub struct BootstrapBundle {
    wire: Vec<u8>,
}
impl BootstrapBundle {
    /// Assemble a portable public container. This checks only the outer grammar,
    /// bounds and explicit proof presence; it does not verify signatures or membership.
    pub fn from_materials(
        quality: PrekeyQuality,
        materials: BootstrapMaterials<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            wire: codec::encode(quality, materials)?,
        })
    }
    /// Parse a bounded canonical container without admitting its public assertions.
    pub fn from_bytes(wire: &[u8]) -> Result<Self, Error> {
        codec::decode(wire)?;
        Ok(Self {
            wire: wire.to_vec(),
        })
    }
    /// Exact untrusted input bytes. The format has no private-key fields.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Verify every credential, exact pinned roster, manifest and selected member
    /// through the existing verifier. The existing policy/runtime owner is retained,
    /// including its closed state; no signed policy from this bundle can reopen it.
    /// The result is a verified snapshot. Current journal authority, prekey use and
    /// durable admission remain mandatory at every operation/release boundary.
    pub fn verify(
        &self,
        policy: Arc<VerifiedSessionPolicy>,
        required: BootstrapRequirements<'_>,
        now: u64,
    ) -> Result<BootstrapContext, Error> {
        let (quality, materials) = codec::decode(&self.wire)?;
        if quality != required.quality {
            return Err(Error::Scope);
        }
        policy.check_mode(required.quality, now)?;
        let initiator = required.initiator.verify(
            materials.initiator_credential,
            materials.initiator_roster,
            now,
        )?;
        let responder = required.responder.verify(
            materials.responder_credential,
            materials.responder_roster,
            now,
        )?;
        let manifest = responder.verify_manifest(materials.responder_manifest, now)?;
        let signed = LeafProof::decode(materials.signed_classical)?;
        let last_resort = LeafProof::decode(materials.last_resort_pq)?;
        let one_classical = materials
            .one_time_classical
            .map(LeafProof::decode)
            .transpose()?;
        let one_pq = materials.one_time_pq.map(LeafProof::decode).transpose()?;
        let classical = match &one_classical {
            Some(proof) => ClassicalChoice::OneTime(proof),
            None => ClassicalChoice::SignedOnly,
        };
        let pq = match &one_pq {
            Some(proof) => PqChoice::OneTime(proof),
            None => PqChoice::LastResort,
        };
        let selection = manifest.select_prekeys(&signed, &last_resort, classical, pq, now)?;
        if selection.quality() != required.quality {
            return Err(Error::Scope);
        }
        BootstrapContext::new(
            policy,
            initiator,
            responder,
            Arc::new(selection),
            required.directory,
            now,
        )
    }
}

#[cfg(test)]
mod tests;
