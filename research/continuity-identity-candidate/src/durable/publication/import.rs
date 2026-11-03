// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read-only import for the reference application's two closed publication plans.
use super::*;
use crate::{AuthenticatedPrekeySelection, ClassicalChoice, LeafProof, PqChoice, PrekeyQuality};

impl PrekeyPublicationPlan {
    /// Admit an entire QPPUBA01 advertisement under independently supplied device,
    /// policy, directory checkpoint, validity, member plan and expected operation.
    /// Supports the reusable pair and the four-member one-time-both plan. Never
    /// substitutes a weaker quality or treats producer correlation as a lease.
    /// The manifest signs the device, epoch and members. Its signature does not
    /// bind the producer journal or operation ID: their public correlations can
    /// be recomputed. This selection is not proof of issuance or exclusive use.
    pub fn verify_artifact(
        &self,
        wire: &[u8],
        journal: &[u8; 32],
        expected_id: PrekeyPublicationId,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AuthenticatedPrekeySelection, Error> {
        use LeafKind::{LastResortPq, OneTimeClassical, OneTimePq, SignedClassical};
        if self.keys.len() != 2 && self.keys.len() != 4 {
            return Err(Error::Scope);
        }
        let kinds: Vec<_> = self.keys.iter().map(PrekeyPublicationKey::kind).collect();
        let quality = match kinds.as_slice() {
            [SignedClassical, LastResortPq] => PrekeyQuality::ReusableBoth,
            [SignedClassical, OneTimeClassical, LastResortPq, OneTimePq] => {
                PrekeyQuality::OneTimeBoth
            }
            _ => return Err(Error::Scope),
        };
        policy.check_mode(quality, now)?;
        crate::codec::nonzero(journal)?;
        let context = codec::publication_context(self, policy, expected_id.check(journal)?)?;
        if wire.len() > self.artifact_size_bound()? {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(wire);
        if d.array::<8>()? != *b"QPPUBA01" || d.array::<32>()? != *expected_id.as_bytes() {
            return Err(Error::Scope);
        }
        let intent = d.array::<32>()?;
        let commitment = d.array::<32>()?;
        let scope = crate::manifest::scope(device, context);
        let expected_intent = codec::intent_bytes(
            &policy.sdk_binding(),
            &codec::policy_checkpoint(policy),
            &scope,
            self,
        )?;
        let intent_hash = digest(
            b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-INTENT/v1",
            &expected_intent,
        );
        if intent != intent_hash {
            return Err(Error::Scope);
        }
        let length = usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| Error::Capacity)?;
        if length != crate::manifest::MANIFEST_WIRE_BYTES {
            return Err(Error::Encoding);
        }
        let manifest = d.take(length)?;
        let count = usize::from(d.u16()?);
        if count != self.keys.len() {
            return Err(Error::Scope);
        }
        // IDs are in original plan order; proofs have their own signed tree order.
        for id in self.requests(expected_id)? {
            if d.array::<32>()? != *id.as_bytes() {
                return Err(Error::Scope);
            }
        }
        let mut proofs = Vec::with_capacity(count);
        for index in 0..count {
            let size = usize::from(d.u16()?);
            let bytes = d.take(size)?;
            let index = u16::try_from(index).map_err(|_| Error::Capacity)?;
            if bytes.get(..2) != Some(index.to_be_bytes().as_slice()) {
                return Err(Error::Encoding);
            }
            proofs.push(LeafProof::decode(bytes)?);
        }
        d.finish()?;
        let (signed, leaves) =
            device.verify_prekey_publication(manifest, &proofs, policy, context, now)?;
        let index_of = |kind| {
            leaves
                .iter()
                .position(|leaf| leaf.kind() == kind)
                .ok_or(Error::Scope)
        };
        let mut payload = intent.to_vec();
        payload.extend_from_slice(manifest);
        for key in &self.keys {
            let leaf = leaves.get(index_of(key.kind)?).ok_or(Error::Scope)?;
            if leaf.validity() != key.validity {
                return Err(Error::Scope);
            }
            payload.extend_from_slice(leaf.public_key());
        }
        let artifact_hash = digest(
            b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ARTIFACT/v1",
            &payload,
        );
        if commitment != artifact_hash {
            return Err(Error::Authentication);
        }
        let proof = |kind| proofs.get(index_of(kind)?).ok_or(Error::Scope);
        let (classical, pq) = if quality == PrekeyQuality::OneTimeBoth {
            (
                ClassicalChoice::OneTime(proof(OneTimeClassical)?),
                PqChoice::OneTime(proof(OneTimePq)?),
            )
        } else {
            (ClassicalChoice::SignedOnly, PqChoice::LastResort)
        };
        let selected = signed.select_prekeys(
            proof(SignedClassical)?,
            proof(LastResortPq)?,
            classical,
            pq,
            now,
        )?;
        policy.check_mode(quality, now)?;
        Ok(selected)
    }
}
