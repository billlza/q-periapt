// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh signed public materials on the bounded test-control pipe.
//! Existing sessions and their original advertisement are never rewritten.
use crate::{fixture::Fixture, Result, NOW};
use q_periapt_continuity_identity_candidate::{
    bootstrap_suite_digest, LeafKind, ManifestContext, PrekeyLeaf, PrekeyQuality, Validity,
};

pub(super) fn issue(fixture: &Fixture, payload: &[u8]) -> Result<Vec<u8>> {
    let now = u64::from_be_bytes(payload.try_into()?);
    if now < NOW {
        return Err("fresh test advertisement cannot predate original admission".into());
    }
    fixture
        .policy
        .check_mode(PrekeyQuality::ReusableBoth, now)?;
    let until = now.checked_add(20).ok_or("advertisement time exhausted")?;
    let validity = Validity::new(now, until)?;
    let sdk = fixture.policy.sdk_binding();
    let public = fixture.prekey.public_key()?.to_bytes();
    let (pq, classical) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let manifest = fixture.signer.issue_manifest(
        &fixture.responder,
        ManifestContext::new(
            now,
            sdk[36..].try_into()?,
            bootstrap_suite_digest(),
            [99; 32],
            validity,
        )?,
        &[
            PrekeyLeaf::new(LeafKind::SignedClassical, classical, validity)?,
            PrekeyLeaf::new(LeafKind::LastResortPq, pq, validity)?,
        ],
    )?;
    let verified = fixture
        .responder
        .verify_manifest(manifest.as_bytes(), now)?;
    let mut proofs = std::collections::BTreeMap::new();
    for index in 0..2 {
        let proof = manifest.proof(index)?;
        let kind = verified.verify_leaf(&proof, now)?.kind() as u8;
        proofs.insert(kind, proof.encode()?);
    }
    let mut result = Vec::new();
    for part in [
        manifest.as_bytes(),
        proofs.get(&1).ok_or("missing refreshed classical proof")?,
        proofs.get(&3).ok_or("missing refreshed PQ proof")?,
    ] {
        result.extend_from_slice(&u32::try_from(part.len())?.to_be_bytes());
        result.extend_from_slice(part);
    }
    Ok(result)
}
