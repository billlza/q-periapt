// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test authority supplies verified public inputs to independently created devices.
use crate::{fixture, p, Result};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(crate) fn peer_bundle_at(
    remote: &Path,
    peer: &Path,
    root: &p::RootSigningKey,
    certificate: &[u8],
    roster: &p::IssuedRoster,
    witness: Option<&fixture::WitnessFixture>,
) -> Result<PathBuf> {
    let family = fixture::array(remote, "family")?;
    let pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let enrolled = pin.verify_device(certificate, roster.as_bytes(), fixture::now()?)?;
    let mut sdk = fixture::sdk(remote)?;
    let policy_digest = sdk.runtime()?.trusted_state().digest();
    sdk.close();
    let mut server = fixture::Peer::open_with_witness(remote, witness)?;
    let context = Arc::clone(&server.context);
    let device = context.device(p::BootstrapRole::Responder);
    let at = fixture::now()?;
    let validity = p::Validity::new(
        at.saturating_sub(1),
        at.checked_add(600).ok_or("clock overflow")?
            .min(context.current_policy()?.validity().until()),
    )?;
    let mut leaves = Vec::new();
    for (index, kind) in [
        p::LeafKind::SignedClassical,
        p::LeafKind::OneTimeClassical,
        p::LeafKind::LastResortPq,
        p::LeafKind::OneTimePq,
    ]
    .into_iter()
    .enumerate()
    {
        leaves.push(server.service.stores()?.0.generate_prekey(
            context.current_policy()?,
            device,
            p::PrekeyId::from_trusted_state([u8::try_from(index + 71)?; 32])?,
            kind,
            validity,
            at,
        )?);
    }
    let manifest = server.service.parts()?.1.issue_manifest(
        device,
        p::ManifestContext::new(
            2,
            policy_digest,
            p::bootstrap_suite_digest(),
            [99; 32],
            validity,
        )?,
        &leaves,
    )?;
    let verified = device.verify_manifest(manifest.as_bytes(), at)?;
    let mut proofs = BTreeMap::new();
    for index in 0..manifest.leaf_count() {
        let proof = manifest.proof(index)?;
        proofs.insert(
            verified.verify_leaf(&proof, at)?.kind() as u8,
            proof.encode()?,
        );
    }
    let proof =
        |kind: p::LeafKind| -> Result<&[u8]> { Ok(proofs.get(&(kind as u8)).ok_or("proof")?) };
    let remote_certificate = fixture::read(remote, "local-certificate", 8192)?;
    let remote_roster = fixture::read(remote, "local-roster", 8192)?;
    let bundle = p::BootstrapBundle::from_materials(
        p::PrekeyQuality::OneTimeBoth,
        p::BootstrapMaterials {
            initiator_credential: certificate,
            initiator_roster: roster.as_bytes(),
            responder_credential: &remote_certificate,
            responder_roster: &remote_roster,
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(p::LeafKind::SignedClassical)?,
            last_resort_pq: proof(p::LeafKind::LastResortPq)?,
            one_time_classical: Some(proof(p::LeafKind::OneTimeClassical)?),
            one_time_pq: Some(proof(p::LeafKind::OneTimePq)?),
        },
    )?;
    server.close();
    fs::DirBuilder::new().mode(0o700).create(peer)?;
    for name in [
        "responder-account",
        "responder-root",
        "responder-roster-version",
        "responder-roster-digest",
        "responder-device",
        "responder-generation",
        "directory",
    ] {
        fixture::store(peer, name, &fixture::read(remote, name, 8192)?)?;
    }
    for (name, bytes) in [
        ("initiator-account", root.account_id()?.to_vec()),
        ("initiator-root", root.public_key()?.encode()),
        (
            "initiator-roster-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "initiator-roster-digest",
            roster.checkpoint().digest().to_vec(),
        ),
        ("initiator-device", enrolled.device_id().to_vec()),
        (
            "initiator-generation",
            enrolled.generation().to_be_bytes().to_vec(),
        ),
        ("bootstrap.bundle", bundle.as_bytes().to_vec()),
    ] {
        fixture::store(peer, name, &bytes)?;
        // Independently approved new remote peer inputs; the server's local identity is unchanged.
        fs::write(remote.join(name), bytes)?;
    }
    fixture::store(peer, "family", &family)?;
    fixture::store(peer, "tls-peer", &fixture::read(remote, "tls-cert", 8192)?)?;
    fixture::store(peer, "tls-peer-name", b"responder.test")?;
    Ok(peer.to_owned())
}
