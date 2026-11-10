// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh public peer inputs for the successor and a separate C server process.
use super::*;
use std::collections::BTreeMap;

pub(super) fn peers(case: &setup::Case) -> Result<(PathBuf, PathBuf)> {
    let at = fixture::now()?;
    let advertisement =
        p::Validity::new(at.saturating_sub(1), at.checked_add(300).ok_or("clock")?)?;
    let mut owner = fixture::Peer::open_with_witness(
        &case.reference.responder,
        Some(&case.witness.configured),
    )?;
    let context = std::sync::Arc::clone(&owner.context);
    let policy = context.current_policy()?;
    let device = context.device(p::BootstrapRole::Responder);
    let (service, signer) = owner.service.parts()?;
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
        leaves.push(service.stores()?.0.generate_prekey(
            policy,
            device,
            p::PrekeyId::from_trusted_state([u8::try_from(160 + index)?; 32])?,
            kind,
            advertisement,
            at,
        )?);
    }
    let manifest = signer.issue_manifest(
        device,
        p::ManifestContext::new(
            1,
            case.sdk.runtime()?.trusted_state().digest(),
            p::bootstrap_suite_digest(),
            [99; 32],
            advertisement,
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
    let bundle = p::BootstrapBundle::from_materials(
        p::PrekeyQuality::OneTimeBoth,
        p::BootstrapMaterials {
            initiator_credential: &case.target.certificate,
            initiator_roster: &case.target.roster,
            responder_credential: &fixture::read(
                &case.reference.responder,
                "local-certificate",
                8192,
            )?,
            responder_roster: &fixture::read(&case.reference.responder, "local-roster", 8192)?,
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(p::LeafKind::SignedClassical)?,
            last_resort_pq: proof(p::LeafKind::LastResortPq)?,
            one_time_classical: Some(proof(p::LeafKind::OneTimeClassical)?),
            one_time_pq: Some(proof(p::LeafKind::OneTimePq)?),
        },
    )?;
    owner.close();
    let paths = (
        case.target.path.join("peer"),
        case.reference.responder.join("root-peer"),
    );
    for path in [&paths.0, &paths.1] {
        fixture::create_private_directory(path)?;
        fixture::store(path, "bootstrap.bundle", bundle.as_bytes())?;
        fixture::store(path, "directory", &[99; 32])?;
        for name in ["certificate", "roster"] {
            fixture::store(
                path,
                &format!("responder-{name}"),
                &fixture::read(&case.reference.responder, &format!("local-{name}"), 8192)?,
            )?;
        }
        for (name, bytes) in [
            ("account", case.target.credential.account_id().to_vec()),
            ("root", case.target.root.public_key()?.encode()),
            (
                "roster-version",
                case.target
                    .credential
                    .roster()
                    .checkpoint()
                    .version()
                    .to_be_bytes()
                    .to_vec(),
            ),
            (
                "roster-digest",
                case.target
                    .credential
                    .roster()
                    .checkpoint()
                    .digest()
                    .to_vec(),
            ),
            ("device", case.target.credential.device_id().to_vec()),
            (
                "generation",
                case.target.credential.generation().to_be_bytes().to_vec(),
            ),
        ] {
            fixture::store(path, &format!("initiator-{name}"), &bytes)?;
        }
        for name in [
            "account",
            "root",
            "roster-version",
            "roster-digest",
            "device",
            "generation",
        ] {
            fixture::store(
                path,
                &format!("responder-{name}"),
                &fixture::read(&case.reference.responder, &format!("local-{name}"), 8192)?,
            )?;
        }
    }
    for (peer, remote, name) in [
        (&paths.0, &case.reference.responder, "responder.test"),
        (&paths.1, &case.target.path, "initiator.test"),
    ] {
        fixture::store(peer, "tls-peer", &fixture::read(remote, "tls-cert", 8192)?)?;
        fixture::store(peer, "tls-peer-name", name.as_bytes())?;
    }
    fixture::store(&case.public.join("traffic"), "peer-application", &[156; 32])?;
    Ok(paths)
}
