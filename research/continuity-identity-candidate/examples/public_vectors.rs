// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Emit public-only, freshly generated fixtures for an independent verifier.
use q_periapt_backends::{MlKem768, X25519};
use q_periapt_continuity_identity_candidate::{
    AccountPin, DeviceDescription, DeviceSigningKey, LeafKind, ManifestContext, PrekeyLeaf,
    RootSigningKey, Validity,
};
use q_periapt_core::ZeroizingBytes;
use std::{error::Error, fs, io::Write, path::Path};

fn save(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    Ok(())
}

fn public_prekey(kind: LeafKind, validity: Validity) -> Result<PrekeyLeaf, Box<dyn Error>> {
    let public = match kind {
        LeafKind::SignedClassical | LeafKind::OneTimeClassical => {
            let mut secret = ZeroizingBytes::<32>::zeroed();
            getrandom::fill(secret.as_mut_bytes())?;
            X25519::public_key(secret.as_bytes()).to_vec()
        }
        LeafKind::LastResortPq | LeafKind::OneTimePq => {
            let mut seed = ZeroizingBytes::<64>::zeroed();
            getrandom::fill(seed.as_mut_bytes())?;
            let (_secret, public) = MlKem768::generate_zeroizing(seed.as_bytes())
                .map_err(|error| format!("fixture ML-KEM generation failed: {error:?}"))?;
            public.to_vec()
        }
    };
    Ok(PrekeyLeaf::new(kind, &public, validity)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments
        .next()
        .ok_or("expected one new output directory")?;
    if arguments.next().is_some() {
        return Err("expected one new output directory".into());
    }
    let directory = Path::new(&output);
    fs::create_dir(directory)?;
    let mut root = RootSigningKey::generate()?;
    let mut signer = DeviceSigningKey::generate()?;
    let validity = Validity::new(100, 200)?;
    let family = [6; 32];
    let description = DeviceDescription::new([5; 16], 1, family, validity)?;
    let certificate = root.issue_device(description, signer.public_key()?)?;
    let entry = root.roster_entry(&certificate)?;
    let roster = root.issue_roster(1, validity, &[entry])?;
    // Enrollment is local to this fixture generator. A real receiver must retain
    // its expected root/checkpoint independently of incoming signed messages.
    let pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let device = pin.verify_device(&certificate, roster.as_bytes(), 150)?;
    save(directory, "root.pub", &root.public_key()?.encode())?;
    save(directory, "device.pub", &signer.public_key()?.encode())?;
    save(directory, "account.bin", &root.account_id()?)?;
    save(directory, "family.bin", &family)?;
    save(directory, "credential.bin", &certificate)?;
    save(directory, "roster.bin", roster.as_bytes())?;
    save(
        directory,
        "roster-digest.bin",
        &roster.checkpoint().digest(),
    )?;
    save(directory, "authority.bin", &device.authority_binding())?;
    root.close();

    let mut leaves = Vec::new();
    for index in 0..17 {
        let kind = match index {
            0 => LeafKind::SignedClassical,
            1 => LeafKind::OneTimeClassical,
            2 => LeafKind::LastResortPq,
            _ => LeafKind::OneTimePq,
        };
        leaves.push(public_prekey(kind, validity)?);
    }
    for count in [1, 2, 3, 5, 17] {
        let context = ManifestContext::new(count as u64, [7; 32], [8; 32], [9; 32], validity)?;
        let issued = signer.issue_manifest(
            &device,
            context,
            leaves.get(..count).ok_or("fixture count exceeds leaves")?,
        )?;
        let verified = device.verify_manifest(issued.as_bytes(), 150)?;
        save(
            directory,
            &format!("manifest-{count}.bin"),
            issued.as_bytes(),
        )?;
        save(
            directory,
            &format!("manifest-{count}.digest"),
            &verified.digest(),
        )?;
        for index in 0..count {
            let proof = issued.proof(index)?;
            let leaf = verified.verify_leaf(&proof, 150)?;
            save(
                directory,
                &format!("proof-{count}-{index}.bin"),
                &proof.encode()?,
            )?;
            save(directory, &format!("proof-{count}-{index}.id"), &leaf.id())?;
            save(
                directory,
                &format!("proof-{count}-{index}.fingerprint"),
                &leaf.key_fingerprint(),
            )?;
        }
    }
    signer.close();
    println!("public fixtures written; private fixture keys discarded");
    Ok(())
}
