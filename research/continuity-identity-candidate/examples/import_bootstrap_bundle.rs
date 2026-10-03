// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent public-material consumer for the generated fixture trust directory.
//! This program does not enroll trust from a received bundle or provide a durable
//! production trust store. TRUST must come from the local fixture issuer separately.
use q_periapt_continuity_identity_candidate::{
    AccountPin, BootstrapBundle, BootstrapRequirements, DirectoryExpectation, ExpectedDevice,
    PolicyCheckpoint, PolicyPin, PrekeyQuality, PublicKey, RosterCheckpoint,
    MAX_BOOTSTRAP_BUNDLE_BYTES,
};
use q_periapt_sdk::{Limits, Runtime};
use std::{error::Error, fs::File, io::Read, path::Path, sync::Arc};

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds its public bound".into());
    }
    Ok(bytes)
}
fn exact<const N: usize>(path: &Path) -> Result<[u8; N], Box<dyn Error>> {
    bounded(path, N)?
        .try_into()
        .map_err(|_| "wrong trusted field width".into())
}
fn integer(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_be_bytes(bytes.try_into()?))
}
struct DeviceTrust {
    pin: AccountPin,
    device: [u8; 16],
    generation: u64,
}
fn trust(path: &Path, role: &str, family: [u8; 32]) -> Result<DeviceTrust, Box<dyn Error>> {
    let public = PublicKey::decode(&bounded(
        &path.join(format!("bootstrap-{role}-root.pub")),
        1985,
    )?)?;
    let bytes = exact::<96>(&path.join(format!("bootstrap-{role}-expectation.bin")))?;
    let account = bytes.get(..32).ok_or("account")?.try_into()?;
    let version = integer(bytes.get(32..40).ok_or("roster version")?)?;
    let digest = bytes.get(40..72).ok_or("roster digest")?.try_into()?;
    let device = bytes.get(72..88).ok_or("device")?.try_into()?;
    let generation = integer(bytes.get(88..96).ok_or("generation")?)?;
    Ok(DeviceTrust {
        pin: AccountPin::new(
            account,
            public,
            RosterCheckpoint::from_trusted_state(version, digest)?,
            family,
        )?,
        device,
        generation,
    })
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err("expected TRUST_DIRECTORY BUNDLE_FILE REQUIRED_QUALITY TRUSTED_TIME".into());
    }
    let path = Path::new(args.first().ok_or("trust directory")?);
    let bundle_path = Path::new(args.get(1).ok_or("bundle")?);
    let quality = match args.get(2).and_then(|s| s.to_str()) {
        Some("1") => PrekeyQuality::OneTimeBoth,
        Some("2") => PrekeyQuality::ReusableBoth,
        Some("3") => PrekeyQuality::SignedClassicalOneTimePq,
        Some("4") => PrekeyQuality::OneTimeClassicalLastResortPq,
        _ => return Err("explicit quality must be 1, 2, 3 or 4".into()),
    };
    let now: u64 = args
        .get(3)
        .and_then(|s| s.to_str())
        .ok_or("trusted time")?
        .parse()?;
    // Explicit fresh-fixture genesis. A production host must use its already
    // protected monotonic SDK state rather than re-enrolling this public fixture.
    let runtime = Arc::new(Runtime::from_signed_policy(
        &bounded(&path.join("bootstrap-sdk-policy.toml"), 8192)?,
        &exact::<3309>(&path.join("bootstrap-sdk-policy.sig"))?,
        &exact::<1952>(&path.join("bootstrap-sdk-root.pub"))?,
        None,
        Limits::default(),
    )?);
    let family = exact::<32>(&path.join("bootstrap-family.bin"))?;
    let bytes = exact::<40>(&path.join("bootstrap-policy-checkpoint.bin"))?;
    let checkpoint = PolicyCheckpoint::from_trusted_state(
        integer(bytes.get(..8).ok_or("policy version")?)?,
        bytes.get(8..).ok_or("policy digest")?.try_into()?,
    )?;
    let pin = PolicyPin::new(
        family,
        PublicKey::decode(&bounded(&path.join("bootstrap-policy.pub"), 1985)?)?,
        checkpoint,
    )?;
    let policy = Arc::new(pin.verify(
        &bounded(&path.join("bootstrap-policy.bin"), 8192)?,
        runtime,
        now,
    )?);
    let initiator = trust(path, "i", family)?;
    let responder = trust(path, "r", family)?;
    let required = BootstrapRequirements {
        initiator: ExpectedDevice::new(&initiator.pin, initiator.device, initiator.generation)?,
        responder: ExpectedDevice::new(&responder.pin, responder.device, responder.generation)?,
        quality,
        directory: DirectoryExpectation::from_trusted_state(exact::<32>(
            &path.join("bootstrap-directory.bin"),
        )?)?,
    };
    let bundle = BootstrapBundle::from_bytes(&bounded(bundle_path, MAX_BOOTSTRAP_BUNDLE_BYTES)?)?;
    let context = bundle.verify(policy, required, now)?;
    if context.digest() != exact::<32>(&path.join("bootstrap-context.digest"))? {
        return Err("context differs from independently issued fixture expectation".into());
    }
    println!(
        "{}",
        context
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Ok(())
}
