// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Source-built test authority; outputs contain public material only.
use q_periapt_continuity_identity_candidate::{
    DeviceDescription, DeviceSigningKey, RootSigningKey, Validity,
};
use std::path::Path;

#[path = "../src/account_fixture.rs"]
mod account_fixture;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("expected new output directory and member count (3 or 32)".into());
    }
    let count: u8 = args[2].parse()?;
    if count != 3 && count != 32 {
        return Err("fixture member count must be 3 or 32".into());
    }
    let root = RootSigningKey::generate()?;
    let family = [84; 32];
    let mut certificates = Vec::new();
    for id in 1..=count {
        certificates.push(root.issue_device(
            DeviceDescription::new([id; 16], 1, family, Validity::new(100, 200)?)?,
            DeviceSigningKey::generate()?.public_key()?,
        )?);
    }
    let published =
        account_fixture::publish(Path::new(&args[1]), &root, certificates, family, [83; 32])?;
    if published.initial_roster.is_empty()
        || published.checkpoint.version() != 1
        || published.local_grants.len() != 2
    {
        return Err("incomplete native account fixture".into());
    }
    Ok(())
}
