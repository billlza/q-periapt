// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted original G approval/closure, separate from device-signed commands.
use super::{
    operator_io::{identifier, print, read, Result},
    USAGE,
};
use q_periapt_continuity_reference_app::{
    credential_grant::{witness::Preparation, IssuedCredentialGrant},
    native_device::clock,
    witness::{CredentialRenewalTrust, Witness},
};
use std::{ffi::OsString, path::Path};
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|v| v.to_str()).ok_or(USAGE)?;
    if args.len() != 7 || !matches!(command, "credential-prepare" | "credential-close") {
        return Err(USAGE.into());
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() {
        return Err("Witness host path must be absolute".into());
    }
    let trust: CredentialRenewalTrust =
        serde_json::from_slice(&read(Path::new(&args[4]), 384 * 1024)?)?;
    let preparation: Preparation = serde_json::from_slice(&read(Path::new(&args[5]), 4096)?)?;
    let issued: IssuedCredentialGrant =
        serde_json::from_slice(&read(Path::new(&args[6]), 128 * 1024)?)?;
    let mut owner = Witness::open(path, identifier(&args[3])?)?;
    print(&if command == "credential-prepare" {
        owner.prepare_credential_renewal(&trust, &preparation, &issued, clock()?)?
    } else {
        owner.close_credential_renewal(&trust, &preparation, &issued)?
    })
}
