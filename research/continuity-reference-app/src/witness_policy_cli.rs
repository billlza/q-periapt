// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently selected operator policy approval/closure, never a network API.
use super::{
    operator_io::{identifier, print, read, Result},
    USAGE,
};
use q_periapt_continuity_reference_app::{
    native_device::clock,
    policy_renewal::witness::Preparation,
    witness::{PolicyRenewalTrust, Witness},
};
use std::{ffi::OsString, path::Path};
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|v| v.to_str()).ok_or(USAGE)?;
    if args.len() != 6 || !matches!(command, "policy-prepare" | "policy-close") {
        return Err(USAGE.into());
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() {
        return Err("Witness host path must be absolute".into());
    }
    let trust: PolicyRenewalTrust =
        serde_json::from_slice(&read(Path::new(&args[4]), 512 * 1024)?)?;
    let preparation: Preparation = serde_json::from_slice(&read(Path::new(&args[5]), 128 * 1024)?)?;
    let mut owner = Witness::open(path, identifier(&args[3])?)?;
    print(&if command == "policy-prepare" {
        owner.prepare_policy_renewal(&trust, &preparation, clock()?)?
    } else {
        owner.close_policy_renewal(&trust, &preparation)?
    })
}
