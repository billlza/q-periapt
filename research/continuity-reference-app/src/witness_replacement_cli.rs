// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted device replacement and exact outcome observation on the original witness.
use super::{
    operator_io::{export_directory, identifier, print, read, Result},
    USAGE,
};
use q_periapt_continuity_reference_app::{
    native_device::clock,
    witness::{DeviceReplacementDecision, DeviceReplacementTrust, EnrollmentRequest, Witness},
};
use std::{ffi::OsString, path::Path};

pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|s| s.to_str()).ok_or(USAGE)?;
    let count = match command {
        "replacement-prepare" | "replacement-commit" => 7,
        "replacement-status" => 5,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() {
        return Err("Witness host path must be absolute".into());
    }
    let mut owner = Witness::open(path, identifier(&args[3])?)?;
    if command == "replacement-status" {
        let decision: DeviceReplacementDecision =
            serde_json::from_slice(&read(Path::new(&args[4]), 128 * 1024)?)?;
        return print(&owner.device_replacement_status(&decision)?);
    }
    // This bounded private file is operator-selected authority. Device exports
    // cannot choose their account root, predecessor set, policy or approved head.
    let trust: DeviceReplacementTrust =
        serde_json::from_slice(&read(Path::new(&args[4]), 8 * 1024 * 1024)?)?;
    let request: EnrollmentRequest = serde_json::from_slice(&read(Path::new(&args[5]), 8192)?)?;
    if command == "replacement-prepare" {
        let directory = Path::new(&args[6]);
        export_directory(directory)?;
        let decision = owner.prepare_device_replacement(&trust, &request, clock()?)?;
        q_periapt_host_store::filesystem::publish_private_bytes(
            &directory.join("device-replacement-decision.json"),
            &serde_json::to_vec(&decision)?,
        )?;
        print(&decision)
    } else {
        let decision: DeviceReplacementDecision =
            serde_json::from_slice(&read(Path::new(&args[6]), 128 * 1024)?)?;
        print(&owner.commit_device_replacement(&trust, &request, &decision, clock()?)?)
    }
}
