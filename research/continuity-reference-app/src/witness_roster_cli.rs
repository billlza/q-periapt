// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted local R approval/closure; the device performs signed commit/recovery.
use super::{
    operator_io::{identifier, print, read, Result},
    USAGE,
};
use q_periapt_continuity_reference_app::{
    native_device::clock,
    roster_refresh::Request,
    witness::{RosterRefreshTrust, Witness},
};
use std::{ffi::OsString, path::Path};
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|v| v.to_str()).ok_or(USAGE)?;
    if args.len() != 6 || !matches!(command, "roster-prepare" | "roster-close") {
        return Err(USAGE.into());
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() {
        return Err("Witness host path must be absolute".into());
    }
    let trust: RosterRefreshTrust =
        serde_json::from_slice(&read(Path::new(&args[4]), 512 * 1024)?)?;
    let request: Request = serde_json::from_slice(&read(Path::new(&args[5]), 128 * 1024)?)?;
    let mut owner = Witness::open(path, identifier(&args[3])?)?;
    print(&if command == "roster-prepare" {
        owner.prepare_roster_refresh(&trust, &request, clock()?)?
    } else {
        owner.close_roster_refresh(&trust, &request)?
    })
}
