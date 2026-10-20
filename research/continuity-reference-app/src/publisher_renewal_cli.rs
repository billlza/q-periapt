// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact operator selections, separate from untrusted device-request files.
use super::{identifier, print, read, Result, USAGE};
use q_periapt_continuity_reference_app::{
    enrollment::RootInfo,
    policy_publisher::{Publisher, RenewalRequest, RenewalStatus},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{ffi::OsString, path::Path};

pub(super) fn run(mut owner: Publisher, args: &[OsString]) -> Result<()> {
    let command = args[1].to_str().ok_or(USAGE)?;
    if command == "renewal-policies" {
        let inputs = owner.renewal_inputs(
            identifier(&args[4])?,
            identifier(&args[5])?,
            identifier(&args[6])?,
        )?;
        publish_private_bytes(Path::new(&args[7]), &serde_json::to_vec(&inputs)?)?;
        drop(owner);
        return print(&serde_json::json!({"state":"PolicyInputsExported"}));
    }
    if command == "renewal-enable" {
        owner.enable_renewals()?;
        drop(owner);
        return print(&serde_json::json!({"state":"RenewalsEnabled","schema":2}));
    }
    let request = RenewalRequest {
        retained: serde_json::from_slice(&read(Path::new(&args[4]), 64 * 1024)?)?,
        original_publication: identifier(&args[6])?,
        previous_publication: identifier(&args[7])?,
        target_publication: identifier(&args[8])?,
    };
    let account: RootInfo = serde_json::from_slice(&read(Path::new(&args[5]), 128 * 1024)?)?;
    let status = match command {
        "renewal-approve" => {
            let result = owner.approve_renewal(&request, &account)?;
            // A failed exclusive export can follow a durable signature. Retry
            // the exact selection with another output path, never another ID.
            publish_private_bytes(Path::new(&args[9]), &result.approval)?;
            RenewalStatus::Issued { result }
        }
        "renewal-status" => owner.renewal_status(&request, &account)?,
        "renewal-cancel" => {
            owner.cancel_renewal(&request, &account)?;
            owner.renewal_status(&request, &account)?
        }
        _ => return Err(USAGE.into()),
    };
    drop(owner);
    print(&status)
}
