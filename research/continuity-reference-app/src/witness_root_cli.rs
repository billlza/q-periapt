// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local independently authorized root cutover. Never exposed by the TCP handler.
use super::operator_io::{export_directory, identifier, print, read, Result};
use q_periapt_continuity_reference_app::{
    native_device::clock,
    witness::{
        AccountRootDecision, AccountRootFreeze, AccountRootPlan, AccountRootTrust,
        EnrollmentRequest, Witness,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use std::{ffi::OsString, path::Path};

pub(super) const USAGE: &str = concat!(
    "q-periapt-continuity-witness <root-command> <absolute-host-db> <retained-witness-identity> ...\n",
    "root-plan: <independently-approved-trust-json> <successor-preparation-json> <empty-private-output-directory>\n",
    "root-freeze/root-plan-close: <independently-retained-plan-json> <empty-private-output-directory>\n",
    "root-bind: <same-trust> <same-preparation> <same-plan> <signed-freeze-json> <empty-private-output-directory>\n",
    "root-replan: <new-approved-trust> <new-preparation> <original-closed-plan> <original-signed-freeze> <empty-private-output-directory>\n",
    "root-commit: <same-trust> <same-preparation> <same-plan> <signed-freeze-json> <retained-decision-json> <empty-private-output-directory>\n",
    "root-status/root-close: <retained-decision-json> <empty-private-output-directory>\n",
    "Freeze/closure/commit are trusted local approvals. Retain original inputs after errors; no command reactivates old authority."
);

fn input<T: DeserializeOwned>(path: &OsString, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read(Path::new(path), maximum)?)?)
}
fn export(value: &impl Serialize, path: &OsString, filename: &str) -> Result<()> {
    let directory = Path::new(path);
    export_directory(directory)?;
    q_periapt_host_store::filesystem::publish_private_bytes(
        &directory.join(filename),
        &serde_json::to_vec(value)?,
    )?;
    print(value)
}

pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|s| s.to_str()).ok_or(USAGE)?;
    let count = match command {
        "root-plan" => 7,
        "root-freeze" | "root-status" | "root-close" | "root-plan-close" => 6,
        "root-bind" | "root-replan" => 9,
        "root-commit" => 10,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() {
        return Err("Witness host path must be absolute".into());
    }
    // Validate the output directory before any mutation. Publication can still
    // fail after commit; use a fresh output directory to recover the same input.
    export_directory(Path::new(&args[count - 1]))?;
    let mut owner = Witness::open(path, identifier(&args[3])?)?;
    if matches!(command, "root-freeze" | "root-plan-close") {
        let plan: AccountRootPlan = input(&args[4], 32 * 1024)?;
        return if command == "root-freeze" {
            export(
                &owner.freeze_account_root(&plan)?,
                &args[5],
                "account-root-freeze.json",
            )
        } else {
            export(
                &owner.close_account_root_plan(&plan)?,
                &args[5],
                "account-root-plan-outcome.json",
            )
        };
    }
    if matches!(command, "root-status" | "root-close") {
        let decision: AccountRootDecision = input(&args[4], 512 * 1024)?;
        let value = if command == "root-status" {
            owner.account_root_replacement_status(&decision)?
        } else {
            owner.close_account_root_replacement(&decision)?
        };
        return export(&value, &args[5], "account-root-outcome.json");
    }
    let trust: AccountRootTrust = input(&args[4], 512 * 1024)?;
    let request: EnrollmentRequest = input(&args[5], 8192)?;
    if command == "root-plan" {
        return export(
            &owner.plan_account_root_replacement(&trust, &request, clock()?)?,
            &args[6],
            "account-root-plan.json",
        );
    }
    let plan: AccountRootPlan = input(&args[6], 32 * 1024)?;
    let frozen: AccountRootFreeze = input(&args[7], 512 * 1024)?;
    if command == "root-replan" {
        return export(
            &owner.replan_frozen_account_root(&trust, &request, &plan, &frozen, clock()?)?,
            &args[8],
            "account-root-plan.json",
        );
    }
    if command == "root-bind" {
        export(
            &owner.bind_account_root_replacement(&trust, &request, &plan, &frozen, clock()?)?,
            &args[8],
            "account-root-decision.json",
        )
    } else {
        let decision: AccountRootDecision = input(&args[8], 512 * 1024)?;
        export(
            &owner.commit_account_root_replacement(
                &trust,
                &request,
                &plan,
                &frozen,
                &decision,
                clock()?,
            )?,
            &args[9],
            "account-root-outcome.json",
        )
    }
}
