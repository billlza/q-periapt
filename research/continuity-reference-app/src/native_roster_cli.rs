// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original own-account R commands; outputs distinguish local progress and history.
use super::{
    json,
    operator_io::{identifier, print},
    Result, USAGE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Checkpoint, Invitation, RootInfo},
    native_device::{clock, NativeDevice, RosterRefreshInputs},
    policy_publisher::PolicyInput,
    roster_refresh::Request,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{ffi::OsString, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    target: RootInfo,
    original: PolicyInput,
    policy: PolicyInput,
}
fn scope(s: sdk::RosterRefreshScope) -> Value {
    json!({"operation":s.operation.as_bytes(),"previous":Checkpoint::from(s.previous),
        "target":Checkpoint::from(s.target),
        "policy":{"version":s.policy.version(),"digest":s.policy.digest()},
        "policy_authorization":s.policy_authorization})
}
fn progress(value: Option<sdk::WitnessedRosterRefreshProgress>) -> Value {
    use sdk::WitnessedRosterRefreshProgress as P;
    let mut result = match value {
        None => json!({"state":"Absent"}),
        Some(P::Staged(s)) => json!({"state":"Staged","scope":scope(s)}),
        Some(P::AbandonedBeforePreparation(s)) => {
            json!({"state":"AbandonedBeforePreparation","scope":scope(s)})
        }
        Some(P::Reserved(p)) => {
            json!({"state":"Reserved","scope":scope(*p.scope()),"binding":p.binding(),"proposal":URL_SAFE_NO_PAD.encode(p.to_bytes())})
        }
        Some(P::Terminal {
            proposal: p,
            disposition,
            retired,
        }) => {
            let state = match disposition {
                sdk::WitnessedRosterRefreshDisposition::Applied => "Applied",
                sdk::WitnessedRosterRefreshDisposition::Closed => "Closed",
            };
            json!({"state":state,"scope":scope(*p.scope()),"binding":p.binding(),"proposal":URL_SAFE_NO_PAD.encode(p.to_bytes()),"retired":retired})
        }
    };
    result["schema"] = json!("qperiapt-roster-refresh-progress/1");
    result
}
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|v| v.to_str()).ok_or(USAGE)?;
    let count = match command {
        "roster-status" => 5,
        "roster-prepare" => 9,
        "roster-recover-preparation" | "roster-commit" | "roster-observe" | "roster-close" => 8,
        "roster-abandon-unprepared" => 7,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let invitation: Invitation = json(&args[4], 16384)?;
    if command == "roster-status" {
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let value = progress(owner.roster_refresh_status()?);
        owner.close();
        return print(&value);
    }
    if matches!(command, "roster-prepare" | "roster-commit") {
        let selection: Selection = json(&args[6], 512 * 1024)?;
        if selection.schema != "qperiapt-roster-refresh-inputs/1" {
            return Err("Roster selection schema differs".into());
        }
        let now = clock()?;
        let (original, old_pin) = selection
            .original
            .pins
            .verify_historical(&selection.original.materials, invitation.family)?;
        let (policy, pin) =
            selection
                .policy
                .pins
                .verify(&selection.policy.materials, invitation.family, now)?;
        let pin = pin.ok_or("Own-account roster coordination requires a pinned witness")?;
        if old_pin.as_ref().map(|p| p.binding()) != Some(pin.binding()) {
            return Err("Roster policies select different witnesses".into());
        }
        let address = args[7]
            .to_str()
            .ok_or("Witness endpoint is not UTF-8")?
            .parse()?;
        let inputs = RosterRefreshInputs {
            target: &selection.target,
            original_policy: &original,
            policy: &policy,
        };
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let value = if command == "roster-prepare" {
            let operation = sdk::RosterRefreshId::from_trusted_state(identifier(&args[5])?)?;
            let request = owner.prepare_roster_refresh(operation, &inputs, pin, address, now)?;
            publish_private_bytes(Path::new(&args[8]), &serde_json::to_vec(&request)?)?;
            serde_json::to_value(request)?
        } else {
            let request: Request = json(&args[5], 128 * 1024)?;
            serde_json::to_value(
                owner.commit_roster_refresh(&request, &inputs, pin, address, now)?,
            )?
        };
        owner.close();
        return print(&value);
    }
    let history: PolicyInput = json(&args[6], 160 * 1024)?;
    let (original, pin) = history
        .pins
        .verify_historical(&history.materials, invitation.family)?;
    let pin = pin.ok_or("Original roster policy must require a witness")?;
    let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
    let value = match command {
        "roster-recover-preparation" => {
            let operation = sdk::RosterRefreshId::from_trusted_state(identifier(&args[5])?)?;
            match owner.recover_roster_refresh_preparation(operation, &original)? {
                Some(request) => {
                    publish_private_bytes(Path::new(&args[7]), &serde_json::to_vec(&request)?)?;
                    serde_json::to_value(request)?
                }
                None => progress(owner.roster_refresh_status()?),
            }
        }
        "roster-abandon-unprepared" => {
            let operation = sdk::RosterRefreshId::from_trusted_state(identifier(&args[5])?)?;
            progress(Some(
                owner.abandon_unprepared_roster_refresh(operation, &original)?,
            ))
        }
        "roster-observe" | "roster-close" => {
            let request: Request = json(&args[5], 128 * 1024)?;
            let endpoint = args[7]
                .to_str()
                .ok_or("Witness endpoint is not UTF-8")?
                .parse()?;
            serde_json::to_value(if command == "roster-observe" {
                owner.observe_roster_refresh(&request, &original, pin, endpoint)?
            } else {
                owner.close_roster_refresh(&request, &original, pin, endpoint)?
            })?
        }
        _ => return Err(USAGE.into()),
    };
    owner.close();
    print(&value)
}
