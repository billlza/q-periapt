// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native policy-only transactions under separate account and policy approvals.
use super::{
    json,
    operator_io::{identifier, print, read},
    Result, USAGE,
};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Checkpoint, Invitation, RootInfo},
    native_device::{clock, NativeDevice, PolicyRecoveryInputs},
    policy_publisher::{PolicyMaterials, PolicyPins},
    policy_renewal::{checkpoint, Request},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde_json::{json, Value};
use std::{ffi::OsString, path::Path};

fn progress(value: sdk::PolicyRenewalStatus) -> Value {
    match value {
        sdk::PolicyRenewalStatus::Absent => json!({"state":"Absent"}),
        sdk::PolicyRenewalStatus::Pending {
            operation,
            statement,
            target,
        } => {
            json!({"state":"Pending","operation":operation.as_bytes(),"statement":statement,"target":checkpoint(target)})
        }
        sdk::PolicyRenewalStatus::Committed {
            operation,
            statement,
            target,
        } => {
            json!({"state":"Committed","operation":operation.as_bytes(),"statement":statement,"target":checkpoint(target)})
        }
        sdk::PolicyRenewalStatus::AbandonedUncommitted {
            operation,
            statement,
            target,
            reason,
            observed_roster,
            observed_at,
        } => {
            let reason = match reason {
                sdk::PolicyRenewalAbandonment::Expired => "Expired",
                sdk::PolicyRenewalAbandonment::RosterAdvanced => "RosterAdvanced",
            };
            json!({"state":"AbandonedUncommitted","operation":operation.as_bytes(),"statement":statement,"target":checkpoint(target),
                "reason":reason,"observed_roster":Checkpoint::from(observed_roster),"observed_at":observed_at})
        }
    }
}
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|s| s.to_str()).ok_or(USAGE)?;
    let count = match command {
        "policy-status" => 5,
        "policy-request" | "policy-recover" => 9,
        "policy-resolve" => 11,
        "policy-stage" | "policy-adopt" => 15,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let invitation: Invitation = json(&args[4], 16384)?;
    if command == "policy-status" {
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let result = progress(owner.policy_recovery_status()?);
        owner.close();
        return print(&result);
    }
    if command == "policy-resolve" {
        let operation = sdk::PolicyRenewalId::from_trusted_state(identifier(&args[5])?)?;
        let statement = identifier(&args[6])?;
        let original_pins: PolicyPins = json(&args[7], 16384)?;
        let original_materials: PolicyMaterials = json(&args[8], 128 * 1024)?;
        let target_pins: PolicyPins = json(&args[9], 16384)?;
        let target_materials: PolicyMaterials = json(&args[10], 128 * 1024)?;
        let (original, original_witness) =
            original_pins.verify_historical(&original_materials, invitation.family)?;
        let (target, target_witness) =
            target_pins.verify_historical(&target_materials, invitation.family)?;
        if original_witness.is_some() || target_witness.is_some() {
            return Err(
                "Policy-only local commands cannot replace required witness coordination".into(),
            );
        }
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let result =
            progress(owner.resolve_policy(operation, statement, &original, &target, clock()?)?);
        owner.close();
        return print(&result);
    }
    if command == "policy-request" || command == "policy-recover" {
        let operation = sdk::PolicyRenewalId::from_trusted_state(identifier(&args[5])?)?;
        let at = if command == "policy-request" { 6 } else { 7 };
        let pins: PolicyPins = json(&args[at], 16384)?;
        let materials: PolicyMaterials = json(&args[at + 1], 128 * 1024)?;
        let (original, witness) = pins.verify_historical(&materials, invitation.family)?;
        if witness.is_some() {
            return Err(
                "Policy-only local commands cannot replace required witness coordination".into(),
            );
        }
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let result = if command == "policy-request" {
            let request = owner.policy_renewal_request(operation, &original)?;
            publish_private_bytes(Path::new(&args[8]), &serde_json::to_vec(&request)?)?;
            json!({"state":"RequestExported","operation":operation.as_bytes(),"journal":request.scope.journal})
        } else {
            progress(owner.recover_policy(operation, identifier(&args[6])?, &original)?)
        };
        owner.close();
        return print(&result);
    }
    let request: Request = json(&args[5], 64 * 1024)?;
    let account = read(Path::new(&args[6]), sdk::MAX_POLICY_RENEWAL_BYTES)?;
    let authority = read(Path::new(&args[7]), sdk::MAX_POLICY_RENEWAL_BYTES)?;
    let current: RootInfo = json(&args[8], 128 * 1024)?;
    let original_pins: PolicyPins = json(&args[9], 16384)?;
    let original_materials: PolicyMaterials = json(&args[10], 128 * 1024)?;
    let previous_pins: PolicyPins = json(&args[11], 16384)?;
    let previous_materials: PolicyMaterials = json(&args[12], 128 * 1024)?;
    let target_pins: PolicyPins = json(&args[13], 16384)?;
    let target_materials: PolicyMaterials = json(&args[14], 128 * 1024)?;
    let (original, original_witness) =
        original_pins.verify_historical(&original_materials, invitation.family)?;
    let (previous, previous_witness) =
        previous_pins.verify_historical(&previous_materials, invitation.family)?;
    let (target, target_witness) =
        target_pins.verify(&target_materials, invitation.family, clock()?)?;
    if original_witness.is_some() || previous_witness.is_some() || target_witness.is_some() {
        return Err(
            "Policy-only local commands cannot replace required witness coordination".into(),
        );
    }
    let inputs = PolicyRecoveryInputs {
        request: &request,
        account_approval: &account,
        policy_approval: &authority,
        current: &current,
        original: &original,
        previous: &previous,
        target: &target,
    };
    let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
    let result = progress(if command == "policy-stage" {
        owner.stage_policy_recovery(&inputs, clock()?)?
    } else {
        owner.adopt_policy(&inputs, clock()?)?
    });
    owner.close();
    print(&result)
}
