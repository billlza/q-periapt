// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit original G commands; successful output follows owner closure.
use super::{
    json,
    operator_io::{identifier, print},
    Result, USAGE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate::CredentialRenewalStatus;
use q_periapt_continuity_reference_app::{
    credential_grant::{CredentialGrantRequest, IssuedCredentialGrant},
    enrollment::{Checkpoint, Invitation, RootInfo},
    native_device::{clock, CredentialRecoveryInputs, NativeDevice},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde_json::{json, Value};
use std::{ffi::OsString, path::Path};

fn progress(value: CredentialRenewalStatus) -> Value {
    match value {
        CredentialRenewalStatus::Absent => json!({"state":"Absent"}),
        CredentialRenewalStatus::Pending {
            operation,
            statement,
        } => json!({"state":"Pending","operation":operation.as_bytes(),"statement":statement}),
        CredentialRenewalStatus::Committed {
            operation,
            statement,
            target,
        } => {
            json!({"state":"Committed","operation":operation.as_bytes(),"statement":statement,"target":Checkpoint::from(target)})
        }
        CredentialRenewalStatus::Closed {
            operation,
            statement,
            target,
        } => {
            json!({"state":"Closed","operation":operation.as_bytes(),"statement":statement,"target":Checkpoint::from(target)})
        }
        CredentialRenewalStatus::ExpiredUncommitted {
            operation,
            statement,
            observed_head,
            observed_at,
        } => {
            json!({"state":"ExpiredUncommitted","operation":operation.as_bytes(),"statement":statement,"observed_head":Checkpoint::from(observed_head),"observed_at":observed_at})
        }
    }
}
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|s| s.to_str()).ok_or(USAGE)?;
    let count = match command {
        "renewal-status" => 5,
        "renewal-reconcile-expired" => 8,
        "renewal-witness-observe" => 10,
        "renewal-stage" | "renewal-activate" => 13,
        "renewal-witness-prepare" => 14,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let invitation: Invitation = json(&args[4], 16384)?;
    if command == "renewal-status" {
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let result = progress(owner.credential_recovery_status()?);
        owner.close();
        return print(&result);
    }
    if command == "renewal-reconcile-expired" {
        let issued: IssuedCredentialGrant = json(&args[5], 128 * 1024)?;
        let pins: PolicyPins = json(&args[6], 16384)?;
        let materials: PolicyMaterials = json(&args[7], 128 * 1024)?;
        let (policy, witness) = pins.verify(&materials, invitation.family, clock()?)?;
        if witness.is_some() {
            return Err("Required witness outcomes need independent witness reconciliation".into());
        }
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let result =
            progress(owner.reconcile_expired_credential_recovery(&issued, &policy, clock()?)?);
        owner.close();
        return print(&result);
    }
    if command == "renewal-witness-observe" {
        let operation =
            q_periapt_continuity_identity_candidate::CredentialRenewalId::from_trusted_state(
                identifier(&args[5])?,
            )?;
        let statement = identifier(&args[6])?;
        let pins: PolicyPins = json(&args[7], 16384)?;
        let materials: PolicyMaterials = json(&args[8], 128 * 1024)?;
        let (original, witness) = pins.verify_historical(&materials, invitation.family)?;
        let witness =
            witness.ok_or("Original policy must require an independently pinned witness")?;
        let endpoint = args[9]
            .to_str()
            .ok_or("Witness endpoint is not UTF-8")?
            .parse()?;
        let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
        let result = progress(owner.observe_credential_recovery(
            operation,
            statement,
            &original,
            witness,
            endpoint,
            clock()?,
        )?);
        owner.close();
        return print(&result);
    }
    let approval: CredentialGrantRequest = json(&args[5], 64 * 1024)?;
    let issued: IssuedCredentialGrant = json(&args[6], 128 * 1024)?;
    let current: RootInfo = json(&args[7], 128 * 1024)?;
    let original_pins: PolicyPins = json(&args[8], 16384)?;
    let original_materials: PolicyMaterials = json(&args[9], 128 * 1024)?;
    let pins: PolicyPins = json(&args[10], 16384)?;
    let materials: PolicyMaterials = json(&args[11], 128 * 1024)?;
    let (original, _) = original_pins.verify_historical(&original_materials, invitation.family)?;
    let (policy, witness) = pins.verify(&materials, invitation.family, clock()?)?;
    let endpoint = match args[12].to_str().ok_or("Witness endpoint is not UTF-8")? {
        "none" => None,
        value => Some(value.parse()?),
    };
    if witness.is_some() != endpoint.is_some()
        || original.anchor_requirement() != policy.anchor_requirement()
        || (command == "renewal-witness-prepare" && witness.is_none())
    {
        return Err("Credential recovery requires the exact witness configuration".into());
    }
    let inputs = CredentialRecoveryInputs {
        approval: &approval,
        issued: &issued,
        current: &current,
        original_policy: &original,
        policy: &policy,
    };
    let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
    let result = match command {
        "renewal-stage" => {
            let result = progress(owner.stage_credential_recovery(&inputs, clock()?)?);
            owner.close();
            result
        }
        "renewal-witness-prepare" => {
            let proposal = owner.prepare_credential_recovery_witness(
                &inputs,
                witness.ok_or("Witness pin is required")?,
                endpoint.ok_or("Witness endpoint is required")?,
                clock()?,
            )?;
            let result = json!({"schema":"qperiapt-credential-witness-proposal/1","operation":approval.retained.operation,
                "journal":approval.retained.journal,"proposal":URL_SAFE_NO_PAD.encode(proposal.to_bytes())});
            publish_private_bytes(Path::new(&args[13]), &serde_json::to_vec(&result)?)?;
            owner.close();
            json!({"state":"RequiresWitnessApproval","operation":approval.retained.operation,"journal":approval.retained.journal})
        }
        "renewal-activate" => {
            let mut active =
                owner.activate_credential_recovery(&inputs, witness, endpoint, clock()?)?;
            let result = json!({"state":"Active","operation":approval.retained.operation,"statement":issued.statement,
                "journal":active.journal(),"checkpoint":issued.checkpoint});
            active.close();
            result
        }
        _ => return Err(USAGE.into()),
    };
    print(&result)
}
