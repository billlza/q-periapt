// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact original P handoff and historical recovery; no issuer or clock override.
use super::{
    json,
    operator_io::{identifier, print},
    Result, USAGE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Invitation, RootInfo},
    native_device::{clock, NativeDevice, PolicyTransitionInputs},
    policy_publisher::{PolicyApprovalInputs, PolicyInput},
    policy_renewal::{checkpoint, witness::Preparation},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde_json::{json, Value};
use std::{ffi::OsString, path::Path};

fn progress(p: Option<sdk::WitnessedPolicyRenewalProgress>) -> Value {
    use sdk::WitnessedPolicyRenewalProgress as P;
    let mut value = match p {
        None => json!({"state":"Absent"}),
        Some(P::AbandonedBeforePreparation {
            operation,
            statement,
            target,
        }) => {
            json!({"state":"AbandonedBeforePreparation","operation":operation.as_bytes(),"statement":statement,"target":checkpoint(target)})
        }
        Some(P::Reserved { proposal, target }) => {
            json!({"state":"Reserved","proposal":URL_SAFE_NO_PAD.encode(proposal.to_bytes()),"binding":proposal.binding(),"target":checkpoint(target)})
        }
        Some(P::Terminal {
            proposal,
            target,
            disposition,
            retired,
        }) => {
            let state = match disposition {
                sdk::WitnessedPolicyRenewalDisposition::Applied => "Applied",
                sdk::WitnessedPolicyRenewalDisposition::Closed => "Closed",
            };
            json!({"state":state,"proposal":URL_SAFE_NO_PAD.encode(proposal.to_bytes()),"binding":proposal.binding(),"target":checkpoint(target),"retired":retired})
        }
    };
    value["schema"] = json!("qperiapt-policy-witness-progress/1");
    value
}
fn history(
    path: &OsString,
    family: [u8; 32],
) -> Result<(sdk::HistoricalSessionPolicy, sdk::AnchorPin)> {
    let input: PolicyInput = json(path, 160 * 1024)?;
    let (policy, pin) = input.pins.verify_historical(&input.materials, family)?;
    Ok((
        policy,
        pin.ok_or("Original policy must require a pinned witness")?,
    ))
}
fn endpoint(value: &OsString) -> Result<std::net::SocketAddr> {
    Ok(value
        .to_str()
        .ok_or("Witness endpoint is not UTF-8")?
        .parse()?)
}
pub(super) fn run(args: &[OsString]) -> Result<()> {
    let command = args.get(1).and_then(|v| v.to_str()).ok_or(USAGE)?;
    let count = match command {
        "policy-witness-status" => 5,
        "policy-witness-request"
        | "policy-witness-recover-preparation"
        | "policy-witness-activate" => 9,
        "policy-witness-prepare" => 10,
        "policy-witness-commit"
        | "policy-witness-observe"
        | "policy-witness-close"
        | "policy-witness-abandon-unprepared" => 8,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let invitation: Invitation = json(&args[4], 16384)?;
    let family = invitation.family;
    let mut owner = NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?;
    let value = match command {
        "policy-witness-status" => progress(owner.witnessed_policy_status()?),
        "policy-witness-request" => {
            let op = sdk::PolicyRenewalId::from_trusted_state(identifier(&args[5])?)?;
            let (original, pin) = history(&args[6], family)?;
            let request =
                owner.witnessed_policy_request(op, &original, pin, endpoint(&args[7])?)?;
            publish_private_bytes(Path::new(&args[8]), &serde_json::to_vec(&request)?)?;
            json!({"state":"RequestExported","operation":op.as_bytes(),"journal":request.scope.journal})
        }
        "policy-witness-prepare" | "policy-witness-commit" => {
            let preparing = command == "policy-witness-prepare";
            let preparation: Option<Preparation> = if preparing {
                None
            } else {
                Some(json(&args[5], 128 * 1024)?)
            };
            let (op, statement, at) = match &preparation {
                None => (
                    sdk::PolicyRenewalId::from_trusted_state(identifier(&args[5])?)?,
                    identifier(&args[6])?,
                    7,
                ),
                Some(p) => {
                    let p = p.as_proposal()?;
                    (p.operation(), p.statement(), 6)
                }
            };
            let selection: PolicyApprovalInputs = json(&args[at], 512 * 1024)?;
            if selection.schema != "qperiapt-policy-approval-inputs/1" || selection.family != family
            {
                return Err("Policy transition selection differs".into());
            }
            let now = clock()?;
            let (original, old_pin) = selection
                .original
                .pins
                .verify_historical(&selection.original.materials, family)?;
            let (previous, previous_pin) = selection
                .previous
                .pins
                .verify_historical(&selection.previous.materials, family)?;
            let (target, pin) =
                selection
                    .target
                    .pins
                    .verify(&selection.target.materials, family, now)?;
            let pin = pin.ok_or("Policy target must require a pinned witness")?;
            if [old_pin, previous_pin]
                .iter()
                .any(|p| p.as_ref().map(|p| p.binding()) != Some(pin.binding()))
            {
                return Err("Selected policies require different witnesses".into());
            }
            let inputs = PolicyTransitionInputs {
                operation: op,
                statement,
                original: &original,
                previous: &previous,
                target: &target,
            };
            let endpoint = endpoint(&args[at + 1])?;
            match preparation {
                None => {
                    let p = owner.prepare_witnessed_policy(&inputs, pin, endpoint, now)?;
                    publish_private_bytes(Path::new(&args[at + 2]), &serde_json::to_vec(&p)?)?;
                    serde_json::to_value(p)?
                }
                Some(p) => serde_json::to_value(
                    owner.commit_witnessed_policy(&p, &inputs, pin, endpoint, now)?,
                )?,
            }
        }
        "policy-witness-recover-preparation" | "policy-witness-abandon-unprepared" => {
            let op = sdk::PolicyRenewalId::from_trusted_state(identifier(&args[5])?)?;
            let statement = identifier(&args[6])?;
            let (original, _) = history(&args[7], family)?;
            if command == "policy-witness-abandon-unprepared" {
                progress(Some(
                    owner.abandon_unprepared_policy(op, statement, &original)?,
                ))
            } else {
                match owner.recover_witnessed_policy_preparation(op, statement, &original)? {
                    None => {
                        json!({"state":"NoLocalPreparation","operation":op.as_bytes(),"statement":statement})
                    }
                    Some(p) => {
                        publish_private_bytes(Path::new(&args[8]), &serde_json::to_vec(&p)?)?;
                        serde_json::to_value(p)?
                    }
                }
            }
        }
        "policy-witness-activate" => {
            let current: RootInfo = json(&args[5], 128 * 1024)?;
            let (original, old_pin) = history(&args[6], family)?;
            let target: PolicyInput = json(&args[7], 160 * 1024)?;
            let now = clock()?;
            let (target, pin) = target.pins.verify(&target.materials, family, now)?;
            let pin = pin.ok_or("Policy activation requires a witness")?;
            if old_pin.binding() != pin.binding() {
                return Err("Policy witness changed".into());
            }
            let mut active = owner.activate_witnessed_policy(
                &current,
                &original,
                &target,
                pin,
                endpoint(&args[8])?,
                now,
            )?;
            let value = json!({"state":"Activated","journal":active.journal()});
            active.close();
            return print(&value);
        }
        "policy-witness-observe" | "policy-witness-close" => {
            let p: Preparation = json(&args[5], 128 * 1024)?;
            let (original, pin) = history(&args[6], family)?;
            serde_json::to_value(owner.reconcile_witnessed_policy(
                &p,
                &original,
                pin,
                endpoint(&args[7])?,
                command == "policy-witness-close",
            )?)?
        }
        _ => return Err(USAGE.into()),
    };
    owner.close();
    print(&value)
}
