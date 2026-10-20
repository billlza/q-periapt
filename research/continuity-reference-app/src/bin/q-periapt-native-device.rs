// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual-time local consumer; host approval and trust distribution are external.
use q_periapt_continuity_identity_candidate::{InstallationPreparation, JournalKey};
use q_periapt_continuity_reference_app::{
    enrollment::{
        CredentialExtensionRequest, Invitation, IssuedCredentialExtension, IssuedEnrollment,
        RootInfo,
    },
    native_device::{clock, NativeDevice, PublicationPlan},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde::de::DeserializeOwned;
use std::{ffi::OsString, path::Path};
#[path = "../native_policy_cli.rs"]
mod native_policy_cli;
#[path = "../native_renewal_cli.rs"]
mod native_renewal_cli;
#[path = "../operator_io.rs"]
mod operator_io;
use operator_io::{export_directory, identifier, print, read};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const USAGE: &str = concat!(
    "Usage: q-periapt-native-device provision-key <absolute-key-file>\n",
    "Or: <begin|status|request|accept|extend|prepare|activate|refresh-roster|publication-next|publish|renewal-request> ",
    "<absolute-device-dir> <absolute-key-file> <original-invitation-json> [arguments]\n",
    "request: <new-request-output>\n",
    "renewal-request: <retained-renewal-id> <original-policy-pins-json> ",
    "<original-policy-materials-json> <witness-address-or-none> <new-request-output>\n",
    "policy-status: no extra arguments (historical progress only)\n",
    "policy-request: <original-policy-operation> <original-policy-pins> <original-policy-materials> <new-request-output>\n",
    "policy-stage/policy-adopt: <retained-request> <account-approval> <policy-approval> <current-root> ",
    "<original-pins> <original-materials> <previous-pins> <previous-materials> <target-pins> <target-materials>\n",
    "policy-recover: <original-policy-operation> <original-statement> <original-policy-pins> <original-policy-materials>\n",
    "policy-resolve: <original-policy-operation> <original-statement> <original-pins> <original-materials> <target-pins> <target-materials>\n",
    "renewal-status: no extra arguments (historical progress only)\n",
    "renewal-reconcile-expired: <issued-grant-json> <unchanged-live-policy-pins-json> ",
    "<unchanged-live-policy-materials-json> (local-only retained outcome, no activation)\n",
    "renewal-witness-observe: <original-operation-base64url> <original-statement-base64url> ",
    "<original-policy-pins-json> <original-policy-materials-json> <witness-address>\n",
    "renewal-stage/renewal-activate/renewal-witness-prepare: <approved-grant-request-json> ",
    "<issued-grant-json> <current-root-json> <original-policy-pins-json> ",
    "<original-policy-materials-json> <current-policy-pins-json> <current-policy-materials-json> ",
    "<witness-address-or-none> [new-proposal-output for renewal-witness-prepare]\n",
    "accept: <issued-json> <current-root-json> <policy-pins-json> <policy-materials-json>\n",
    "extend: <approved-extension-json> <issued-extension-json> ",
    "<current-root-json> <policy-pins-json> <policy-materials-json>\n",
    "prepare/refresh-roster: <current-root-json> <policy-pins-json> <policy-materials-json>\n",
    "activate/publication-next: <current-root-json> <policy-pins-json> ",
    "<policy-materials-json> <witness-address-or-none>\n",
    "publish: <current-root-json> <policy-pins-json> <policy-materials-json> ",
    "<witness-address-or-none> <retained-publication-id> <plan-json> <existing-empty-private-export-dir>\n",
    "Existing private directories and independently supplied trust are required. ",
    "No signup, issuer or clock override.",
);
fn json<T: DeserializeOwned>(path: &OsString, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read(Path::new(path), maximum)?)?)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let command = args.get(1).and_then(|v| v.to_str()).ok_or(USAGE)?;
    if matches!(
        command,
        "policy-request"
            | "policy-status"
            | "policy-stage"
            | "policy-adopt"
            | "policy-recover"
            | "policy-resolve"
    ) {
        return native_policy_cli::run(&args);
    }
    if matches!(
        command,
        "renewal-status"
            | "renewal-stage"
            | "renewal-activate"
            | "renewal-witness-prepare"
            | "renewal-reconcile-expired"
            | "renewal-witness-observe"
    ) {
        return native_renewal_cli::run(&args);
    }
    if command == "provision-key" {
        if args.len() != 3 {
            return Err(USAGE.into());
        }
        drop(JournalKey::provision(Path::new(&args[2]))?);
        println!("Host wrapping key provisioned; retain this exact file separately from journal backups.");
        return Ok(());
    }
    let expected = match command {
        "begin" | "status" => 5,
        "request" => 6,
        "accept" => 9,
        "extend" => 10,
        "renewal-request" => 10,
        "prepare" | "refresh-roster" => 8,
        "activate" | "publication-next" => 9,
        "publish" => 12,
        _ => return Err(USAGE.into()),
    };
    if args.len() != expected {
        return Err(USAGE.into());
    }
    let publication_inputs = if command == "publish" {
        let id = identifier(&args[9])?;
        let plan: PublicationPlan = json(&args[10], 16384)?;
        let plan = plan.verify(clock()?)?;
        export_directory(Path::new(&args[11]))?;
        Some((id, plan))
    } else {
        None
    };
    let invitation: Invitation = json(&args[4], 16384)?;
    let family = invitation.family;
    let mut owner = if command == "begin" {
        NativeDevice::begin(
            Path::new(&args[2]),
            Path::new(&args[3]),
            invitation,
            clock()?,
        )?
    } else {
        NativeDevice::open(Path::new(&args[2]), Path::new(&args[3]), invitation)?
    };
    match command {
        "begin" | "status" => return print(&owner.status()?),
        "request" => {
            let bytes = owner.request(clock()?)?;
            publish_private_bytes(Path::new(&args[5]), &bytes)?;
            return print(&owner.status()?);
        }
        "renewal-request" => {
            let operation = identifier(&args[5])?;
            let pins: PolicyPins = json(&args[6], 16384)?;
            let materials: PolicyMaterials = json(&args[7], 128 * 1024)?;
            let (policy, witness) = pins.verify_historical(&materials, family)?;
            let endpoint = match args[8].to_str().ok_or("Witness endpoint is not UTF-8")? {
                "none" => None,
                text => Some(text.parse()?),
            };
            let request =
                owner.credential_renewal_request(operation, &policy, witness, endpoint)?;
            publish_private_bytes(Path::new(&args[9]), &serde_json::to_vec(&request)?)?;
            owner.close();
            return print(
                &serde_json::json!({"request":"RetainedCredential","operation":request.operation,
                "journal":request.journal,"previous_checkpoint":request.previous_checkpoint}),
            );
        }
        _ => {}
    }
    let at = match command {
        "accept" => 6,
        "extend" => 7,
        _ => 5,
    };
    let current: RootInfo = json(&args[at], 128 * 1024)?;
    let pins: PolicyPins = json(&args[at + 1], 16384)?;
    let materials: PolicyMaterials = json(&args[at + 2], 128 * 1024)?;
    let (policy, witness) = pins.verify(&materials, family, clock()?)?;
    match command {
        "accept" => {
            let issued: IssuedEnrollment = json(&args[5], 128 * 1024)?;
            owner.accept(&issued, &current, &policy, clock()?)?;
            print(&owner.status()?)
        }
        "extend" => {
            let approval: CredentialExtensionRequest = json(&args[5], 16384)?;
            let issued: IssuedCredentialExtension = json(&args[6], 128 * 1024)?;
            owner.extend(&approval, &issued, &current, &policy, clock()?)?;
            print(&owner.status()?)
        }
        "refresh-roster" => {
            owner.refresh_current(&current, &policy, clock()?)?;
            print(&owner.status()?)
        }
        "prepare" => {
            let result = owner.prepare(&current, &policy, clock()?)?;
            match result {
                InstallationPreparation::Local => {
                    print(&serde_json::json!({"preparation":"LocalReady"}))
                }
                InstallationPreparation::RequiresEnrollment(g) => print(
                    &serde_json::json!({"preparation":"RequiresWitnessEnrollment","subject":g.subject().to_bytes(),"head":g.image_digest()}),
                ),
            }
        }
        "activate" | "publication-next" | "publish" => {
            let endpoint = match args[8].to_str().ok_or("Witness endpoint is not UTF-8")? {
                "none" => None,
                text => Some(text.parse()?),
            };
            let mut active = owner.activate(&current, &policy, witness, endpoint, clock()?)?;
            match command {
                "activate" => print(
                    &serde_json::json!({"persisted_phase":"Active","journal":active.journal()}),
                ),
                "publication-next" => {
                    print(&serde_json::json!({"publication":active.next_publication()?}))
                }
                "publish" => {
                    let (id, plan) = publication_inputs
                        .as_ref()
                        .ok_or("Publication inputs were not validated")?;
                    let publication = active.publish(*id, plan, &policy)?;
                    publish_private_bytes(
                        &Path::new(&args[11]).join("publication.json"),
                        &serde_json::to_vec(&publication)?,
                    )?;
                    print(
                        &serde_json::json!({"publication":id,"journal":active.journal(),"prepared":true}),
                    )
                }
                _ => Err(USAGE.into()),
            }
        }
        _ => Err(USAGE.into()),
    }
}
