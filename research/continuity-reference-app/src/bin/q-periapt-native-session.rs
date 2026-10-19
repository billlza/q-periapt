// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One explicit QPCXCH01 exchange. Files are an untrusted opaque carrier.
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Invitation, RootInfo},
    native_device::{clock, ExchangeOperation, Mailbox, NativeDevice, PeerTrust},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
#[path = "../network_service.rs"]
mod network_service;
#[path = "../operator_io.rs"]
mod operator_io;
use operator_io::{export_directory, identifier, print, read};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const USAGE: &str = concat!(
    "q-periapt-native-session provision-inbox <absolute-new-database> <original-journal-base64url> | ",
    "exchange <absolute-invocation-json> | ",
    "serve <absolute-service-json> | ",
    "read-inbox <absolute-database> <journal-base64url> <session-base64url> <message-base64url> <fresh-private-output>"
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    schema: String,
    device_directory: PathBuf,
    wrapping_key: PathBuf,
    invitation: PathBuf,
    current_root: PathBuf,
    policy_pins: PathBuf,
    policy_materials: PathBuf,
    witness_endpoint: String,
    peer_trust: PathBuf,
    bundle: PathBuf,
    operation: ExchangeOperation,
    request: PathBuf,
    inbox: PathBuf,
    output_directory: PathBuf,
}
fn json<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read(path, maximum)?)?)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    match args.get(1).and_then(|v| v.to_str()) {
        Some("provision-inbox") if args.len() == 4 => {
            drop(Mailbox::provision(
                Path::new(&args[2]),
                identifier(&args[3])?,
            )?);
            print(&serde_json::json!({"inbox":"Provisioned"}))
        }
        Some("exchange") if args.len() == 3 => exchange(json(Path::new(&args[2]), 16384)?),
        Some("serve") if args.len() == 3 => network_service::serve(Path::new(&args[2])),
        Some("read-inbox") if args.len() == 7 => {
            let inbox = Mailbox::open(Path::new(&args[2]), identifier(&args[3])?)?;
            let bytes = inbox.delivery(identifier(&args[4])?, identifier(&args[5])?)?;
            publish_private_bytes(Path::new(&args[6]), &bytes)?;
            print(&serde_json::json!({"delivery":"Exported"}))
        }
        _ => Err(USAGE.into()),
    }
}
fn exchange(input: Invocation) -> Result<()> {
    if input.schema != "qperiapt-native-exchange/1" {
        return Err("Unknown exchange schema".into());
    }
    export_directory(&input.output_directory)?;
    let request = read(&input.request, sdk::contract::MAX_CONNECTION_FRAME_BYTES)?;
    let trust: PeerTrust = json(&input.peer_trust, 128 * 1024)?;
    let bundle =
        sdk::BootstrapBundle::from_bytes(&read(&input.bundle, sdk::MAX_BOOTSTRAP_BUNDLE_BYTES)?)?;
    let invitation: Invitation = json(&input.invitation, 16384)?;
    let current: RootInfo = json(&input.current_root, 128 * 1024)?;
    let pins: PolicyPins = json(&input.policy_pins, 16384)?;
    let materials: PolicyMaterials = json(&input.policy_materials, 128 * 1024)?;
    let (policy, witness) = pins.verify(&materials, invitation.family, clock()?)?;
    let endpoint = match input.witness_endpoint.as_str() {
        "none" => None,
        text => Some(text.parse()?),
    };
    if endpoint.is_some() != witness.is_some() {
        return Err("Witness endpoint differs from pinned policy".into());
    }
    let owner = NativeDevice::open(&input.device_directory, &input.wrapping_key, invitation)?;
    let mut active = owner.activate(&current, &policy, witness, endpoint, clock()?)?;
    let mut inbox = Mailbox::open(&input.inbox, active.journal())?;
    let response = active.exchange(
        &trust,
        &bundle,
        Arc::new(policy),
        &input.operation,
        &request,
        &mut inbox,
    )?;
    publish_private_bytes(&input.output_directory.join("response.bin"), &response)?;
    print(&serde_json::json!({"response":"Exported","journal":active.journal()}))
}
