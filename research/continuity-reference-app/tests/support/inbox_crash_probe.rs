// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Isolated qualification process. No barrier is compiled into a product entry point.
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Invitation, RootInfo},
    native_device::{clock, ExchangeOperation, Mailbox, NativeDevice, PeerTrust},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use q_periapt_host_store::filesystem::{open_private_file, publish_private_bytes};
use sdk::session_exchange::Consumer;
use serde::de::DeserializeOwned;
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = open_private_file(path, false)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("Probe input bound".into());
    }
    Ok(bytes)
}
fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read(path, 128 * 1024)?)?)
}
fn path<'a>(input: &'a serde_json::Value, name: &str) -> Result<&'a Path> {
    Ok(Path::new(
        input
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or("Probe path field")?,
    ))
}
fn barrier(marker: &Path, stage: &str) -> io::Result<()> {
    let bytes = format!("{} {}\n", std::process::id(), stage);
    publish_private_bytes(marker, bytes.as_bytes()).map_err(|e| io::Error::other(e.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Parent did not kill the selected probe",
    ))
}
struct CutConsumer {
    inbox: Mailbox,
    stage: String,
    marker: PathBuf,
    calls: usize,
}
impl Consumer for CutConsumer {
    fn commit(&mut self, session: [u8; 32], delivery: &sdk::CommittedPlaintext) -> io::Result<()> {
        if self.calls != 0 {
            return Err(io::Error::other("Probe consumer called more than once"));
        }
        self.calls += 1;
        if self.stage == "before-effect" {
            barrier(&self.marker, &self.stage)?;
        }
        self.inbox.commit(session, delivery)?;
        if self.stage == "after-effect" {
            barrier(&self.marker, &self.stage)?;
        }
        Ok(())
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("inbox-crash-probe <invocation-json> <stage> <new-marker>".into());
    }
    let stage = args[2].to_str().ok_or("Probe stage is not UTF-8")?;
    if !matches!(
        stage,
        "before-effect" | "after-effect" | "after-consumption"
    ) {
        return Err("Unknown probe stage".into());
    }
    let input: serde_json::Value = json(Path::new(&args[1]))?;
    if input.get("schema").and_then(|v| v.as_str()) != Some("qperiapt-native-exchange/1")
        || input.get("witness_endpoint").and_then(|v| v.as_str()) != Some("none")
    {
        return Err("Probe requires explicit local exchange schema".into());
    }
    let operation: ExchangeOperation =
        serde_json::from_value(input.get("operation").ok_or("Probe operation")?.clone())?;
    if !matches!(operation, ExchangeOperation::Message { .. }) {
        return Err("Probe requires a message operation".into());
    }
    let invitation: Invitation = json(path(&input, "invitation")?)?;
    let current: RootInfo = json(path(&input, "current_root")?)?;
    let pins: PolicyPins = json(path(&input, "policy_pins")?)?;
    let materials: PolicyMaterials = json(path(&input, "policy_materials")?)?;
    let (policy, witness) = pins.verify(&materials, invitation.family, clock()?)?;
    if witness.is_some() {
        return Err("Probe does not downgrade a required witness".into());
    }
    let trust: PeerTrust = json(path(&input, "peer_trust")?)?;
    let bundle = sdk::BootstrapBundle::from_bytes(&read(
        path(&input, "bundle")?,
        sdk::MAX_BOOTSTRAP_BUNDLE_BYTES,
    )?)?;
    let request = read(
        path(&input, "request")?,
        sdk::contract::MAX_CONNECTION_FRAME_BYTES,
    )?;
    let owner = NativeDevice::open(
        path(&input, "device_directory")?,
        path(&input, "wrapping_key")?,
        invitation,
    )?;
    let mut active = owner.activate(&current, &policy, None, None, clock()?)?;
    let mut consumer = CutConsumer {
        inbox: Mailbox::open(path(&input, "inbox")?, active.journal())?,
        stage: stage.to_owned(),
        marker: PathBuf::from(&args[3]),
        calls: 0,
    };
    let _response = active.exchange(
        &trust,
        &bundle,
        Arc::new(policy),
        &operation,
        &request,
        &mut consumer,
    )?;
    if stage != "after-consumption" || consumer.calls != 1 {
        return Err("Probe did not cross the intended effect boundary".into());
    }
    barrier(&consumer.marker, stage)?;
    Err("Probe unexpectedly returned".into())
}
