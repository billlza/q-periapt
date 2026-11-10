// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exercise the returned G owner directly, without reopening NativeDevice.
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    credential_grant::{CredentialGrantRequest, IssuedCredentialGrant},
    enrollment::{Invitation, RootInfo},
    native_device::{clock, CredentialRecoveryInputs, NativeDevice, PeerTrust},
    policy_publisher::PolicyInput,
};
use q_periapt_host_store::filesystem::open_private_file;
use serde::{de::DeserializeOwned, Deserialize};
use std::{io::Read, path::Path, path::PathBuf, sync::Arc};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    schema: String,
    device_directory: PathBuf,
    wrapping_key: PathBuf,
    invitation: PathBuf,
    approval: PathBuf,
    issued: PathBuf,
    current_root: PathBuf,
    original_policy: PathBuf,
    target_policy: PathBuf,
    witness_endpoint: std::net::SocketAddr,
    peer_trust: PathBuf,
    bundle: PathBuf,
    session: [u8; 32],
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_private_file(path, false)?
        .take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("Recovery probe input bound".into());
    }
    Ok(bytes)
}
fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read(path, 192 * 1024)?)?)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("credential-recovery-probe <private-invocation-json>".into());
    }
    let input: Invocation = json(Path::new(&args[1]))?;
    if input.schema != "qperiapt-credential-recovery-probe/1" {
        return Err("Unknown recovery probe schema".into());
    }
    let invitation: Invitation = json(&input.invitation)?;
    let approval: CredentialGrantRequest = json(&input.approval)?;
    let issued: IssuedCredentialGrant = json(&input.issued)?;
    let current: RootInfo = json(&input.current_root)?;
    let history: PolicyInput = json(&input.original_policy)?;
    let target: PolicyInput = json(&input.target_policy)?;
    let (original, original_pin) = history
        .pins
        .verify_historical(&history.materials, invitation.family)?;
    let (policy, witness) = target
        .pins
        .verify(&target.materials, invitation.family, clock()?)?;
    let witness = witness.ok_or("Recovery probe requires a witness")?;
    if original_pin.as_ref().map(|pin| pin.binding()) != Some(witness.binding())
        || original.checkpoint() == policy.checkpoint()
    {
        return Err("Recovery probe requires the original witness and a successor policy".into());
    }
    let trust: PeerTrust = json(&input.peer_trust)?;
    let bundle =
        sdk::BootstrapBundle::from_bytes(&read(&input.bundle, sdk::MAX_BOOTSTRAP_BUNDLE_BYTES)?)?;
    let owner = NativeDevice::open(&input.device_directory, &input.wrapping_key, invitation)?;
    let mut active = owner.activate_credential_recovery(
        &CredentialRecoveryInputs {
            approval: &approval,
            issued: &issued,
            companions: None,
            current: &current,
            original_policy: &original,
            policy: &policy,
        },
        Some(witness),
        Some(input.witness_endpoint),
        clock()?,
    )?;
    // Reopening a new NativeDevice would hide loss of the returned owner's P0.
    let session = active.reopen_session(&trust, &bundle, Arc::new(policy), input.session)?;
    let message = active.next_message(&session)?;
    if active.message_status(&session, message)? != sdk::MessageStatus::Absent {
        return Err("Recovered owner did not observe a fresh original-session message".into());
    }
    let journal = active.journal();
    active.close();
    println!(
        "{}",
        serde_json::json!({
            "journal": journal, "session": input.session, "message": message.as_bytes(),
            "status": "Absent", "same_returned_owner": true,
        })
    );
    Ok(())
}
