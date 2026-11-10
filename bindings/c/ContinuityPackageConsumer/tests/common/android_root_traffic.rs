// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicitly approved new account peer on the unchanged native receiver.
use crate::{
    android_credential_traffic, android_roster_traffic::Case, fixture, p, peer_bundle,
    receiver_process, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{ffi::OsString, fs, net::SocketAddr};
fn receiver(
    case: &Case<'_>,
    mode: &str,
    session: Option<[u8; 32]>,
) -> Result<(receiver_process::Server, SocketAddr)> {
    let remote = case.reference.responder.as_path();
    let mut args: Vec<OsString> = vec![
        "--witness".into(),
        fs::read_to_string(case.inputs.join("witness-address"))?.into(),
        "--enrollment-parent".into(),
        remote.as_os_str().into(),
        "2".into(),
    ];
    if let Some(id) = session {
        args.extend(["--session".into(), fixture::hex(&id).into()]);
    }
    args.extend(["serve".into(), remote.as_os_str().into(), mode.into()]);
    receiver_process::start_selected(
        &android_credential_traffic::executable()?,
        None,
        case.base,
        &format!("root-target-{mode}"),
        &args,
    )
}
pub(crate) fn exercise(
    case: &Case<'_>,
    root: &p::RootSigningKey,
    certificate: &[u8],
    roster: &p::IssuedRoster,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    let inputs = case.inputs.join("root-target");
    peer_bundle::peer_bundle_at_revision(
        &case.reference.responder,
        &inputs.join("peer"),
        root,
        certificate,
        roster,
        case.witness,
        3,
    )?;
    publish_private_bytes(
        &inputs.join("connection-initiation"),
        p::InitiationId::generate()?.as_bytes(),
    )?;
    let (server, address) = receiver(case, "bootstrap", None)?;
    publish_private_bytes(
        &inputs.join("connection-address"),
        address.to_string().as_bytes(),
    )?;
    let session: [u8; 32] = run("root-peer-connect", "root-connected")?
        .try_into()
        .map_err(|_| "root session width")?;
    android_credential_traffic::received(server, 0, Some((session, [0; 32])))?;
    assert_ne!(
        session,
        fixture::array::<32>(case.inputs, "connection-session")?
    );
    publish_private_bytes(&inputs.join("connection-session"), &session)?;
    let (server, address) = receiver(case, "crash-after", Some(session))?;
    fs::write(inputs.join("connection-address"), address.to_string())?;
    let unknown = run("root-peer-uncertain", "root-unknown")?;
    android_credential_traffic::received(server, 77, None)?;
    assert_eq!(unknown.len(), 64);
    assert_eq!(unknown.get(..32).ok_or("root session")?, session);
    let message: [u8; 32] = unknown.get(32..).ok_or("root message")?.try_into()?;
    assert_ne!(
        message,
        fixture::array::<32>(case.inputs, "connection-message")?
    );
    publish_private_bytes(&inputs.join("connection-message"), &message)?;
    let effect_path = case
        .reference
        .responder
        .join(format!("application-{}", fixture::hex(&message)));
    let before = fs::read(&effect_path)?;
    assert_eq!(
        before,
        [unknown.as_slice(), b"persisted before process exit"].concat()
    );
    publish_private_bytes(&case.base.join("root-effect-before"), &before)?;
    let (server, address) = receiver(case, "message", Some(session))?;
    fs::write(inputs.join("connection-address"), address.to_string())?;
    assert_eq!(run("root-peer-retry", "root-acknowledged")?, unknown);
    android_credential_traffic::received(server, 0, Some((session, message)))?;
    let after = fs::read(effect_path)?;
    assert_eq!(after, before);
    publish_private_bytes(&case.base.join("root-effect-after"), &after)?;
    let count = fs::read_dir(&case.reference.responder)?
        .collect::<std::io::Result<Vec<_>>>()?
        .iter()
        .filter(|e| e.file_name().to_string_lossy().starts_with("application-"))
        .count();
    assert_eq!(count, 2);
    publish_private_bytes(&case.base.join("root-effect-count"), &2u64.to_be_bytes())?;
    Ok(())
}
