// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real installed C whole-account cleanup fixtures and independent native readback.
#[path = "common/account_cleanup.rs"]
mod common;
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
use common::{bytes_id, client};
use q_periapt_continuity_identity_candidate as p;
use std::path::PathBuf;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn selected() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("QPC_TEST_PATH").ok_or("original account path missing")?,
    ))
}

#[test]
fn prepare_account_cleanup_case() -> Result<()> {
    let (setup, second) = fixture::setup_devices(None, None, None, true, false)?;
    let second = second.ok_or("second account member")?;
    let root = &setup.initiator;
    let peer_paths = [root.join("peer-0"), root.join("peer-1")];
    let (mut server0, address0) = fixture::spawn(&setup.responder, 90, "bootstrap")?;
    let (mut server1, address1) = fixture::spawn(&second, 91, "bootstrap")?;
    let args = vec![
        "account-connect".into(),
        root.as_os_str().to_owned(),
        peer_paths
            .first()
            .ok_or("peer zero")?
            .as_os_str()
            .to_owned(),
        peer_paths.get(1).ok_or("peer one")?.as_os_str().to_owned(),
        address0.to_string().into(),
        address1.to_string().into(),
        fixture::hex(p::InitiationId::generate()?.as_bytes()).into(),
        fixture::hex(p::InitiationId::generate()?.as_bytes()).into(),
    ];
    let output = client(root, "connect", &args)?;
    assert!(fixture::wait(&mut server0)?.success());
    assert!(fixture::wait(&mut server1)?.success());
    let sessions = output.lines().map(bytes_id).collect::<Result<Vec<_>>>()?;
    assert_eq!(sessions.len(), 2);
    common::prepare(&setup, &second, None, sessions)
}

#[test]
fn observe_account_cleanup_case() -> Result<()> {
    common::observe(&selected()?, None)
}

#[test]
fn revoke_account_cleanup_case() -> Result<()> {
    common::revoke(&selected()?)
}

#[test]
fn compare_account_cleanup_report() -> Result<()> {
    common::compare(&selected()?, None)
}

#[test]
fn verify_account_cleanup_terminal() -> Result<()> {
    common::terminal(&selected()?, None)
}
