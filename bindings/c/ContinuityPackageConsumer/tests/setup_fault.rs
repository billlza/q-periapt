// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native observation of original setup state across installed-consumer sync cuts.
#[path = "setup.rs"]
mod setup;
use q_periapt_continuity_identity_candidate as p;
#[path = "common/setup_state.rs"]
mod state;
use setup::fixture;
use std::{fs, io, path::PathBuf};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn prepare_setup_fault_case() -> Result<()> {
    let (configured, _) = fixture::setup_devices(None, None, None, false, false, false)?;
    for name in ["installation.redb", "journal.redb", "archives.redb"] {
        match fs::symlink_metadata(configured.responder.join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("setup fault fixture already owns durable children".into()),
        }
    }
    Ok(())
}

#[test]
fn inspect_setup_fault_case() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("QPC_TEST_PATH").ok_or("setup path missing")?);
    let label = std::env::var("QPC_TEST_SETUP_OBSERVATION")?;
    if !matches!(label.as_str(), "original" | "observed" | "reconciled") {
        return Err("unknown setup observation".into());
    }
    state::inspect(&root, &label, None)
}
