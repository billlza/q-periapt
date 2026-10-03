// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native observation of original setup state across installed-consumer sync cuts.
#[path = "setup.rs"]
mod setup;
use q_periapt_continuity_identity_candidate as p;
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
    let mut sdk = fixture::sdk(&root)?;
    let policy = fixture::protocol_policy(&root, &sdk)?;
    let device = setup::local(&root)?;
    let key = p::JournalKey::open(&root.join("wrap.key"))?;
    let mut installation = p::DeviceInstallation::open(
        setup::paths(&root)?,
        &key,
        &device,
        &policy,
        fixture::now()?,
    )?;
    let id = installation.identity()?;
    let phase = installation.status()?;
    if (label == "original" && phase != p::InstallationStatus::Creating)
        || (label == "reconciled" && phase != p::InstallationStatus::Active)
    {
        return Err("setup observation crossed its durable phase".into());
    }
    let mut journal = p::DeviceJournal::open(&root.join("journal.redb"), key, &device, id)?;
    let batch = journal.next_fanout_id()?;
    if journal.fanout_status(batch)? != p::FanoutStatus::Absent {
        return Err("setup reserved an account operation".into());
    }
    let mut archives = p::SessionArchiveStore::open(&root.join("archives.redb"), id)?;
    if !archives.session_ids()?.is_empty() {
        return Err("setup released a session archive".into());
    }
    archives.close();
    journal.close();
    installation.close();
    policy.close();
    sdk.close();
    if label == "original" {
        fixture::store(&root, "setup-fault-original-id", id.as_bytes())?;
        fixture::store(&root, "setup-fault-original-batch", batch.as_bytes())?;
    } else {
        if id.as_bytes() != &fixture::array::<32>(&root, "setup-fault-original-id")?
            || batch.as_bytes() != &fixture::array::<32>(&root, "setup-fault-original-batch")?
        {
            return Err(
                "setup interruption replaced its original identity or account position".into(),
            );
        }
    }
    let phase = match phase {
        p::InstallationStatus::Creating => 1,
        p::InstallationStatus::Active => 2,
    };
    fixture::store(
        &root,
        &format!("setup-fault-{label}.json"),
        format!("{{\"schema_version\":1,\"phase\":{phase},\"journal\":\"{}\",\"next_account\":\"{}\",\"account_absent\":true,\"archives_empty\":true}}\n",
            fixture::hex(id.as_bytes()), fixture::hex(batch.as_bytes())).as_bytes(),
    )?;
    Ok(())
}
