// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original native setup observation shared by local and required-witness fixtures.
use crate::{fixture, p, setup, Result};
use std::path::Path;
pub(crate) fn inspect(root: &Path, label: &str, anchor: Option<p::AnchorClient>) -> Result<()> {
    if !matches!(label, "original" | "observed" | "reconciled") {
        return Err("unknown setup observation".into());
    }
    let mut sdk = fixture::sdk(root)?;
    let policy = fixture::protocol_policy(root, &sdk)?;
    let device = setup::local(root)?;
    let key = p::JournalKey::open(&root.join("wrap.key"))?;
    let mut installation =
        p::DeviceInstallation::open(setup::paths(root)?, &key, &device, &policy, fixture::now()?)?;
    let id = installation.identity()?;
    let phase = installation.status()?;
    if (label == "original" && phase != p::InstallationStatus::Creating)
        || (label == "reconciled" && phase != p::InstallationStatus::Active)
    {
        return Err("setup observation crossed its durable phase".into());
    }
    let mut journal = match (policy.anchor_requirement().binding(), anchor) {
        (None, None) => p::DeviceJournal::open(&root.join("journal.redb"), key, &device, id)?,
        (Some(_), Some(client)) => p::DeviceJournal::open_anchored(
            &root.join("journal.redb"),
            key,
            &device,
            &policy,
            id,
            client,
        )?,
        _ => return Err("setup observation witness requirement differs".into()),
    };
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
        fixture::store(root, "setup-fault-original-id", id.as_bytes())?;
        fixture::store(root, "setup-fault-original-batch", batch.as_bytes())?;
    } else {
        if id.as_bytes() != &fixture::array::<32>(root, "setup-fault-original-id")?
            || batch.as_bytes() != &fixture::array::<32>(root, "setup-fault-original-batch")?
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
        root,
        &format!("setup-fault-{label}.json"),
        format!("{{\"schema_version\":1,\"phase\":{phase},\"journal\":\"{}\",\"next_account\":\"{}\",\"account_absent\":true,\"archives_empty\":true}}\n",
            fixture::hex(id.as_bytes()), fixture::hex(batch.as_bytes())).as_bytes(),
    )?;
    Ok(())
}
