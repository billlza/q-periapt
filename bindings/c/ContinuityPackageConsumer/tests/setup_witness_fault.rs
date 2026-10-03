// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Keep the original real witness alive across installed-consumer storage faults.
#[path = "setup.rs"]
mod setup;
#[path = "common/setup_state.rs"]
mod state;
use q_periapt_continuity_identity_candidate as p;
use setup::fixture;
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn wait(root: &Path, name: &str, deadline: Instant) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(format!("setup witness deadline waiting for {name}").into());
        }
        match fs::symlink_metadata(root.join(name)) {
            Ok(info) => {
                if !info.file_type().is_file()
                    || info.len() != 1
                    || info.nlink() != 1
                    || info.mode() & 0o777 != 0o600
                    || fixture::read(root, name, 1)? != b"1"
                {
                    return Err("setup witness marker differs".into());
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn counts(
    witness: &setup::witness::Witness,
    tls: Option<&setup::witness_tls::TlsWitness>,
) -> Result<(usize, usize)> {
    let plain = witness
        .captured
        .lock()
        .map_err(|_| "setup witness captures poisoned")?
        .len();
    let encrypted = match tls {
        Some(server) => server.admitted.load(Ordering::Acquire),
        None => 0, // No TLS endpoint exists in the explicitly selected signed-TCP case.
    };
    Ok((plain, encrypted))
}

#[test]
fn hold_original_setup_witness_across_fault() -> Result<()> {
    let carrier = std::env::var("QPC_TEST_SETUP_CARRIER")?;
    if !matches!(carrier.as_str(), "signed-tcp" | "mutual-tls") {
        return Err("unknown setup witness carrier".into());
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut witness = setup::witness::Witness::start()?;
    let (configured, _) =
        fixture::setup_devices(Some(&witness.configured), None, None, false, false, false)?;
    let root = &configured.responder;
    fixture::store(root, "witness-controller-carrier", carrier.as_bytes())?;
    fixture::publish_marker(root, "witness-controller-ready")?;
    wait(root, "witness-controller-storage", deadline)?;

    let mut sdk = fixture::sdk(root)?;
    let policy = fixture::protocol_policy(root, &sdk)?;
    let device = setup::local(root)?;
    let key = p::JournalKey::open(&root.join("wrap.key"))?;
    let mut installation =
        p::DeviceInstallation::open(setup::paths(root)?, &key, &device, &policy, fixture::now()?)?;
    let id = installation.identity()?;
    if installation.status()? != p::InstallationStatus::Creating
        || counts(&witness, None)? != (0, 0)
    {
        return Err("setup did not preserve original unenrolled Creating state".into());
    }
    installation.close();
    let genesis = p::DeviceJournal::recover_anchor_genesis(
        &root.join("journal.redb"),
        key,
        &device,
        &policy,
        id,
    )?;
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "setup witness enrollment poisoned")?
        .enroll(&genesis, &device, &policy, fixture::now()?)?;
    fixture::store(
        root,
        "witness-controller-subject",
        &genesis.subject().to_bytes(),
    )?;
    fixture::store(root, "witness-controller-image", &genesis.image_digest())?;
    fixture::store(root, "witness-subject", &genesis.subject().to_bytes())?;
    policy.close();
    sdk.close();

    let mut tls = if carrier == "mutual-tls" {
        Some(setup::witness_tls::TlsWitness::start(
            Arc::clone(&witness.configured.store),
            [root.as_path()],
        )?)
    } else {
        None
    };
    let address = match &tls {
        Some(server) => server.address,
        None => witness.configured.address,
    };
    fixture::store(
        root,
        "witness-controller-address",
        address.to_string().as_bytes(),
    )?;
    state::inspect(root, "original", Some(witness.configured.client(root)?))?;
    let (plain_before_activation, tls_before_activation) = counts(&witness, tls.as_ref())?;
    fixture::publish_marker(root, "witness-controller-enrolled")?;
    wait(root, "witness-controller-observe", deadline)?;
    let (plain_after_activation, tls_after_activation) = counts(&witness, tls.as_ref())?;
    state::inspect(root, "observed", Some(witness.configured.client(root)?))?;
    let (plain_before_reconciliation, tls_before_reconciliation) = counts(&witness, tls.as_ref())?;
    fixture::publish_marker(root, "witness-controller-observed")?;
    wait(root, "witness-controller-reconciled", deadline)?;
    let (plain_after_reconciliation, tls_after_reconciliation) = counts(&witness, tls.as_ref())?;
    state::inspect(root, "reconciled", Some(witness.configured.client(root)?))?;
    let (plain_total, tls_total) = counts(&witness, tls.as_ref())?;
    match tls.as_mut() {
        Some(server) => {
            if plain_before_activation != plain_after_activation
                || plain_before_reconciliation != plain_after_reconciliation
                || tls_before_activation != 0
                || tls_after_activation != tls_before_reconciliation
                || tls_after_reconciliation != tls_total
                || tls_total == 0
                || !server.finish()?.is_empty()
            {
                return Err("setup TLS observation or carrier isolation differs".into());
            }
        }
        None => {
            if [
                tls_before_activation,
                tls_after_activation,
                tls_before_reconciliation,
                tls_after_reconciliation,
                tls_total,
            ] != [0; 5]
            {
                return Err("signed setup unexpectedly admitted TLS".into());
            }
        }
    }
    witness.join()?;
    let records = witness
        .captured
        .lock()
        .map_err(|_| "setup witness final captures poisoned")?;
    if records.len() != plain_total
        || records.is_empty()
        || records.len() > 128
        || records
            .iter()
            .any(|row| !row.delivered || row.request.len() != 3674 || row.reply.len() != 3659)
    {
        return Err("setup witness transcript incomplete or oversized".into());
    }
    let mut wire = Vec::new();
    for row in records.iter() {
        wire.push(1);
        wire.extend_from_slice(&row.request);
        wire.extend_from_slice(&row.reply);
    }
    fixture::store(root, "witness-controller-transcript", &wire)?;
    fixture::store(root,"witness-controller-result.json",format!(
        "{{\"schema_version\":1,\"completed\":true,\"carrier\":\"{carrier}\",\"plain_before_activation\":{plain_before_activation},\"plain_after_activation\":{plain_after_activation},\"plain_before_reconciliation\":{plain_before_reconciliation},\"plain_after_reconciliation\":{plain_after_reconciliation},\"plain_total\":{plain_total},\"tls_before_activation\":{tls_before_activation},\"tls_after_activation\":{tls_after_activation},\"tls_before_reconciliation\":{tls_before_reconciliation},\"tls_after_reconciliation\":{tls_after_reconciliation},\"tls_total\":{tls_total}}}\n").as_bytes())?;
    fixture::publish_marker(root, "witness-controller-done")?;
    Ok(())
}

#[test]
fn publish_setup_witness_marker() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("QPC_TEST_PATH").ok_or("setup marker path missing")?);
    if !root.is_absolute() {
        return Err("setup marker path must be absolute".into());
    }
    let name = match std::env::var("QPC_TEST_SETUP_MARKER")?.as_str() {
        "storage" => "witness-controller-storage",
        "observe" => "witness-controller-observe",
        "reconciled" => "witness-controller-reconciled",
        _ => return Err("unknown setup marker selection".into()),
    };
    fixture::publish_marker(&root, name)?;
    Ok(())
}
