// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Installed-language setup calls over native independently provisioned enrollment inputs.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
pub(crate) mod fixture;
#[path = "common/witness.rs"]
mod witness;
#[path = "common/witness_tls.rs"]
mod witness_tls;
use q_periapt_continuity_identity_candidate as p;
use std::{
    ffi::OsString,
    fs,
    io::{self, Read},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{atomic::Ordering, Arc},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn language() -> Result<&'static str> {
    match std::env::var("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") {
        Err(std::env::VarError::NotPresent) => Ok("C"),
        Ok(value) if value == "C" => Ok("C"),
        Ok(value) if value == "Swift" => Ok("Swift"),
        Ok(value) if value == "Kotlin" => Ok("Kotlin"),
        _ => Err("unsupported installed setup language".into()),
    }
}

fn run(
    path: &Path,
    label: &str,
    operation: &str,
    refusal: Option<i32>,
    witness: Option<&witness::Witness>,
) -> Result<String> {
    run_at(
        path,
        label,
        operation,
        refusal,
        witness.map(|w| (w.configured.address, false)),
    )
}

fn run_at(
    path: &Path,
    label: &str,
    operation: &str,
    refusal: Option<i32>,
    endpoint: Option<(SocketAddr, bool)>,
) -> Result<String> {
    let executable =
        PathBuf::from(std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C client missing")?);
    if !executable.is_absolute() || !executable.is_file() {
        return Err("setup client must be an absolute existing executable".into());
    }
    let stdout = path.join(format!("setup-{label}.stdout"));
    let stderr = path.join(format!("setup-{label}.stderr"));
    let out = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&stdout)?;
    let err = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&stderr)?;
    let mut args = Vec::<OsString>::new();
    if let Some((address, tls)) = endpoint {
        args.extend([
            if tls { "--witness-tls" } else { "--witness" }.into(),
            address.to_string().into(),
        ]);
    }
    args.extend([
        format!("setup-{operation}").into(),
        path.as_os_str().to_owned(),
    ]);
    if let Some(code) = refusal {
        args.push(code.to_string().into());
    }
    if operation == "cancel" {
        args.push(path.join("setup-cancel-barrier").into_os_string());
    }
    let mut child = fixture::OwnedChild(
        Command::new(executable)
            .args(args)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()?,
    );
    let exit = fixture::wait(&mut child)?;
    let read = |path: &Path| -> Result<Vec<u8>> {
        let mut data = Vec::new();
        fs::File::open(path)?.take(65537).read_to_end(&mut data)?;
        if data.len() > 65536 {
            return Err("setup log exceeded bound".into());
        }
        Ok(data)
    };
    let output = String::from_utf8(read(&stdout)?)?;
    let diagnostic = String::from_utf8(read(&stderr)?)?;
    if !exit.success() || !diagnostic.is_empty() {
        return Err(format!("setup command failed: {exit}: {diagnostic}").into());
    }
    if let Some(code) = refusal {
        assert_eq!(output, format!("setup-refused:{code}\n"));
    }
    Ok(output)
}

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("unexpected setup state already exists".into()),
    }
}

fn status(text: &str, phase: u32) -> Result<[u8; 32]> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 2
        || lines.first() != Some(&format!("setup-status:{phase}").as_str())
        || !text.ends_with('\n')
    {
        return Err("setup status framing".into());
    }
    let encoded = lines.get(1).ok_or("setup identity")?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("setup identity encoding".into());
    }
    let mut id = [0; 32];
    for (out, pair) in id.iter_mut().zip(encoded.as_bytes().as_chunks::<2>().0) {
        *out = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(*p::JournalIdentity::from_trusted_state(id)?.as_bytes())
}

pub(crate) fn paths(root: &Path) -> Result<p::InstallationPaths> {
    Ok(p::InstallationPaths::new(
        &root.join("installation.redb"),
        &root.join("journal.redb"),
        &root.join("archives.redb"),
    )?)
}

pub(crate) fn local(root: &Path) -> Result<p::VerifiedDevice> {
    let account = p::AccountPin::new(
        fixture::array(root, "local-account")?,
        p::PublicKey::decode(&fixture::read(root, "local-root", p::PUBLIC_KEY_BYTES)?)?,
        p::RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(fixture::array(root, "local-roster-version")?),
            fixture::array(root, "local-roster-digest")?,
        )?,
        fixture::array(root, "family")?,
    )?;
    Ok(account.verify_device(
        &fixture::read(root, "local-certificate", 8192)?,
        &fixture::read(root, "local-roster", 8192)?,
        fixture::now()?,
    )?)
}

fn native_phase(root: &Path, expected: [u8; 32], phase: p::InstallationStatus) -> Result<()> {
    let mut sdk = fixture::sdk(root)?;
    let policy = fixture::protocol_policy(root, &sdk)?;
    let device = local(root)?;
    let key = p::JournalKey::open(&root.join("wrap.key"))?;
    let mut installation =
        p::DeviceInstallation::open(paths(root)?, &key, &device, &policy, fixture::now()?)?;
    assert_eq!(installation.identity()?.as_bytes(), &expected);
    assert_eq!(installation.status()?, phase);
    installation.close();
    policy.close();
    sdk.close();
    Ok(())
}

#[test]
fn c_setup_preserves_original_creation_and_active_identity() -> Result<()> {
    let language = language()?;
    let (setup, _) = fixture::setup_devices(None, None, None, false, false, false)?;
    let root = &setup.initiator;
    for name in ["installation.redb", "journal.redb", "archives.redb"] {
        absent(&root.join(name))?;
    }
    run(root, "precancel", "pre-cancel", Some(302), None)?;
    absent(&root.join("installation.redb"))?;
    let id = status(&run(root, "create", "create", None, None)?, 1)?;
    absent(&root.join("journal.redb"))?;
    absent(&root.join("archives.redb"))?;
    native_phase(root, id, p::InstallationStatus::Creating)?;
    let prepared = run(root, "prepare", "storage", None, None)?;
    assert_eq!(
        prepared,
        format!(
            "setup-prepared:1\n{}\n{}\n{}\n",
            fixture::hex(&id),
            "0".repeat(192),
            "0".repeat(64)
        )
    );
    assert_eq!(
        prepared,
        run(root, "prepare-repeat", "storage", None, None)?
    );
    assert_eq!(
        id,
        status(&run(root, "creating", "status", None, None)?, 1)?
    );
    let activated = run(root, "activate", "activate", None, None)?;
    assert!(activated.starts_with("setup-activated\n"));
    native_phase(root, id, p::InstallationStatus::Active)?;
    assert_eq!(id, status(&run(root, "active", "status", None, None)?, 2)?);
    run(root, "active-refuses-prepare", "storage", Some(211), None)?;
    assert_eq!(activated, run(root, "reactivate", "activate", None, None)?);
    fixture::store(root, "setup-original-journal", &id)?;
    fixture::store(root, "setup-local-result.json", format!("{{\"schema_version\":1,\"language\":\"{language}\",\"completed\":true,\"pre_cancel_absent\":true,\"same_genesis\":true,\"active_prepare_refused\":true,\"release_claim_eligible\":false}}\n").as_bytes())?;
    Ok(())
}

#[test]
fn c_setup_requires_independent_original_witness_enrollment() -> Result<()> {
    let language = language()?;
    let mut witness = witness::Witness::start()?;
    let (setup, _) =
        fixture::setup_devices(Some(&witness.configured), None, None, false, false, false)?;
    let root = &setup.initiator;
    let id = status(&run(root, "create", "create", None, None)?, 1)?;
    let prepared = run(root, "prepare", "storage", None, None)?;
    assert_eq!(
        prepared,
        run(root, "prepare-repeat", "storage", None, None)?
    );
    assert!(witness
        .captured
        .lock()
        .map_err(|_| "witness captures")?
        .is_empty());
    run(root, "required", "activate", Some(216), None)?;
    native_phase(root, id, p::InstallationStatus::Creating)?;
    let mut sdk = fixture::sdk(root)?;
    let policy = fixture::protocol_policy(root, &sdk)?;
    let device = local(root)?;
    let genesis = p::DeviceJournal::recover_anchor_genesis(
        &root.join("journal.redb"),
        p::JournalKey::open(&root.join("wrap.key"))?,
        &device,
        &policy,
        p::JournalIdentity::from_trusted_state(id)?,
    )?;
    assert_eq!(
        prepared,
        format!(
            "setup-prepared:2\n{}\n{}\n{}\n",
            fixture::hex(&id),
            fixture::hex(&genesis.subject().to_bytes()),
            fixture::hex(&genesis.image_digest())
        )
    );
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness enrollment")?
        .enroll(&genesis, &device, &policy, fixture::now()?)?;
    policy.close();
    sdk.close();
    witness.arm(2)?;
    run(root, "bad-signature", "activate", Some(218), Some(&witness))?;
    native_phase(root, id, p::InstallationStatus::Creating)?;
    *witness
        .hold_marker
        .lock()
        .map_err(|_| "witness hold marker")? = Some(root.join("setup-cancel-barrier"));
    witness.arm(4)?;
    let cancelled = run(root, "cancel", "cancel", None, Some(&witness))?;
    assert!(cancelled.starts_with("setup-cancelled:218:"));
    native_phase(root, id, p::InstallationStatus::Creating)?;
    let activated = run(root, "activate", "activate", None, Some(&witness))?;
    assert!(activated.starts_with("setup-activated\n"));
    native_phase(root, id, p::InstallationStatus::Active)?;
    assert_eq!(
        activated,
        run(root, "reactivate", "activate", None, Some(&witness))?
    );
    assert_eq!(id, status(&run(root, "active", "status", None, None)?, 2)?);
    run(root, "active-required", "activate", Some(216), None)?;
    fixture::store(root, "witness-subject", &genesis.subject().to_bytes())?;
    let mut tls =
        witness_tls::TlsWitness::start(Arc::clone(&witness.configured.store), [root.as_path()])?;
    let plain_before = witness
        .captured
        .lock()
        .map_err(|_| "plaintext captures")?
        .len();
    assert_eq!(
        activated,
        run_at(
            root,
            "tls-reactivate",
            "activate",
            None,
            Some((tls.address, true))
        )?
    );
    assert_eq!(
        plain_before,
        witness
            .captured
            .lock()
            .map_err(|_| "plaintext captures")?
            .len()
    );
    assert!(tls.finish()?.is_empty());
    let admissions = tls.admitted.load(Ordering::Acquire);
    assert!(admissions > 0);
    fixture::store(
        root,
        "setup-tls-admissions",
        &u64::try_from(admissions)?.to_be_bytes(),
    )?;
    assert_eq!(witness.fault.load(Ordering::Acquire), 0);
    assert!(witness
        .hold_marker
        .lock()
        .map_err(|_| "witness marker")?
        .is_none());
    let captured = Arc::clone(&witness.captured);
    witness.join()?;
    let records = captured.lock().map_err(|_| "witness final captures")?;
    assert!(!records.is_empty());
    assert_eq!(records.iter().filter(|row| !row.delivered).count(), 1);
    assert!(records
        .iter()
        .all(|row| row.request.len() == 3674 && row.reply.len() == 3659));
    let mut transcript = Vec::new();
    for row in records.iter() {
        transcript.push(u8::from(row.delivered));
        transcript.extend_from_slice(&row.request);
        transcript.extend_from_slice(&row.reply);
    }
    fixture::store(root, "setup-witness-transcript", &transcript)?;
    fixture::store(root, "setup-original-journal", &id)?;
    fixture::store(
        root,
        "setup-original-subject",
        &genesis.subject().to_bytes(),
    )?;
    fixture::store(root, "setup-original-image", &genesis.image_digest())?;
    fixture::store(root, "setup-witness-result.json", format!("{{\"schema_version\":1,\"language\":\"{language}\",\"completed\":true,\"independent_enrollment\":true,\"missing_witness_refused\":true,\"same_genesis\":true,\"release_claim_eligible\":false}}\n").as_bytes())?;
    Ok(())
}
