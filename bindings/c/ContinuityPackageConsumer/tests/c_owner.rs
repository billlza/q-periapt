// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual C client and independent Rust process consuming the same installed core.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;

use q_periapt_continuity_identity_candidate as p;
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PAYLOAD: &[u8] = b"persisted before process exit";

struct CProcess {
    child: fixture::OwnedChild,
    stdout: PathBuf,
    stderr: PathBuf,
}
fn start(path: &Path, label: &str, arguments: &[OsString]) -> Result<CProcess> {
    let client =
        PathBuf::from(std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C client missing")?);
    if !client.is_absolute() || !client.is_file() {
        return Err("C client is not an existing absolute executable".into());
    }
    let stdout = path.join(format!("c-{label}.stdout"));
    let stderr = path.join(format!("c-{label}.stderr"));
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
    let child = fixture::OwnedChild(
        Command::new(client)
            .args(arguments)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()?,
    );
    Ok(CProcess {
        child,
        stdout,
        stderr,
    })
}
fn log(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("C log exceeded bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn finish(mut process: CProcess) -> Result<String> {
    let status = fixture::wait(&mut process.child)?;
    let stdout = log(&process.stdout)?;
    let stderr = log(&process.stderr)?;
    if !status.success() || !stderr.is_empty() {
        return Err(format!("C client failed: {status}; stdout={stdout}; stderr={stderr}").into());
    }
    Ok(stdout)
}
fn run(path: &Path, label: &str, arguments: &[OsString]) -> Result<String> {
    finish(start(path, label, arguments)?)
}
fn id(text: &str) -> Result<[u8; 32]> {
    if text.len() != 65 || !text.ends_with('\n') {
        return Err("C ID output shape".into());
    }
    let mut bytes = [0; 32];
    for (out, chunk) in bytes.iter_mut().zip(
        text.as_bytes()
            .get(..64)
            .ok_or("C ID prefix")?
            .as_chunks::<2>()
            .0,
    ) {
        let value = std::str::from_utf8(chunk)?;
        if !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("C ID was not canonical lowercase hex".into());
        }
        *out = u8::from_str_radix(value, 16)?;
    }
    Ok(bytes)
}
fn args(command: &str, path: &Path, tail: &[String]) -> Vec<OsString> {
    let mut arguments = vec![command.into(), path.as_os_str().into()];
    arguments.extend(tail.iter().map(OsString::from));
    arguments
}

#[test]
fn c_client_owns_installed_connection_rekeys_and_reconciles_exact_delivery() -> Result<()> {
    let setup = fixture::setup()?;
    let path = &setup.initiator;
    assert_eq!(
        run(path, "self-check", &["self-check".into()])?,
        "self-check-passed\n"
    );
    fs::write(path.join("role"), [2])?;
    assert_eq!(
        run(path, "wrong-role", &args("reject-open", path, &[]))?,
        "rejected:211\n"
    );
    fs::write(path.join("role"), [1])?;

    let request = p::InitiationId::generate()?;
    fixture::store(path, "initiation", request.as_bytes())?;
    let (mut server, address) = fixture::spawn(&setup.responder, 20, "bootstrap")?;
    let session = id(&run(
        path,
        "connect",
        &args(
            "connect",
            path,
            &[address.to_string(), fixture::hex(request.as_bytes())],
        ),
    )?)?;
    assert!(fixture::wait(&mut server)?.success());
    assert_eq!(fixture::array::<32>(&setup.responder, "session")?, session);
    fixture::store(path, "session", &session)?;
    let session_hex = fixture::hex(&session);
    let message = id(&run(
        path,
        "next",
        &args("next", path, std::slice::from_ref(&session_hex)),
    )?)?;
    fixture::store(path, "uncertain-message", &message)?;
    let message_hex = fixture::hex(&message);
    let (mut server, address) = fixture::spawn(&setup.responder, 21, "crash-after-application")?;
    assert_eq!(
        run(
            path,
            "uncertain-send",
            &args(
                "uncertain-send",
                path,
                &[
                    address.to_string(),
                    session_hex.clone(),
                    message_hex.clone()
                ]
            )
        )?,
        "delivery-unknown-committed\n"
    );
    assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
    fixture::effect(
        &setup.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    assert_eq!(
        run(
            path,
            "committed-status",
            &args("status", path, &[session_hex.clone(), message_hex.clone()])
        )?,
        "2\n"
    );

    let (mut server, address) = fixture::spawn(&setup.responder, 22, "application")?;
    assert_eq!(
        run(
            path,
            "exact-resend",
            &args(
                "send",
                path,
                &[
                    address.to_string(),
                    session_hex.clone(),
                    message_hex.clone()
                ]
            )
        )?,
        "consumed\n"
    );
    assert!(fixture::wait(&mut server)?.success());
    fixture::effect(
        &setup.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    let (mut server, address) = fixture::spawn(&setup.responder, 23, "rekey")?;
    assert_eq!(
        run(
            path,
            "rekey",
            &args("rekey", path, &[address.to_string(), session_hex.clone()])
        )?,
        "rekey-1-confirmed\n"
    );
    assert!(fixture::wait(&mut server)?.success());

    let next = id(&run(
        path,
        "next-after-rekey",
        &args("next", path, std::slice::from_ref(&session_hex)),
    )?)?;
    fixture::store(path, "cancelled-message", &next)?;
    let next_hex = fixture::hex(&next);
    assert_ne!(next, message);
    assert_eq!(
        run(
            path,
            "pre-cancel",
            &args(
                "cancel-send",
                path,
                &[address.to_string(), session_hex.clone(), next_hex.clone()]
            )
        )?,
        "cancelled-absent\n"
    );

    // Hold an actual socket after observing TLS bytes. The C thread owns the
    // service while its other thread attempts close and then signals cancellation.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let marker = path.join("c-socket-ready");
    let pending = start(
        path,
        "concurrent-cancel",
        &args(
            "busy-cancel",
            path,
            &[
                listener.local_addr()?.to_string(),
                session_hex.clone(),
                next_hex.clone(),
                marker.to_str().ok_or("marker UTF-8")?.into(),
            ],
        ),
    )?;
    let mut stream = fixture::accept(&listener)?;
    // Accepted sockets can inherit the listener's nonblocking mode on this host.
    // This observation is bounded by SO_RCVTIMEO rather than a readiness spin.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut first = [0];
    stream.read_exact(&mut first)?;
    assert_eq!(first, [22], "observed TLS ClientHello record");
    let mut ready = tempfile::NamedTempFile::new_in(path)?;
    ready.write_all(b"1")?;
    ready.as_file().sync_all()?;
    ready.persist_noclobber(&marker).map_err(|e| e.error)?;
    fs::File::open(path)?.sync_all()?;
    assert_eq!(finish(pending)?, "cancelled-committed-reopened\n");
    drop(stream);
    drop(listener);
    let (mut server, address) = fixture::spawn(&setup.responder, 24, "application")?;
    assert_eq!(
        run(
            path,
            "resume-cancelled",
            &args(
                "send",
                path,
                &[address.to_string(), session_hex.clone(), next_hex.clone()]
            )
        )?,
        "consumed\n"
    );
    assert!(fixture::wait(&mut server)?.success());
    fixture::effect(
        &setup.responder,
        session,
        p::MessageId::from_trusted_state(next)?,
        PAYLOAD,
    )?;
    assert_eq!(
        run(
            path,
            "final-status",
            &args("status", path, &[session_hex.clone(), next_hex.clone()])
        )?,
        "3\n"
    );

    let mut store = fixture::sdk(path)?;
    let prior = store.runtime()?.trusted_state();
    let (policy, signature) = setup.issuer.policy(2, false)?;
    store.replace_policy(prior, &policy, &signature)?;
    assert!(!store.runtime()?.is_enabled()?);
    store.close();
    assert_eq!(
        run(path, "revoked-open", &args("reject-open", path, &[]))?,
        "rejected:603\n"
    );
    let report = format!(concat!("{{\"schema_version\":1,\"completed\":true,",
        "\"scope\":\"unpublished C client to installed Rust peer; same host; local journal profile\",",
        "\"session\":\"{}\",\"first_message\":\"{}\",\"post_rekey_message\":\"{}\",",
        "\"network_rekeys\":1,\"unknown_delivery_reconciled\":true,",
        "\"pre_cancel_absent\":true,\"concurrent_close_busy\":true,",
        "\"cancelled_commit_reopened\":true,\"durable_sdk_revocation\":true,",
        "\"independent_readbacks\":3,\"release_claim_eligible\":false}}\n"),
        session_hex, message_hex, next_hex);
    fixture::store(
        path.parent().ok_or("runtime parent")?,
        "c-public-result.json",
        report.as_bytes(),
    )?;
    eprintln!("C_PUBLIC_SERVICE_RESULT {}", report.trim());
    Ok(())
}
