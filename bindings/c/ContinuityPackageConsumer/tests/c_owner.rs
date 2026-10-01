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

fn installed_language() -> Result<&'static str> {
    // The collector selects and hashes the actual foreign executable. Retain
    // explicit language identity for both client and server protocol traces.
    match std::env::var("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") {
        Err(std::env::VarError::NotPresent) => Ok("C"),
        Ok(language) if language == "Swift" => Ok("Swift"),
        _ => Err("unsupported installed client language".into()),
    }
}

#[test]
fn c_client_owns_installed_connection_rekeys_and_reconciles_exact_delivery() -> Result<()> {
    let scope = format!(
        "unpublished {} client to installed Rust peer; same host; local journal profile",
        installed_language()?
    );
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
    let report = format!(
        concat!(
            "{{\"schema_version\":1,\"completed\":true,",
            "\"scope\":\"{}\",",
            "\"session\":\"{}\",\"first_message\":\"{}\",\"post_rekey_message\":\"{}\",",
            "\"network_rekeys\":1,\"unknown_delivery_reconciled\":true,",
            "\"pre_cancel_absent\":true,\"concurrent_close_busy\":true,",
            "\"cancelled_commit_reopened\":true,\"durable_sdk_revocation\":true,",
            "\"independent_readbacks\":3,\"release_claim_eligible\":false}}\n"
        ),
        scope, session_hex, message_hex, next_hex
    );
    fixture::store(
        path.parent().ok_or("runtime parent")?,
        "c-public-result.json",
        report.as_bytes(),
    )?;
    eprintln!("C_PUBLIC_SERVICE_RESULT {}", report.trim());
    Ok(())
}

fn start_server(
    path: &Path,
    label: &str,
    mode: &str,
    session: Option<[u8; 32]>,
) -> Result<(CProcess, std::net::SocketAddr)> {
    let mut tail = vec![mode.to_owned()];
    if let Some(session) = session {
        tail.push(fixture::hex(&session));
    }
    let mut process = start(path, label, &args("serve", path, &tail))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let output = log(&process.stdout)?;
        if let Some((line, _)) = output.split_once('\n') {
            let port: u16 = line
                .strip_prefix("listening:")
                .ok_or("C server readiness shape")?
                .parse()?;
            if port == 0 {
                return Err("C server port zero".into());
            }
            return Ok((process, ([127, 0, 0, 1], port).into()));
        }
        if process.child.0.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
            return Err(format!("C server not ready: {output}; {}", log(&process.stderr)?).into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn finish_server(mut process: CProcess, exit: i32) -> Result<String> {
    let status = fixture::wait(&mut process.child)?;
    let stdout = log(&process.stdout)?;
    let stderr = log(&process.stderr)?;
    if status.code() != Some(exit) || !stderr.is_empty() {
        return Err(format!("C server exit {status}, expected {exit}: {stdout}; {stderr}").into());
    }
    Ok(stdout
        .split_once('\n')
        .ok_or("C server missing readiness")?
        .1
        .to_owned())
}
fn server_event(
    session: [u8; 32],
    message: [u8; 32],
    duplicate: bool,
    calls: u8,
    created: u8,
) -> String {
    format!(
        "served:{}:{}:{calls}:{created}\n{}\n{}\n",
        if message == [0; 32] { 1 } else { 2 },
        u8::from(duplicate),
        fixture::hex(&session),
        fixture::hex(&message)
    )
}

#[test]
fn c_server_preserves_callback_failures_unknown_commits_replay_and_rekey() -> Result<()> {
    use p::connection_transport::{Cancellation, ConnectionEndpoint, Consumption, Run};
    let scope = format!(
        "installed native Rust client to unpublished {} server; same host; local journal profile",
        installed_language()?
    );
    let setup = fixture::setup()?;
    let path = &setup.responder;
    // The original implementation refreshed a 20-second budget after accept:
    // 15 seconds listening plus the TLS engine's 10 seconds took about 25 seconds.
    let (deadline_server, address) = start_server(path, "server-deadline", "deadline", None)?;
    let started = std::time::Instant::now();
    std::thread::sleep(Duration::from_secs(15));
    let mut stalled = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    assert_eq!(finish_server(deadline_server, 0)?, "server-deadline\n");
    let listener_tls_deadline_ms = u64::try_from(started.elapsed().as_millis())?;
    assert!(
        (18_000..23_000).contains(&listener_tls_deadline_ms),
        "listener plus TLS deadline: {listener_tls_deadline_ms} ms"
    );
    stalled.set_read_timeout(Some(Duration::from_secs(2)))?;
    assert_eq!(
        stalled.read(&mut [0])?,
        0,
        "expired server retained its socket"
    );
    drop(stalled);
    let mut peer = fixture::Peer::open(&setup.initiator)?;
    let endpoint =
        ConnectionEndpoint::client(&peer.context, peer.credentials(), fixture::tls_limits())?;
    let name = peer.peer_name.clone();
    let (server, address) = start_server(path, "server-bootstrap", "bootstrap", None)?;
    let initial = p::InitiationId::generate()?;
    let session = endpoint
        .establish(
            peer.actor()?,
            initial,
            Run {
                address,
                server_name: &name,
                cancel: &Cancellation::default(),
                limits: fixture::limits(),
            },
            fixture::now,
        )?
        .session;
    assert_eq!(
        finish_server(server, 0)?,
        server_event(session, [0; 32], false, 0, 0)
    );
    fixture::store(path, "session", &session)?;
    let (server, address) = start_server(path, "server-cancel", "pre-cancel", None)?;
    assert_eq!(finish_server(server, 0)?, "server-cancelled\n");
    // No connection was accepted: rebinding the exact port checks listener release
    // without confusing a TCP TIME_WAIT endpoint with a leaked listening owner.
    drop(TcpListener::bind(address)?);

    let mut messages = Vec::new();
    for (ordinal, mode) in ["fail-before", "uncertain", "crash-after"]
        .into_iter()
        .enumerate()
    {
        let message =
            peer.service
                .stores()?
                .0
                .next_message_id(&peer.context, session, fixture::now()?)?;
        messages.push(*message.as_bytes());
        let label = format!("server-{mode}");
        let (server, address) = start_server(path, &label, mode, None)?;
        let result = fixture::send(&mut peer, &endpoint, address, session, message, PAYLOAD);
        let error = result.expect_err("C callback failure must not confirm consumption");
        assert!(matches!(
            error.downcast_ref::<p::connection_transport::Error>(),
            Some(
                p::connection_transport::Error::RetryExhausted { .. }
                    | p::connection_transport::Error::Io(_)
                    | p::connection_transport::Error::Deadline
                    | p::connection_transport::Error::Connection(_)
            )
        ));
        let expected = match ordinal {
            0 => "application-failed:1:0\n",
            1 => "application-failed:1:1\n",
            _ => "",
        };
        assert_eq!(
            finish_server(server, if ordinal == 2 { 77 } else { 0 })?,
            expected
        );
        assert_eq!(
            peer.service
                .stores()?
                .0
                .message_status(&peer.context, session, message)?,
            p::MessageStatus::Committed
        );
        if ordinal == 0 {
            assert!(!path
                .join(format!("application-{}", fixture::hex(message.as_bytes())))
                .exists());
        } else {
            fixture::effect(path, session, message, PAYLOAD)?;
        }
        let (server, address) =
            start_server(path, &format!("server-retry-{ordinal}"), "message", None)?;
        assert_eq!(
            fixture::send(&mut peer, &endpoint, address, session, message, PAYLOAD)?.consumption,
            Consumption::Confirmed
        );
        assert_eq!(
            finish_server(server, 0)?,
            server_event(
                session,
                *message.as_bytes(),
                false,
                1,
                u8::from(ordinal == 0)
            )
        );
        fixture::effect(path, session, message, PAYLOAD)?;
        if ordinal == 0 {
            let error = fixture::send(&mut peer, &endpoint, address, session, message, PAYLOAD)
                .expect_err("acknowledged ciphertext is retired");
            assert!(matches!(
                error.downcast_ref::<p::connection_transport::Error>(),
                Some(p::connection_transport::Error::Durable(
                    p::DurableError::Protocol(p::Error::Retired)
                ))
            ));
        }
    }
    // A separate recovery consumer confirms an already durable C application
    // record via the real public API, before any ACK reaches the sender. The
    // sender therefore retains its original ciphertext for an actual duplicate.
    let duplicate =
        peer.service
            .stores()?
            .0
            .next_message_id(&peer.context, session, fixture::now()?)?;
    messages.push(*duplicate.as_bytes());
    let (server, address) = start_server(path, "server-duplicate-prepare", "uncertain", None)?;
    let error = fixture::send(&mut peer, &endpoint, address, session, duplicate, PAYLOAD)
        .expect_err("preparation retains unknown application outcome");
    assert!(matches!(
        error.downcast_ref::<p::connection_transport::Error>(),
        Some(
            p::connection_transport::Error::RetryExhausted { .. }
                | p::connection_transport::Error::Io(_)
                | p::connection_transport::Error::Deadline
                | p::connection_transport::Error::Connection(_)
        )
    ));
    assert_eq!(finish_server(server, 0)?, "application-failed:1:1\n");
    fixture::effect(path, session, duplicate, PAYLOAD)?;
    assert_eq!(
        peer.service
            .stores()?
            .0
            .message_status(&peer.context, session, duplicate)?,
        p::MessageStatus::Committed
    );
    let mut recovered = fixture::Peer::open(path)?;
    assert_eq!(
        recovered.service.stores()?.0.consume_message(
            &recovered.context,
            session,
            duplicate,
            fixture::now()?
        )?,
        4
    );
    recovered.close();
    let (server, address) = start_server(path, "server-duplicate", "message", None)?;
    assert_eq!(
        fixture::send(&mut peer, &endpoint, address, session, duplicate, PAYLOAD)?.consumption,
        Consumption::Confirmed
    );
    assert_eq!(
        finish_server(server, 0)?,
        server_event(session, *duplicate.as_bytes(), true, 0, 0)
    );
    fixture::effect(path, session, duplicate, PAYLOAD)?;
    let (server, address) = start_server(path, "server-rekey", "rekey", Some(session))?;
    let control = p::control_transport::ControlEndpoint::client(
        &peer.context,
        session,
        peer.credentials(),
        fixture::tls_limits(),
    )?;
    let (journal, _) = peer.service.stores()?;
    let completed = control.run(
        p::control_transport::Session {
            journal,
            context: &peer.context,
            signer: &peer.signer,
        },
        p::control_transport::Run {
            target: 1,
            address,
            server_name: &name,
            cancel: &Cancellation::default(),
            limits: fixture::limits(),
        },
        fixture::now,
    )?;
    assert_eq!(completed.epoch, 1);
    assert_eq!(finish_server(server, 0)?, "server-rekey-1\n");
    let last = peer
        .service
        .stores()?
        .0
        .next_message_id(&peer.context, session, fixture::now()?)?;
    messages.push(*last.as_bytes());
    let (server, address) = start_server(path, "server-after-rekey", "message", None)?;
    assert_eq!(
        fixture::send(&mut peer, &endpoint, address, session, last, PAYLOAD)?.consumption,
        Consumption::Confirmed
    );
    assert_eq!(
        finish_server(server, 0)?,
        server_event(session, *last.as_bytes(), false, 1, 1)
    );
    fixture::effect(path, session, last, PAYLOAD)?;
    peer.close();
    let ids = messages
        .iter()
        .map(|id| format!("\"{}\"", fixture::hex(id)))
        .collect::<Vec<_>>()
        .join(",");
    let report = format!(concat!("{{\"schema_version\":1,\"completed\":true,",
        "\"scope\":\"{}\",",
        "\"session\":\"{}\",\"messages\":[{}],\"network_rekeys\":1,",
        "\"callback_failure_preserved\":true,\"unknown_commit_reconciled\":true,",
        "\"crash_after_application_reconciled\":true,\"duplicate_skips_callback\":true,",
        "\"reentrant_close_busy\":true,\"cancelled_listener_released\":true,",
        "\"acknowledged_send_refused\":true,\"native_recovery_consumption\":true,",
        "\"application_records\":5,\"listener_tls_deadline_ms\":{},\"release_claim_eligible\":false}}\n"), scope, fixture::hex(&session), ids, listener_tls_deadline_ms);
    fixture::store(
        path.parent().ok_or("runtime root")?,
        "c-server-public-result.json",
        report.as_bytes(),
    )?;
    eprintln!("C_SERVER_PUBLIC_SERVICE_RESULT {}", report.trim());
    Ok(())
}

fn recovery_call(
    path: &Path,
    label: &str,
    command: &str,
    tail: &[String],
    exit: i32,
) -> Result<String> {
    let mut process = start(path, label, &args(command, path, tail))?;
    let status = fixture::wait(&mut process.child)?;
    let stdout = log(&process.stdout)?;
    let stderr = log(&process.stderr)?;
    if status.code() != Some(exit) || !stderr.is_empty() {
        return Err(
            format!("C recovery {label}: {status}, expected {exit}: {stdout}; {stderr}").into(),
        );
    }
    Ok(stdout)
}
#[test]
fn c_recovery_preserves_complete_loss_accounting_after_revocation_and_process_exit() -> Result<()> {
    let setup = fixture::setup()?;
    let session = {
        let request = p::InitiationId::generate()?;
        let (mut server, address) = fixture::spawn(&setup.responder, 60, "bootstrap")?;
        let session = id(&run(
            &setup.initiator,
            "recovery-bootstrap",
            &args(
                "connect",
                &setup.initiator,
                &[address.to_string(), fixture::hex(request.as_bytes())],
            ),
        )?)?;
        assert!(fixture::wait(&mut server)?.success());
        session
    };
    let mut left = fixture::Peer::open(&setup.initiator)?;
    let mut right = fixture::Peer::open(&setup.responder)?;
    let ad = b"owned-service";
    let old = left
        .service
        .stores()?
        .0
        .next_message_id(&left.context, session, fixture::now()?)?;
    let wire = left.service.stores()?.0.send_message(
        &left.context,
        session,
        old,
        PAYLOAD,
        ad,
        fixture::now()?,
    )?;
    let received = right.service.stores()?.0.receive_message(
        &right.context,
        session,
        &wire,
        ad,
        fixture::now()?,
    )?;
    assert_eq!(received.message_id(), old);
    assert_eq!(received.as_bytes(), PAYLOAD);
    drop(received);
    right.close();
    let (mut server, address) = fixture::spawn(&setup.responder, 61, "rekey")?;
    let control = p::control_transport::ControlEndpoint::client(
        &left.context,
        session,
        left.credentials(),
        fixture::tls_limits(),
    )?;
    let name = left.peer_name.clone();
    let (journal, _) = left.service.stores()?;
    assert_eq!(
        control
            .run(
                p::control_transport::Session {
                    journal,
                    context: &left.context,
                    signer: &left.signer
                },
                p::control_transport::Run {
                    target: 1,
                    address,
                    server_name: &name,
                    limits: fixture::limits(),
                    cancel: &p::connection_transport::Cancellation::default()
                },
                fixture::now
            )?
            .epoch,
        1
    );
    assert!(fixture::wait(&mut server)?.success());
    right = fixture::Peer::open(&setup.responder)?;
    let mut incoming = Vec::new();
    for index in 0..3 {
        let message =
            left.service
                .stores()?
                .0
                .next_message_id(&left.context, session, fixture::now()?)?;
        let wire = left.service.stores()?.0.send_message(
            &left.context,
            session,
            message,
            PAYLOAD,
            ad,
            fixture::now()?,
        )?;
        if index != 1 {
            let received = right.service.stores()?.0.receive_message(
                &right.context,
                session,
                &wire,
                ad,
                fixture::now()?,
            )?;
            assert_eq!(received.message_id(), message);
            assert_eq!(received.as_bytes(), PAYLOAD);
            drop(received);
            incoming.push(*message.as_bytes());
        }
    }
    let unknown =
        right
            .service
            .stores()?
            .0
            .next_message_id(&right.context, session, fixture::now()?)?;
    let unknown_wire = right.service.stores()?.0.send_message(
        &right.context,
        session,
        unknown,
        PAYLOAD,
        ad,
        fixture::now()?,
    )?;
    fixture::store(&setup.responder, "cleanup-unconfirmed-wire", &unknown_wire)?;
    let resolution = right.service.stores()?.0.begin_closed_epoch_resolution(
        &right.context,
        session,
        0,
        fixture::now()?,
    )?;
    let old_resolution = *resolution.resolution_id().as_bytes();
    drop(resolution);
    let _offer = right.service.stores()?.0.prepare_rekey_offer(
        &right.context,
        session,
        &right.signer,
        fixture::now()?,
    )?;
    let progress = right
        .service
        .stores()?
        .0
        .rekey_progress(&right.context, session)?;
    assert_eq!(
        (
            progress.confirmed_epoch,
            progress.sending_epoch,
            progress.receiving_epoch,
            progress.pending_epoch
        ),
        (1, 1, 1, Some(2))
    );
    let context = right.context.digest();
    let archive = right.service.stores()?.1.get(session)?;
    fixture::store(
        &setup.responder,
        "native-closure-archive",
        archive.as_bytes(),
    )?;
    left.close();
    right.close();
    assert_eq!(
        recovery_call(&setup.responder, "recovery-kind", "recover-kind", &[], 0)?,
        "operational-owner-not-recovery\n"
    );
    let mut store = fixture::sdk(&setup.responder)?;
    let prior = store.runtime()?.trusted_state();
    let (policy, signature) = setup.issuer.policy(2, false)?;
    store.replace_policy(prior, &policy, &signature)?;
    assert!(!store.runtime()?.is_enabled()?);
    store.close();
    assert_eq!(
        run(
            &setup.responder,
            "recovery-denied",
            &args("reject-open", &setup.responder, &[])
        )?,
        "rejected:603\n"
    );
    let session_text = fixture::hex(&session);
    let tail = std::slice::from_ref(&session_text);
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-list-before",
            "recover-list",
            &[],
            0
        )?,
        "catalogue:1\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-missing",
            "recover-missing",
            tail,
            0
        )?,
        "missing-session-refused\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-tamper",
            "recover-tamper",
            &[],
            0
        )?,
        "tampered-archive-refused\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-cancel",
            "recover-cancel",
            tail,
            0
        )?,
        "cancelled-cleanup-not-frozen\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-freeze",
            "recover-freeze",
            tail,
            77
        )?,
        ""
    );
    let original = fixture::read(&setup.responder, "c-loss-report", 1048576)?;
    let retained_archive = fixture::read(&setup.responder, "c-closure-archive", 1024)?;
    assert_eq!(retained_archive, archive.as_bytes());
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-ack-crash",
            "recover-ack-crash",
            tail,
            77
        )?,
        ""
    );
    assert_eq!(
        fixture::read(&setup.responder, "c-loss-report", 1048576)?,
        original
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-finish",
            "recover-finish",
            tail,
            0
        )?,
        "original-report-closed-retired\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-list-after",
            "recover-list",
            &[],
            0
        )?,
        "catalogue:0\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-archive",
            "recover-archive",
            &[],
            0
        )?,
        "archive-closed-metadata-only\n"
    );
    assert_eq!(
        recovery_call(
            &setup.responder,
            "recovery-list-final",
            "recover-list",
            &[],
            0
        )?,
        "catalogue:0\n"
    );
    assert_eq!(
        fixture::read(&setup.responder, "c-loss-report", 1048576)?,
        original
    );
    let mut discovery = p::InstallationRecovery::open(
        p::InstallationPaths::new(
            &setup.responder.join("installation.redb"),
            &setup.responder.join("journal.redb"),
            &setup.responder.join("archives.redb"),
        )?,
        p::JournalKey::open(&setup.responder.join("wrap.key"))?,
    )?;
    assert!(discovery.session_ids()?.is_empty());
    let mut recovered = discovery.open_session_from_archive(&archive, None)?;
    let p::SessionClosureStatus::Closed(report) = recovered.stores()?.0.status()? else {
        return Err("C cleanup did not remain closed".into());
    };
    recovered.close();
    let incoming = incoming
        .iter()
        .map(|x| format!("\"{}\"", fixture::hex(x)))
        .collect::<Vec<_>>()
        .join(",");
    let report = format!(concat!("{{\"schema_version\":1,\"completed\":true,",
        "\"scope\":\"installed C recovery of original local-profile session after SDK revocation; same host\",",
        "\"session\":\"{}\",\"context\":\"{}\",\"report\":\"{}\",",
        "\"peer_account\":\"{}\",\"peer_device\":\"{}\",",
        "\"old_incoming\":\"{}\",\"incoming\":[{}],\"unconfirmed\":\"{}\",\"old_resolution\":\"{}\",",
        "\"revoked_operation_refused\":true,\"owner_kinds_separated\":true,",
        "\"report_exit_reconciled\":true,\"ack_exit_reconciled\":true,",
        "\"original_report_unchanged\":true,\"catalogue_retired\":true,\"archive_metadata_only\":true,\"cancelled_cleanup_unfrozen\":true,",
        "\"reserved_positive_case_executed\":false,\"release_claim_eligible\":false}}\n"),
        session_text, fixture::hex(&context), fixture::hex(report.as_bytes()),
        fixture::hex(&fixture::array::<32>(&setup.responder, "initiator-account")?),
        fixture::hex(&fixture::array::<16>(&setup.responder, "initiator-device")?),
        fixture::hex(old.as_bytes()), incoming, fixture::hex(unknown.as_bytes()), fixture::hex(&old_resolution));
    fixture::store(
        setup.responder.parent().ok_or("runtime root")?,
        "c-recovery-public-result.json",
        report.as_bytes(),
    )?;
    eprintln!("C_RECOVERY_PUBLIC_SERVICE_RESULT {}", report.trim());
    Ok(())
}
