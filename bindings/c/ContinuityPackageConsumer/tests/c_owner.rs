// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual C client and independent Rust process consuming the same installed core.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;

use q_periapt_continuity_identity_candidate as p;
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    net::TcpListener,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
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
    // explicit language identity for client, server and recovery traces.
    match std::env::var("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") {
        Err(std::env::VarError::NotPresent) => Ok("C"),
        Ok(language) if language == "Swift" => Ok("Swift"),
        Ok(language) if language == "Kotlin" => Ok("Kotlin"),
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
    start_listening(path, label, &args("serve", path, &tail))
}
fn start_listening(
    path: &Path,
    label: &str,
    arguments: &[OsString],
) -> Result<(CProcess, std::net::SocketAddr)> {
    let mut process = start(path, label, arguments)?;
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

#[test]
fn c_device_parents_keep_peer_lifetimes_and_reconcile_original_delivery() -> Result<()> {
    assert_eq!(
        installed_language()?,
        "C",
        "device child API requires its C consumer"
    );
    let setup = fixture::setup()?;
    let mut peers = Vec::new();
    let mut reopen_changed = 0;
    for (root, role) in [(&setup.initiator, "1"), (&setup.responder, "2")] {
        let peer = root.join("peer");
        fs::create_dir(&peer)?;
        fs::set_permissions(&peer, fs::Permissions::from_mode(0o700))?;
        let mut names = vec![
            "bootstrap.bundle".to_owned(),
            "directory".into(),
            "tls-peer".into(),
            "tls-peer-name".into(),
        ];
        for label in ["initiator", "responder"] {
            for leaf in [
                "account",
                "root",
                "roster-version",
                "roster-digest",
                "device",
                "generation",
            ] {
                names.push(format!("{label}-{leaf}"));
            }
        }
        for name in names {
            fs::rename(root.join(&name), peer.join(name))?;
        }
        assert!(!root.join("bootstrap.bundle").exists());
        let device_id = fixture::array::<16>(root, "local-device")?;
        let mut wrong = device_id;
        *wrong.first_mut().ok_or("device ID width")? ^= 1;
        fs::write(root.join("local-device"), wrong)?;
        assert_eq!(
            run(
                root,
                "device-wrong-local-id",
                &args("device-reject-open", root, &[])
            )?,
            "device-rejected:103\n"
        );
        fs::write(root.join("local-device"), device_id)?;
        // A different authentic controlled signer under the original wrapping
        // key and persisted signer ID still cannot impersonate this credential.
        fs::rename(root.join("signer.key"), root.join("original-signer.key"))?;
        p::DeviceSigningKey::provision(
            &root.join("signer.key"),
            &p::JournalKey::open(&root.join("wrap.key"))?,
            p::SigningKeyId::from_trusted_state(fixture::array(root, "signer-id")?)?,
        )?
        .close();
        assert_eq!(
            run(
                root,
                "device-wrong-signer",
                &args("device-reject-open", root, &[])
            )?,
            "device-rejected:103\n"
        );
        fs::remove_file(root.join("signer.key"))?;
        fs::rename(root.join("original-signer.key"), root.join("signer.key"))?;
        let before = ["installation.redb", "journal.redb", "archives.redb"]
            .map(|name| fs::read(root.join(name)))
            .into_iter()
            .collect::<io::Result<Vec<_>>>()?;
        assert_eq!(
            run(
                root,
                "device-reopen-control",
                &["device-open-close".into(), root.as_os_str().into(),]
            )?,
            "device-open-close-passed\n"
        );
        for (name, original) in ["installation.redb", "journal.redb", "archives.redb"]
            .iter()
            .zip(before)
        {
            reopen_changed += usize::from(fs::read(root.join(name))? != original);
        }
        let lifecycle = run(
            root,
            "device-lifecycle",
            &[
                "device-check".into(),
                root.as_os_str().into(),
                peer.as_os_str().into(),
                role.into(),
            ],
        )?;
        let busy = lifecycle
            .strip_prefix("device-parent-lifecycle-passed:busy=")
            .and_then(|line| line.strip_suffix('\n'))
            .ok_or("parent lifecycle receipt")?
            .parse::<u32>()?;
        assert!(busy <= 64, "fixture admission retry budget");
        peers.push(peer);
    }
    let left = peers.first().ok_or("initiator peer")?;
    let right = peers.get(1).ok_or("responder peer")?;
    let selected = |root: &Path,
                    role: &str,
                    peer: &Path,
                    command: &str,
                    session: Option<[u8; 32]>,
                    tail: &[String]| {
        let mut result: Vec<OsString> = vec![
            "--device-parent".into(),
            root.as_os_str().into(),
            role.into(),
        ];
        if let Some(session) = session {
            result.extend(["--session".into(), fixture::hex(&session).into()]);
        }
        result.extend(args(command, peer, tail));
        result
    };
    let (server, address) = start_listening(
        &setup.responder,
        "device-bootstrap-server",
        &selected(
            &setup.responder,
            "2",
            right,
            "serve",
            None,
            &["bootstrap".into()],
        ),
    )?;
    let request = p::InitiationId::generate()?;
    let session = id(&run(
        &setup.initiator,
        "device-bootstrap-client",
        &selected(
            &setup.initiator,
            "1",
            left,
            "connect",
            None,
            &[address.to_string(), fixture::hex(request.as_bytes())],
        ),
    )?)?;
    assert_eq!(
        finish_server(server, 0)?,
        server_event(session, [0; 32], false, 0, 0)
    );
    let message = id(&run(
        &setup.initiator,
        "device-next",
        &selected(
            &setup.initiator,
            "1",
            left,
            "next",
            Some(session),
            &[fixture::hex(&session)],
        ),
    )?)?;
    let (server, address) = start_listening(
        &setup.responder,
        "device-crash-server",
        &selected(
            &setup.responder,
            "2",
            right,
            "serve",
            Some(session),
            &["crash-after".into()],
        ),
    )?;
    assert_eq!(
        run(
            &setup.initiator,
            "device-unknown",
            &selected(
                &setup.initiator,
                "1",
                left,
                "uncertain-send",
                Some(session),
                &[
                    address.to_string(),
                    fixture::hex(&session),
                    fixture::hex(&message)
                ],
            )
        )?,
        "delivery-unknown-committed\n"
    );
    assert_eq!(finish_server(server, 77)?, "");
    fixture::effect(
        right,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    let (server, address) = start_listening(
        &setup.responder,
        "device-replay-server",
        &selected(
            &setup.responder,
            "2",
            right,
            "serve",
            Some(session),
            &["message".into()],
        ),
    )?;
    assert_eq!(
        run(
            &setup.initiator,
            "device-replay",
            &selected(
                &setup.initiator,
                "1",
                left,
                "send",
                Some(session),
                &[
                    address.to_string(),
                    fixture::hex(&session),
                    fixture::hex(&message)
                ],
            )
        )?,
        "consumed\n"
    );
    assert_eq!(
        finish_server(server, 0)?,
        server_event(session, message, false, 1, 0)
    );
    fixture::effect(
        right,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    assert_eq!(
        run(
            &setup.initiator,
            "device-final-status",
            &selected(
                &setup.initiator,
                "1",
                left,
                "status",
                Some(session),
                &[fixture::hex(&session), fixture::hex(&message)],
            )
        )?,
        "3\n"
    );
    let mut store = fixture::sdk(&setup.initiator)?;
    let prior = store.runtime()?.trusted_state();
    let (policy, signature) = setup.issuer.policy(2, false)?;
    store.replace_policy(prior, &policy, &signature)?;
    assert!(!store.runtime()?.is_enabled()?);
    store.close();
    assert_eq!(
        run(
            &setup.initiator,
            "device-revoked",
            &args("device-reject-open", &setup.initiator, &[])
        )?,
        "device-rejected:603\n"
    );
    let report = format!("{{\"schema_version\":1,\"completed\":true,\"session\":\"{}\",\"message\":\"{}\",\"local_roles\":2,\"owner_capacity\":64,\"independent_readbacks\":2,\"independent_identity_refusals\":4,\"sdk_revocation_refused\":true,\"physical_reopen_changed_files\":{},\"release_claim_eligible\":false}}\n", fixture::hex(&session), fixture::hex(&message), reopen_changed);
    fixture::store(
        setup.initiator.parent().ok_or("evidence root")?,
        "c-device-parent-public-result.json",
        report.as_bytes(),
    )?;
    eprintln!("C_DEVICE_PARENT_RESULT {}", report.trim());
    Ok(())
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
        "\"scope\":\"installed {} recovery of original local-profile session after SDK revocation; same host\",",
        "\"session\":\"{}\",\"context\":\"{}\",\"report\":\"{}\",",
        "\"peer_account\":\"{}\",\"peer_device\":\"{}\",",
        "\"old_incoming\":\"{}\",\"incoming\":[{}],\"unconfirmed\":\"{}\",\"old_resolution\":\"{}\",",
        "\"revoked_operation_refused\":true,\"owner_kinds_separated\":true,",
        "\"report_exit_reconciled\":true,\"ack_exit_reconciled\":true,",
        "\"original_report_unchanged\":true,\"catalogue_retired\":true,\"archive_metadata_only\":true,\"cancelled_cleanup_unfrozen\":true,",
        "\"reserved_positive_case_executed\":false,\"release_claim_eligible\":false}}\n"),
        installed_language()?, session_text, fixture::hex(&context), fixture::hex(report.as_bytes()),
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

/// Qualification fixture only: establish at an explicit historical protocol
/// instant, then let foreign owners operate with their real current wall clock.
/// No product clock override, sleep race or expired fresh constructor is used.
fn setup_established_expired_advertisement() -> Result<fixture::Setup> {
    let at = fixture::now()?
        .checked_sub(120)
        .ok_or("historical fixture time")?;
    let s = fixture::setup_with_time(None, Some(60), Some(at))?;
    let mut initiator = fixture::Peer::open_at_with_witness(&s.initiator, None, at)?;
    let mut responder = fixture::Peer::open_at_with_witness(&s.responder, None, at)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let server_endpoint = p::connection_transport::ConnectionEndpoint::server(
        &responder.context,
        responder.credentials(),
        fixture::tls_limits(),
    )?;
    let server = std::thread::spawn(move || -> Result<[u8; 32]> {
        struct NoApplication;
        impl p::connection_transport::Consumer for NoApplication {
            fn commit(&mut self, _: [u8; 32], _: &p::CommittedPlaintext) -> std::io::Result<()> {
                Err(std::io::Error::other(
                    "unexpected application during historical bootstrap",
                ))
            }
        }
        let mut app = NoApplication;
        match server_endpoint.serve(
            fixture::accept(&listener)?,
            responder.actor()?,
            &mut app,
            fixture::limits(),
            &p::connection_transport::Cancellation::default(),
            || Ok(at),
        )? {
            p::connection_transport::Served::Established(session) => Ok(session),
            _ => Err("fixture bootstrap returned application result".into()),
        }
    });
    let endpoint = p::connection_transport::ConnectionEndpoint::client(
        &initiator.context,
        initiator.credentials(),
        fixture::tls_limits(),
    )?;
    let name = initiator.peer_name.clone();
    let result = endpoint.establish(
        initiator.actor()?,
        p::InitiationId::generate()?,
        p::connection_transport::Run {
            address,
            server_name: &name,
            limits: fixture::limits(),
            cancel: &p::connection_transport::Cancellation::default(),
        },
        || Ok(at),
    );
    let peer_result = server
        .join()
        .map_err(|_| "historical fixture server panicked")?;
    let result = result?;
    assert_eq!(result.session, peer_result?);
    initiator.close();
    for path in [&s.initiator, &s.responder] {
        fixture::store(path, "session", &result.session)?;
    }
    assert!(at + 60 < fixture::now()?);
    Ok(s)
}

#[test]
fn installed_owner_restores_expired_advertisement_and_reconciles_original_message() -> Result<()> {
    let language = installed_language()?;
    let s = setup_established_expired_advertisement()?;
    let path = &s.initiator;
    let session = fixture::array::<32>(path, "session")?;
    let selected = |command: &str, tail: &[String]| {
        let mut values = vec![OsString::from("--session"), fixture::hex(&session).into()];
        values.extend(args(command, path, tail));
        values
    };
    assert_eq!(
        run(
            path,
            "restore-fresh-refused",
            &args("reject-open", path, &[])
        )?,
        "rejected:104\n"
    );
    let mut wrong = vec![OsString::from("--session"), fixture::hex(&[91; 32]).into()];
    wrong.extend(args("reject-open", path, &[]));
    assert_eq!(
        run(path, "restore-wrong-session", &wrong)?,
        "rejected:201\n"
    );
    let message = id(&run(
        path,
        "restore-next",
        &selected("next", &[fixture::hex(&session)]),
    )?)?;
    let session_text = fixture::hex(&session);
    let message_text = fixture::hex(&message);
    let identity = [session_text.clone(), message_text.clone()];
    assert_eq!(
        run(
            path,
            "restore-cancelled",
            &selected(
                "cancel-send",
                &[
                    "127.0.0.1:1".into(),
                    session_text.clone(),
                    message_text.clone(),
                ]
            )
        )?,
        "cancelled-absent\n"
    );
    assert_eq!(
        id(&run(
            path,
            "restore-same-slot",
            &selected("next", &[fixture::hex(&session)])
        )?)?,
        message
    );
    let (mut server, address) =
        fixture::spawn(&s.responder, 70, "restore-current-crash-after-application")?;
    assert_eq!(
        run(
            path,
            "restore-unknown",
            &selected(
                "uncertain-send",
                &[
                    address.to_string(),
                    fixture::hex(&session),
                    fixture::hex(&message),
                ]
            )
        )?,
        "delivery-unknown-committed\n"
    );
    assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
    fixture::effect(
        &s.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    assert_eq!(
        run(path, "restore-committed", &selected("status", &identity))?,
        "2\n"
    );
    let (mut server, address) = fixture::spawn(&s.responder, 71, "restore-current-application")?;
    assert_eq!(
        run(
            path,
            "restore-exact-resend",
            &selected(
                "send",
                &[
                    address.to_string(),
                    fixture::hex(&session),
                    fixture::hex(&message),
                ]
            )
        )?,
        "consumed\n"
    );
    assert!(fixture::wait(&mut server)?.success());
    fixture::effect(
        &s.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    assert_eq!(
        run(path, "restore-acknowledged", &selected("status", &identity))?,
        "3\n"
    );
    let advertisement_until = u64::from_be_bytes(fixture::array(path, "reopen-test-time")?);
    let current = fixture::now()?;
    assert!(advertisement_until < current);
    let report = format!("{{\"language\":\"{language}\",\"session\":\"{}\",\"message\":\"{}\",\"advertisement_until\":{advertisement_until},\"current_time\":{current},\"fresh_refused\":true,\"wrong_session_refused\":true,\"pre_cancel_absent\":true,\"unknown_commit_reconciled\":true,\"independent_readbacks\":2,\"actual_foreign_clock\":true}}\n", fixture::hex(&session), fixture::hex(&message));
    fixture::store(
        path.parent().ok_or("evidence root")?,
        "c-restore-public-result.json",
        report.as_bytes(),
    )?;
    eprintln!("FOREIGN_SESSION_RESTORE_RESULT {}", report.trim());
    Ok(())
}

#[test]
fn c_account_owner_requires_all_devices_and_reconciles_original_members() -> Result<()> {
    let language = installed_language()?;
    let (setup, extra) = fixture::setup_devices(None, None, None, true, false, true)?;
    let right2 = extra.ok_or("second recipient missing")?;
    let left = &setup.initiator;
    let line_id = |text: &str| id(&format!("{text}\n"));
    let paths = [left.join("peer-0"), left.join("peer-1")];
    let recipients = [&setup.responder, &right2];
    let account = fixture::array::<32>(&setup.responder, "local-account")?;
    assert_eq!(account, fixture::array(&right2, "local-account")?);
    assert_ne!(
        fixture::array::<16>(&setup.responder, "local-device")?,
        fixture::array::<16>(&right2, "local-device")?
    );
    let (mut server0, address0) = fixture::spawn(&setup.responder, 80, "bootstrap")?;
    let (mut server1, address1) = fixture::spawn(&right2, 81, "bootstrap")?;
    let connected = run(
        left,
        "account-connect",
        &args(
            "account-connect",
            left,
            &[
                paths
                    .first()
                    .ok_or("first peer")?
                    .to_string_lossy()
                    .into_owned(),
                paths
                    .get(1)
                    .ok_or("second peer")?
                    .to_string_lossy()
                    .into_owned(),
                address0.to_string(),
                address1.to_string(),
                fixture::hex(p::InitiationId::generate()?.as_bytes()),
                fixture::hex(p::InitiationId::generate()?.as_bytes()),
            ],
        ),
    )?;
    assert!(fixture::wait(&mut server0)?.success());
    assert!(fixture::wait(&mut server1)?.success());
    let sessions = connected
        .split_inclusive('\n')
        .map(id)
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(sessions.len(), 2);
    for (session, path) in sessions.iter().zip(recipients) {
        assert_eq!(*session, fixture::array::<32>(path, "session")?);
    }
    assert_ne!(sessions.first(), sessions.get(1));
    let next = |label: &str| -> Result<[u8; 32]> {
        id(&run(left, label, &args("account-next", left, &[]))?)
    };
    let state = |label: &str, request: &[u8; 32], expected: u8| -> Result<()> {
        assert_eq!(
            run(
                left,
                label,
                &args("account-status", left, &[fixture::hex(request)])
            )?,
            format!("account-status:{expected}\n{}\n", fixture::hex(&[0; 32]))
        );
        Ok(())
    };
    let send_args = |request: &[u8; 32],
                     selected: usize,
                     address: String,
                     mode: &str,
                     extra: Option<&Path>|
     -> Result<Vec<OsString>> {
        let mut arguments = args(
            "account-send",
            left,
            &[
                paths
                    .first()
                    .ok_or("first peer")?
                    .to_string_lossy()
                    .into_owned(),
                fixture::hex(sessions.first().ok_or("first session")?),
                paths
                    .get(1)
                    .ok_or("second peer")?
                    .to_string_lossy()
                    .into_owned(),
                fixture::hex(sessions.get(1).ok_or("second session")?),
                fixture::hex(&account),
                fixture::hex(request),
                selected.to_string(),
                address,
                mode.into(),
            ],
        );
        if let Some(path) = extra {
            arguments.push(path.as_os_str().to_owned());
        }
        Ok(arguments)
    };
    let request = next("account-next")?;
    for (index, (mode, code)) in [
        ("omit", 106),
        ("duplicate-peer", 1),
        ("duplicate-session", 1),
        ("cancel-peer", 302),
        ("closed-peer", 2),
        ("wrong-parent", 211),
    ]
    .into_iter()
    .enumerate()
    {
        let other = (mode == "wrong-parent").then_some(right2.as_path());
        assert_eq!(
            run(
                left,
                &format!("account-refusal-{index}"),
                &send_args(&request, 0, "127.0.0.1:1".into(), mode, other)?
            )?,
            format!("account-refused:{code}\n")
        );
        state(&format!("account-absent-{index}"), &request, 0)?;
    }
    assert_eq!(request, next("account-still-next")?);
    let (mut crashing, address) = fixture::spawn(&setup.responder, 82, "crash-after-application")?;
    assert_eq!(
        run(
            left,
            "account-unknown",
            &send_args(&request, 0, address.to_string(), "unknown", None)?
        )?,
        "account-refused:311\n"
    );
    assert_eq!(fixture::wait(&mut crashing)?.code(), Some(77));
    state("account-committed-unknown", &request, 2)?;
    let mut records = fs::read_dir(&setup.responder)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    records.retain(|name| name.to_string_lossy().starts_with("application-"));
    assert_eq!(records.len(), 1);
    let leaf = records
        .first()
        .ok_or("original application record")?
        .to_str()
        .ok_or("record name")?;
    let original = line_id(
        leaf.strip_prefix("application-")
            .ok_or("application prefix")?,
    )?;
    fixture::effect(
        &setup.responder,
        *sessions.first().ok_or("session")?,
        p::MessageId::from_trusted_state(original)?,
        PAYLOAD,
    )?;
    let mut unary = send_args(&request, 0, "127.0.0.1:1".into(), "unary", None)?;
    unary.push(fixture::hex(&original).into());
    assert_eq!(
        run(left, "account-unary-refused", &unary)?,
        "account-refused:215\n"
    );
    assert_eq!(
        run(
            left,
            "account-changed-input",
            &send_args(&request, 0, "127.0.0.1:1".into(), "changed-input", None)?
        )?,
        "account-refused:211\n"
    );
    let mut delivered = Vec::new();
    for (index, path) in recipients.into_iter().enumerate() {
        let (mut server, address) = fixture::spawn(path, u8::try_from(83 + index)?, "application")?;
        let output = run(
            left,
            &format!("account-deliver-{index}"),
            &send_args(&request, index, address.to_string(), "deliver", None)?,
        )?;
        assert!(fixture::wait(&mut server)?.success());
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.first(), Some(&"account-delivered:1:1"));
        let session = line_id(lines.get(1).ok_or("session output")?)?;
        let message = line_id(lines.get(2).ok_or("message output")?)?;
        assert_eq!(Some(&session), sessions.get(index));
        assert_eq!(
            *lines.get(3).ok_or("device output")?,
            fixture::hex(&fixture::array::<16>(path, "local-device")?)
        );
        if index == 0 {
            assert_eq!(message, original);
        }
        fixture::effect(
            path,
            session,
            p::MessageId::from_trusted_state(message)?,
            PAYLOAD,
        )?;
        delivered.push(message);
        let retained = run(
            left,
            &format!("account-retained-{index}"),
            &send_args(&request, index, "127.0.0.1:1".into(), "retained", None)?,
        )?;
        assert_eq!(
            retained,
            output.replacen("account-delivered:1:1", "account-delivered:1:0", 1)
        );
        assert_eq!(
            run(
                left,
                &format!("account-reversed-{index}"),
                &send_args(
                    &request,
                    index,
                    "127.0.0.1:1".into(),
                    "reverse-retained",
                    None
                )?
            )?,
            retained
        );
    }
    state("account-committed-delivered", &request, 2)?;
    let cancelled = next("account-next-cancel")?;
    assert_ne!(cancelled, request);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let marker = left.join("account-socket-ready");
    let pending = start(
        left,
        "account-cancel-active",
        &send_args(
            &cancelled,
            0,
            listener.local_addr()?.to_string(),
            "cancel-active",
            Some(&marker),
        )?,
    )?;
    let mut stream = fixture::accept(&listener)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut first = [0];
    stream.read_exact(&mut first)?;
    assert_eq!(first, [22]);
    let mut ready = tempfile::NamedTempFile::new_in(left)?;
    ready.write_all(b"1")?;
    ready.as_file().sync_all()?;
    ready
        .persist_noclobber(&marker)
        .map_err(|error| error.error)?;
    fs::File::open(left)?.sync_all()?;
    let observed = finish(pending)?;
    assert!(observed.starts_with("account-refused:302\naccount-cancel-active:"));
    let observation = observed.lines().nth(1).ok_or("cancel observation")?;
    let fields = observation.split(':').collect::<Vec<_>>();
    let elapsed = fields.get(1).ok_or("cancel time")?.parse::<u64>()?;
    assert!(elapsed < 1000);
    assert_eq!(fields.get(2), Some(&"3"));
    drop(stream);
    drop(listener);
    state("account-cancel-committed", &cancelled, 2)?;
    for (index, path) in recipients.into_iter().enumerate() {
        let (mut server, address) = fixture::spawn(path, u8::try_from(85 + index)?, "application")?;
        let output = run(
            left,
            &format!("account-after-cancel-{index}"),
            &send_args(&cancelled, index, address.to_string(), "deliver", None)?,
        )?;
        assert!(fixture::wait(&mut server)?.success());
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.first(), Some(&"account-delivered:1:1"));
        let message = line_id(lines.get(2).ok_or("message")?)?;
        assert_ne!(Some(&message), delivered.get(index));
        fixture::effect(
            path,
            *sessions.get(index).ok_or("session")?,
            p::MessageId::from_trusted_state(message)?,
            PAYLOAD,
        )?;
        delivered.push(message);
    }
    let report = format!("{{\"schema_version\":2,\"language\":\"{language}\",\"completed\":true,\"devices\":3,\"recipients\":2,\"accounts\":2,\"admission_refusals\":6,\"shape_controls\":4,\"unary_refused\":true,\"reversed_targets_reconciled\":true,\"application_readbacks\":5,\"unknown_commit_reconciled\":true,\"cancelled_original_reconciled\":true,\"busy_owners\":3,\"cancellation_ms\":{elapsed},\"release_claim_eligible\":false}}\n");
    fixture::store(left, "c-account-result.json", report.as_bytes())?;
    Ok(())
}
