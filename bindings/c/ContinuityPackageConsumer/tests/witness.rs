// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual installed C owners against an independently owned native witness socket.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "witness/opening.rs"]
mod opening;
#[path = "witness/openssl.rs"]
mod openssl;
#[path = "witness/tls.rs"]
mod tls;
use q_periapt_continuity_identity_candidate as p;
use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Capture {
    request: Vec<u8>,
    reply: Vec<u8>,
    delivered: bool,
}
struct Witness {
    _directory: tempfile::TempDir,
    configured: fixture::WitnessFixture,
    stop: Arc<AtomicBool>,
    fault: Arc<AtomicU8>,
    hold_marker: Arc<Mutex<Option<PathBuf>>>,
    captured: Arc<Mutex<Vec<Capture>>>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl Witness {
    fn start() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = directory.path().canonicalize()?;
        let key = p::JournalKey::provision(&path.join("wrap.key"))?;
        let store = p::AnchorStore::provision(
            &path.join("witness.redb"),
            key,
            p::AnchorSigningKey::generate()?,
            p::AnchorIdentity::generate()?,
        )?;
        let store = Arc::new(Mutex::new(store));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let fault = Arc::new(AtomicU8::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let hold_marker: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
        let held = Arc::clone(&hold_marker);
        let control = Arc::clone(&stop);
        let pending = Arc::clone(&fault);
        let records = Arc::clone(&captured);
        let witness = Arc::clone(&store);
        let worker = thread::spawn(move || -> Result<()> {
            while !control.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let mut size = [0; 4];
                stream.read_exact(&mut size).map_err(|error| {
                    io::Error::new(error.kind(), format!("witness request prefix: {error}"))
                })?;
                if u32::from_be_bytes(size) != 3674 {
                    return Err("witness request frame differs".into());
                }
                let mut request = vec![0; 3674];
                stream.read_exact(&mut request).map_err(|error| {
                    io::Error::new(error.kind(), format!("witness request body: {error}"))
                })?;
                let mut reply = witness
                    .lock()
                    .map_err(|_| "witness lock poisoned")?
                    .handle(&request, fixture::now()?)?;
                if reply.len() != 3659 {
                    return Err("witness reply frame differs".into());
                }
                // Inspect only the public signed outcome AFTER the real witness
                // authenticated the request and durably applied its transition.
                let advanced = reply.get(204) == Some(&2);
                let mut delivered = true;
                if (advanced
                    && pending
                        .compare_exchange(3, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok())
                    || pending
                        .compare_exchange(4, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    let marker = held
                        .lock()
                        .map_err(|_| "hold lock poisoned")?
                        .take()
                        .ok_or("missing cancellation barrier")?;
                    let mut prefix = (reply.len() as u32).to_be_bytes().to_vec();
                    prefix.extend_from_slice(reply.get(..1800).ok_or("reply prefix")?);
                    stream.write_all(&prefix)?;
                    fixture::store(
                        marker.parent().ok_or("marker parent")?,
                        "witness-cancelled-prefix",
                        &prefix,
                    )?;
                    fixture::store(
                        marker.parent().ok_or("marker parent")?,
                        marker
                            .file_name()
                            .ok_or("marker name")?
                            .to_str()
                            .ok_or("marker encoding")?,
                        b"1",
                    )?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut byte = [0];
                    if stream.read(&mut byte)? != 0 {
                        return Err("cancelled witness connection sent extra bytes".into());
                    }
                    delivered = false;
                } else if advanced
                    && pending
                        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    delivered = false;
                } else if pending
                    .compare_exchange(2, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let last = reply.last_mut().ok_or("empty witness reply")?;
                    *last ^= 1;
                }
                let mut log = records
                    .lock()
                    .map_err(|_| "witness capture lock poisoned")?;
                if log.len() >= 4096 {
                    return Err("witness capture capacity".into());
                }
                log.push(Capture {
                    request,
                    reply: reply.clone(),
                    delivered,
                });
                drop(log);
                if delivered {
                    stream
                        .write_all(&u32::try_from(reply.len())?.to_be_bytes())
                        .map_err(|error| {
                            io::Error::new(error.kind(), format!("witness reply prefix: {error}"))
                        })?;
                    stream.write_all(&reply).map_err(|error| {
                        io::Error::new(error.kind(), format!("witness reply body: {error}"))
                    })?;
                }
            }
            Ok(())
        });
        Ok(Self {
            _directory: directory,
            configured: fixture::WitnessFixture { store, address },
            stop,
            fault,
            captured,
            hold_marker,
            worker: Some(worker),
        })
    }
    fn arm(&self, fault: u8) -> Result<()> {
        self.fault
            .compare_exchange(0, fault, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "unconsumed witness fault")?;
        Ok(())
    }
    fn hold_next_advance(&self, marker: PathBuf) -> Result<()> {
        let mut pending = self.hold_marker.lock().map_err(|_| "hold lock poisoned")?;
        if pending.is_some() {
            return Err("unconsumed hold marker".into());
        }
        self.arm(3)?;
        *pending = Some(marker);
        Ok(())
    }
    fn hold_next_reply(&self, marker: PathBuf) -> Result<()> {
        let mut pending = self.hold_marker.lock().map_err(|_| "hold lock poisoned")?;
        if pending.is_some() {
            return Err("unconsumed hold marker".into());
        }
        self.arm(4)?;
        *pending = Some(marker);
        Ok(())
    }
    fn join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "witness worker panicked")??;
        }
        Ok(())
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Normal completion checks join explicitly. During unwinding report a
        // worker failure rather than silently treating cleanup as success.
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("witness cleanup failed: {error}"),
                Err(_) => eprintln!("witness cleanup worker panicked"),
            }
        }
    }
}
struct Process {
    child: fixture::OwnedChild,
    stdout: PathBuf,
    stderr: PathBuf,
}
fn start(
    path: &Path,
    label: &str,
    mode: &str,
    tail: &[String],
    witness: Option<SocketAddr>,
) -> Result<Process> {
    start_carrier(path, label, mode, tail, witness, "--witness")
}
fn start_carrier(
    path: &Path,
    label: &str,
    mode: &str,
    tail: &[String],
    witness: Option<SocketAddr>,
    carrier: &str,
) -> Result<Process> {
    let client = PathBuf::from(
        std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("installed C client missing")?,
    );
    if !client.is_absolute() || !client.is_file() {
        return Err("invalid installed C path".into());
    }
    let stdout = path.join(format!("witness-{label}.stdout"));
    let stderr = path.join(format!("witness-{label}.stderr"));
    let file = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    let mut command = Command::new(client);
    if let Some(address) = witness {
        command.args([carrier, &address.to_string()]);
    }
    command
        .arg(mode)
        .arg(path)
        .args(tail)
        .stdout(Stdio::from(file(&stdout)?))
        .stderr(Stdio::from(file(&stderr)?));
    Ok(Process {
        child: fixture::OwnedChild(command.spawn()?),
        stdout,
        stderr,
    })
}
fn finish(mut process: Process, expected: i32) -> Result<String> {
    let status = fixture::wait(&mut process.child)?;
    let stdout = fs::read_to_string(&process.stdout)?;
    let stderr = fs::read_to_string(&process.stderr)?;
    if status.code() != Some(expected) || !stderr.is_empty() || stdout.len() > 65536 {
        return Err(format!("C witness command: {status}; {stdout}; {stderr}").into());
    }
    Ok(stdout)
}
fn run(
    path: &Path,
    label: &str,
    mode: &str,
    tail: &[String],
    witness: Option<SocketAddr>,
    expected: i32,
) -> Result<String> {
    finish(start(path, label, mode, tail, witness)?, expected)
}
fn server(
    path: &Path,
    label: &str,
    mode: &str,
    session: Option<&str>,
    witness: SocketAddr,
) -> Result<(Process, SocketAddr)> {
    let mut tail = vec![mode.to_owned()];
    if let Some(session) = session {
        tail.push(session.to_owned());
    }
    listening(start(path, label, "serve", &tail, Some(witness))?)
}
fn listening(mut process: Process) -> Result<(Process, SocketAddr)> {
    let until = Instant::now() + Duration::from_secs(25);
    loop {
        let output = fs::read_to_string(&process.stdout)?;
        if let Some(line) = output.lines().next() {
            let port: u16 = line
                .strip_prefix("listening:")
                .ok_or("C listener marker")?
                .parse()?;
            if port == 0 {
                return Err("zero witness-case listener".into());
            }
            return Ok((process, SocketAddr::from(([127, 0, 0, 1], port))));
        }
        if process.child.0.try_wait()?.is_some() || Instant::now() >= until {
            return Err(format!(
                "C witness listener unavailable: {}",
                fs::read_to_string(&process.stderr)?
            )
            .into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn id(output: String) -> Result<String> {
    if output.len() != 65
        || !output.ends_with('\n')
        || !output
            .trim()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical C witness identity".into());
    }
    Ok(output.trim().to_owned())
}
fn bytes(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err("identity width".into());
    }
    let mut result = [0; 32];
    for (byte, pair) in result.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(result)
}
#[test]
fn c_witness_owners_reconcile_actual_lost_advances_and_revoked_cleanup() -> Result<()> {
    let mut witness = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let endpoint = witness.configured.address;
    let left = &setup.initiator;
    let right = &setup.responder;
    assert_eq!(
        run(left, "missing", "reject-open", &[], None, 0)?,
        "rejected:216\n"
    );
    let original = fixture::array::<32>(left, "witness-id")?;
    let different = p::AnchorIdentity::generate()?;
    fs::write(left.join("witness-id"), different.as_bytes())?;
    assert_eq!(
        run(left, "wrong-pin", "reject-open", &[], Some(endpoint), 0)?,
        "rejected:211\n"
    );
    fs::write(left.join("witness-id"), original)?;
    witness.arm(2)?;
    assert_eq!(
        run(left, "bad-signature", "reject-open", &[], Some(endpoint), 0)?,
        "rejected:218\n"
    );
    let (receiver, address) = server(right, "bootstrap-server", "bootstrap", None, endpoint)?;
    let request = p::InitiationId::generate()?;
    let session = id(run(
        left,
        "bootstrap-client",
        "connect",
        &[address.to_string(), fixture::hex(request.as_bytes())],
        Some(endpoint),
        0,
    )?)?;
    let served = finish(receiver, 0)?;
    assert!(served.contains(&format!("served:1:0:0:0\n{session}\n{}\n", "0".repeat(64))));
    let message = id(run(
        right,
        "next",
        "next",
        std::slice::from_ref(&session),
        Some(endpoint),
        0,
    )?)?;
    let marker = right.join("witness-cancel-ready");
    witness.hold_next_advance(marker.clone())?;
    let cancelled = run(
        right,
        "lost-send",
        "cancel-witness-send",
        &[
            "127.0.0.1:9".into(),
            session.clone(),
            message.clone(),
            marker.to_str().ok_or("marker path")?.to_owned(),
        ],
        Some(endpoint),
        0,
    )?;
    let cancellation_ms: u64 = cancelled
        .strip_prefix("witness-cancelled-outcome-unavailable:")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or("cancellation output")?
        .parse()?;
    assert!(cancellation_ms < 1000);
    assert_eq!(
        run(
            right,
            "reserved",
            "status",
            &[session.clone(), message.clone()],
            Some(endpoint),
            0
        )?,
        "1\n"
    );
    let (receiver, address) = server(left, "application-server", "message", None, endpoint)?;
    assert_eq!(
        run(
            right,
            "exact-send",
            "send",
            &[address.to_string(), session.clone(), message.clone()],
            Some(endpoint),
            0
        )?,
        "consumed\n"
    );
    assert!(finish(receiver, 0)?.contains(&format!("served:2:0:1:1\n{session}\n{message}\n")));
    let mut expected = bytes(&session)?.to_vec();
    expected.extend_from_slice(&bytes(&message)?);
    expected.extend_from_slice(b"persisted before process exit");
    assert_eq!(
        fixture::read(left, &format!("application-{message}"), 65536)?,
        expected
    );
    let (receiver, address) = server(right, "rekey-server", "rekey", Some(&session), endpoint)?;
    assert_eq!(
        run(
            left,
            "rekey-client",
            "rekey",
            &[address.to_string(), session.clone()],
            Some(endpoint),
            0
        )?,
        "rekey-1-confirmed\n"
    );
    assert!(finish(receiver, 0)?.ends_with("server-rekey-1\n"));
    let message2 = id(run(
        right,
        "next-after-rekey",
        "next",
        std::slice::from_ref(&session),
        Some(endpoint),
        0,
    )?)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let unavailable = listener.local_addr()?;
    drop(listener);
    assert_eq!(
        run(
            right,
            "unknown-send",
            "uncertain-send",
            &[unavailable.to_string(), session.clone(), message2.clone()],
            Some(endpoint),
            0
        )?,
        "delivery-unknown-committed\n"
    );
    let mut native = fixture::Peer::open_with_witness(right, Some(&witness.configured))?;
    let context = fixture::hex(&native.context.digest());
    let unknown = p::MessageId::from_trusted_state(bytes(&message2)?)?;
    assert_eq!(
        native
            .service
            .stores()?
            .0
            .message_status(&native.context, bytes(&session)?, unknown)?,
        p::MessageStatus::Committed
    );
    let wire = native.service.stores()?.0.send_message(
        &native.context,
        bytes(&session)?,
        unknown,
        b"persisted before process exit",
        b"owned-service",
        fixture::now()?,
    )?;
    fixture::store(right, "witness-unknown-wire", &wire)?;
    fixture::store(
        right,
        "native-closure-archive",
        native.service.stores()?.1.get(bytes(&session)?)?.as_bytes(),
    )?;
    native.close();
    let mut policy = fixture::sdk(right)?;
    let before = policy.runtime()?.trusted_state();
    let (disabled, signature) = setup.issuer.policy(2, false)?;
    policy.replace_policy(before, &disabled, &signature)?;
    policy.close();
    assert_eq!(
        run(right, "revoked", "reject-open", &[], Some(endpoint), 0)?,
        "rejected:603\n"
    );
    assert_eq!(
        run(
            right,
            "cleanup-missing",
            "recover-reject-select",
            std::slice::from_ref(&session),
            None,
            0
        )?,
        "selection-refused:216\n"
    );
    assert_eq!(
        run(
            right,
            "cleanup-cancel",
            "recover-cancel",
            std::slice::from_ref(&session),
            Some(endpoint),
            0
        )?,
        "cancelled-cleanup-not-frozen\n"
    );
    let paths = p::InstallationPaths::new(
        &right.join("installation.redb"),
        &right.join("journal.redb"),
        &right.join("archives.redb"),
    )?;
    let discovery =
        p::InstallationRecovery::open(paths, p::JournalKey::open(&right.join("wrap.key"))?)?;
    let mut unfrozen =
        discovery.open_session(bytes(&session)?, Some(witness.configured.client(right)?))?;
    assert_eq!(
        unfrozen.stores()?.0.status()?,
        p::SessionClosureStatus::Open
    );
    unfrozen.close();
    witness.arm(1)?;
    assert_eq!(
        run(
            right,
            "lost-freeze",
            "recover-witness-failed-freeze",
            std::slice::from_ref(&session),
            Some(endpoint),
            0
        )?,
        "witness-freeze-outcome-unavailable\n"
    );
    assert_eq!(
        run(
            right,
            "freeze",
            "recover-freeze",
            std::slice::from_ref(&session),
            Some(endpoint),
            77
        )?,
        ""
    );
    let accounting = fixture::read(right, "c-loss-report", 1048576)?;
    assert!(
        String::from_utf8(accounting.clone())?.contains(&format!("unconfirmed 1 0 {message2} "))
    );
    assert_eq!(
        run(
            right,
            "ack",
            "recover-ack-crash",
            std::slice::from_ref(&session),
            Some(endpoint),
            77
        )?,
        ""
    );
    assert_eq!(
        run(
            right,
            "retire",
            "recover-finish",
            std::slice::from_ref(&session),
            Some(endpoint),
            0
        )?,
        "original-report-closed-retired\n"
    );
    assert_eq!(
        run(right, "archive", "recover-archive", &[], Some(endpoint), 0)?,
        "archive-closed-metadata-only\n"
    );
    assert_eq!(fixture::read(right, "c-loss-report", 1048576)?, accounting);
    assert_eq!(
        run(
            right,
            "closed-missing",
            "recover-reject-archive",
            &[],
            None,
            0
        )?,
        "archive-refused:216\n"
    );
    let paths = p::InstallationPaths::new(
        &right.join("installation.redb"),
        &right.join("journal.redb"),
        &right.join("archives.redb"),
    )?;
    let mut discovery =
        p::InstallationRecovery::open(paths, p::JournalKey::open(&right.join("wrap.key"))?)?;
    assert!(discovery.session_ids()?.is_empty());
    let archive = p::SessionClosureArchive::from_bytes(&fixture::read(
        right,
        "native-closure-archive",
        1024,
    )?)?;
    let mut checked =
        discovery.open_session_from_archive(&archive, Some(witness.configured.client(right)?))?;
    let p::SessionClosureStatus::Closed(closed) = checked.stores()?.0.status()? else {
        return Err("witnessed closure not durable".into());
    };
    checked.close();
    witness.join()?;
    assert_eq!(
        run(
            right,
            "closed-unavailable",
            "recover-reject-archive",
            &[],
            Some(endpoint),
            0
        )?,
        "archive-refused:218\n"
    );
    assert_eq!(witness.fault.load(Ordering::Acquire), 0);
    let records = witness
        .captured
        .lock()
        .map_err(|_| "capture lock poisoned")?;
    let lost = records.iter().filter(|r| !r.delivered).collect::<Vec<_>>();
    assert_eq!(lost.len(), 2);
    for record in &lost {
        let command = record.request.get(140..172).ok_or("command ID")?;
        assert_eq!(record.reply.get(204), Some(&2));
        assert!(records.iter().any(|retry| retry.delivered
            && retry.reply.get(204) == Some(&3)
            && retry.request.get(140..172) == Some(command)
            && retry.request.get(172..204) != record.request.get(172..204)));
    }
    let mut transcript = Vec::new();
    for record in records.iter() {
        transcript.push(u8::from(record.delivered));
        transcript.extend_from_slice(&record.request);
        transcript.extend_from_slice(&record.reply);
    }
    let root = right.parent().ok_or("witness runtime root")?;
    fixture::store(root, "witness-transcript", &transcript)?;
    let report=format!(concat!("{{\"schema_version\":1,\"completed\":true,\"session\":\"{}\",\"message\":\"{}\",\"unknown\":\"{}\",",
        "\"context\":\"{}\",\"peer_account\":\"{}\",\"peer_device\":\"{}\",\"report\":\"{}\",",
        "\"witness_exchanges\":{},\"lost_advances\":2,\"release_claim_eligible\":false}}\n"),
        session,message,message2,context,
        fixture::hex(&fixture::array::<32>(right,"initiator-account")?),
        fixture::hex(&fixture::array::<16>(right,"initiator-device")?),
        fixture::hex(closed.as_bytes()),records.len());
    fixture::store(root, "c-witness-public-result.json", report.as_bytes())?;
    Ok(())
}
