// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Archive-shipped public API recovery, with a separate device process and a real
//! signed TCP witness. The injected clock is protocol time, not a wall-clock wait.
use super::*;
use p::AnchorTransport;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};

struct Capture {
    at: u64,
    request: Vec<u8>,
    reply: Option<Vec<u8>>,
}
struct Witness {
    _directory: tempfile::TempDir,
    configured: WitnessFixture,
    clock: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    captures: Arc<Mutex<Vec<Capture>>>,
    worker: Option<std::thread::JoinHandle<Result<()>>>,
}
impl Witness {
    fn start(at: u64) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = directory.path().canonicalize()?;
        let store = Arc::new(Mutex::new(p::AnchorStore::provision(
            &path.join("witness.redb"),
            p::JournalKey::provision(&path.join("wrap.key"))?,
            p::AnchorSigningKey::generate()?,
            p::AnchorIdentity::generate()?,
        )?));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let clock = Arc::new(AtomicU64::new(at));
        let stop = Arc::new(AtomicBool::new(false));
        let captures = Arc::new(Mutex::new(Vec::new()));
        let (state, time, stopped, records) = (
            Arc::clone(&store),
            Arc::clone(&clock),
            Arc::clone(&stop),
            Arc::clone(&captures),
        );
        let worker = std::thread::spawn(move || -> Result<()> {
            while !stopped.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                // Accepted sockets may inherit the listener's nonblocking mode.
                // The bounded framed exchange below uses blocking I/O timeouts.
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let mut size = [0; 4];
                stream.read_exact(&mut size)?;
                if u32::from_be_bytes(size) != 3674 {
                    return Err("witness request length".into());
                }
                let mut request = vec![0; 3674];
                stream.read_exact(&mut request)?;
                let at = time.load(Ordering::Acquire);
                let reply = match state
                    .lock()
                    .map_err(|_| "witness poisoned")?
                    .handle(&request, at)
                {
                    Ok(reply) => Some(reply),
                    // This exact native rejection is the intended expiry case.
                    // No acknowledgement is fabricated for the failed command.
                    Err(p::AnchorError::Rejected(p::Error::Validity)) => None,
                    Err(error) => return Err(error.into()),
                };
                let mut log = records.lock().map_err(|_| "capture poisoned")?;
                if log.len() >= 256 {
                    return Err("witness capture limit".into());
                }
                log.push(Capture {
                    at,
                    request,
                    reply: reply.clone(),
                });
                drop(log);
                if let Some(reply) = reply {
                    stream.write_all(&u32::try_from(reply.len())?.to_be_bytes())?;
                    stream.write_all(&reply)?;
                }
            }
            Ok(())
        });
        Ok(Self {
            _directory: directory,
            configured: WitnessFixture { store, address },
            clock,
            stop,
            captures,
            worker: Some(worker),
        })
    }
    fn join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "witness panicked")??;
        }
        Ok(())
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        if let Err(error) = self.join() {
            eprintln!("roster witness cleanup failed: {error}");
        }
    }
}
fn pin(path: &Path) -> Result<p::AnchorPin> {
    Ok(p::AnchorPin::new(
        p::AnchorIdentity::from_trusted_state(array(path, "witness-id")?)?,
        p::PublicKey::decode(&read(path, "witness-public", p::PUBLIC_KEY_BYTES)?)?,
    ))
}
fn signer(path: &Path) -> Result<p::DeviceSigningKey> {
    Ok(p::DeviceSigningKey::open(
        &path.join("signer.key"),
        &key(path)?,
        p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?,
    )?)
}
fn client(path: &Path, address: SocketAddr) -> Result<p::AnchorClient> {
    Ok(p::AnchorClient::new(
        pin(path)?,
        signer(path)?,
        Box::new(p::AnchorTcpTransport::new(address)),
        Duration::from_secs(3),
    )?)
}
fn subject(path: &Path) -> Result<p::AnchorSubject> {
    Ok(p::AnchorSubject::from_trusted_state(&read(
        path,
        "witness-subject",
        96,
    )?)?)
}
fn checkpoint(path: &Path, version: u64) -> Result<p::RosterCheckpoint> {
    Ok(p::RosterCheckpoint::from_trusted_state(
        version,
        array(path, &format!("renewal-digest-{version}"))?,
    )?)
}
fn account_for(path: &Path, version: u64) -> Result<p::AccountPin> {
    Ok(p::AccountPin::new(
        array(path, "local-account")?,
        p::PublicKey::decode(&read(path, "local-root", p::PUBLIC_KEY_BYTES)?)?,
        checkpoint(path, version)?,
        array(path, "family")?,
    )?)
}
fn device(path: &Path, version: u64, at: u64) -> Result<p::VerifiedDevice> {
    Ok(account_for(path, version)?.verify_device(
        &read(path, "local-certificate", 8192)?,
        &read(path, &format!("renewal-roster-{version}"), 8192)?,
        at,
    )?)
}
fn observe(path: &Path, address: SocketAddr) -> Result<Vec<u8>> {
    let pin = pin(path)?;
    let request = p::AnchorRequest::new(
        &pin,
        subject(path)?,
        p::AnchorOperation::query(),
        &signer(path)?,
    )?;
    let wire = p::AnchorTcpTransport::new(address)
        .exchange(request.as_bytes(), Instant::now() + Duration::from_secs(3))?;
    let reply = pin.verify_reply(&request, &wire)?;
    assert_eq!(reply.outcome(), p::AnchorOutcome::Current);
    let head = reply.observed_head();
    let mut bytes = head.fence().to_be_bytes().to_vec();
    bytes.extend_from_slice(&head.revision().to_be_bytes());
    bytes.extend_from_slice(&head.digest());
    bytes.extend_from_slice(&reply.last_command_id().ok_or("expected committed head")?);
    Ok(bytes)
}
fn expect_unacknowledged(error: &p::DurableError) {
    assert!(
        matches!(error, p::DurableError::Anchor(error) if matches!(**error,
        p::AnchorClientError::Transport(ref error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset))),
        "wrong failure: {error:?}"
    );
}
fn request_id() -> Result<p::InitiationId> {
    Ok(p::InitiationId::from_trusted_state([51; 32])?)
}

pub(super) fn device_process(path: &Path, mode: &str) -> Result<()> {
    let at = u64::from_be_bytes(array(path, "renewal-time")?);
    let address: SocketAddr = String::from_utf8(read(path, "renewal-address", 128)?)?.parse()?;
    store(
        path,
        &format!("{mode}-pid"),
        &u64::from(std::process::id()).to_be_bytes(),
    )?;
    let opened = Peer::open_with_anchor(path, Some(client(path, address)?), at);
    if mode == "expired" {
        let error = match opened {
            Ok(_) => return Err("expired witness admitted pending write".into()),
            Err(error) => error,
        };
        expect_unacknowledged(
            error
                .downcast_ref::<p::DurableError>()
                .ok_or("non-journal open failure")?,
        );
        return Ok(());
    }
    let mut peer = opened?;
    let context = Arc::clone(&peer.context);
    let journal = peer.service.stores()?.0;
    if mode == "recover" {
        assert_eq!(
            journal.roster_checkpoint(array(path, "local-account")?)?,
            checkpoint(path, 3)?
        );
        store(path, "recovered-journal", journal.identity()?.as_bytes())?;
        store(path, "recovered-checkpoint", &checkpoint(path, 3)?.digest())?;
        store(path, "recovered-context", &context.digest())?;
        let outbox = journal.resume_initial(context, request_id()?, at)?;
        store(path, "restored-outbox", &outbox)?;
        let before = observe(path, address)?;
        journal.install_roster(device(path, 3, at)?.roster(), at)?;
        assert_eq!(
            observe(path, address)?,
            before,
            "roster retry advanced twice"
        );
        store(path, "retried-head", &before)?;
    } else if mode == "revoke" {
        let revoked =
            account_for(path, 4)?.verify_roster(&read(path, "renewal-roster-4", 8192)?, at)?;
        journal.install_roster(&revoked, at)?;
        assert!(matches!(
            journal.resume_initial(Arc::clone(&context), request_id()?, at),
            Err(p::DurableError::Protocol(p::Error::Scope))
        ));
        peer.close();
        peer = Peer::open_with_anchor(path, Some(client(path, address)?), at)?;
        assert!(matches!(
            peer.service
                .stores()?
                .0
                .resume_initial(Arc::clone(&peer.context), request_id()?, at),
            Err(p::DurableError::Protocol(p::Error::Scope))
        ));
        store(
            path,
            "revoked-checkpoint",
            &peer
                .service
                .stores()?
                .0
                .roster_checkpoint(array(path, "local-account")?)?
                .digest(),
        )?;
    } else {
        return Err("unknown roster device mode".into());
    }
    peer.close();
    Ok(())
}

pub(super) fn public_roster_refresh_recovers_original_intent_over_signed_tcp() -> Result<()> {
    let at = now()?;
    let expired = at.checked_add(60).ok_or("protocol clock overflow")?;
    let mut witness = Witness::start(at)?;
    let (s, _) = setup_devices_for(
        Some(&witness.configured),
        None,
        Some(at),
        false,
        false,
        true,
        true,
    )?;
    let root = s.initiator.parent().ok_or("evidence root")?;
    let public = root.join("public");
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    let path = &s.initiator;
    let address = witness.configured.address;
    let mut peer = Peer::open_at_with_witness(path, Some(&witness.configured), at)?;
    let short = device(path, 2, at)?;
    let next = device(path, 3, expired)?;
    let subject = subject(path)?;
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness poisoned")?
        .update_roster_authority(
            subject,
            peer.context
                .device(p::BootstrapRole::Initiator)
                .roster()
                .checkpoint(),
            &short,
            peer.context.policy(),
            at,
        )?;
    let context = Arc::clone(&peer.context);
    let journal = peer.service.stores()?.0;
    journal.install_roster(short.roster(), at)?;
    store(&public, "original-journal", journal.identity()?.as_bytes())?;
    let initial = journal.initiate(Arc::clone(&context), request_id()?, &peer.signer, at)?;
    store(&public, "original-outbox", &initial)?;
    store(&public, "original-context", &context.digest())?;
    let before = observe(path, address)?;
    store(&public, "before-head", &before)?;
    let start = witness
        .captures
        .lock()
        .map_err(|_| "capture poisoned")?
        .len();
    witness.clock.store(expired, Ordering::Release);
    assert!(matches!(
        journal.resume_initial(Arc::clone(&context), request_id()?, expired),
        Err(p::DurableError::Protocol(p::Error::Validity))
    ));
    expect_unacknowledged(
        &journal
            .install_roster(next.roster(), expired)
            .expect_err("expired witness accepted new write"),
    );
    assert!(matches!(journal.identity(), Err(p::DurableError::Closed)));
    peer.close();
    store(path, "renewal-time", &expired.to_be_bytes())?;
    store(path, "renewal-address", address.to_string().as_bytes())?;
    let mut blocked = child(path, 81, "roster-renewal-expired")?;
    assert!(wait(&mut blocked)?.success());
    assert_eq!(observe(path, address)?, before);
    store(&public, "expired-head", &before)?;
    let expired_end = witness
        .captures
        .lock()
        .map_err(|_| "capture poisoned")?
        .len();
    // The independently admitted new roster changes authority metadata only.
    let mut policy_store = sdk(path)?;
    let policy = protocol_policy(path, &policy_store)?;
    let admitted = witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness poisoned")?
        .update_roster_authority(
            subject,
            short.roster().checkpoint(),
            &next,
            &policy,
            expired,
        )?;
    assert_eq!(admitted, next.roster().checkpoint());
    store(&public, "admitted-checkpoint", &admitted.digest())?;
    assert_eq!(observe(path, address)?, before);
    store(&public, "refreshed-head", &before)?;
    let refreshed_end = witness
        .captures
        .lock()
        .map_err(|_| "capture poisoned")?
        .len();
    policy.close();
    policy_store.close();
    let mut recovered = child(path, 82, "roster-renewal-recover")?;
    assert!(wait(&mut recovered)?.success());
    let after = observe(path, address)?;
    assert_eq!(after.get(..8), before.get(..8));
    assert_eq!(
        u64::from_be_bytes(after.get(8..16).ok_or("head revision")?.try_into()?),
        u64::from_be_bytes(before.get(8..16).ok_or("head revision")?.try_into()?) + 1
    );
    assert_eq!(read(path, "restored-outbox", 65536)?, initial);
    store(&public, "recovered-head", &after)?;
    let end = witness
        .captures
        .lock()
        .map_err(|_| "capture poisoned")?
        .len();
    let mut phases = Vec::new();
    for boundary in [expired_end, refreshed_end, end] {
        phases.extend_from_slice(
            &u64::try_from(boundary.checked_sub(start).ok_or("capture boundary")?)?.to_be_bytes(),
        );
    }
    store(&public, "trace-phases", &phases)?;
    let mut revoked = child(path, 83, "roster-renewal-revoke")?;
    assert!(wait(&mut revoked)?.success());
    witness.join()?;
    for (attempt, mode) in [(81, "expired"), (82, "recover"), (83, "revoke")] {
        store(
            &public,
            &format!("{mode}-process.stdout"),
            &read(path, &format!("peer-{attempt}.log"), 65536)?,
        )?;
    }
    for name in [
        "witness-subject",
        "local-account",
        "local-certificate",
        "local-root",
        "witness-public",
        "witness-id",
        "renewal-roster-2",
        "renewal-roster-3",
        "renewal-roster-4",
        "renewal-digest-2",
        "renewal-digest-3",
        "renewal-digest-4",
        "recovered-journal",
        "recovered-checkpoint",
        "recovered-context",
        "restored-outbox",
        "retried-head",
        "revoked-checkpoint",
        "expired-pid",
        "recover-pid",
        "revoke-pid",
    ] {
        store(&public, name, &read(path, name, 65536)?)?;
    }
    let captures = witness.captures.lock().map_err(|_| "capture poisoned")?;
    let records = captures.get(start..end).ok_or("capture range")?;
    for (index, capture) in records.iter().enumerate() {
        store(
            &public,
            &format!("trace-{index:03}.request"),
            &capture.request,
        )?;
        store(
            &public,
            &format!("trace-{index:03}.time"),
            &capture.at.to_be_bytes(),
        )?;
        match &capture.reply {
            Some(reply) => store(&public, &format!("trace-{index:03}.reply"), reply)?,
            None => store(
                &public,
                &format!("trace-{index:03}.rejection"),
                b"Rejected(Validity)",
            )?,
        }
    }
    let report = format!("{{\"schema\":1,\"parent_pid\":{},\"initial_time\":{at},\"expired_time\":{expired},\"trace_count\":{},\"device_exit_codes\":[0,0,0],\"carrier\":\"signed-tcp\",\"clock\":\"injected-protocol-time\"}}\n", std::process::id(), records.len());
    store(&public, "public-roster-result.json", report.as_bytes())?;
    Ok(())
}
