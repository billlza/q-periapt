// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent OpenSSL TLS endpoint; the authenticated witness engine is shared.
use super::tls::{provision, run_tls, serve_tls};
use super::*;
use std::{
    io::{BufRead, BufReader},
    process::ChildStdin,
};

fn executable() -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("QPERIAPT_WITNESS_OPENSSL_PEER")
            .ok_or("independent OpenSSL witness peer is required")?,
    );
    if !path.is_absolute() || !path.is_file() {
        return Err("invalid OpenSSL peer executable".into());
    }
    Ok(path)
}
fn capture(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
fn public_log(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("OpenSSL public log exceeded bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn result_lines(text: &str, role: &str, count: usize) -> Result<()> {
    let expected = (1..=count).map(|i| format!(
        "OPENSSL_WITNESS_OK role={role} tls=1.3 group=X25519MLKEM768 alpn=q-periapt-anchor/1 exchange={i}\n"
    )).collect::<String>();
    if text != expected {
        return Err(format!("independent TLS result differs: {text}").into());
    }
    Ok(())
}
struct Host {
    child: fixture::OwnedChild,
    input: Arc<Mutex<Option<ChildStdin>>>,
    worker: Option<thread::JoinHandle<Result<usize>>>,
    address: SocketAddr,
    stderr: PathBuf,
}
impl Host {
    fn start(root: &Path, paths: [&Path; 2], store: Arc<Mutex<p::AnchorStore>>) -> Result<Self> {
        let configured = provision(paths)?;
        let [left, right] = paths;
        fixture::store(root, "openssl-server-cert", &configured.certificate)?;
        fixture::store(root, "openssl-server-key", configured.key.as_slice())?;
        // The native TLS configuration is deliberately not used by this peer.
        drop(configured);
        let stderr = root.join("openssl-witness-server.stderr");
        let mut child = fixture::OwnedChild(
            Command::new(executable()?)
                .args(["server", "127.0.0.1:0"])
                .arg(root.join("openssl-server-cert"))
                .arg(root.join("openssl-server-key"))
                .arg(left.join("witness-tls-cert"))
                .arg(left.join("witness-subject"))
                .arg(right.join("witness-tls-cert"))
                .arg(right.join("witness-subject"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(capture(&stderr)?))
                .spawn()?,
        );
        let input = Arc::new(Mutex::new(Some(child.0.stdin.take().ok_or("host input")?)));
        let mut reader = BufReader::new(child.0.stdout.take().ok_or("host output")?);
        let (ready, announcement) = std::sync::mpsc::sync_channel(1);
        let replies = Arc::clone(&input);
        let worker = thread::spawn(move || -> Result<usize> {
            let mut line = String::new();
            (&mut reader).take(96).read_line(&mut line)?;
            let address: SocketAddr = line
                .strip_prefix("LISTEN ")
                .and_then(|v| v.strip_suffix('\n'))
                .ok_or("OpenSSL listener announcement")?
                .parse()?;
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err("OpenSSL listener scope".into());
            }
            ready.send(address)?;
            let mut count = 0;
            loop {
                let mut prefix = [0; 4];
                let first = reader.read(prefix.get_mut(..1).ok_or("prefix slice")?)?;
                if first == 0 {
                    break;
                }
                reader.read_exact(prefix.get_mut(1..).ok_or("prefix tail")?)?;
                if u32::from_be_bytes(prefix) != 3674 {
                    return Err("OpenSSL request frame width".into());
                }
                let mut request = vec![0; 3674];
                reader.read_exact(&mut request)?;
                if count >= 1024 {
                    return Err("OpenSSL reference request capacity".into());
                }
                // This is the first store access for each network request. The
                // independent TLS peer has already checked its exact leaf/scope
                // binding and authenticated request end; native signatures and
                // the original durable transaction still govern the command.
                let reply = store
                    .lock()
                    .map_err(|_| "witness store poisoned")?
                    .handle(&request, fixture::now()?)?;
                if reply.len() != 3659 {
                    return Err("native reply frame width".into());
                }
                let mut input = replies.lock().map_err(|_| "host input poisoned")?;
                let input = input.as_mut().ok_or("host input closed during request")?;
                input.write_all(&3659_u32.to_be_bytes())?;
                input.write_all(&reply)?;
                input.flush()?;
                count += 1;
            }
            Ok(count)
        });
        let mut host = Self {
            child,
            input,
            worker: Some(worker),
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            stderr,
        };
        // On a partial/absent announcement Drop reaps the process before it
        // joins the blocked reader; readiness has its own finite deadline.
        host.address = announcement.recv_timeout(Duration::from_secs(5))?;
        Ok(host)
    }
    fn finish(&mut self) -> Result<usize> {
        self.input.lock().map_err(|_| "host input poisoned")?.take();
        let (status, count, text) = self.complete()?;
        if !status.success() {
            return Err(format!("OpenSSL server {status}: {text}").into());
        }
        result_lines(&text, "server", count)?;
        Ok(count)
    }
    fn rejected(&mut self, reason: &str) -> Result<()> {
        let (status, count, text) = self.complete()?;
        if status.code() != Some(1)
            || count != 0
            || !text.starts_with(&format!("OPENSSL_WITNESS_ERROR {reason}\n"))
            || text.contains("OPENSSL_WITNESS_OK")
        {
            return Err(format!("OpenSSL rejection {status}, {count} store calls: {text}").into());
        }
        Ok(())
    }
    fn complete(&mut self) -> Result<(std::process::ExitStatus, usize, String)> {
        let status = fixture::wait(&mut self.child)?;
        let count = self
            .worker
            .take()
            .ok_or("host worker missing")?
            .join()
            .map_err(|_| "host worker panicked")??;
        let text = public_log(&self.stderr)?;
        Ok((status, count, text))
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            // Error cleanup reaps the process before joining its pipe reader.
            match self.child.0.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(error) = self.child.0.kill() {
                        eprintln!("OpenSSL peer cleanup: {error}");
                    }
                    if let Err(error) = self.child.0.wait() {
                        eprintln!("OpenSSL peer reap: {error}");
                    }
                }
                Err(error) => {
                    eprintln!("OpenSSL peer state: {error}");
                    if let Err(error) = self.child.0.kill() {
                        eprintln!("OpenSSL peer cleanup: {error}");
                    }
                    if let Err(error) = self.child.0.wait() {
                        eprintln!("OpenSSL peer reap: {error}");
                    }
                }
            }
            match worker.join() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => eprintln!("OpenSSL host cleanup: {error}"),
                Err(_) => eprintln!("OpenSSL host cleanup panicked"),
            }
        }
    }
}

fn openssl_client(
    path: &Path,
    label: &str,
    address: SocketAddr,
    request: &[u8],
) -> Result<Vec<u8>> {
    let stderr = path.join(format!("openssl-{label}.stderr"));
    let stdout = path.join(format!("openssl-{label}.reply"));
    fixture::store(path, &format!("openssl-{label}.request"), request)?;
    let mut child = fixture::OwnedChild(
        Command::new(executable()?)
            .arg("client")
            .arg(address.to_string())
            .arg(path.join("witness-tls-cert"))
            .arg(path.join("witness-tls-key"))
            .arg(path.join("witness-tls-peer"))
            .arg("localhost")
            .stdin(Stdio::piped())
            .stdout(Stdio::from(capture(&stdout)?))
            .stderr(Stdio::from(capture(&stderr)?))
            .spawn()?,
    );
    let mut input = child.0.stdin.take().ok_or("client request pipe")?;
    input.write_all(&3674_u32.to_be_bytes())?;
    input.write_all(request)?;
    drop(input);
    let status = fixture::wait(&mut child)?;
    let text = public_log(&stderr)?;
    if !status.success() {
        return Err(format!("OpenSSL client {status}: {text}").into());
    }
    result_lines(&text, "client", 1)?;
    let wire = fixture::read(
        path,
        stdout
            .file_name()
            .ok_or("reply name")?
            .to_str()
            .ok_or("reply UTF8")?,
        3663,
    )?;
    if wire.len() != 3663 || wire.get(..4) != Some(3659_u32.to_be_bytes().as_slice()) {
        return Err("OpenSSL reply width".into());
    }
    Ok(wire.get(4..).ok_or("reply body")?.to_vec())
}

#[test]
fn openssl_client_and_native_witness_exchange_exact_signed_frames() -> Result<()> {
    let mut original = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&original.configured))?;
    original.join()?;
    let left = &setup.initiator;
    let right = &setup.responder;
    let root = left.parent().ok_or("fixture root")?;
    let material = provision([left, right])?;
    let pin = original
        .configured
        .store
        .lock()
        .map_err(|_| "store")?
        .pin()?;
    let key = p::JournalKey::open(&left.join("wrap.key"))?;
    let signer = p::DeviceSigningKey::open(
        &left.join("signer.key"),
        &key,
        p::SigningKeyId::from_trusted_state(fixture::array(left, "signer-id")?)?,
    )?;
    let subject =
        p::AnchorSubject::from_trusted_state(&fixture::read(left, "witness-subject", 96)?)?;
    let mut observed = None;
    for (label, operation) in [("query", None), ("advance", Some([47; 32]))] {
        let operation = if let Some(next) = operation {
            p::AnchorOperation::advance(observed.ok_or("query head")?, next)?
        } else {
            p::AnchorOperation::query()
        };
        let request = p::AnchorRequest::new(&pin, subject, operation, &signer)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let store = Arc::clone(&original.configured.store);
        let server = material.native.clone();
        let worker = thread::spawn(move || -> io::Result<()> {
            let until = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => return Err(error),
                }
            };
            server.serve(
                stream,
                &store,
                until,
                p::Cancellation::default(),
                &mut || fixture::now().map_err(io::Error::other),
            )
        });
        let reply = openssl_client(left, label, address, request.as_bytes());
        let served = worker.join().map_err(|_| "native server panicked")?;
        let reply = pin.verify_reply(&request, &reply?)?;
        served?;
        assert_eq!(
            reply.outcome(),
            if label == "query" {
                p::AnchorOutcome::Current
            } else {
                p::AnchorOutcome::Advanced
            }
        );
        observed = Some(reply.observed_head());
    }
    fixture::store(root,"openssl-client-public-result.json",b"{\"completed\":true,\"exchanges\":2,\"outcomes\":[1,2],\"independent_tls_implementation\":true,\"independent_witness_engine\":false,\"release_claim_eligible\":false}\n")?;
    Ok(())
}

#[test]
fn native_c_owners_and_openssl_witness_reconcile_revoked_cleanup() -> Result<()> {
    let mut original = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&original.configured))?;
    original.join()?;
    let left = &setup.initiator;
    let right = &setup.responder;
    let root = left.parent().ok_or("fixture root")?;
    let mut witness = Host::start(root, [left, right], Arc::clone(&original.configured.store))?;
    let address = witness.address;
    assert_eq!(
        run_tls(left, "openssl-kind", "recover-kind", &[], address, 0)?,
        "operational-owner-not-recovery\n"
    );
    let (receiver, peer) = serve_tls(right, "openssl-bootstrap-server", "bootstrap", address)?;
    let initiation = p::InitiationId::generate()?;
    let session = id(run_tls(
        left,
        "openssl-bootstrap-client",
        "connect",
        &[peer.to_string(), fixture::hex(initiation.as_bytes())],
        address,
        0,
    )?)?;
    assert!(
        finish(receiver, 0)?.contains(&format!("served:1:0:0:0\n{session}\n{}\n", "0".repeat(64)))
    );
    let message = id(run_tls(
        right,
        "openssl-next",
        "next",
        std::slice::from_ref(&session),
        address,
        0,
    )?)?;
    let (receiver, peer) = serve_tls(left, "openssl-message-server", "message", address)?;
    assert_eq!(
        run_tls(
            right,
            "openssl-send",
            "send",
            &[peer.to_string(), session.clone(), message.clone()],
            address,
            0
        )?,
        "consumed\n"
    );
    assert!(finish(receiver, 0)?.contains(&format!("served:2:0:1:1\n{session}\n{message}\n")));
    let mut expected = bytes(&session)?.to_vec();
    expected.extend_from_slice(&bytes(&message)?);
    expected.extend_from_slice(b"persisted before process exit");
    assert_eq!(
        fixture::read(left, &format!("application-{message}"), 4096)?,
        expected
    );
    let mut policy = fixture::sdk(right)?;
    let before = policy.runtime()?.trusted_state();
    let (disabled, signature) = setup.issuer.policy(2, false)?;
    policy.replace_policy(before, &disabled, &signature)?;
    policy.close();
    assert_eq!(
        run_tls(right, "openssl-revoked", "reject-open", &[], address, 0)?,
        "rejected:603\n"
    );
    assert_eq!(
        run_tls(
            right,
            "openssl-cancel",
            "recover-cancel",
            std::slice::from_ref(&session),
            address,
            0
        )?,
        "cancelled-cleanup-not-frozen\n"
    );
    assert_eq!(
        run_tls(
            right,
            "openssl-freeze",
            "recover-freeze",
            std::slice::from_ref(&session),
            address,
            77
        )?,
        ""
    );
    assert_eq!(
        run_tls(
            right,
            "openssl-ack",
            "recover-ack-crash",
            std::slice::from_ref(&session),
            address,
            77
        )?,
        ""
    );
    assert_eq!(
        run_tls(
            right,
            "openssl-retire",
            "recover-finish",
            std::slice::from_ref(&session),
            address,
            0
        )?,
        "original-report-closed-retired\n"
    );
    assert_eq!(
        run_tls(right, "openssl-archive", "recover-archive", &[], address, 0)?,
        "archive-closed-metadata-only\n"
    );
    let exchanges = witness.finish()?;
    assert!(exchanges > 0);
    fixture::store(root,"c-witness-openssl-public-result.json",format!(
        "{{\"completed\":true,\"witness_exchanges\":{exchanges},\"session\":\"{session}\",\"message\":\"{message}\",\"independent_tls_implementation\":true,\"independent_witness_engine\":false,\"release_claim_eligible\":false}}\n").as_bytes())?;
    Ok(())
}

#[test]
fn openssl_rejects_scope_trailing_data_missing_end_and_wrong_protocol_before_store() -> Result<()> {
    let mut original = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&original.configured))?;
    original.join()?;
    let left = &setup.initiator;
    let right = &setup.responder;
    let root = left.parent().ok_or("fixture root")?;
    let pin = original
        .configured
        .store
        .lock()
        .map_err(|_| "store")?
        .pin()?;
    let key = p::JournalKey::open(&left.join("wrap.key"))?;
    let signer = p::DeviceSigningKey::open(
        &left.join("signer.key"),
        &key,
        p::SigningKeyId::from_trusted_state(fixture::array(left, "signer-id")?)?,
    )?;
    let subject =
        p::AnchorSubject::from_trusted_state(&fixture::read(left, "witness-subject", 96)?)?;
    let request = p::AnchorRequest::new(&pin, subject, p::AnchorOperation::query(), &signer)?;
    for (case, reason) in [
        ("wrong-subject", "certificate/subject admission"),
        ("trailing-data", "trailing TLS application bytes"),
        ("missing-end", "missing authenticated TLS end"),
        ("wrong-protocol", "TLS handshake"),
    ] {
        let directory = root.join(case);
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let first = directory.join("first");
        let second = directory.join("second");
        for (destination, source) in [(&first, left), (&second, right)] {
            fs::create_dir(destination)?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
            fixture::store(
                destination,
                "witness-subject",
                &fixture::read(source, "witness-subject", 96)?,
            )?;
        }
        let mut host = Host::start(
            &directory,
            [&first, &second],
            Arc::clone(&original.configured.store),
        )?;
        let client = if case == "wrong-subject" {
            &second
        } else {
            &first
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(fixture::read(client, "witness-tls-peer", 8192)?.into())?;
        let secret = zeroize::Zeroizing::new(fixture::read(client, "witness-tls-key", 8192)?);
        let config = q_periapt_rustls::standard::MutualTlsClient::new(
            roots,
            vec![fixture::read(client, "witness-tls-cert", 8192)?.into()],
            rustls::pki_types::PrivateKeyDer::try_from(secret.as_slice())?.clone_key(),
        )?
        .with_application_protocol(if case == "wrong-protocol" {
            b"q-periapt-wrong/1"
        } else {
            b"q-periapt-anchor/1"
        })?;
        let socket = std::net::TcpStream::connect_timeout(&host.address, Duration::from_secs(3))?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut stream = rustls::StreamOwned::new(config.connect("localhost".try_into()?)?, socket);
        if case == "wrong-protocol" {
            assert!(stream.conn.complete_io(&mut stream.sock).is_err());
        } else {
            stream.write_all(&3674_u32.to_be_bytes())?;
            stream.write_all(request.as_bytes())?;
            if case == "trailing-data" {
                stream.write_all(&[1])?;
            }
            if case != "missing-end" {
                stream.conn.send_close_notify();
            }
            stream.flush()?;
        }
        // A plain TCP close must not substitute for the authenticated end.
        drop(stream);
        host.rejected(reason)?;
    }
    fixture::store(root, "openssl-rejections-public-result.json", b"{\"completed\":true,\"cases\":[\"wrong-subject\",\"trailing-data\",\"missing-end\",\"wrong-protocol\"],\"store_calls\":0,\"independent_tls_implementation\":true,\"independent_witness_engine\":false,\"release_claim_eligible\":false}\n")?;
    Ok(())
}
