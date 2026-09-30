// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, Fixture},
    durable::tests::{directory, new_store},
    AnchorGenesis, AnchorHead, AnchorIdentity, AnchorOperation, AnchorOutcome, AnchorPin,
    AnchorRequest, AnchorSigningKey, DeviceJournal, JournalKey, PrekeyQuality,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::DirBuilderExt,
    sync::mpsc,
};

fn accepted(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let cancel = Cancellation::default();
    loop {
        checked_remaining(deadline, &cancel)?;
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(error),
        }
    }
}

struct Identity {
    certificate: CertificateDer<'static>,
    key: rcgen::KeyPair,
}
impl Identity {
    fn new(name: &str) -> Self {
        let identity = generate_simple_self_signed(vec![name.to_owned()]).expect("certificate");
        Self {
            certificate: identity.cert.der().clone(),
            key: identity.signing_key,
        }
    }
    fn roots(identities: &[&Self]) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        for identity in identities {
            roots.add(identity.certificate.clone()).expect("root");
        }
        roots
    }
    fn client(&self, servers: &[&Self]) -> MutualTlsClient {
        MutualTlsClient::new(
            Self::roots(servers),
            vec![self.certificate.clone()],
            PrivatePkcs8KeyDer::from(self.key.serialize_der()).into(),
        )
        .expect("client config")
    }
    fn server(&self, clients: &[&Self]) -> MutualTlsServer {
        MutualTlsServer::new(
            Self::roots(clients),
            vec![self.certificate.clone()],
            PrivatePkcs8KeyDer::from(self.key.serialize_der()).into(),
        )
        .expect("server config")
    }
    fn with_validity(name: &str, before: i32, after: i32) -> Self {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
        params.not_before = rcgen::date_time_ymd(before, 1, 1);
        params.not_after = rcgen::date_time_ymd(after, 1, 1);
        let certificate = params.self_signed(&key).expect("certificate").der().clone();
        Self { certificate, key }
    }
}
fn initial(genesis: &AnchorGenesis) -> AnchorHead {
    AnchorHead::from_trusted_state(1, 1, genesis.image_digest()).expect("genesis head")
}
struct Case {
    store: Arc<Mutex<AnchorStore>>,
    pin: AnchorPin,
    genesis: AnchorGenesis,
    peer: Fixture,
    _journal: DeviceJournal,
    directory: tempfile::TempDir,
}
impl Case {
    fn new() -> Self {
        let directory = directory();
        let path = directory.path().canonicalize().expect("path");
        let client = path.join("client");
        let server = path.join("witness");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&client)
            .expect("client");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&server)
            .expect("server");
        let peer = fixture(PrekeyQuality::OneTimeBoth);
        let (policy, device, _) = peer.responder.inventory_inputs();
        let mut journal = new_store(&client, device);
        let genesis = journal.anchor_genesis(device, policy).expect("genesis");
        let key = JournalKey::provision(&server.join("wrap.key")).expect("key");
        let mut store = AnchorStore::provision(
            &server.join("witness.redb"),
            key,
            AnchorSigningKey::generate().expect("signer"),
            AnchorIdentity::generate().expect("id"),
        )
        .expect("store");
        store.enroll(&genesis, device, policy, 150).expect("enroll");
        let pin = store.pin().expect("pin");
        Self {
            store: Arc::new(Mutex::new(store)),
            pin,
            genesis,
            peer,
            _journal: journal,
            directory,
        }
    }
    fn request(&self, subject: AnchorSubject, operation: AnchorOperation) -> AnchorRequest {
        AnchorRequest::new(&self.pin, subject, operation, &self.peer.signer_r).expect("request")
    }
    fn query(&self, subject: AnchorSubject) -> AnchorHead {
        let query = self.request(subject, AnchorOperation::query());
        let wire = self
            .store
            .lock()
            .expect("store")
            .handle(query.as_bytes(), 150)
            .expect("query");
        self.pin
            .verify_reply(&query, &wire)
            .expect("reply")
            .observed_head()
    }
}

fn exchange(
    case: &Case,
    client: MutualTlsClient,
    server: AnchorTlsServer,
    pin: Vec<u8>,
    request: &AnchorRequest,
) -> (io::Result<Vec<u8>>, io::Result<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");
    let store = Arc::clone(&case.store);
    let worker = thread::spawn(move || {
        let socket = accepted(&listener)?;
        server.serve(
            socket,
            &store,
            Instant::now() + Duration::from_secs(5),
            Cancellation::default(),
            &mut || Ok(150),
        )
    });
    let mut client = AnchorTlsTransport::new(
        address,
        "localhost".try_into().expect("name"),
        pin,
        client,
        Cancellation::default(),
    )
    .expect("transport");
    let outcome = client.exchange(request.as_bytes(), Instant::now() + Duration::from_secs(5));
    (outcome, worker.join().expect("server thread"))
}

#[test]
fn tls_committed_advance_and_exact_retry_preserve_native_authority() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("TLS server");
    let before = initial(&case.genesis);
    let next = AnchorHead::from_trusted_state(before.fence(), before.revision() + 1, [19; 32])
        .expect("next");
    let operation = AnchorOperation::advance(before, next.digest()).expect("advance");
    for expected in [AnchorOutcome::Advanced, AnchorOutcome::AlreadyAppliedExact] {
        let request = case.request(case.genesis.subject(), operation);
        let (reply, served) = exchange(
            &case,
            client.client(&[&server]),
            tls.clone(),
            server.certificate.to_vec(),
            &request,
        );
        served.expect("served");
        let reply = case
            .pin
            .verify_reply(&request, &reply.expect("encrypted reply"))
            .expect("both signatures");
        assert_eq!(reply.outcome(), expected);
        assert_eq!(reply.observed_head(), next);
    }
    assert_eq!(case.query(case.genesis.subject()), next);
}

#[test]
fn tls_ca_valid_wrong_server_pin_releases_no_request() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let expected = Identity::new("localhost");
    let substitute = Identity::new("localhost");
    let server = AnchorTlsServer::new(
        substitute.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let request = case.request(case.genesis.subject(), AnchorOperation::query());
    let (reply, served) = exchange(
        &case,
        client.client(&[&expected, &substitute]),
        server,
        expected.certificate.to_vec(),
        &request,
    );
    assert_eq!(
        reply.expect_err("wrong server leaf").kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(served.is_err());
    assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
}

#[test]
fn tls_ca_valid_unconfigured_client_is_denied() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let substitute = Identity::new("client.test");
    let server = Identity::new("localhost");
    let tls = AnchorTlsServer::new(
        server.server(&[&client, &substitute]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let request = case.request(case.genesis.subject(), AnchorOperation::query());
    let (reply, served) = exchange(
        &case,
        substitute.client(&[&server]),
        tls,
        server.certificate.to_vec(),
        &request,
    );
    assert!(reply.is_err());
    assert_eq!(
        served.expect_err("unconfigured client").kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
}

#[test]
fn tls_certificate_cannot_authorize_another_enrolled_subject() {
    let case = Case::new();
    let path = case
        .directory
        .path()
        .canonicalize()
        .expect("path")
        .join("other");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("other");
    let policy = case.peer.initiator.policy();
    let device = case.peer.initiator.device(crate::BootstrapRole::Initiator);
    let mut other = new_store(&path, device);
    let genesis = other.anchor_genesis(device, policy).expect("other genesis");
    case.store
        .lock()
        .expect("store")
        .enroll(&genesis, device, policy, 150)
        .expect("enroll neighbor");
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let next = AnchorHead::from_trusted_state(
        initial(&genesis).fence(),
        initial(&genesis).revision() + 1,
        [21; 32],
    )
    .expect("head");
    let request = AnchorRequest::new(
        &case.pin,
        genesis.subject(),
        AnchorOperation::advance(initial(&genesis), next.digest()).expect("advance"),
        &case.peer.signer_i,
    )
    .expect("neighbor request");
    let (reply, served) = exchange(
        &case,
        client.client(&[&server]),
        tls,
        server.certificate.to_vec(),
        &request,
    );
    assert!(reply.is_err());
    assert_eq!(
        served.expect_err("neighbor scope").kind(),
        io::ErrorKind::PermissionDenied
    );
    let query = AnchorRequest::new(
        &case.pin,
        genesis.subject(),
        AnchorOperation::query(),
        &case.peer.signer_i,
    )
    .expect("neighbor query");
    let reply = case
        .store
        .lock()
        .expect("store")
        .handle(query.as_bytes(), 150)
        .expect("native neighbor query");
    assert_eq!(
        case.pin
            .verify_reply(&query, &reply)
            .expect("neighbor reply")
            .observed_head(),
        initial(&genesis)
    );
}

#[test]
fn tls_configuration_requires_explicit_bounded_leaf_subject_bindings() {
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let subject = AnchorSubject::from_trusted_state(&[1; 96]).expect("subject");
    assert!(AnchorTlsServer::new(server.server(&[&client]), vec![]).is_err());
    assert!(PeerBinding::new(vec![], subject).is_err());
    assert!(PeerBinding::new(vec![0; MAX_CERTIFICATE_BYTES + 1], subject).is_err());
    assert!(PeerBinding::new(vec![0; 100], subject).is_err());
    let peers = (0..2)
        .map(|_| PeerBinding::new(client.certificate.to_vec(), subject).expect("pin"))
        .collect();
    assert!(AnchorTlsServer::new(server.server(&[&client]), peers).is_err());
}

#[test]
fn tls_witness_query_requires_no_live_operational_sdk_runtime() {
    let case = Case::new();
    case.peer.responder.policy().runtime.close();
    assert!(case.peer.responder.check_session_identity(150).is_err());
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let request = case.request(case.genesis.subject(), AnchorOperation::query());
    let (reply, served) = exchange(
        &case,
        client.client(&[&server]),
        tls,
        server.certificate.to_vec(),
        &request,
    );
    served.expect("witness without SDK activation");
    assert_eq!(
        case.pin
            .verify_reply(&request, &reply.expect("reply"))
            .expect("signed reply")
            .observed_head(),
        initial(&case.genesis)
    );
}

#[test]
fn tls_held_handshake_observes_cancellation_and_original_deadline() {
    for cancel_case in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let (ready, wait) = mpsc::channel();
        let witness = thread::spawn(move || -> io::Result<()> {
            let mut socket = accepted(&listener)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut prefix = [0; 5];
            socket.read_exact(&mut prefix)?;
            assert_eq!(prefix.first(), Some(&22));
            let size = u16::from_be_bytes(
                prefix
                    .get(3..5)
                    .expect("TLS prefix")
                    .try_into()
                    .expect("length"),
            );
            assert!(size > 0 && size <= 16_384);
            let mut hello = vec![0; usize::from(size)];
            socket.read_exact(&mut hello)?;
            ready.send(()).map_err(io::Error::other)?;
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(0) => Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    Ok(())
                }
                Ok(_) => Err(io::Error::other(
                    "unexpected data after uncompleted TLS hello",
                )),
                Err(e) => Err(e),
            }
        });
        let client = Identity::new("client.test");
        let server = Identity::new("localhost");
        let cancel = Cancellation::default();
        let mut transport = AnchorTlsTransport::new(
            address,
            "localhost".try_into().expect("name"),
            server.certificate.to_vec(),
            client.client(&[&server]),
            cancel.clone(),
        )
        .expect("transport");
        let budget = if cancel_case {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(300)
        };
        let started = Instant::now();
        let worker =
            thread::spawn(move || transport.exchange(&[0; REQUEST_BYTES], started + budget));
        wait.recv_timeout(Duration::from_secs(5))
            .expect("real TLS hello");
        let observed = Instant::now();
        if cancel_case {
            cancel.cancel();
        }
        let error = worker
            .join()
            .expect("client")
            .expect_err("held TLS handshake");
        assert_eq!(
            error.kind(),
            if cancel_case {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::TimedOut
            }
        );
        assert!(observed.elapsed() < Duration::from_secs(1));
        if !cancel_case {
            assert!(started.elapsed() >= budget);
        }
        witness.join().expect("witness").expect("released socket");
    }
}

#[test]
fn tls_truncated_or_pipelined_request_has_no_witness_effect() {
    for trailing in [false, true] {
        let case = Case::new();
        let client = Identity::new("client.test");
        let server = Identity::new("localhost");
        let config = client
            .client(&[&server])
            .with_application_protocol(APPLICATION_PROTOCOL)
            .expect("ALPN");
        let tls = AnchorTlsServer::new(
            server.server(&[&client]),
            vec![
                PeerBinding::new(client.certificate.to_vec(), case.genesis.subject())
                    .expect("binding"),
            ],
        )
        .expect("server");
        let request = case.request(
            case.genesis.subject(),
            AnchorOperation::advance(initial(&case.genesis), [27; 32]).expect("advance"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let store = Arc::clone(&case.store);
        let worker = thread::spawn(move || {
            tls.serve(
                accepted(&listener)?,
                &store,
                Instant::now() + Duration::from_secs(5),
                Cancellation::default(),
                &mut || Ok(150),
            )
        });
        let mut channel = Channel::new(
            TcpStream::connect(address).expect("connect"),
            Connection::Client(
                config
                    .connect("localhost".try_into().expect("name"))
                    .expect("TLS"),
            ),
            Instant::now() + Duration::from_secs(5),
            Cancellation::default(),
        )
        .expect("channel");
        channel.handshake().expect("handshake");
        channel
            .send_frame(request.as_bytes())
            .expect("complete request");
        if trailing {
            channel
                .send_frame(request.as_bytes())
                .expect("second request");
            channel.close().expect("end");
        }
        drop(channel);
        assert!(worker.join().expect("server").is_err());
        assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
    }
}

#[test]
fn tls_wrong_alpn_is_rejected_before_witness_data() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let config = client
        .client(&[&server])
        .with_application_protocol(b"another-protocol/1")
        .expect("ALPN");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let store = Arc::clone(&case.store);
    let worker = thread::spawn(move || {
        tls.serve(
            accepted(&listener)?,
            &store,
            Instant::now() + Duration::from_secs(5),
            Cancellation::default(),
            &mut || Ok(150),
        )
    });
    let mut channel = Channel::new(
        TcpStream::connect(address).expect("connect"),
        Connection::Client(
            config
                .connect("localhost".try_into().expect("name"))
                .expect("TLS"),
        ),
        Instant::now() + Duration::from_secs(5),
        Cancellation::default(),
    )
    .expect("channel");
    assert!(channel.handshake().is_err());
    drop(channel);
    assert!(worker.join().expect("server").is_err());
    assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
}

fn relay(
    mut input: TcpStream,
    mut output: TcpStream,
    capture: Arc<Mutex<Vec<u8>>>,
) -> io::Result<()> {
    input.set_nonblocking(false)?;
    input.set_read_timeout(Some(Duration::from_secs(10)))?;
    output.set_nonblocking(false)?;
    output.set_write_timeout(Some(Duration::from_secs(10)))?;
    output.set_nodelay(true)?;
    let mut buffer = [0; 1024];
    loop {
        let length = input.read(&mut buffer)?;
        if length == 0 {
            return Ok(());
        }
        let bytes = buffer.get(..length).ok_or(io::ErrorKind::InvalidData)?;
        {
            let mut captured = capture
                .lock()
                .map_err(|_| io::Error::other("capture poisoned"))?;
            if captured.len() + bytes.len() > 256 * 1024 {
                return Err(io::Error::other("capture capacity"));
            }
            captured.extend_from_slice(bytes);
        }
        for fragment in bytes.chunks(37) {
            output.write_all(fragment)?;
            thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn tls_fragmented_encrypted_wire_does_not_expose_signed_journal_metadata() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let upstream = TcpListener::bind("127.0.0.1:0").expect("upstream");
    let upstream_address = upstream.local_addr().expect("address");
    let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy");
    let proxy_address = proxy.local_addr().expect("address");
    let store = Arc::clone(&case.store);
    let serving = thread::spawn(move || {
        tls.serve(
            accepted(&upstream)?,
            &store,
            Instant::now() + Duration::from_secs(10),
            Cancellation::default(),
            &mut || Ok(150),
        )
    });
    let request_wire = Arc::new(Mutex::new(Vec::new()));
    let response_wire = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::clone(&request_wire);
    let responses = Arc::clone(&response_wire);
    let forwarding = thread::spawn(move || -> io::Result<()> {
        let client = accepted(&proxy)?;
        let server = TcpStream::connect_timeout(&upstream_address, Duration::from_secs(5))?;
        let input = client.try_clone()?;
        let output = server.try_clone()?;
        let sender = thread::spawn(move || relay(input, output, requests));
        let received = relay(server, client, responses);
        let sent = sender
            .join()
            .map_err(|_| io::Error::other("relay panicked"))?;
        received?;
        sent
    });
    let request = case.request(case.genesis.subject(), AnchorOperation::query());
    let mut transport = AnchorTlsTransport::new(
        proxy_address,
        "localhost".try_into().expect("name"),
        server.certificate.to_vec(),
        client.client(&[&server]),
        Cancellation::default(),
    )
    .expect("client");
    let reply = transport
        .exchange(request.as_bytes(), Instant::now() + Duration::from_secs(10))
        .expect("fragmented TLS exchange");
    assert_eq!(
        case.pin
            .verify_reply(&request, &reply)
            .expect("signed reply")
            .observed_head(),
        initial(&case.genesis)
    );
    serving.join().expect("server").expect("served");
    forwarding.join().expect("proxy").expect("forwarded");
    let subject = case.genesis.subject().to_bytes();
    for trace in [&request_wire, &response_wire] {
        let bytes = trace.lock().expect("trace");
        assert!(bytes.len() > REQUEST_BYTES);
        for public in [
            b"QPANRQ01".as_slice(),
            b"QPANRS01".as_slice(),
            subject.as_slice(),
        ] {
            assert!(
                !bytes.windows(public.len()).any(|window| window == public),
                "journal metadata appeared on the TLS wire"
            );
        }
    }
    // This observed absence of cleartext supplements real TLS negotiation and
    // authenticated endpoint checks; it is not a standalone secrecy proof.
}

#[test]
fn tls_expired_future_and_wrong_name_certificates_cannot_advance() {
    for invalid in [
        "expired-server",
        "future-server",
        "name",
        "expired-client",
        "future-client",
    ] {
        let case = Case::new();
        let client = match invalid {
            "expired-client" => Identity::with_validity("client.test", 1975, 2001),
            "future-client" => Identity::with_validity("client.test", 4090, 4096),
            _ => Identity::new("client.test"),
        };
        let server = match invalid {
            "expired-server" => Identity::with_validity("localhost", 1975, 2001),
            "future-server" => Identity::with_validity("localhost", 4090, 4096),
            "name" => Identity::new("other.test"),
            _ => Identity::new("localhost"),
        };
        let tls = AnchorTlsServer::new(
            server.server(&[&client]),
            vec![
                PeerBinding::new(client.certificate.to_vec(), case.genesis.subject())
                    .expect("binding"),
            ],
        )
        .expect("server");
        let request = case.request(
            case.genesis.subject(),
            AnchorOperation::advance(initial(&case.genesis), [35; 32]).expect("advance"),
        );
        let (reply, served) = exchange(
            &case,
            client.client(&[&server]),
            tls,
            server.certificate.to_vec(),
            &request,
        );
        assert!(reply.is_err(), "accepted {invalid}");
        assert!(served.is_err(), "server admitted {invalid}");
        assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
    }
}

#[test]
fn tls_classic_only_server_cannot_negotiate_a_fallback() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let provider = Arc::new(provider);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(Identity::roots(&[&client])),
        Arc::clone(&provider),
    )
    .build()
    .expect("verifier");
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server.certificate.clone()],
            PrivatePkcs8KeyDer::from(server.key.serialize_der()).into(),
        )
        .expect("config");
    config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let worker = thread::spawn(move || -> io::Result<()> {
        let mut stream = accepted(&listener)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut connection =
            rustls::ServerConnection::new(Arc::new(config)).map_err(io::Error::other)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut stream)?;
        }
        Ok(())
    });
    let mut transport = AnchorTlsTransport::new(
        address,
        "localhost".try_into().expect("name"),
        server.certificate.to_vec(),
        client.client(&[&server]),
        Cancellation::default(),
    )
    .expect("transport");
    let request = case.request(
        case.genesis.subject(),
        AnchorOperation::advance(initial(&case.genesis), [36; 32]).expect("advance"),
    );
    assert!(transport
        .exchange(request.as_bytes(), Instant::now() + Duration::from_secs(5))
        .is_err());
    assert!(
        worker.join().expect("server").is_err(),
        "classic-only peer completed a handshake"
    );
    assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
}

#[test]
fn tls_clock_failure_cannot_commit_a_valid_signed_advance() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let store = Arc::clone(&case.store);
    let worker = thread::spawn(move || {
        tls.serve(
            accepted(&listener)?,
            &store,
            Instant::now() + Duration::from_secs(5),
            Cancellation::default(),
            &mut || Err(io::Error::other("host clock unavailable")),
        )
    });
    let mut transport = AnchorTlsTransport::new(
        address,
        "localhost".try_into().expect("name"),
        server.certificate.to_vec(),
        client.client(&[&server]),
        Cancellation::default(),
    )
    .expect("transport");
    let request = case.request(
        case.genesis.subject(),
        AnchorOperation::advance(initial(&case.genesis), [37; 32]).expect("advance"),
    );
    assert!(transport
        .exchange(request.as_bytes(), Instant::now() + Duration::from_secs(5))
        .is_err());
    assert_eq!(
        worker
            .join()
            .expect("server")
            .expect_err("clock failure")
            .to_string(),
        "host clock unavailable"
    );
    assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
}

#[test]
fn tls_waiting_for_a_busy_store_observes_cancel_and_deadline() {
    for cancel_case in [true, false] {
        let case = Case::new();
        let client = Identity::new("client.test");
        let server = Identity::new("localhost");
        let config = client
            .client(&[&server])
            .with_application_protocol(APPLICATION_PROTOCOL)
            .expect("ALPN");
        let tls = AnchorTlsServer::new(
            server.server(&[&client]),
            vec![
                PeerBinding::new(client.certificate.to_vec(), case.genesis.subject())
                    .expect("binding"),
            ],
        )
        .expect("server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let store = Arc::clone(&case.store);
        let busy = case.store.lock().expect("hold store");
        let cancel = Cancellation::default();
        let signal = cancel.clone();
        let (waiting, observed) = mpsc::channel();
        let started = Instant::now();
        let budget = if cancel_case {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(500)
        };
        let worker = thread::spawn(move || -> io::Result<_> {
            let mut clock_called = false;
            let mut waiting = Some(waiting);
            let result = tls.serve_observing_wait(
                accepted(&listener)?,
                &store,
                started + budget,
                signal,
                &mut || {
                    clock_called = true;
                    Err(io::Error::other("unavailable store reached clock/commit"))
                },
                &mut || {
                    if let Some(sender) = waiting.take() {
                        sender.send(()).expect("first real blocked lock attempt");
                    }
                },
            );
            Ok((result, clock_called))
        });
        let mut channel = Channel::new(
            TcpStream::connect(address).expect("connect"),
            Connection::Client(
                config
                    .connect("localhost".try_into().expect("name"))
                    .expect("TLS"),
            ),
            started + Duration::from_secs(5),
            Cancellation::default(),
        )
        .expect("channel");
        channel.handshake().expect("handshake despite held store");
        let request = case.request(
            case.genesis.subject(),
            AnchorOperation::advance(initial(&case.genesis), [38; 32]).expect("advance"),
        );
        channel
            .send_frame(request.as_bytes())
            .expect("signed request");
        channel.close().expect("authenticated end");
        observed
            .recv_timeout(Duration::from_secs(1))
            .expect("server actually waiting for store");
        let sent = Instant::now();
        if cancel_case {
            cancel.cancel();
        }
        let (result, clock_called) = worker.join().expect("server").expect("accepted stream");
        assert!(!clock_called, "busy store reached clock/commit");
        let error = result.expect_err("busy store must not be admitted");
        assert_eq!(
            error.kind(),
            if cancel_case {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::TimedOut
            }
        );
        assert!(sent.elapsed() < Duration::from_secs(1));
        if !cancel_case {
            assert!(started.elapsed() >= budget);
        }
        drop(busy);
        assert_eq!(case.query(case.genesis.subject()), initial(&case.genesis));
    }
}

#[test]
fn tls_unreceived_committed_reply_reconciles_as_the_exact_original_advance() {
    let case = Case::new();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let config = client
        .client(&[&server])
        .with_application_protocol(APPLICATION_PROTOCOL)
        .expect("ALPN");
    let tls = AnchorTlsServer::new(
        server.server(&[&client]),
        vec![
            PeerBinding::new(client.certificate.to_vec(), case.genesis.subject()).expect("binding"),
        ],
    )
    .expect("server");
    let before = initial(&case.genesis);
    let operation = AnchorOperation::advance(before, [39; 32]).expect("advance");
    let request = case.request(case.genesis.subject(), operation);
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let store = Arc::clone(&case.store);
    let serving = tls.clone();
    let worker = thread::spawn(move || {
        serving.serve(
            accepted(&listener)?,
            &store,
            Instant::now() + Duration::from_secs(5),
            Cancellation::default(),
            &mut || Ok(150),
        )
    });
    let socket = TcpStream::connect(address).expect("connect");
    let shutdown = socket.try_clone().expect("socket control");
    let mut channel = Channel::new(
        socket,
        Connection::Client(
            config
                .connect("localhost".try_into().expect("name"))
                .expect("TLS"),
        ),
        Instant::now() + Duration::from_secs(5),
        Cancellation::default(),
    )
    .expect("channel");
    channel.handshake().expect("handshake");
    channel
        .send_frame(request.as_bytes())
        .expect("signed request");
    channel.close().expect("authenticated request end");
    // No application reply is consumed. A local successful server write is not
    // a receiver acknowledgement; platform socket errors are also permitted.
    shutdown
        .shutdown(std::net::Shutdown::Both)
        .expect("disconnect receiver");
    drop(channel);
    if let Err(error) = worker.join().expect("server") {
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ),
            "unexpected server failure: {error}"
        );
    }
    let next = AnchorHead::from_trusted_state(before.fence(), before.revision() + 1, [39; 32])
        .expect("next");
    assert_eq!(
        case.query(case.genesis.subject()),
        next,
        "disconnect must not erase commitment"
    );
    let retry = case.request(case.genesis.subject(), operation);
    assert_ne!(
        retry.as_bytes(),
        request.as_bytes(),
        "retry requires a fresh challenge"
    );
    let (reply, served) = exchange(
        &case,
        client.client(&[&server]),
        tls,
        server.certificate.to_vec(),
        &retry,
    );
    served.expect("reconciliation server");
    let reply = case
        .pin
        .verify_reply(&retry, &reply.expect("reconciliation reply"))
        .expect("both signatures");
    assert_eq!(reply.outcome(), AnchorOutcome::AlreadyAppliedExact);
    assert_eq!(reply.observed_head(), next);
}
