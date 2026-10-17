use super::*;
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;

struct Identity {
    certificate: Vec<u8>,
    key: Vec<u8>,
}
impl Identity {
    fn new(name: &str) -> Self {
        let certificate =
            rcgen::generate_simple_self_signed(vec![name.into()]).expect("test identity");
        Self {
            certificate: certificate.cert.der().to_vec(),
            key: certificate.signing_key.serialize_der(),
        }
    }
    fn credentials<'a>(&'a self, peer: &'a Self) -> Credentials<'a> {
        Credentials {
            certificate: &self.certificate,
            private_key: &self.key,
            peer_certificate: &peer.certificate,
        }
    }
}
impl Drop for Identity {
    fn drop(&mut self) {
        q_periapt_core::secure_wipe(&mut self.key);
    }
}

fn policy(seed: u8, version: u32, suffix: &str) -> Arc<Runtime> {
    let policy = format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"ML-KEM-768\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n{suffix}");
    let (key, root) = MlDsa65::generate([seed; 32]);
    let mut signature = [0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &key,
            &policy_signature_message(policy.as_bytes()),
            &[0; 32],
            &mut signature,
        )
        .expect("signed policy");
    Arc::new(
        Runtime::from_signed_policy(
            policy.as_bytes(),
            &signature,
            &root,
            None,
            q_periapt_sdk::Limits::default(),
        )
        .expect("verified policy"),
    )
}
fn endpoints(
    client_policy: Arc<Runtime>,
    server_policy: Arc<Runtime>,
    client_context: &[u8],
    server_context: &[u8],
    max: usize,
) -> (Endpoint, Endpoint) {
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let limits = Limits {
        max_connections: max,
        handshake_ms: 120_000,
        request_ms: 120_000,
        ..Limits::default()
    };
    (
        Endpoint::client(
            client_policy,
            client.credentials(&server),
            client_context,
            limits,
        )
        .expect("client endpoint"),
        Endpoint::server(
            server_policy,
            server.credentials(&client),
            server_context,
            limits,
        )
        .expect("server endpoint"),
    )
}
fn transfer(
    source: &mut Connection,
    target: &mut Connection,
    fragment: usize,
) -> Result<bool, Error> {
    if !source.progress()?.wants_write {
        return Ok(false);
    }
    let mut bytes = [0; MAX_TLS_IO_BYTES];
    let written = source.drain_tls(&mut bytes)?;
    for mut part in bytes
        .get(..written)
        .expect("drained extent")
        .chunks(fragment)
    {
        while !part.is_empty() {
            let consumed = target.feed_tls(part)?;
            assert!(consumed > 0, "bounded engine failed to make progress");
            part = part.get(consumed..).expect("consumed extent");
        }
    }
    Ok(written != 0)
}
fn drive(client: &mut Connection, server: &mut Connection, fragment: usize) -> Result<(), Error> {
    for _ in 0..128 {
        let wrote_client = transfer(client, server, fragment)?;
        let wrote_server = transfer(server, client, fragment)?;
        if !wrote_client && !wrote_server {
            return Ok(());
        }
    }
    Err(Error::Protocol)
}
fn pair(client: &Endpoint, server: &Endpoint) -> (Connection, Connection) {
    (
        client.connect("localhost").expect("client connection"),
        server.accept().expect("server connection"),
    )
}
fn attack(client: &mut Connection, bytes: &[u8]) {
    client
        .live
        .as_mut()
        .expect("test peer state")
        .tls
        .writer()
        .write_all(bytes)
        .expect("authenticated adversarial peer");
}

fn raw_client(identity: &Identity, server: &Identity, alpn: bool) -> rustls::ClientConnection {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server.certificate.clone()))
        .expect("peer anchor");
    let key = PrivateKeyDer::try_from(identity.key.as_slice())
        .expect("DER")
        .clone_key();
    let client = MutualTlsClient::new(roots, vec![identity.certificate.clone().into()], key)
        .expect("raw client config");
    let client = if alpn {
        client
            .with_application_protocol(APPLICATION_PROTOCOL)
            .expect("ALPN")
    } else {
        client
    };
    client
        .connect(ServerName::try_from("localhost").expect("name"))
        .expect("raw peer")
}

fn drive_raw(
    client: &mut rustls::ClientConnection,
    server: &mut Connection,
    first_application: &[u8],
) -> Result<(), Error> {
    let mut sent = false;
    for _ in 0..32 {
        if !client.is_handshaking() && !sent {
            client.writer().write_all(first_application)?;
            sent = true;
        }
        let mut output = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut output)?;
        }
        for mut part in output.chunks(MAX_TLS_IO_BYTES) {
            while !part.is_empty() {
                let read = server.feed_tls(part)?;
                assert!(read > 0);
                part = part.get(read..).expect("consumed");
            }
        }
        let mut bytes = [0; MAX_TLS_IO_BYTES];
        while server.progress()?.wants_write {
            let written = server.drain_tls(&mut bytes)?;
            let mut input = bytes.get(..written).expect("TLS output");
            while !input.is_empty() {
                assert!(client.read_tls(&mut input)? > 0);
                client.process_new_packets()?;
            }
        }
        if sent {
            return Ok(());
        }
    }
    Err(Error::Protocol)
}

#[test]
fn tls_success_without_alpn_or_policy_confirmation_never_exposes_a_request() {
    let p = policy(8, 2, "");
    let client_identity = Identity::new("client.test");
    let server_identity = Identity::new("localhost");
    let server_endpoint = Endpoint::server(
        p,
        server_identity.credentials(&client_identity),
        b"",
        Limits::default(),
    )
    .expect("server");
    for alpn in [false, true] {
        let mut client = raw_client(&client_identity, &server_identity, alpn);
        let mut server = server_endpoint.accept().expect("session");
        let early = Outgoing::message(REQUEST, 1, b"must not reach application").expect("frame");
        assert!(matches!(
            drive_raw(&mut client, &mut server, &early.bytes.0),
            Err(Error::Protocol)
        ));
        assert!(matches!(server.take_request(), Err(Error::Closed)));
    }
}

#[test]
fn rfc9266_binding_rejects_a_valid_confirmation_replayed_on_another_tls_session() {
    let p = policy(8, 2, "");
    let client_identity = Identity::new("client.test");
    let server_identity = Identity::new("localhost");
    let client_endpoint = Endpoint::client(
        Arc::clone(&p),
        client_identity.credentials(&server_identity),
        b"scope",
        Limits::default(),
    )
    .expect("client");
    let server_endpoint = Endpoint::server(
        p,
        server_identity.credentials(&client_identity),
        b"scope",
        Limits::default(),
    )
    .expect("server");
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    drive(&mut client, &mut server, 4096).expect("confirmation");
    let live = client.live.as_ref().expect("old session");
    let mut binding = ZeroizingBytes::<32>::zeroed();
    live.tls
        .export_keying_material(
            binding.as_mut_bytes(),
            b"EXPORTER-Channel-Binding",
            Some(&[]),
        )
        .expect("RFC 9266 exporter");
    let replay = Outgoing::confirmation(
        CLIENT_CONFIRM,
        &live.policy,
        &live.confirmation_context,
        binding.as_bytes(),
    )
    .expect("same old confirmation");
    attack(&mut client, &replay.bytes.0);
    assert!(
        matches!(drive(&mut client, &mut server, 4096), Err(Error::Protocol)),
        "second confirmation in one protocol instance must fail"
    );
    client.close();
    server.close();
    let mut external_client = raw_client(&client_identity, &server_identity, true);
    let mut new_server = server_endpoint.accept().expect("fresh TLS session");
    assert!(matches!(
        drive_raw(&mut external_client, &mut new_server, &replay.bytes.0),
        Err(Error::BindingMismatch)
    ));
}

#[test]
fn exact_leaf_pin_rejects_another_certificate_even_when_its_public_key_is_trusted() {
    let key = rcgen::KeyPair::generate().expect("test signer");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("parameters");
    params.serial_number = Some(1u64.into());
    let actual = params.self_signed(&key).expect("actual certificate");
    params.serial_number = Some(2u64.into());
    let pinned = params
        .self_signed(&key)
        .expect("same key, different certificate");
    let actual = Identity {
        certificate: actual.der().to_vec(),
        key: key.serialize_der(),
    };
    let pinned = Identity {
        certificate: pinned.der().to_vec(),
        key: key.serialize_der(),
    };
    let client = Identity::new("client.test");
    let p = policy(8, 2, "");
    let client_endpoint = Endpoint::client(
        Arc::clone(&p),
        client.credentials(&pinned),
        b"",
        Limits::default(),
    )
    .expect("client");
    let server_endpoint =
        Endpoint::server(p, actual.credentials(&client), b"", Limits::default()).expect("server");
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    assert!(matches!(
        drive(&mut client, &mut server, 4096),
        Err(Error::PeerIdentity)
    ));
}

#[test]
fn confirmation_and_single_request_roundtrips_survive_fragmentation_and_reconnect() {
    let p = policy(8, 2, "");
    let (client_endpoint, server_endpoint) =
        endpoints(Arc::clone(&p), p, &[42; 65_536], &[42; 65_536], 1);
    for fragment in [1, 17, MAX_TLS_IO_BYTES] {
        let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
        assert!(matches!(
            client.send_request(b"early"),
            Err(Error::NotReady)
        ));
        drive(&mut client, &mut server, fragment).expect("confirmation");
        assert_eq!(client.progress().expect("progress").phase, Phase::Ready);
        assert_eq!(server.progress().expect("progress").phase, Phase::Ready);
        for size in [0, 1, MAX_PAYLOAD_BYTES] {
            let payload = vec![0x5a; size];
            let id = client.send_request(&payload).expect("queue request");
            assert!(matches!(
                client.send_request(b"overlap"),
                Err(Error::NotReady)
            ));
            drive(&mut client, &mut server, fragment).expect("request transfer");
            let request = server.take_request().expect("authenticated request");
            assert_eq!(request.request_id(), id);
            assert_eq!(request.bytes(), payload);
            assert!(matches!(
                server.send_response(id + 1, b"wrong id"),
                Err(Error::NotReady)
            ));
            server.send_response(id, request.bytes()).expect("response");
            drive(&mut client, &mut server, fragment).expect("response transfer");
            let response = client.take_response().expect("matching response");
            assert_eq!(response.request_id(), id);
            assert_eq!(response.bytes(), payload);
            assert!(matches!(client.take_response(), Err(Error::NotReady)));
        }
        client.close();
        server.close();
        assert!(matches!(client.progress(), Err(Error::Closed)));
    }
}

#[test]
fn policy_root_version_digest_and_application_context_are_bound_independently() {
    for case in 0..4 {
        let a = policy(8, 2, "");
        let b = match case {
            0 => policy(9, 2, ""),
            1 => policy(8, 3, ""),
            2 => policy(8, 2, "\n"),
            _ => policy(8, 2, ""),
        };
        let right_context = if case == 3 {
            b"different".as_slice()
        } else {
            b"same".as_slice()
        };
        let (client_endpoint, server_endpoint) = endpoints(a, b, b"same", right_context, 1);
        let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
        let result = drive(&mut client, &mut server, 17);
        if case == 3 {
            assert!(matches!(result, Err(Error::BindingMismatch)));
        } else {
            assert!(matches!(result, Err(Error::PolicyMismatch)));
        }
        assert!(matches!(server.take_request(), Err(Error::Closed)));
    }
}

#[test]
fn malformed_lengths_kinds_sequences_and_replayed_confirmation_are_terminal() {
    let p = policy(8, 2, "");
    let (client_endpoint, server_endpoint) = endpoints(Arc::clone(&p), p, b"", b"", 1);
    let mut replay = vec![0, 0, 0, 101, CLIENT_CONFIRM];
    replay.extend_from_slice(&[0; 100]);
    for bytes in [
        vec![0xff; 4],
        vec![0; 4],
        vec![0, 0, 0, 1, 255],
        vec![0, 0, 0, 9, REQUEST, 0, 0, 0, 0, 0, 0, 0, 2],
        replay,
    ] {
        let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
        drive(&mut client, &mut server, 4096).expect("confirmation");
        attack(&mut client, &bytes);
        assert!(matches!(
            drive(&mut client, &mut server, 1),
            Err(Error::Protocol)
        ));
        assert!(matches!(server.progress(), Err(Error::Closed)));
        client.close();
    }
}

#[test]
fn concurrent_connection_admission_keeps_the_exact_limit_and_recovers_capacity() {
    let p = policy(8, 2, "");
    let (client, _server) = endpoints(Arc::clone(&p), p, b"", b"", 3);
    let start = std::sync::Barrier::new(17);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    client.connect("localhost")
                })
            })
            .collect();
        start.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("connection worker"))
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
    assert!(results
        .iter()
        .all(|result| matches!(result, Ok(_) | Err(Error::ResourceLimit))));
    assert_eq!(client.shared.live.load(Ordering::Acquire), 3);
    drop(results);
    assert_eq!(client.shared.live.load(Ordering::Acquire), 0);
    assert!(client.connect("localhost").is_ok());
}

#[test]
fn runtime_and_endpoint_revocation_erase_queued_work_and_release_capacity() {
    let p = policy(8, 2, "");
    let (client_endpoint, server_endpoint) = endpoints(Arc::clone(&p), Arc::clone(&p), b"", b"", 1);
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    assert!(matches!(
        client_endpoint.connect("localhost"),
        Err(Error::ResourceLimit)
    ));
    drive(&mut client, &mut server, 4096).expect("confirmation");
    client.send_request(b"pending").expect("request");
    p.close();
    let mut output = [0xa5; 1024];
    assert!(matches!(client.drain_tls(&mut output), Err(Error::Closed)));
    assert_eq!(output, [0; 1024]);
    assert_eq!(client_endpoint.shared.live.load(Ordering::Acquire), 0);
    assert!(matches!(server.take_request(), Err(Error::Closed)));
    let fresh = policy(8, 2, "");
    let (client_endpoint, server_endpoint) = endpoints(Arc::clone(&fresh), fresh, b"", b"", 1);
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    drop(client_endpoint);
    assert!(matches!(client.progress(), Err(Error::Closed)));
    server_endpoint.close();
    assert!(matches!(server.progress(), Err(Error::Closed)));
}

#[test]
fn absolute_deadlines_and_caller_shape_errors_have_distinct_effects() {
    let p = policy(8, 2, "");
    let (client_endpoint, server_endpoint) = endpoints(Arc::clone(&p), p, b"", b"", 1);
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    assert!(matches!(client.feed_tls(&[]), Err(Error::InvalidLength)));
    assert!(matches!(
        client.feed_tls(&vec![0; MAX_TLS_IO_BYTES + 1]),
        Err(Error::InvalidLength)
    ));
    assert_eq!(
        client.progress().expect("still open").phase,
        Phase::Handshaking
    );
    client.live.as_mut().expect("test deadline").deadline = Instant::now();
    assert!(matches!(client.progress(), Err(Error::Timeout)));
    assert_eq!(client_endpoint.shared.live.load(Ordering::Acquire), 0);
    server.close();
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    drive(&mut client, &mut server, 4096).expect("confirmation");
    assert!(matches!(
        client.send_request(&vec![0; MAX_PAYLOAD_BYTES + 1]),
        Err(Error::InvalidLength)
    ));
    let id = client
        .send_request(b"bounded deadline")
        .expect("valid request");
    assert_eq!(id, 1);
    client.live.as_mut().expect("request deadline").deadline = Instant::now();
    assert!(matches!(client.take_response(), Err(Error::Timeout)));
    assert!(matches!(client.take_response(), Err(Error::Closed)));
}

#[test]
fn eof_never_becomes_an_empty_response_or_successful_partial_frame() {
    let p = policy(8, 2, "");
    let (client_endpoint, server_endpoint) = endpoints(Arc::clone(&p), p, b"", b"", 1);
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    drive(&mut client, &mut server, 4096).expect("confirmation");
    client.send_request(b"waiting").expect("request");
    assert!(matches!(client.end_of_input(), Err(Error::Io(_))));
    assert!(matches!(client.take_response(), Err(Error::Closed)));
    server.close();
    let (mut client, mut server) = pair(&client_endpoint, &server_endpoint);
    drive(&mut client, &mut server, 4096).expect("confirmation");
    attack(&mut client, &[0, 0, 0, 20, REQUEST]);
    client
        .live
        .as_mut()
        .expect("peer close")
        .tls
        .send_close_notify();
    assert!(matches!(
        drive(&mut client, &mut server, 1),
        Err(Error::Protocol)
    ));
    assert!(matches!(server.take_request(), Err(Error::Closed)));
}
