//! A real loopback TLS 1.3 handshake driven entirely by Q-Periapt's private-use hybrid
//! KEX group, exercising the research integration against the production rustls
//! stack: both peers use
//! `q_periapt_rustls::provider()`, complete a handshake over an in-memory transport,
//! and exchange application data.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, NamedGroup, RootCertStore, ServerConnection};

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    (cert_der, key_der)
}

/// Pump TLS records between the two connections until both finish the handshake.
fn drive(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _round in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
        // client -> server
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).unwrap();
        }
        let mut off = 0;
        while off < c2s.len() {
            off += server.read_tls(&mut &c2s[off..]).unwrap();
            server.process_new_packets().unwrap();
        }
        // server -> client
        let mut s2c = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut s2c).unwrap();
        }
        let mut off = 0;
        while off < s2c.len() {
            off += client.read_tls(&mut &s2c[off..]).unwrap();
            client.process_new_packets().unwrap();
        }
    }
    panic!("handshake did not converge");
}

fn tls13_round_trip(
    server_provider: CryptoProvider,
    client_provider: CryptoProvider,
) -> NamedGroup {
    let (cert, key) = self_signed();

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    drive(&mut client, &mut server);

    assert!(!client.is_handshaking() && !server.is_handshaking());
    let group = client
        .negotiated_key_exchange_group()
        .expect("a kx group was negotiated")
        .name();
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    // Application data round-trips both directions (server -> client).
    server
        .writer()
        .write_all(b"hello from the PQ/T server")
        .unwrap();
    let mut s2c = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut s2c).unwrap();
    }
    let mut off = 0;
    while off < s2c.len() {
        off += client.read_tls(&mut &s2c[off..]).unwrap();
        client.process_new_packets().unwrap();
    }
    let mut buf = [0u8; 64];
    let n = client.reader().read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello from the PQ/T server");
    group
}

#[test]
fn tls13_handshake_over_q_periapt_private_hybrid() {
    let server_provider = q_periapt_rustls::provider();
    let private_groups = server_provider
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect::<Vec<_>>();
    assert_eq!(
        private_groups,
        vec![
            q_periapt_rustls::Q_PERIAPT_CONTEXTBOUND,
            q_periapt_rustls::Q_PERIAPT_COMPATXWING,
        ],
        "default provider exposed a non-private or reordered group",
    );
    let group = tls13_round_trip(server_provider, q_periapt_rustls::provider());
    assert!(
        group == q_periapt_rustls::Q_PERIAPT_CONTEXTBOUND
            || group == q_periapt_rustls::Q_PERIAPT_COMPATXWING,
        "negotiated a non-Q-Periapt group: {group:?}"
    );
    assert_ne!(
        u16::from(group),
        0x11EC,
        "private group used RFC 10024 codepoint"
    );
}

#[cfg(feature = "bench-baseline")]
fn rfc10024_provider() -> CryptoProvider {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    CryptoProvider {
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
        ..base
    }
}

#[cfg(feature = "bench-baseline")]
#[test]
fn rfc10024_x25519_mlkem768_direct_contract() {
    const CLIENT_SHARE_LEN: usize = 1_216;
    const SERVER_SHARE_LEN: usize = 1_120;
    const SHARED_SECRET_LEN: usize = 64;

    let group = rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768;
    assert_eq!(group.name(), NamedGroup::X25519MLKEM768);
    assert_eq!(u16::from(group.name()), 0x11EC);

    let client = group.start().unwrap();
    let client_share = client.pub_key().to_vec();
    assert_eq!(client_share.len(), CLIENT_SHARE_LEN);
    let server = group.start_and_complete(&client_share).unwrap();
    assert_eq!(server.pub_key.len(), SERVER_SHARE_LEN);
    assert_eq!(server.secret.secret_bytes().len(), SHARED_SECRET_LEN);
    let client_secret = client.complete(&server.pub_key).unwrap();
    assert_eq!(client_secret.secret_bytes().len(), SHARED_SECRET_LEN);
    assert!(
        client_secret.secret_bytes() == server.secret.secret_bytes(),
        "RFC 10024 peers derived different secrets"
    );

    assert!(group
        .start_and_complete(&client_share[..CLIENT_SHARE_LEN - 1])
        .is_err());
    let mut oversized_client_share = client_share.clone();
    oversized_client_share.push(0);
    assert!(group.start_and_complete(&oversized_client_share).is_err());
    let mut noncanonical_encapsulation_key = client_share.clone();
    // The first two 12-bit ML-KEM coefficients become 4095, which is outside
    // the canonical modulus range and must fail the FIPS 203 key check.
    noncanonical_encapsulation_key[..3].fill(0xFF);
    assert!(group
        .start_and_complete(&noncanonical_encapsulation_key)
        .is_err());
    let mut zero_x25519_client_share = client_share;
    zero_x25519_client_share[1_184..].fill(0);
    assert!(group.start_and_complete(&zero_x25519_client_share).is_err());

    let client = group.start().unwrap();
    let server = group.start_and_complete(client.pub_key()).unwrap();
    assert!(client
        .complete(&server.pub_key[..SERVER_SHARE_LEN - 1])
        .is_err());
    let client = group.start().unwrap();
    let server = group.start_and_complete(client.pub_key()).unwrap();
    let mut oversized_server_share = server.pub_key;
    oversized_server_share.push(0);
    assert!(client.complete(&oversized_server_share).is_err());
    let client = group.start().unwrap();
    let server = group.start_and_complete(client.pub_key()).unwrap();
    let mut zero_x25519_server_share = server.pub_key;
    zero_x25519_server_share[1_088..].fill(0);
    assert!(client.complete(&zero_x25519_server_share).is_err());
}

#[cfg(feature = "bench-baseline")]
#[test]
fn tls13_handshake_over_rfc10024_baseline() {
    let group = tls13_round_trip(rfc10024_provider(), rfc10024_provider());
    assert_eq!(group, NamedGroup::X25519MLKEM768);
    assert_eq!(u16::from(group), 0x11EC);
}
