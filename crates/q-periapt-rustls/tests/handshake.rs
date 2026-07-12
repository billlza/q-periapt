//! A real loopback TLS 1.3 handshake driven entirely by Q-Periapt's private-use hybrid
//! KEX group, proving the production-stack integration demo: both peers use
//! `q_periapt_rustls::provider()`, complete a handshake over an in-memory transport,
//! and exchange application data.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, RootCertStore, ServerConnection};

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

#[test]
fn tls13_handshake_over_q_periapt_hybrid() {
    let (cert, key) = self_signed();

    let server_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(q_periapt_rustls::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_config =
        rustls::ClientConfig::builder_with_provider(Arc::new(q_periapt_rustls::provider()))
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

    // Handshake completed over a Q-Periapt hybrid group.
    assert!(!client.is_handshaking() && !server.is_handshaking());
    let group = client
        .negotiated_key_exchange_group()
        .expect("a kx group was negotiated")
        .name();
    assert!(
        group == q_periapt_rustls::Q_PERIAPT_CONTEXTBOUND
            || group == q_periapt_rustls::Q_PERIAPT_COMPATXWING,
        "negotiated a non-Q-Periapt group: {group:?}"
    );
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
}
