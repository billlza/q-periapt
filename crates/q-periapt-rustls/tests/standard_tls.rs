// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual standard TLS handshakes, authentication failures and no-fallback checks.
#![cfg(feature = "standard-tls")]

use q_periapt_rustls::standard::{ConfigurationError, MutualTlsClient, MutualTlsServer};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, Error, NamedGroup, RootCertStore, ServerConfig,
    ServerConnection,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

struct Identity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}
impl Identity {
    fn new(name: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![name.into()]).expect("test certificate");
        Self {
            cert: cert.cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        }
    }
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert.clone()).expect("pin test peer");
        roots
    }
}
fn configs(server: &Identity, client: &Identity) -> (MutualTlsClient, MutualTlsServer) {
    (
        MutualTlsClient::new(
            server.roots(),
            vec![client.cert.clone()],
            client.key.clone_key(),
        )
        .expect("client"),
        MutualTlsServer::new(
            client.roots(),
            vec![server.cert.clone()],
            server.key.clone_key(),
        )
        .expect("server"),
    )
}
fn name(value: &'static str) -> ServerName<'static> {
    ServerName::try_from(value).expect("test DNS name")
}

fn client_to_server(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    fragment: usize,
) -> Result<(), Error> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).expect("memory writer");
    }
    for mut input in bytes.chunks(fragment) {
        while !input.is_empty() {
            assert!(server.read_tls(&mut input).expect("memory reader") > 0);
            server.process_new_packets()?;
        }
    }
    Ok(())
}
fn server_to_client(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    fragment: usize,
) -> Result<(), Error> {
    let mut bytes = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut bytes).expect("memory writer");
    }
    for mut input in bytes.chunks(fragment) {
        while !input.is_empty() {
            assert!(client.read_tls(&mut input).expect("memory reader") > 0);
            client.process_new_packets()?;
        }
    }
    Ok(())
}
fn drive(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    fragment: usize,
) -> Result<(), Error> {
    for _ in 0..32 {
        client_to_server(client, server, fragment)?;
        server_to_client(client, server, fragment)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(Error::General("test handshake exceeded 32 flights".into()))
}

#[test]
fn standard_mutual_tls_authenticates_both_peers_and_uses_fresh_hybrid_handshakes() {
    let server_identity = Identity::new("localhost");
    let client_identity = Identity::new("client.test");
    let (client, server) = configs(&server_identity, &client_identity);
    for fragment in [1, 17, 4096] {
        let mut client = client
            .connect(name("localhost"))
            .expect("client connection");
        let mut server = server.accept().expect("server connection");
        drive(&mut client, &mut server, fragment).expect("mutually authenticated handshake");
        for common in [&**client, &**server] {
            assert_eq!(
                common.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                common
                    .negotiated_key_exchange_group()
                    .expect("group")
                    .name(),
                NamedGroup::X25519MLKEM768
            );
            assert_eq!(common.handshake_kind(), Some(rustls::HandshakeKind::Full));
        }
        assert_eq!(
            client.peer_certificates(),
            Some([server_identity.cert.clone()].as_slice())
        );
        assert_eq!(
            server.peer_certificates(),
            Some([client_identity.cert.clone()].as_slice())
        );
        client
            .writer()
            .write_all(b"authenticated request")
            .expect("request");
        client_to_server(&mut client, &mut server, fragment).expect("transfer");
        let mut request = [0; 21];
        server
            .reader()
            .read_exact(&mut request)
            .expect("authenticated data");
        assert_eq!(&request, b"authenticated request");
        server
            .writer()
            .write_all(b"authenticated response")
            .expect("response");
        server_to_client(&mut client, &mut server, fragment).expect("transfer");
        let mut response = [0; 22];
        client
            .reader()
            .read_exact(&mut response)
            .expect("authenticated data");
        assert_eq!(&response, b"authenticated response");
    }
}

#[test]
fn standard_configs_reject_empty_trust_and_mismatched_identity_keys() {
    let a = Identity::new("localhost");
    let b = Identity::new("client.test");
    assert!(matches!(
        MutualTlsClient::new(
            RootCertStore::empty(),
            vec![a.cert.clone()],
            a.key.clone_key()
        ),
        Err(ConfigurationError::EmptyPeerRoots)
    ));
    assert!(matches!(
        MutualTlsServer::new(
            RootCertStore::empty(),
            vec![a.cert.clone()],
            a.key.clone_key()
        ),
        Err(ConfigurationError::EmptyPeerRoots)
    ));
    assert!(matches!(
        MutualTlsClient::new(a.roots(), vec![a.cert.clone()], b.key.clone_key()),
        Err(ConfigurationError::Tls(_))
    ));
    assert!(matches!(
        MutualTlsServer::new(a.roots(), vec![a.cert.clone()], b.key.clone_key()),
        Err(ConfigurationError::Tls(_))
    ));
}

#[test]
fn standard_tls_rejects_wrong_server_name_and_untrusted_certificates() {
    let a = Identity::new("localhost");
    let b = Identity::new("client.test");
    let wrong = Identity::new("other.test");
    let (client, server) = configs(&a, &b);
    let bad_client = MutualTlsClient::new(wrong.roots(), vec![b.cert.clone()], b.key.clone_key())
        .expect("wrong trust config");
    for mut connection in [
        client.connect(name("wrong.test")).expect("name"),
        bad_client.connect(name("localhost")).expect("trust"),
    ] {
        assert!(matches!(
            drive(&mut connection, &mut server.accept().expect("server"), 4096),
            Err(Error::InvalidCertificate(_))
        ));
    }
    let bad_server = MutualTlsServer::new(wrong.roots(), vec![a.cert.clone()], a.key.clone_key())
        .expect("wrong client trust");
    assert!(matches!(
        drive(
            &mut client.connect(name("localhost")).expect("client"),
            &mut bad_server.accept().expect("server"),
            4096
        ),
        Err(Error::InvalidCertificate(_)) | Err(Error::NoCertificatesPresented)
    ));
}

fn restricted_provider(standard: bool) -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = if standard {
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]
    } else {
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519]
    };
    provider
}

#[test]
fn standard_server_rejects_anonymous_clients_and_classic_only_peers() {
    let a = Identity::new("localhost");
    let b = Identity::new("client.test");
    let (_, server) = configs(&a, &b);
    let anonymous = ClientConfig::builder_with_provider(Arc::new(restricted_provider(true)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(a.roots())
        .with_no_client_auth();
    let mut client =
        ClientConnection::new(Arc::new(anonymous), name("localhost")).expect("anonymous client");
    assert!(matches!(
        drive(&mut client, &mut server.accept().expect("server"), 4096),
        Err(Error::NoCertificatesPresented)
    ));
    let classic = ClientConfig::builder_with_provider(Arc::new(restricted_provider(false)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(a.roots())
        .with_client_auth_cert(vec![b.cert.clone()], b.key.clone_key())
        .expect("client identity");
    let mut client =
        ClientConnection::new(Arc::new(classic), name("localhost")).expect("classic client");
    assert!(matches!(
        drive(&mut client, &mut server.accept().expect("server"), 4096),
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::NoKxGroupsInCommon
        ))
    ));
}

#[derive(Debug, Default)]
struct CertificateRequestProbe {
    requests: Mutex<Vec<Vec<Vec<u8>>>>,
}
impl rustls::client::ResolvesClientCert for CertificateRequestProbe {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.requests
            .lock()
            .expect("record certificate request")
            .push(
                root_hint_subjects
                    .iter()
                    .map(|name| name.to_vec())
                    .collect(),
            );
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

#[test]
fn standard_server_withholds_pinned_client_subjects_before_authentication() {
    let server_identity = Identity::new("localhost");
    let mut parameters = rcgen::CertificateParams::new(vec!["private-device.test".into()])
        .expect("client parameters");
    parameters.distinguished_name = rcgen::DistinguishedName::new();
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "private enrolled device 27");
    let key = rcgen::KeyPair::generate().expect("client key");
    let client_identity = Identity {
        cert: parameters
            .self_signed(&key)
            .expect("client certificate")
            .der()
            .clone(),
        key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    };
    let (_, server_config) = configs(&server_identity, &client_identity);
    let probe = Arc::new(CertificateRequestProbe::default());
    let client_config = ClientConfig::builder_with_provider(Arc::new(restricted_provider(true)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(server_identity.roots())
        .with_client_cert_resolver(probe.clone());
    let mut client = ClientConnection::new(Arc::new(client_config), name("localhost"))
        .expect("unauthenticated peer");
    let mut server = server_config.accept().expect("server");
    client_to_server(&mut client, &mut server, 17).expect("ClientHello");
    server_to_client(&mut client, &mut server, 17).expect("server handshake flight");
    // The peer can decrypt CertificateRequest before presenting any identity.
    // Observe the actual handshake through rustls's public certificate resolver.
    assert!(server.is_handshaking());
    assert!(server.peer_certificates().is_none());
    let requests = probe.requests.lock().expect("observed requests");
    assert_eq!(requests.len(), 1);
    assert!(
        requests.iter().all(Vec::is_empty),
        "unauthenticated peer received pinned client distinguished names: {requests:?}"
    );
    drop(requests);
    assert!(matches!(
        client_to_server(&mut client, &mut server, 17),
        Err(Error::NoCertificatesPresented)
    ));

    // Empty hints must not change the pinned trust set or make auth optional.
    for (identity, trusted) in [
        (&client_identity, true),
        (&Identity::new("foreign.test"), false),
    ] {
        let client = MutualTlsClient::new(
            server_identity.roots(),
            vec![identity.cert.clone()],
            identity.key.clone_key(),
        )
        .expect("client config");
        let result = drive(
            &mut client.connect(name("localhost")).expect("client"),
            &mut server_config.accept().expect("server"),
            17,
        );
        if trusted {
            result.expect("pinned client still authenticates");
        } else {
            assert!(matches!(result, Err(Error::InvalidCertificate(_))));
        }
    }
}

#[test]
fn standard_client_never_falls_back_to_classic_or_private_groups() {
    let a = Identity::new("localhost");
    let b = Identity::new("client.test");
    let (client, _) = configs(&a, &b);
    for provider in [restricted_provider(false), q_periapt_rustls::provider()] {
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![a.cert.clone()], a.key.clone_key())
            .expect("server identity");
        let mut server = ServerConnection::new(Arc::new(config)).expect("server");
        assert!(matches!(
            drive(
                &mut client.connect(name("localhost")).expect("client"),
                &mut server,
                4096
            ),
            Err(Error::PeerIncompatible(
                rustls::PeerIncompatible::NoKxGroupsInCommon
            ))
        ));
    }
}
