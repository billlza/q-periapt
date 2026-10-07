// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
//! Explicit RFC 10024 TLS 1.3 with mandatory mutual certificate authentication.
//!
//! Uses rustls/AWS-LC's unmodified X25519MLKEM768 construction, never the private
//! ContextBound/X-Wing combiner. A configuration has exactly one KX group, no
//! TLS 1.2, resumption or early data. Each connection performs a fresh handshake.
//! Certificates may use classical signatures: PQ key agreement is not PQ identity
//! authentication. CA trust establishes certificate validity; the application
//! must authorize the authenticated client identity before granting access.
//!
//! No signed Q-Periapt policy, device identity or application-context agreement is
//! implied. Those require a separately authenticated application protocol. These
//! wrappers retain private configs so callers cannot accidentally add a classic
//! fallback. I/O, deadlines, cancellation and capacity remain transport concerns.

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::{fmt, sync::Arc};

/// Invalid authentication material or TLS configuration. No permissive fallback.
#[derive(Debug)]
pub enum ConfigurationError {
    /// An explicit, nonempty set of pinned server/client trust anchors is required.
    EmptyPeerRoots,
    /// An ALPN identifier must contain 1..=255 bytes.
    InvalidApplicationProtocol,
    /// The upstream TLS configuration rejected certificate/key material.
    Tls(rustls::Error),
    /// The upstream client-certificate verifier could not be built.
    Verifier(VerifierBuilderError),
}
impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPeerRoots => {
                f.write_str("standard TLS requires explicit peer trust anchors")
            }
            Self::InvalidApplicationProtocol => {
                f.write_str("ALPN identifier must contain 1..=255 bytes")
            }
            Self::Tls(error) => write!(f, "standard TLS configuration: {error}"),
            Self::Verifier(error) => write!(f, "standard TLS client verifier: {error}"),
        }
    }
}
impl std::error::Error for ConfigurationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EmptyPeerRoots | Self::InvalidApplicationProtocol => None,
            Self::Tls(error) => Some(error),
            Self::Verifier(error) => Some(error),
        }
    }
}
impl From<rustls::Error> for ConfigurationError {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

fn provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // Restrict both lists even when dependency feature unification enables TLS 1.2.
    provider
        .cipher_suites
        .retain(|suite| suite.tls13().is_some());
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(provider)
}

/// Certificate signature capability reported by the configured verifier.
/// These are complete DER AlgorithmIdentifier contents, not a certificate/key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAlgorithm {
    /// SubjectPublicKeyInfo algorithm identifier, including curve/parameters.
    pub public_key_algorithm: Vec<u8>,
    /// Signature algorithm identifier, including hash/padding parameters.
    pub signature_algorithm: Vec<u8>,
}

/// Read-only algorithm choices from the same factory used by both TLS roles.
/// This is a configuration inventory, not evidence that a peer negotiated an
/// algorithm or a census of every internal primitive in the provider binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmInventory {
    /// IANA NamedGroup codepoints allowed by this configuration.
    pub key_exchange_groups: Vec<u16>,
    /// IANA cipher-suite codepoints and the upstream reported hash names.
    pub cipher_suites: Vec<(u16, String)>,
    /// Offered certificate/handshake SignatureScheme codepoints. TLS 1.3 still
    /// applies its own narrower handshake-signature restrictions.
    pub signature_schemes: Vec<u16>,
    /// Full certificate-chain verification capabilities, including combinations
    /// that cannot be represented by a TLS 1.3 SignatureScheme alone.
    pub certificate_algorithms: Vec<CertificateAlgorithm>,
}

/// Inspect the standard configuration without exposing mutable provider state.
/// No cryptographic operation, key generation, network or global install occurs.
#[must_use]
pub fn algorithm_inventory() -> AlgorithmInventory {
    let provider = provider();
    AlgorithmInventory {
        key_exchange_groups: provider
            .kx_groups
            .iter()
            .map(|g| u16::from(g.name()))
            .collect(),
        cipher_suites: provider
            .cipher_suites
            .iter()
            .map(|s| {
                (
                    u16::from(s.suite()),
                    format!(
                        "{:?}",
                        s.tls13()
                            .expect("provider retains only TLS 1.3 suites")
                            .common
                            .hash_provider
                            .algorithm()
                    ),
                )
            })
            .collect(),
        signature_schemes: provider
            .signature_verification_algorithms
            .supported_schemes()
            .into_iter()
            .map(u16::from)
            .collect(),
        certificate_algorithms: provider
            .signature_verification_algorithms
            .all
            .iter()
            .map(|a| CertificateAlgorithm {
                public_key_algorithm: a.public_key_alg_id().as_ref().to_vec(),
                signature_algorithm: a.signature_alg_id().as_ref().to_vec(),
            })
            .collect(),
    }
}

fn identity(
    provider: &CryptoProvider,
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<SingleCertAndKey>, ConfigurationError> {
    // AWS-LC's KeyProvider wraps its owned DER input in Zeroizing on every
    // parse path. Consume it before any later configuration validation can fail;
    // PrivateKeyDer itself does not implement erasure on ordinary Drop.
    let key = provider.key_provider.load_private_key(private_key)?;
    let certified = CertifiedKey::new(certificates, key);
    certified.keys_match()?;
    Ok(Arc::new(SingleCertAndKey::from(certified)))
}

/// Reusable immutable client configuration. Clones share the upstream owner.
#[derive(Clone, Debug)]
pub struct MutualTlsClient {
    config: Arc<ClientConfig>,
}
impl MutualTlsClient {
    /// Pin server trust anchors and provide this client's certificate/key. The
    /// server name supplied to `connect` is verified on every fresh connection.
    pub fn new(
        server_roots: RootCertStore,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, ConfigurationError> {
        let provider = provider();
        let identity = identity(&provider, certificates, private_key)?;
        if server_roots.is_empty() {
            return Err(ConfigurationError::EmptyPeerRoots);
        }
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(server_roots)
            .with_client_cert_resolver(identity);
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Create a fresh handshake state. No I/O or retry occurs here; application
    /// data is authenticated only after the TLS handshake successfully completes.
    pub fn connect(
        &self,
        server_name: ServerName<'static>,
    ) -> Result<ClientConnection, rustls::Error> {
        ClientConnection::new(Arc::clone(&self.config), server_name)
    }

    /// Configure one ALPN identifier on a new immutable configuration. Existing
    /// clones/connections are unaffected. The application must reject a missing
    /// or unexpected negotiated ALPN before exchanging its protocol messages.
    pub fn with_application_protocol(
        mut self,
        protocol: &[u8],
    ) -> Result<Self, ConfigurationError> {
        if !(1..=255).contains(&protocol.len()) {
            return Err(ConfigurationError::InvalidApplicationProtocol);
        }
        Arc::make_mut(&mut self.config).alpn_protocols = vec![protocol.to_vec()];
        Ok(self)
    }
}

/// Reusable immutable server configuration requiring a trusted client certificate.
#[derive(Clone, Debug)]
pub struct MutualTlsServer {
    config: Arc<ServerConfig>,
}
impl MutualTlsServer {
    /// Pin client trust anchors and provide this server's certificate/key.
    /// Anonymous clients and classic-only peers are rejected during the handshake.
    /// Client-authority name hints are omitted: a pinned peer's subject must not
    /// be disclosed to a connecting client before it authenticates.
    pub fn new(
        client_roots: RootCertStore,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, ConfigurationError> {
        let provider = provider();
        let identity = identity(&provider, certificates, private_key)?;
        if client_roots.is_empty() {
            return Err(ConfigurationError::EmptyPeerRoots);
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::clone(&provider),
        )
        .clear_root_hint_subjects()
        .build()
        .map_err(ConfigurationError::Verifier)?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(identity);
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Create a fresh handshake state. The transport must enforce I/O deadlines
    /// and connection limits, and authorize the verified client certificate.
    pub fn accept(&self) -> Result<ServerConnection, rustls::Error> {
        ServerConnection::new(Arc::clone(&self.config))
    }

    /// Configure one ALPN identifier on a new immutable configuration. The
    /// application must enforce successful negotiation before application data.
    pub fn with_application_protocol(
        mut self,
        protocol: &[u8],
    ) -> Result<Self, ConfigurationError> {
        if !(1..=255).contains(&protocol.len()) {
            return Err(ConfigurationError::InvalidApplicationProtocol);
        }
        Arc::make_mut(&mut self.config).alpn_protocols = vec![protocol.to_vec()];
        Ok(self)
    }
}
