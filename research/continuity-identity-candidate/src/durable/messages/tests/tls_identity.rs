// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_rustls::connection::{Credentials, Limits};
pub(super) struct Identity {
    pub(super) certificate: Vec<u8>,
    pub(super) key: Zeroizing<Vec<u8>>,
}
impl Identity {
    pub(super) fn new(name: &str) -> Self {
        let identity =
            rcgen::generate_simple_self_signed(vec![name.into()]).expect("TLS test identity");
        Self {
            certificate: identity.cert.der().to_vec(),
            key: Zeroizing::new(identity.signing_key.serialize_der()),
        }
    }
    pub(super) fn credentials<'a>(&'a self, peer: &'a Self) -> Credentials<'a> {
        Credentials {
            certificate: &self.certificate,
            private_key: &self.key,
            peer_certificate: &peer.certificate,
        }
    }
}
pub(super) fn tls_limits() -> Limits {
    Limits {
        max_connections: 1,
        handshake_ms: 10_000,
        request_ms: 10_000,
        idle_ms: 10_000,
    }
}
