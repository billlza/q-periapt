// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit trusted witness configuration, reusing the native authenticated carrier.
use super::*;
use q_periapt_host_store::filesystem::OwnedPrivateDirectory;
use q_periapt_rustls::standard::MutualTlsClient;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use std::time::Duration;

/// Borrowed endpoint options; no caller pointer is retained by the owner.
#[repr(C)]
pub struct Options {
    pub address: *const u8,
    pub address_length: usize,
    pub timeout_ms: u32,
}
#[derive(Clone, Copy)]
pub(crate) enum Carrier {
    SignedTcp,
    Tls,
}
#[derive(Clone, Copy)]
pub(crate) struct Configuration {
    address: SocketAddr,
    timeout: Duration,
    carrier: Carrier,
}
impl Configuration {
    pub(crate) unsafe fn read(options: *const Options, carrier: Carrier) -> Result<Self> {
        if options.is_null() || !options.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller supplies an immutable readable Options and address region.
        let options = unsafe { &*options };
        let address = address(&unsafe { text(options.address, options.address_length, 128) }?)?;
        if address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || !(1..=10_000).contains(&options.timeout_ms)
        {
            return Err(Failure::argument());
        }
        Ok(Self {
            address,
            timeout: Duration::from_millis(u64::from(options.timeout_ms)),
            carrier,
        })
    }
    pub(crate) fn client(self, path: &Path, cancel: Cancellation) -> Result<p::AnchorClient> {
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let pin = p::AnchorPin::new(
            p::AnchorIdentity::from_trusted_state(owner::array(&directory, "witness-id")?)?,
            p::PublicKey::decode(&owner::read(&directory, "witness-public", 8192)?)?,
        );
        let key = p::JournalKey::open(&path.join("wrap.key"))?;
        let signer = p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key,
            p::SigningKeyId::from_trusted_state(owner::array(&directory, "signer-id")?)?,
        )?;
        let transport: Box<dyn p::AnchorTransport> = match self.carrier {
            Carrier::SignedTcp => Box::new(p::AnchorTcpTransport::with_cancellation(
                self.address,
                cancel,
            )),
            Carrier::Tls => Box::new(self.tls(&directory, cancel)?),
        };
        p::AnchorClient::new(pin, signer, transport, self.timeout)
            .map_err(|error| p::DurableError::from(error).into())
    }
    fn tls(
        self,
        directory: &OwnedPrivateDirectory,
        cancel: Cancellation,
    ) -> Result<p::anchor_tls::AnchorTlsTransport> {
        // Original protected witness credentials are independent of application
        // TLS and SDK operational authority, including during revoked cleanup.
        let peer = owner::read(directory, "witness-tls-peer", 8192)?;
        let certificate = owner::read(directory, "witness-tls-cert", 8192)?;
        let name = String::from_utf8(owner::read(directory, "witness-tls-name", 128)?)
            .map_err(Failure::configuration)?;
        let name = ServerName::try_from(name).map_err(Failure::configuration)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(peer.as_slice()))
            .map_err(Failure::configuration)?;
        let secret = owner::private_bytes(directory, "witness-tls-key", 8192)?;
        // Borrow for parsing; immediately consume the sole owned DER copy in
        // the standard factory's zeroizing key loader on success AND failure.
        let key = PrivateKeyDer::try_from(secret.as_slice())
            .map_err(|_| Failure::argument())?
            .clone_key();
        let config = MutualTlsClient::new(roots, vec![CertificateDer::from(certificate)], key)
            .map_err(Failure::configuration)?;
        p::anchor_tls::AnchorTlsTransport::new(self.address, name, peer, config, cancel)
            .map_err(Failure::configuration)
    }
}
