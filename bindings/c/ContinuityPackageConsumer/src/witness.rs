// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit trusted witness configuration, reusing the native authenticated carrier.
use super::*;
use q_periapt_host_store::filesystem::OwnedPrivateDirectory;
use q_periapt_rustls::standard::MutualTlsClient;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use std::{
    io,
    time::{Duration, Instant},
};

struct ScopedTransport {
    endpoint: Endpoint,
    invocation: invocation::Scope,
}
enum Endpoint {
    SignedTcp(SocketAddr),
    Tls(Box<TlsEndpoint>),
}
struct TlsEndpoint {
    address: SocketAddr,
    name: ServerName<'static>,
    peer: Vec<u8>,
    config: MutualTlsClient,
}
impl Endpoint {
    fn with_transport<T>(
        &self,
        cancel: Cancellation,
        action: impl FnOnce(&mut dyn p::AnchorTransport) -> io::Result<T>,
    ) -> io::Result<T> {
        match self {
            Self::SignedTcp(address) => action(&mut p::AnchorTcpTransport::with_cancellation(
                *address, cancel,
            )),
            Self::Tls(endpoint) => action(&mut p::anchor_tls::AnchorTlsTransport::new(
                endpoint.address,
                endpoint.name.clone(),
                endpoint.peer.clone(),
                endpoint.config.clone(),
                cancel,
            )?),
        }
    }
}
impl p::AnchorTransport for ScopedTransport {
    fn constrain_deadline(&self, deadline: Instant) -> io::Result<Instant> {
        self.invocation.constrain(deadline)
    }

    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        let (deadline, cancel) = self.invocation.transport_context(deadline)?;
        // Native carriers already use one fresh connection per exchange. Keep
        // the immutable endpoint/credentials, but bind I/O to this invocation.
        // No configuration file or trust pin is reread while switching callers.
        self.endpoint
            .with_transport(cancel, |transport| transport.exchange(request, deadline))
    }
}

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
    pub(crate) fn client(
        self,
        path: &Path,
        cancel: Cancellation,
        invocation: invocation::Scope,
    ) -> Result<p::AnchorClient> {
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
        let endpoint = match self.carrier {
            Carrier::SignedTcp => Endpoint::SignedTcp(self.address),
            Carrier::Tls => Endpoint::Tls(Box::new(self.tls(&directory)?)),
        };
        // Preserve constructor-time endpoint/certificate/configuration refusal.
        // This creates no connection and exposes no replacement witness state.
        endpoint
            .with_transport(cancel, |_| Ok(()))
            .map_err(Failure::configuration)?;
        let transport = Box::new(ScopedTransport {
            endpoint,
            invocation,
        });
        p::AnchorClient::new(pin, signer, transport, self.timeout)
            .map_err(|error| p::DurableError::from(error).into())
    }
    fn tls(self, directory: &OwnedPrivateDirectory) -> Result<TlsEndpoint> {
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
        Ok(TlsEndpoint {
            address: self.address,
            name,
            peer,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p::AnchorTransport;
    use std::{io::Read, net::TcpListener, sync::mpsc, thread};

    // A stalled byte endpoint intentionally supplies no authenticated reply.
    // Cancellation must close the real socket and cannot imply witness success.
    fn stalled_attempt(
        listener: &TcpListener,
        transport: &mut ScopedTransport,
        cancel: &Cancellation,
        tls: bool,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let listener = listener.try_clone()?;
        let (arrived, observed) = mpsc::sync_channel(1);
        let cancel = cancel.clone();
        let server = thread::spawn(move || -> io::Result<()> {
            let end = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= end {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            };
            // macOS can inherit O_NONBLOCK from the listening socket. Reads in
            // this bounded fixture use socket deadlines after explicit accept.
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            if tls {
                // Consume one complete TLS record, then stall the handshake.
                let mut header = [0; 5];
                stream.read_exact(&mut header)?;
                let [kind, major, _, high, low] = header;
                if kind != 22 || major != 3 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let size = usize::from(u16::from_be_bytes([high, low]));
                if !(1..=16_384).contains(&size) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                stream.read_exact(&mut vec![0; size])?;
            } else {
                let mut request = [0; 3678];
                stream.read_exact(&mut request)?;
            }
            arrived.send(()).map_err(io::Error::other)?;
            let mut byte = [0];
            if stream.read(&mut byte)? != 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        });
        let stop = thread::spawn(move || -> io::Result<()> {
            observed
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            cancel.cancel();
            Ok(())
        });
        let result = transport.exchange(&[0; 3674], Instant::now() + Duration::from_secs(4));
        let stopped = stop.join().map_err(|_| "cancellation worker panicked")?;
        let served = server.join().map_err(|_| "socket worker panicked")?;
        stopped?;
        served?;
        assert_eq!(
            result.expect_err("no witness reply").kind(),
            io::ErrorKind::Interrupted
        );
        Ok(())
    }

    fn exercise(tls: bool) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let endpoint = if tls {
            let peer = rcgen::generate_simple_self_signed(vec!["witness.test".into()])?;
            let local = rcgen::generate_simple_self_signed(vec!["device.test".into()])?;
            let mut roots = RootCertStore::empty();
            roots.add(peer.cert.der().clone())?;
            let key = PrivateKeyDer::try_from(local.signing_key.serialize_der())?;
            Endpoint::Tls(Box::new(TlsEndpoint {
                address,
                name: ServerName::try_from("witness.test")?,
                peer: peer.cert.der().to_vec(),
                config: MutualTlsClient::new(roots, vec![local.cert.der().clone()], key)?,
            }))
        } else {
            Endpoint::SignedTcp(address)
        };
        let scope = invocation::Scope::default();
        let mut transport = ScopedTransport {
            endpoint,
            invocation: scope.clone(),
        };
        // The endpoint is retained across calls. Each token is permanently
        // cancelled, but does not become the next caller's cancellation owner.
        for _ in 0..2 {
            let cancel = Cancellation::default();
            let active = scope
                .enter(Instant::now() + Duration::from_secs(5), &cancel)
                .map_err(|error| io::Error::other(error.message))?;
            stalled_attempt(&listener, &mut transport, &cancel, tls)?;
            assert!(cancel.is_cancelled());
            drop(active);
            assert!(transport
                .exchange(&[0; 3674], Instant::now() + Duration::from_secs(1))
                .is_err());
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        }
        let cancel = Cancellation::default();
        cancel.cancel();
        let _active = scope
            .enter(Instant::now() + Duration::from_secs(1), &cancel)
            .map_err(|error| io::Error::other(error.message))?;
        assert_eq!(
            transport
                .exchange(&[0; 3674], Instant::now() + Duration::from_secs(1))
                .expect_err("pre-cancelled")
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    }

    #[test]
    fn retained_tcp_endpoint_observes_each_invocations_cancellation(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        exercise(false)
    }

    #[test]
    fn retained_tls_endpoint_observes_each_invocations_cancellation(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        exercise(true)
    }
}
