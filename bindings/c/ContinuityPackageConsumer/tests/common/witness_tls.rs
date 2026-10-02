// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real native mutual-TLS witness shared by installed foreign-owner fixtures.
use crate::{fixture, p, Result};
use p::anchor_tls::{AnchorTlsServer, PeerBinding};
use q_periapt_rustls::standard::MutualTlsServer;
use rustls::RootCertStore;
use std::{
    io,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Provisioned {
    pub(crate) native: AnchorTlsServer,
    pub(crate) certificate: Vec<u8>,
    pub(crate) key: zeroize::Zeroizing<Vec<u8>>,
}
pub(crate) fn provision<const N: usize>(paths: [&Path; N]) -> Result<Provisioned> {
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let mut roots = RootCertStore::empty();
    let mut bindings = Vec::new();
    for (index, path) in paths.into_iter().enumerate() {
        // Distinct directly trusted leaves need distinct issuer names: OpenSSL
        // otherwise selects the first same-name self-signed trust anchor.
        let mut params = rcgen::CertificateParams::new(vec!["device.test".into()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("witness-client-{index}"));
        let key = rcgen::KeyPair::generate()?;
        let client = params.self_signed(&key)?;
        let certificate = client.der().to_vec();
        roots.add(client.der().clone())?;
        let subject =
            p::AnchorSubject::from_trusted_state(&fixture::read(path, "witness-subject", 96)?)?;
        bindings.push(PeerBinding::new(certificate.clone(), subject)?);
        fixture::store(path, "witness-tls-cert", &certificate)?;
        fixture::store(path, "witness-tls-key", &key.serialize_der())?;
        fixture::store(path, "witness-tls-peer", server.cert.der())?;
        fixture::store(path, "witness-tls-name", b"localhost")?;
    }
    let certificate = server.cert.der().to_vec();
    let key = zeroize::Zeroizing::new(server.signing_key.serialize_der());
    let config = MutualTlsServer::new(
        roots,
        vec![server.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::try_from(key.as_slice())?.clone_key(),
    )?;
    Ok(Provisioned {
        native: AnchorTlsServer::new(config, bindings)?,
        certificate,
        key,
    })
}

pub(crate) struct TlsWitness {
    pub(crate) address: SocketAddr,
    stop: Arc<AtomicBool>,
    pub(crate) admitted: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<Result<Vec<String>>>>,
}
impl TlsWitness {
    pub(crate) fn start<const N: usize>(
        store: Arc<Mutex<p::AnchorStore>>,
        paths: [&Path; N],
    ) -> Result<Self> {
        let Provisioned {
            native: server,
            certificate,
            key,
        } = provision(paths)?;
        // The native configuration owns its credentials; discard the separate
        // export copies needed only by the independent OpenSSL fixture.
        drop((certificate, key));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let control = Arc::clone(&stop);
        let admitted = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&admitted);
        let worker = thread::spawn(move || -> Result<Vec<String>> {
            let mut failures = Vec::new();
            while !control.load(Ordering::Acquire) {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let mut clock = || {
                    calls.fetch_add(1, Ordering::AcqRel);
                    fixture::now().map_err(io::Error::other)
                };
                if let Err(error) = server.serve(
                    stream,
                    &store,
                    Instant::now() + Duration::from_secs(3),
                    p::Cancellation::default(),
                    &mut clock,
                ) {
                    // Retain expected negative-control failures; assert their
                    // exact count at normal completion instead of swallowing.
                    failures.push(format!("{:?}: {error}", error.kind()));
                    if failures.len() > 8 {
                        return Err("unexpected TLS failure capacity".into());
                    }
                }
            }
            Ok(failures)
        });
        Ok(Self {
            address,
            stop,
            admitted,
            worker: Some(worker),
        })
    }
    pub(crate) fn finish(&mut self) -> Result<Vec<String>> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .ok_or("missing TLS worker")?
            .join()
            .map_err(|_| "TLS worker panicked")?
    }
}
impl Drop for TlsWitness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(failures)) => eprintln!("unfinished TLS witness; failures={failures:?}"),
                Ok(Err(error)) => eprintln!("TLS witness failed: {error}"),
                Err(_) => eprintln!("TLS witness panicked"),
            }
        }
    }
}
