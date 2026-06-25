//! Socket-based TLS 1.3 handshake P99 bench for a real `tc netem` evaluation.
//!
//! Unlike the in-memory handshake test, this drives the handshake over a real loopback
//! TCP socket, so kernel netem (`tc qdisc add dev lo root netem delay …`) shapes the link
//! with true TCP dynamics. It measures *time-to-session* (TCP connect + full TLS 1.3
//! handshake) percentiles and the one-handshake wire budget, for:
//!   classical  — X25519 (no PQ): the baseline that quantifies the PQ overhead
//!   bound      — Q-Periapt ContextBound  (ML-KEM-768 + X25519, hash-everything combiner)
//!   compat     — Q-Periapt CompatXWing   (ML-KEM-768 + X25519, X-Wing byte-exact combiner)
//!
//! Usage: cargo run --release -p q-periapt-rustls --example netem_bench -- <kind> <iters> [warmup]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, NamedGroup, RootCertStore, ServerConnection};

static SENT: AtomicU64 = AtomicU64::new(0);
static RECV: AtomicU64 = AtomicU64::new(0);

/// Client-side TcpStream wrapper that counts handshake bytes for the wire-budget report.
struct Counting(TcpStream);
impl Read for Counting {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(b)?;
        RECV.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}
impl Write for Counting {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.0.write(b)?;
        SENT.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn one_group(mut p: CryptoProvider, want: NamedGroup) -> CryptoProvider {
    p.kx_groups.retain(|g| g.name() == want);
    p
}

fn provider_for(kind: &str) -> (CryptoProvider, &'static str) {
    match kind {
        "classical" => {
            let mut p = rustls::crypto::ring::default_provider();
            p.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
            (p, "X25519 (classical baseline)")
        }
        "standard" => {
            // The IANA-standard PQ/T hybrid group (concatenation combiner), via aws-lc-rs.
            let mut p = rustls::crypto::aws_lc_rs::default_provider();
            p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
            (p, "X25519MLKEM768 (IANA standard hybrid)")
        }
        "compat" => (
            one_group(
                q_periapt_rustls::provider(),
                q_periapt_rustls::Q_PERIAPT_COMPATXWING,
            ),
            "Q-Periapt CompatXWing (ML-KEM-768 + X25519)",
        ),
        _ => (
            one_group(
                q_periapt_rustls::provider(),
                q_periapt_rustls::Q_PERIAPT_CONTEXTBOUND,
            ),
            "Q-Periapt ContextBound (ML-KEM-768 + X25519)",
        ),
    }
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        cert.cert.der().clone(),
        PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
    )
}

fn pct(sorted: &[u128], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)] as f64 / 1000.0
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let kind = a.get(1).cloned().unwrap_or_else(|| "bound".into());
    let iters: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
    let warmup: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(50);
    let total = iters + warmup;

    let (cprov, label) = provider_for(&kind);
    let cprov = Arc::new(cprov);
    let (cert, key) = self_signed();

    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(cprov.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(cprov)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        for _ in 0..total {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_nodelay(true).ok();
            // SO_LINGER=0: close() sends RST, so the socket skips TIME_WAIT. Without this, the
            // tens of thousands of short loopback connections pile up TIME_WAIT sockets whose
            // port reuse injects 40ms delayed-ACK / ~100ms retransmit stalls into later reps.
            sock.set_linger(Some(std::time::Duration::ZERO)).ok();
            let mut conn = ServerConnection::new(server_cfg.clone()).unwrap();
            let _ = conn.complete_io(&mut sock);
        }
    });

    let name = ServerName::try_from("localhost").unwrap();
    let mut times = Vec::with_capacity(iters);
    for i in 0..total {
        SENT.store(0, Ordering::Relaxed);
        RECV.store(0, Ordering::Relaxed);
        let t0 = Instant::now();
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_nodelay(true).ok();
        sock.set_linger(Some(std::time::Duration::ZERO)).ok(); // RST on close -> no TIME_WAIT churn
        let mut conn = ClientConnection::new(client_cfg.clone(), name.clone()).unwrap();
        let mut s = Counting(sock);
        conn.complete_io(&mut s).unwrap();
        assert!(!conn.is_handshaking());
        let dt = t0.elapsed().as_nanos();
        if i >= warmup {
            times.push(dt);
        }
    }
    server.join().unwrap();
    times.sort_unstable();

    println!("group = {label}, samples = {}", times.len());
    println!("  time-to-session (TCP connect + TLS 1.3 handshake), microseconds:");
    println!(
        "    p50 = {:.1}  p90 = {:.1}  p99 = {:.1}  p99.9 = {:.1}",
        pct(&times, 50.0),
        pct(&times, 90.0),
        pct(&times, 99.0),
        pct(&times, 99.9)
    );
    println!(
        "  wire (one handshake): client->server = {} B, server->client = {} B",
        SENT.load(Ordering::Relaxed),
        RECV.load(Ordering::Relaxed)
    );
}
