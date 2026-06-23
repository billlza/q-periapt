//! End-to-end P99 harness for the server-authenticated PQ/T hybrid handshake.
//!
//! Measures *time-to-established-session* (TCP connect + full authenticated KEM
//! handshake) and reports latency percentiles plus the on-wire byte budget — the
//! quantity that actually drives tail latency on real links.
//!
//! Usage: `cargo run --release -p pqt-tls-demo --bin p99_bench [-- PROFILE ITERS DELAY_US]`
//!   PROFILE  = `bound` (default) | `compat`
//!   ITERS    = measured handshakes (default 2000)
//!   DELAY_US = emulated one-way latency injected per flight (default 0). This
//!              models flight-count sensitivity to RTT; it does NOT model TCP
//!              slow-start or loss (those need a netem/tc test on real interfaces).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use pqt_core::Profile;
use pqt_tls_demo::{client_handshake, server_handshake, ServerKeys};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Wraps a stream and sleeps `delay` before each write, modeling one-way
/// per-flight network latency.
struct DelayStream {
    inner: TcpStream,
    delay: Duration,
}
impl Read for DelayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for DelayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let profile = match args.get(1).map(String::as_str) {
        Some("compat") => Profile::CompatXWing,
        _ => Profile::ContextBound,
    };
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let delay = Duration::from_micros(args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0));
    let warmup = 200usize;
    let total = iters + warmup;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = Arc::new(ServerKeys::from_seeds([7u8; 64], [9u8; 32], [5u8; 32]));
    let server_vk = keys.verifying_key();
    let server_keys = Arc::clone(&keys);

    let server = thread::spawn(move || {
        for _ in 0..total {
            let (inner, _) = listener.accept().unwrap();
            inner.set_nodelay(true).ok();
            let mut s = DelayStream { inner, delay };
            let _ = server_handshake(&mut s, &server_keys);
        }
    });

    let mut times = Vec::with_capacity(iters);
    let mut sample = None;
    for i in 0..total {
        let t0 = Instant::now();
        let inner = TcpStream::connect(addr).unwrap();
        inner.set_nodelay(true).ok();
        let mut s = DelayStream { inner, delay };
        let (_secret, stats) = client_handshake(&mut s, profile, &server_vk).unwrap();
        let dt = t0.elapsed().as_nanos();
        if i >= warmup {
            times.push(dt);
            sample = Some(stats);
        }
    }
    server.join().unwrap();
    times.sort_unstable();

    let us = |ns: u128| ns as f64 / 1000.0;
    let s = sample.unwrap();
    println!(
        "server-auth PQ/T hybrid handshake — profile={profile:?}, samples={}, per-flight delay={}µs",
        times.len(),
        delay.as_micros()
    );
    println!("  time-to-session (TCP connect + handshake), microseconds:");
    println!("    p50  = {:.1}", us(pct(&times, 50.0)));
    println!("    p90  = {:.1}", us(pct(&times, 90.0)));
    println!("    p99  = {:.1}", us(pct(&times, 99.0)));
    println!("    p99.9= {:.1}", us(pct(&times, 99.9)));
    println!(
        "    min  = {:.1}  max = {:.1}",
        us(times[0]),
        us(times[times.len() - 1])
    );
    println!("  wire budget (one handshake):");
    println!(
        "    client->server = {} B, server->client = {} B",
        s.bytes_sent, s.bytes_recv
    );
    println!(
        "    total = {} B over {} flights each way (server->client carries the ~3.3 KB ML-DSA sig)",
        s.bytes_sent + s.bytes_recv,
        s.messages
    );
    println!("  note: loopback isolates CPU/syscall/copy; DELAY_US models per-flight RTT");
    println!("        (flight-count sensitivity), not slow-start/loss (needs netem/tc).");
}
