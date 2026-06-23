//! End-to-end P99 harness for the PQ/T hybrid handshake over loopback TCP.
//!
//! Measures *time-to-established-session* (TCP connect + full KEM handshake) and
//! reports latency percentiles plus the on-wire byte budget — the quantity that
//! actually drives tail latency on real links (extra bytes -> extra packets ->
//! TCP slow-start / QUIC flow-control effects), as opposed to encap/decap CPU.
//!
//! Usage: `cargo run --release -p pqt-tls-demo --bin p99_bench [-- compat|bound] [iters]`

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use pqt_core::Profile;
use pqt_tls_demo::{client_handshake, server_handshake, ServerKeys};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

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
    let warmup = 200usize;
    let total = iters + warmup;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = Arc::new(ServerKeys::from_seeds([7u8; 64], [9u8; 32]));
    let server_keys = Arc::clone(&keys);

    let server = thread::spawn(move || {
        for _ in 0..total {
            let (mut s, _) = listener.accept().unwrap();
            s.set_nodelay(true).ok();
            let _ = server_handshake(&mut s, &server_keys);
        }
    });

    let mut times = Vec::with_capacity(iters);
    let mut sample = None;
    for i in 0..total {
        let t0 = Instant::now();
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_nodelay(true).ok();
        let (_secret, stats) = client_handshake(&mut s, profile).unwrap();
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
        "PQ/T hybrid handshake — profile={profile:?}, samples={}",
        times.len()
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
        "    total = {} B over {} flights each way",
        s.bytes_sent + s.bytes_recv,
        s.messages
    );
    println!("  note: loopback isolates CPU/syscall/copy cost; on a lossy/high-RTT");
    println!("        link the ~2.2KB ML-KEM material dominates via extra packets.");
}
