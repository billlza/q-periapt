//! End-to-end P99 harness for the server-authenticated PQ/T hybrid handshake.
//!
//! Measures *time-to-established-session* (TCP connect + full authenticated KEM
//! handshake) and reports latency percentiles plus the on-wire byte budget — the
//! quantity that actually drives tail latency on real links.
//!
//! Usage: `cargo run --release -p q-periapt-tls-demo --bin p99_bench [-- PROFILE ITERS DELAY_US]`
//!   PROFILE  = `bound` (default) | `compat` (default L3 suite only)
//!   ITERS    = measured handshakes (default 2000)
//!   DELAY_US = emulated one-way latency injected per flight (default 0). This
//!              models flight-count sensitivity to RTT; it does NOT model TCP
//!              slow-start or loss (those need a netem/tc test on real interfaces).
//!   SUITE    = env var `SUITE=enhanced` selects the NIST-L5 suite (ML-KEM-1024 +
//!              X25519, ML-DSA-87); default is ML-KEM-768 + X25519 + ML-DSA-65. The
//!              L5 suite's larger ct (1568 B) and signature (4627 B) directly show
//!              the bytes-on-wire effect the harness is built to surface. `compat`
//!              is rejected with `SUITE=enhanced`: the L5 expanded-key backend is
//!              ContextBound-only.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use q_periapt_core::Profile;
use q_periapt_tls_demo::{
    client_handshake, client_handshake_enhanced, server_handshake, server_handshake_enhanced,
    ServerKeys,
};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::{fmt::Display, str::FromStr};

const BASE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const WAKE_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_JOIN_POLL: Duration = Duration::from_millis(1);

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
    assert!(!sorted.is_empty(), "percentile input must not be empty");
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn usage_error(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(2);
}

fn parse_number_arg<T>(args: &[String], index: usize, name: &str, default: T) -> Result<T, String>
where
    T: FromStr,
    T::Err: Display,
{
    match args.get(index) {
        Some(value) => value
            .parse()
            .map_err(|error| format!("invalid {name} {value:?}: {error}")),
        None => Ok(default),
    }
}

fn serve_connections<F, E>(
    listener: TcpListener,
    total: usize,
    delay: Duration,
    io_timeout: Duration,
    cancelled: &AtomicBool,
    mut handshake: F,
) -> Result<(), String>
where
    F: FnMut(&mut DelayStream) -> Result<(), E>,
    E: Display,
{
    for _ in 0..total {
        let (inner, _) = listener
            .accept()
            .map_err(|error| format!("server accept failed: {error}"))?;
        if cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        inner
            .set_nodelay(true)
            .map_err(|error| format!("server TCP_NODELAY configuration failed: {error}"))?;
        set_io_timeouts(&inner, io_timeout)
            .map_err(|error| format!("server socket configuration failed: {error}"))?;
        let mut stream = DelayStream { inner, delay };
        handshake(&mut stream).map_err(|error| format!("server handshake failed: {error}"))?;
    }
    Ok(())
}

fn set_io_timeouts(stream: &TcpStream, timeout: Duration) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("write timeout: {error}"))
}

fn allocate_latency_samples(capacity: usize) -> Result<Vec<u128>, String> {
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(capacity)
        .map_err(|error| format!("failed to reserve {capacity} latency samples: {error}"))?;
    Ok(samples)
}

fn join_server_bounded(
    server: thread::JoinHandle<Result<(), String>>,
    timeout: Duration,
) -> Result<Result<(), String>, String> {
    let started = Instant::now();
    while !server.is_finished() {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            drop(server);
            return Err(format!(
                "server did not finish within {} ms and was not joined",
                timeout.as_millis()
            ));
        }
        thread::sleep(std::cmp::min(SERVER_JOIN_POLL, timeout - elapsed));
    }
    server
        .join()
        .map_err(|_| "server thread panicked".to_owned())
}

fn finish_client_failure(
    server: thread::JoinHandle<Result<(), String>>,
    cancelled: &AtomicBool,
    addr: SocketAddr,
    client_error: String,
) -> String {
    cancelled.store(true, Ordering::Release);
    let wake_context = TcpStream::connect_timeout(&addr, WAKE_CONNECT_TIMEOUT)
        .err()
        .map_or_else(String::new, |error| {
            format!("; failed to wake the server accept loop ({error})")
        });
    match join_server_bounded(server, SERVER_JOIN_TIMEOUT) {
        Ok(Ok(())) => format!("{client_error}{wake_context}"),
        Ok(Err(server_error)) => {
            format!("{client_error}{wake_context}; server also failed: {server_error}")
        }
        Err(join_error) => format!("{client_error}{wake_context}; {join_error}"),
    }
}

fn runtime_error(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1);
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 4 {
        usage_error("unexpected trailing arguments; expected PROFILE [ITERS [DELAY_US]]");
    }
    let profile = match args.get(1).map(String::as_str) {
        None | Some("bound") => Profile::ContextBound,
        Some("compat") => Profile::CompatXWing,
        Some(value) => usage_error(&format!(
            "unknown PROFILE {value:?}; expected \"bound\" or \"compat\""
        )),
    };
    let iters =
        parse_number_arg(&args, 2, "ITERS", 2000usize).unwrap_or_else(|error| usage_error(&error));
    if iters == 0 {
        usage_error("ITERS must be greater than zero");
    }
    let delay = Duration::from_micros(
        parse_number_arg(&args, 3, "DELAY_US", 0u64).unwrap_or_else(|error| usage_error(&error)),
    );
    let io_timeout = BASE_IO_TIMEOUT
        .checked_add(delay)
        .unwrap_or_else(|| usage_error("DELAY_US is too large"));
    let warmup = 200usize;
    let total = iters
        .checked_add(warmup)
        .unwrap_or_else(|| usage_error("ITERS is too large"));

    // SUITE=enhanced selects the NIST-L5 suite (ML-KEM-1024 + X25519, ML-DSA-87).
    let enhanced = match std::env::var("SUITE") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value.eq_ignore_ascii_case("default") => false,
        Ok(value) if value.eq_ignore_ascii_case("enhanced") => true,
        Ok(value) => usage_error(&format!(
            "unknown SUITE {value:?}; expected \"default\" or \"enhanced\""
        )),
        Err(std::env::VarError::NotUnicode(_)) => usage_error("SUITE is not valid Unicode"),
    };
    if enhanced && matches!(profile, Profile::CompatXWing) {
        usage_error(
            "SUITE=enhanced uses the expanded ML-KEM-1024 backend, which is ContextBound-only",
        );
    }
    let suite_name = if enhanced {
        "ML-KEM-1024 + X25519 / ML-DSA-87 (NIST L5)"
    } else {
        "ML-KEM-768 + X25519 / ML-DSA-65 (NIST L3)"
    };
    // Select the matching handshake pair once (fn-item -> fn-pointer coercion).
    let server_fn = if enhanced {
        server_handshake_enhanced::<DelayStream>
    } else {
        server_handshake::<DelayStream>
    };
    let client_fn = if enhanced {
        client_handshake_enhanced::<DelayStream>
    } else {
        client_handshake::<DelayStream>
    };
    // Reserve before key generation, listener creation, or thread startup so an
    // invalid/unavailable capacity cannot leave partially initialized resources.
    let mut times = allocate_latency_samples(iters)?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("server listener bind failed: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("server listener address lookup failed: {error}"))?;
    let keys = Arc::new(
        if enhanced {
            ServerKeys::from_seeds_enhanced([7u8; 64], [9u8; 32], [5u8; 32])
        } else {
            ServerKeys::from_seeds([7u8; 64], [9u8; 32], [5u8; 32])
        }
        .map_err(|error| format!("server key derivation failed: {error}"))?,
    );
    let server_vk = keys.verifying_key();
    let server_keys = Arc::clone(&keys);
    let cancelled = Arc::new(AtomicBool::new(false));
    let server_cancelled = Arc::clone(&cancelled);

    let server = thread::spawn(move || {
        serve_connections(
            listener,
            total,
            delay,
            io_timeout,
            &server_cancelled,
            |stream| server_fn(stream, &server_keys).map(|_| ()),
        )
    });

    let mut sample = None;
    for i in 0..total {
        let transport_start = Instant::now();
        let handshake_result = (|| {
            let inner = TcpStream::connect_timeout(&addr, io_timeout)
                .map_err(|error| format!("client TCP connect failed: {error}"))?;
            inner
                .set_nodelay(true)
                .map_err(|error| format!("client TCP_NODELAY configuration failed: {error}"))?;
            let transport_elapsed = transport_start.elapsed();
            // Preserve the original connect + TCP_NODELAY setup + handshake scope.
            // Finite I/O deadlines are harness instrumentation, so pause the
            // metric around exactly those two socket options.
            set_io_timeouts(&inner, io_timeout)
                .map_err(|error| format!("client socket configuration failed: {error}"))?;
            let handshake_start = Instant::now();
            let mut stream = DelayStream { inner, delay };
            let outcome = client_fn(&mut stream, profile, &server_vk)
                .map_err(|error| format!("client handshake failed: {error}"))?;
            Ok((outcome, transport_elapsed + handshake_start.elapsed()))
        })();
        let ((_secret, stats), elapsed) = match handshake_result {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(finish_client_failure(server, &cancelled, addr, error));
            }
        };
        let dt = elapsed.as_nanos();
        if i >= warmup {
            times.push(dt);
            sample = Some(stats);
        }
    }
    match join_server_bounded(server, SERVER_JOIN_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(error) => return Err(error),
    }
    times.sort_unstable();

    let us = |ns: u128| ns as f64 / 1000.0;
    let s = sample.ok_or_else(|| "benchmark completed without sample statistics".to_owned())?;
    println!(
        "server-auth PQ/T hybrid handshake — suite={suite_name}, profile={profile:?}, samples={}, per-flight delay={}µs",
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
    let sig_note = if enhanced {
        "the ~4.6 KB ML-DSA-87 sig"
    } else {
        "the ~3.3 KB ML-DSA-65 sig"
    };
    println!(
        "    total = {} B over {} flights each way (server->client carries {sig_note})",
        s.bytes_sent + s.bytes_recv,
        s.messages
    );
    println!("  note: loopback isolates CPU/syscall/copy; DELAY_US models per-flight RTT");
    println!("        (flight-count sensitivity), not slow-start/loss (needs netem/tc).");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        runtime_error(&error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_arguments_are_explicit_and_fail_on_invalid_input() {
        let args = vec!["p99_bench".to_owned(), "bound".to_owned(), "17".to_owned()];
        assert_eq!(parse_number_arg(&args, 2, "ITERS", 2000usize), Ok(17));
        assert_eq!(parse_number_arg(&args, 3, "DELAY_US", 9u64), Ok(9));

        let invalid = vec![
            "p99_bench".to_owned(),
            "bound".to_owned(),
            "invalid".to_owned(),
        ];
        let error = parse_number_arg(&invalid, 2, "ITERS", 2000usize).unwrap_err();
        assert!(error.contains("invalid ITERS \"invalid\""));
    }

    #[test]
    fn percentile_uses_nonempty_samples() {
        assert_eq!(pct(&[10, 20, 30], 50.0), 20);
    }

    #[test]
    #[should_panic(expected = "percentile input must not be empty")]
    fn percentile_rejects_empty_samples() {
        let _ = pct(&[], 50.0);
    }

    #[test]
    fn latency_sample_allocation_rejects_impossible_capacity() {
        let error = allocate_latency_samples(usize::MAX).unwrap_err();
        assert!(error.contains("failed to reserve"));
        assert!(error.contains(&usize::MAX.to_string()));
    }

    #[test]
    fn bounded_join_detaches_a_stalled_server() {
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            release_rx
                .recv()
                .map_err(|error| format!("release channel failed: {error}"))?;
            done_tx
                .send(())
                .map_err(|error| format!("completion channel failed: {error}"))?;
            Ok(())
        });

        let error = join_server_bounded(server, Duration::from_millis(10)).unwrap_err();
        assert!(
            error.contains("was not joined"),
            "unexpected error: {error}"
        );
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn server_handshake_failure_drops_socket_and_unblocks_client() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let server_cancelled = Arc::clone(&cancelled);
        let server = thread::spawn(move || {
            serve_connections(
                listener,
                1,
                Duration::ZERO,
                Duration::from_secs(2),
                &server_cancelled,
                |_stream| {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "intentional early handshake failure",
                    ))
                },
            )
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut byte = [0u8; 1];
        let read_result = client.read(&mut byte);
        let was_cancelled = match &read_result {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) => !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
        };
        assert!(
            was_cancelled,
            "client was not actively cancelled before its read timeout: {read_result:?}"
        );

        let server_error = server.join().unwrap().unwrap_err();
        assert!(
            server_error
                .to_string()
                .contains("intentional early handshake failure"),
            "unexpected server error: {server_error}"
        );
    }

    #[test]
    fn client_failure_before_connect_wakes_server_blocked_in_accept() -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let server_cancelled = Arc::clone(&cancelled);
        let (server_done_tx, server_done_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let result = serve_connections(
                listener,
                1,
                Duration::ZERO,
                Duration::from_secs(2),
                &server_cancelled,
                |_stream| Ok::<(), io::Error>(()),
            );
            server_done_tx.send(()).unwrap();
            result
        });

        let started = Instant::now();
        let error = finish_client_failure(
            server,
            &cancelled,
            addr,
            "intentional client setup failure before connect".to_owned(),
        );
        let detach_elapsed = started.elapsed();
        match server_done_rx.try_recv() {
            Ok(()) => {}
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                let cleanup_wake = TcpStream::connect_timeout(&addr, WAKE_CONNECT_TIMEOUT);
                if let Err(done_error) = server_done_rx.recv_timeout(SERVER_JOIN_TIMEOUT) {
                    return Err(format!(
                        "server did not finish after fallback cleanup wake {cleanup_wake:?}: {done_error}"
                    ));
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("server completion channel disconnected".to_owned());
            }
        }

        assert_eq!(error, "intentional client setup failure before connect");
        assert!(
            detach_elapsed < Duration::from_secs(1),
            "client cancellation did not promptly wake accept: {detach_elapsed:?}"
        );
        Ok(())
    }
}
