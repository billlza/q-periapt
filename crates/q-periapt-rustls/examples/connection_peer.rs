// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded loopback transport diagnostic using public SDK connection APIs.
//! Both reference peers persist/reopen policy state. Measurement uses the same
//! engine and authentication as the acceptance cases, with per-message logging
//! disabled. This example alone is not installed cross-platform qualification.
use q_periapt_host_store::PolicyStore;
use q_periapt_rustls::connection::{
    Connection, Credentials, Endpoint, Error, Limits, Phase, MAX_TLS_IO_BYTES,
};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Bytes(Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        q_periapt_core::secure_wipe(&mut self.0);
    }
}
fn read(directory: &Path, name: &str, maximum: usize) -> Result<Bytes> {
    let mut bytes = Bytes(Vec::new());
    File::open(directory.join(name))?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes.0)?;
    if bytes.0.len() > maximum {
        return Err("test fixture exceeds its size limit".into());
    }
    Ok(bytes)
}
fn endpoint(directory: &Path, mismatch: bool, provision: bool) -> Result<(PolicyStore, Endpoint)> {
    let policy = read(directory, "policy.toml", 65_536)?;
    let signature = read(directory, "policy.sig", 3309)?;
    let root = read(directory, "policy.vk", 1952)?;
    let path = directory.join("server.policy.redb");
    let store = if provision {
        PolicyStore::provision(
            &path,
            &policy.0,
            &signature.0,
            &root.0,
            q_periapt_sdk::Limits::default(),
        )?
    } else {
        PolicyStore::open_configured(
            &path,
            &policy.0,
            &signature.0,
            &root.0,
            q_periapt_sdk::Limits::default(),
        )?
    };
    let certificate = read(directory, "server.der", 65_536)?;
    let key = read(directory, "server.key.der", 16_384)?;
    let peer = read(directory, "client.der", 65_536)?;
    let endpoint = Endpoint::server(
        store.runtime()?,
        Credentials {
            certificate: &certificate.0,
            private_key: &key.0,
            peer_certificate: &peer.0,
        },
        if mismatch {
            b"different-context"
        } else {
            b"reference-connection-test/v1"
        },
        Limits {
            max_connections: 2,
            handshake_ms: 5000,
            request_ms: 5000,
            idle_ms: 5000,
        },
    )?;
    Ok((store, endpoint))
}

fn exchange(
    mut stream: TcpStream,
    mut engine: Connection,
    delayed: bool,
    trace: bool,
) -> Result<usize> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    let mut buffer = [0; MAX_TLS_IO_BYTES];
    let mut requests = 0;
    let mut confirmed = false;
    loop {
        let progress = match engine.progress() {
            Ok(progress) => progress,
            Err(Error::Closed) if confirmed => return Ok(requests),
            Err(error) => return Err(error.into()),
        };
        if progress.wants_write {
            let length = engine.drain_tls(&mut buffer)?;
            if length == 0 {
                return Err("TLS output made no progress".into());
            }
            let mut pending = buffer.get(..length).ok_or("invalid TLS output length")?;
            while !pending.is_empty() {
                let budget = engine.progress()?.remaining_ms;
                stream.set_write_timeout(Some(Duration::from_millis(budget.into())))?;
                let written = stream.write(pending)?;
                if written == 0 {
                    return Err("TCP write made no progress".into());
                }
                pending = pending.get(written..).ok_or("invalid TCP write length")?;
            }
            continue;
        }
        if !confirmed && matches!(progress.phase, Phase::Ready | Phase::RequestReady) {
            confirmed = true;
            if trace {
                println!("POLICY_CONFIRMED");
                std::io::stdout().flush()?;
            }
        }
        if progress.phase == Phase::RequestReady {
            let request = engine.take_request()?;
            if trace {
                println!("REQUEST {} {}", request.request_id(), request.bytes().len());
                std::io::stdout().flush()?;
            }
            if delayed {
                std::thread::sleep(Duration::from_millis(400));
            }
            engine.send_response(request.request_id(), request.bytes())?;
            requests += 1;
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_millis(progress.remaining_ms.into())))?;
        let length = stream.read(&mut buffer)?;
        if length == 0 {
            engine.end_of_input()?;
            continue;
        }
        let mut pending = buffer.get(..length).ok_or("invalid TCP read length")?;
        while !pending.is_empty() {
            let consumed = engine.feed_tls(pending)?;
            if consumed == 0 {
                return Err("TLS input made no progress".into());
            }
            pending = pending
                .get(consumed..)
                .ok_or("invalid TLS consumption length")?;
        }
    }
}

#[cfg(unix)]
fn accept_before(listener: &TcpListener, deadline: Instant) -> std::io::Result<TcpStream> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    use rustix::io::Errno;
    use std::io::{Error, ErrorKind};

    // A reset between readiness and accept must not turn into an unbounded
    // blocking accept. Recheck one absolute deadline after every wakeup/retry.
    listener.set_nonblocking(true)?;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| Error::new(ErrorKind::TimedOut, "TCP accept deadline expired"))
    };
    loop {
        let timeout = Timespec::try_from(remaining()?)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) | Err(Errno::INTR) => continue,
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
        remaining()?;
        let [descriptor] = descriptors;
        let ready = descriptor.revents();
        if ready.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            return Err(listener
                .take_error()?
                .unwrap_or_else(|| Error::other("TCP listener readiness failed")));
        }
        if !ready.contains(PollFlags::IN) {
            return Err(Error::other("unexpected TCP listener readiness"));
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // Scheduling can cross the deadline even after poll returned.
                // Dropping an undelivered stream keeps admission deadline-bound.
                remaining()?;
                return Ok(stream);
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(unix))]
fn accept_before(_listener: &TcpListener, _deadline: Instant) -> std::io::Result<TcpStream> {
    // The reference peer already requires the Unix host policy store.
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "reference peer requires Unix host persistence and socket readiness",
    ))
}

fn serve(directory: &Path, mode: &str, count: usize, provision: bool) -> Result<()> {
    let valid_count = if mode == "measure" {
        (201..=1001).contains(&count)
    } else {
        (1..=8).contains(&count)
    };
    if !valid_count || !["echo", "delay", "stall", "mismatch", "measure"].contains(&mode) {
        return Err("invalid diagnostic mode/count".into());
    }
    let (_store, endpoint) = endpoint(directory, mode == "mismatch", provision)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("LISTEN {}", listener.local_addr()?);
    std::io::stdout().flush()?;
    let mut total = 0;
    for _ in 0..count {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = accept_before(&listener, deadline)?;
        if mode == "stall" {
            // Deliberately silent peer tests the adapter's independent deadline
            // wakeup/cancellation. The diagnostic driver also bounds this process.
            std::thread::sleep(Duration::from_millis(500));
            drop(stream);
            continue;
        }
        total += exchange(
            stream,
            endpoint.accept()?,
            mode == "delay",
            mode != "measure",
        )?;
    }
    println!("CONNECTION_PEER_DONE requests={total}");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [directory, mode, count, action] if action == "provision" || action == "open" => {
            serve(Path::new(directory), mode, count.parse()?, action == "provision")
        }
        _ => {
            Err("usage: connection_peer TEST_FIXTURES echo|delay|stall|mismatch|measure CONNECTIONS provision|open".into())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn expired_deadline_does_not_consume_a_queued_connection() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let deadline = Instant::now();
        let error =
            accept_before(&listener, deadline).expect_err("deadline must reject queued peer");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let (queued, address) = listener.accept()?;
        assert_eq!(address, client.local_addr()?);
        drop(queued);
        Ok(())
    }

    #[test]
    fn idle_listener_expires_at_its_absolute_deadline() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let deadline = Instant::now() + Duration::from_millis(30);
        let error = accept_before(&listener, deadline).expect_err("idle listener must time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(Instant::now() >= deadline);
        Ok(())
    }

    #[test]
    fn readiness_delivers_a_later_connection() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            TcpStream::connect_timeout(&address, Duration::from_secs(1))
        });
        let accepted = accept_before(&listener, Instant::now() + Duration::from_secs(2));
        let connected = client.join().expect("client thread must finish")?;
        assert_eq!(accepted?.peer_addr()?, connected.local_addr()?);
        Ok(())
    }
}
