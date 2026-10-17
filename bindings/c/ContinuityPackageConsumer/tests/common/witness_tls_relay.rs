// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Encrypted-wire relay around the unchanged, recorded native TLS server.
use crate::{p, Result};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};
const MAX_WIRE: usize = 256 * 1024;

fn window(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(Duration::from_millis(25)))
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TLS fault relay deadline"))
}
fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
pub(crate) fn write(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(window(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = bytes.get(count..).ok_or(io::ErrorKind::InvalidData)?,
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn send_request(
    mut front: TcpStream,
    mut backend: TcpStream,
    done: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    let mut buffer = [0; 8192];
    let mut total = 0_usize;
    while !done.load(Ordering::Acquire) {
        front.set_read_timeout(Some(window(deadline)?))?;
        match front.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                total = total
                    .checked_add(count)
                    .filter(|value| *value <= MAX_WIRE)
                    .ok_or("TLS request relay byte budget")?;
                write(
                    &mut backend,
                    buffer.get(..count).ok_or("TLS request relay range")?,
                    deadline,
                )?;
            }
            Err(error)
                if done.load(Ordering::Acquire)
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::NotConnected
                    ) =>
            {
                return Ok(())
            }
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
pub(crate) fn receive_reply(
    front: &mut TcpStream,
    server: &p::anchor_tls::AnchorTlsServer,
    store: &Mutex<p::AnchorStore>,
    deadline: Instant,
    clock: &mut (impl FnMut() -> io::Result<u64> + Send),
) -> Result<(Vec<u8>, p::anchor_tls::AnchorTlsRecord)> {
    // A local TCP pair lets the unchanged native TLS server own its real socket.
    // The intermediary sees encrypted wire only; it has no TLS traffic secrets.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut backend = TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(1))?;
    let (socket, address) = listener.accept()?;
    if address != backend.local_addr()? {
        return Err("TLS relay peer identity".into());
    }
    drop(listener);
    let input = front.try_clone()?;
    let output = backend.try_clone()?;
    let responding = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    thread::scope(
        |scope| -> Result<(Vec<u8>, p::anchor_tls::AnchorTlsRecord)> {
            let serving = scope.spawn(|| {
                server.serve_recorded(
                    socket,
                    store,
                    deadline,
                    p::Cancellation::default(),
                    &mut || {
                        if responding.swap(true, Ordering::AcqRel) {
                            return Err(io::Error::other("TLS clock was called twice"));
                        }
                        clock()
                    },
                )
            });
            let sending = scope.spawn(|| send_request(input, output, &done, deadline));
            let received = (|| -> Result<Vec<u8>> {
                let mut reply = Vec::new();
                let mut buffer = [0; 8192];
                let mut total = 0_usize;
                loop {
                    backend.set_read_timeout(Some(window(deadline)?))?;
                    let count = match backend.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => count,
                        Err(error) if transient(&error) => continue,
                        Err(error) => return Err(error.into()),
                    };
                    total = total
                        .checked_add(count)
                        .filter(|value| *value <= MAX_WIRE)
                        .ok_or("TLS reply relay byte budget")?;
                    let bytes = buffer.get(..count).ok_or("TLS reply relay range")?;
                    if responding.load(Ordering::Acquire) {
                        reply.extend_from_slice(bytes);
                    } else {
                        write(front, bytes, deadline)?;
                    }
                }
                Ok(reply)
            })();
            let served = serving.join().map_err(|_| "TLS native server panicked");
            done.store(true, Ordering::Release);
            let stopped = front.shutdown(Shutdown::Read).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("TLS relay stop request reader: {error}"),
                )
            });
            let sent = sending.join().map_err(|_| "TLS request relay panicked");
            // Join both bounded workers before evaluating their results. No private
            // before/after image is printed, including on an unexpected failure.
            let served = served?;
            let sent = sent?;
            stopped?;
            sent?;
            let record = served?;
            let reply = received?;
            if reply.is_empty() {
                return Err("TLS native reply was not retained".into());
            }
            Ok((reply, record))
        },
    )
}
