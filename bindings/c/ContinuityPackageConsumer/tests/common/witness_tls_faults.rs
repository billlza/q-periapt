// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded encrypted-wire loss after a real native witness storage commit.
use crate::{fixture, p, witness_tls, Result};
use std::{
    fs,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_WIRE: usize = 256 * 1024;
const MAX_IMAGE: u64 = 32 * 1024 * 1024;

pub(crate) struct Exchange {
    pub(crate) advanced: bool,
    pub(crate) delivered: bool,
    pub(crate) encrypted_reply_bytes: usize,
}
fn snapshot(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("witness storage image is not a regular file".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(MAX_IMAGE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len())? > MAX_IMAGE {
        return Err("witness storage image exceeds observation bound".into());
    }
    Ok(bytes)
}
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
fn write(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
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
fn serve_one(
    mut front: TcpStream,
    server: &p::anchor_tls::AnchorTlsServer,
    store: &Mutex<p::AnchorStore>,
    path: &Path,
    lose_next: &AtomicBool,
    records: &Mutex<Vec<Exchange>>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
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
    thread::scope(|scope| -> Result<()> {
        let serving = scope.spawn(|| {
            let mut before = None;
            let served = server.serve(
                socket,
                store,
                deadline,
                p::Cancellation::default(),
                &mut || {
                    if before.is_some() {
                        return Err(io::Error::other("TLS clock was called twice"));
                    }
                    before = Some(snapshot(path).map_err(io::Error::other)?);
                    responding.store(true, Ordering::Release);
                    fixture::now().map_err(io::Error::other)
                },
            );
            (served, before)
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
                    write(&mut front, bytes, deadline)?;
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
        let (served, before) = served?;
        let sent = sent?;
        stopped?;
        sent?;
        served?;
        let reply = received?;
        let before = before.ok_or("TLS native admission did not run")?;
        let after = snapshot(path)?;
        let advanced = before != after;
        // AnchorStore::handle persists only Advanced. Queries and exact retries
        // are read-only. Observe the real image before handle and after serve,
        // while no other fixture action accesses this witness store.
        let lost = advanced
            && lose_next
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        if reply.is_empty() {
            return Err("TLS native reply was not retained".into());
        }
        {
            let mut records = records.lock().map_err(|_| "TLS fault record lock")?;
            if records.len() >= 4096 {
                return Err("TLS fault record capacity".into());
            }
            records.push(Exchange {
                advanced,
                delivered: !lost,
                encrypted_reply_bytes: reply.len(),
            });
        }
        // Publish the observation before making the corresponding reply or
        // interruption observable to the foreign caller.
        if !lost {
            write(&mut front, &reply, deadline)?;
        }
        // The request clone is joined. Release the last socket in both paths;
        // shutdown after a peer has closed is not part of the reply contract.
        drop(front);
        Ok(())
    })
}

pub(crate) struct FaultWitness {
    pub(crate) address: SocketAddr,
    pub(crate) captured: Arc<Mutex<Vec<Exchange>>>,
    stop: Arc<AtomicBool>,
    lose_next: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl FaultWitness {
    pub(crate) fn start(
        store: Arc<Mutex<p::AnchorStore>>,
        paths: [&Path; 3],
        image: PathBuf,
    ) -> Result<Self> {
        let configured = witness_tls::provision(paths)?;
        let server = configured.native;
        drop((configured.certificate, configured.key));
        snapshot(&image)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let control = Arc::clone(&stop);
        let lose_next = Arc::new(AtomicBool::new(false));
        let fault = Arc::clone(&lose_next);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let records = Arc::clone(&captured);
        let worker = thread::spawn(move || -> Result<()> {
            while !control.load(Ordering::Acquire) {
                let front = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                serve_one(front, &server, &store, &image, &fault, &records)?;
            }
            Ok(())
        });
        Ok(Self {
            address,
            captured,
            stop,
            lose_next,
            worker: Some(worker),
        })
    }
    pub(crate) fn arm(&self) -> Result<()> {
        self.lose_next
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "unconsumed TLS commit-response fault")?;
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .ok_or("TLS fault worker missing")?
            .join()
            .map_err(|_| "TLS fault worker panicked")??;
        if self.lose_next.load(Ordering::Acquire) {
            return Err("TLS commit-response fault did not fire".into());
        }
        Ok(())
    }
}
impl Drop for FaultWitness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => eprintln!("TLS fault witness was not explicitly finished"),
                Ok(Err(error)) => eprintln!("TLS fault witness cleanup failed: {error}"),
                Err(_) => eprintln!("TLS fault witness cleanup panicked"),
            }
        }
    }
}
