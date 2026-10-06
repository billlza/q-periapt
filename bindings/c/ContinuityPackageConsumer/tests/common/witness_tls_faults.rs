// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded encrypted-wire loss after a real native witness storage commit.
use crate::{fixture, p, witness_tls, witness_tls_relay, Result};
use std::{
    fs,
    io::{self, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_IMAGE: u64 = 32 * 1024 * 1024;

pub(crate) struct Exchange {
    pub(crate) advanced: bool,
    pub(crate) delivered: bool,
    pub(crate) encrypted_reply_bytes: usize,
    pub(crate) record: p::anchor_tls::AnchorTlsRecord,
}
enum ReplyFault {
    Drop,
    Hold(PathBuf),
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
fn serve_one(
    mut front: TcpStream,
    server: &p::anchor_tls::AnchorTlsServer,
    store: &Mutex<p::AnchorStore>,
    path: &Path,
    next: &Mutex<Option<ReplyFault>>,
    records: &Mutex<Vec<Exchange>>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut before = None;
    let (reply, record) =
        witness_tls_relay::receive_reply(&mut front, server, store, deadline, &mut || {
            before = Some(snapshot(path).map_err(io::Error::other)?);
            fixture::now().map_err(io::Error::other)
        })?;
    let before = before.ok_or("TLS native admission did not run")?;
    let after = snapshot(path)?;
    let advanced = before != after;
    // AnchorStore::handle persists only Advanced. Queries and exact retries
    // are read-only. Observe the real image before handle and after serve,
    // while no other fixture action accesses this witness store.
    let fault = if advanced {
        next.lock().map_err(|_| "TLS next fault lock")?.take()
    } else {
        None
    };
    if reply.is_empty() {
        return Err("TLS native reply was not retained".into());
    }
    let signed_reply_bytes = record.reply().len();
    {
        let mut records = records.lock().map_err(|_| "TLS fault record lock")?;
        if records.len() >= 4096 {
            return Err("TLS fault record capacity".into());
        }
        records.push(Exchange {
            advanced,
            delivered: fault.is_none(),
            encrypted_reply_bytes: reply.len(),
            record,
        });
    }
    // Publish the observation before making the corresponding reply or
    // interruption observable to the foreign caller.
    match fault {
        None => witness_tls_relay::write(&mut front, &reply, deadline)?,
        Some(ReplyFault::Drop) => {}
        Some(ReplyFault::Hold(marker)) => {
            // Retain the remainder of the real encrypted response. The foreign
            // caller cannot authenticate a complete TLS reply from this prefix.
            let prefix = reply.get(..reply.len() / 2).ok_or("TLS reply prefix")?;
            if prefix.is_empty() || prefix.len() >= signed_reply_bytes {
                return Err("TLS prefix must be shorter than the signed reply".into());
            }
            witness_tls_relay::write(&mut front, prefix, deadline)?;
            fixture::publish_marker(
                marker.parent().ok_or("TLS marker parent")?,
                marker
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("TLS marker name")?,
            )?;
            // receive_reply has joined its request reader. Use an explicit
            // bounded harness release after observed cancellation/process exit;
            // a locally shut-down read side is not proof of peer disconnect.
            let released = marker.with_extension("released");
            loop {
                match fs::read(&released) {
                    Ok(bytes) if bytes == b"1" => break,
                    Ok(_) => return Err("TLS fault release marker differs".into()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if Instant::now() >= deadline {
                    return Err("TLS held reply was not released after observed termination".into());
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
    // The request clone is joined. Release the last socket in both paths;
    // shutdown after a peer has closed is not part of the reply contract.
    drop(front);
    Ok(())
}

pub(crate) struct FaultWitness {
    pub(crate) address: SocketAddr,
    pub(crate) captured: Arc<Mutex<Vec<Exchange>>>,
    stop: Arc<AtomicBool>,
    next: Arc<Mutex<Option<ReplyFault>>>,
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
        let next = Arc::new(Mutex::new(None));
        let fault = Arc::clone(&next);
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
            next,
            worker: Some(worker),
        })
    }
    pub(crate) fn arm(&self, marker: Option<&Path>) -> Result<()> {
        let mut next = self.next.lock().map_err(|_| "TLS next fault lock")?;
        if next.is_some() {
            return Err("unconsumed TLS commit-response fault".into());
        }
        *next = Some(marker.map_or(ReplyFault::Drop, |p| ReplyFault::Hold(p.to_owned())));
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .ok_or("TLS fault worker missing")?
            .join()
            .map_err(|_| "TLS fault worker panicked")??;
        if self
            .next
            .lock()
            .map_err(|_| "TLS next fault lock")?
            .is_some()
        {
            return Err("TLS commit-response fault did not fire".into());
        }
        for exchange in self
            .captured
            .lock()
            .map_err(|_| "TLS fault record lock")?
            .iter()
        {
            if exchange.record.request().len() != 3674
                || exchange.record.reply().len() != 3659
                || exchange.encrypted_reply_bytes == 0
                || (!exchange.delivered && !exchange.advanced)
            {
                return Err("TLS fault exchange frame width".into());
            }
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
