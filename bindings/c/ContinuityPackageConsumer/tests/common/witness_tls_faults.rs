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
    lose_next: &AtomicBool,
    records: &Mutex<Vec<Exchange>>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut before = None;
    let (reply, _record) =
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
        witness_tls_relay::write(&mut front, &reply, deadline)?;
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
