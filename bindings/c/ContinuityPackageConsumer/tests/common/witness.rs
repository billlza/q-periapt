// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The original signed witness socket, shared by independent installed test targets.
use crate::{fixture, p, Result};
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
pub(crate) struct Capture {
    pub(crate) request: Vec<u8>,
    pub(crate) reply: Vec<u8>,
    pub(crate) delivered: bool,
}
pub(crate) struct Witness {
    pub(crate) _directory: tempfile::TempDir,
    pub(crate) configured: fixture::WitnessFixture,
    stop: Arc<AtomicBool>,
    pub(crate) fault: Arc<AtomicU8>,
    pub(crate) hold_marker: Arc<Mutex<Option<PathBuf>>>,
    pub(crate) captured: Arc<Mutex<Vec<Capture>>>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl Witness {
    pub(crate) fn start() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = directory.path().canonicalize()?;
        let key = p::JournalKey::provision(&path.join("wrap.key"))?;
        let store = p::AnchorStore::provision(
            &path.join("witness.redb"),
            key,
            p::AnchorSigningKey::generate()?,
            p::AnchorIdentity::generate()?,
        )?;
        let store = Arc::new(Mutex::new(store));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let fault = Arc::new(AtomicU8::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let hold_marker: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
        let held = Arc::clone(&hold_marker);
        let control = Arc::clone(&stop);
        let pending = Arc::clone(&fault);
        let records = Arc::clone(&captured);
        let witness = Arc::clone(&store);
        let worker = thread::spawn(move || -> Result<()> {
            while !control.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let mut size = [0; 4];
                stream.read_exact(&mut size).map_err(|error| {
                    io::Error::new(error.kind(), format!("witness request prefix: {error}"))
                })?;
                if u32::from_be_bytes(size) != 3674 {
                    return Err("witness request frame differs".into());
                }
                let mut request = vec![0; 3674];
                stream.read_exact(&mut request).map_err(|error| {
                    io::Error::new(error.kind(), format!("witness request body: {error}"))
                })?;
                let mut reply = witness
                    .lock()
                    .map_err(|_| "witness lock poisoned")?
                    .handle(&request, fixture::now()?)?;
                if reply.len() != 3659 {
                    return Err("witness reply frame differs".into());
                }
                // Inspect only the public signed outcome AFTER the real witness
                // authenticated the request and durably applied its transition.
                let advanced = reply.get(204) == Some(&2);
                let mut delivered = true;
                if (advanced
                    && pending
                        .compare_exchange(3, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok())
                    || pending
                        .compare_exchange(4, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    || (request.get(204) == Some(&6)
                        && pending
                            .compare_exchange(6, 0, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok())
                    || (request.get(204) == Some(&8)
                        && pending
                            .compare_exchange(8, 0, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok())
                {
                    let marker = held
                        .lock()
                        .map_err(|_| "hold lock poisoned")?
                        .take()
                        .ok_or("missing cancellation barrier")?;
                    let mut prefix = (reply.len() as u32).to_be_bytes().to_vec();
                    prefix.extend_from_slice(reply.get(..1800).ok_or("reply prefix")?);
                    stream.write_all(&prefix)?;
                    fixture::store(
                        marker.parent().ok_or("marker parent")?,
                        "witness-cancelled-prefix",
                        &prefix,
                    )?;
                    fixture::publish_marker(
                        marker.parent().ok_or("marker parent")?,
                        marker
                            .file_name()
                            .ok_or("marker name")?
                            .to_str()
                            .ok_or("marker encoding")?,
                    )?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut byte = [0];
                    if stream.read(&mut byte)? != 0 {
                        return Err("cancelled witness connection sent extra bytes".into());
                    }
                    delivered = false;
                } else if advanced
                    && pending
                        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    delivered = false;
                } else if pending
                    .compare_exchange(2, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let last = reply.last_mut().ok_or("empty witness reply")?;
                    *last ^= 1;
                }
                let mut log = records
                    .lock()
                    .map_err(|_| "witness capture lock poisoned")?;
                if log.len() >= 4096 {
                    return Err("witness capture capacity".into());
                }
                log.push(Capture {
                    request,
                    reply: reply.clone(),
                    delivered,
                });
                drop(log);
                if delivered {
                    stream
                        .write_all(&u32::try_from(reply.len())?.to_be_bytes())
                        .map_err(|error| {
                            io::Error::new(error.kind(), format!("witness reply prefix: {error}"))
                        })?;
                    stream.write_all(&reply).map_err(|error| {
                        io::Error::new(error.kind(), format!("witness reply body: {error}"))
                    })?;
                }
            }
            Ok(())
        });
        Ok(Self {
            _directory: directory,
            configured: fixture::WitnessFixture { store, address },
            stop,
            fault,
            captured,
            hold_marker,
            worker: Some(worker),
        })
    }
    pub(crate) fn arm(&self, fault: u8) -> Result<()> {
        self.fault
            .compare_exchange(0, fault, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "unconsumed witness fault")?;
        Ok(())
    }
    pub(crate) fn join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "witness worker panicked")??;
        }
        if self
            .hold_marker
            .lock()
            .map_err(|_| "hold lock poisoned")?
            .is_some()
        {
            return Err("witness stopped with an unconsumed hold barrier".into());
        }
        Ok(())
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Normal completion checks join explicitly. During unwinding report a
        // worker failure rather than silently treating cleanup as success.
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("witness cleanup failed: {error}"),
                Err(_) => eprintln!("witness cleanup worker panicked"),
            }
        }
    }
}
