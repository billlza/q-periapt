// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared test-only framed TCP witness, with explicit independent approval.
use super::{clock, sdk};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) fn request_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Accepted sockets inherit nonblocking mode on macOS. Normalize the mode
    // before using blocking, timeout-bounded exact framing on every platform.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    if u32::from_be_bytes(length) != 3674 {
        return Err("Witness request frame length".into());
    }
    let mut request = vec![0; 3674];
    stream.read_exact(&mut request)?;
    Ok(request)
}

pub(crate) struct Server {
    pub(crate) store: Arc<Mutex<sdk::AnchorStore>>,
    pub(crate) pin: sdk::AnchorPin,
    pub(crate) address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<std::result::Result<usize, String>>>,
}
impl Server {
    pub(crate) fn start() -> Result<Self> {
        let dir = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?
            .keep()
            .canonicalize()?;
        eprintln!("Retained grant witness fixture: {}", dir.display());
        let store = sdk::AnchorStore::provision(
            &dir.join("witness.redb"),
            sdk::JournalKey::provision(&dir.join("wrap.key"))?,
            sdk::AnchorSigningKey::generate()?,
            sdk::AnchorIdentity::generate()?,
        )?;
        let pin = store.pin()?;
        let store = Arc::new(Mutex::new(store));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (store, stop) = (Arc::clone(&store), Arc::clone(&stop));
            thread::spawn(move || -> std::result::Result<usize, String> {
                let result = (|| -> Result<usize> {
                    let mut count = 0;
                    let deadline = Instant::now() + Duration::from_secs(120);
                    while !stop.load(Ordering::SeqCst) {
                        if count >= 512 || Instant::now() >= deadline {
                            return Err("Witness fixture resource bound exceeded".into());
                        }
                        let (mut stream, _) = match listener.accept() {
                            Ok(value) => value,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(2));
                                continue;
                            }
                            Err(e) => return Err(e.into()),
                        };
                        let request = request_frame(&mut stream)?;
                        let response = store
                            .lock()
                            .map_err(|_| "witness lock")?
                            .handle(&request, clock()?)?;
                        if response.len() != 3659 {
                            return Err("Witness response frame length".into());
                        }
                        stream.write_all(&3659u32.to_be_bytes())?;
                        stream.write_all(&response)?;
                        count += 1;
                    }
                    Ok(count)
                })();
                result.map_err(|e| e.to_string())
            })
        };
        Ok(Self {
            store,
            pin,
            address,
            stop,
            worker: Some(worker),
        })
    }
    pub(crate) fn close(&mut self) -> Result<usize> {
        self.stop.store(true, Ordering::SeqCst);
        Ok(self
            .worker
            .take()
            .ok_or("Witness fixture already stopped")?
            .join()
            .map_err(|_| "Witness fixture panicked")?
            .map_err(|e| format!("Witness fixture: {e}"))?)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.worker.is_some() {
            if let Err(e) = self.close() {
                eprintln!("Witness fixture cleanup failed: {e}");
            }
        }
    }
}
