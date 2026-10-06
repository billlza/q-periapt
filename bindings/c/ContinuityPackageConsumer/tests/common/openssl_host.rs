// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently authenticated OpenSSL transport with one native store host.
use crate::{fixture, p, witness_tls, Result};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

pub(crate) struct Exchange {
    pub(crate) request: Vec<u8>,
    pub(crate) reply: Vec<u8>,
}
pub(crate) fn executable() -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("QPERIAPT_WITNESS_OPENSSL_PEER")
            .ok_or("independent OpenSSL witness peer is required")?,
    );
    if !path.is_absolute() || !path.is_file() {
        return Err("invalid OpenSSL peer executable".into());
    }
    Ok(path)
}
pub(crate) fn capture(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
pub(crate) fn public_log(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("OpenSSL public log exceeded bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
pub(crate) fn result_lines(text: &str, role: &str, count: usize) -> Result<()> {
    let expected = (1..=count).map(|i| format!(
        "OPENSSL_WITNESS_OK role={role} tls=1.3 group=X25519MLKEM768 alpn=q-periapt-anchor/1 exchange={i}\n"
    )).collect::<String>();
    if text != expected {
        return Err(format!("independent TLS result differs: {text}").into());
    }
    Ok(())
}
pub(crate) struct Host {
    child: fixture::OwnedChild,
    input: Arc<Mutex<Option<ChildStdin>>>,
    worker: Option<thread::JoinHandle<Result<usize>>>,
    pub(crate) address: SocketAddr,
    stderr: PathBuf,
    pub(crate) captured: Arc<Mutex<Vec<Exchange>>>,
    pub(crate) unprocessed: Arc<Mutex<Vec<Vec<u8>>>>,
    pub(crate) drop_advance: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<bool>>>,
}
impl Host {
    pub(crate) fn start<const N: usize>(
        root: &Path,
        paths: [&Path; N],
        store: Arc<Mutex<p::AnchorStore>>,
        faults: bool,
    ) -> Result<Self> {
        if !(2..=3).contains(&N) {
            return Err("OpenSSL peer binding count".into());
        }
        let configured = witness_tls::provision(paths)?;
        fixture::store(root, "openssl-server-cert", &configured.certificate)?;
        fixture::store(root, "openssl-server-key", configured.key.as_slice())?;
        // The native TLS configuration is deliberately not used by this peer.
        drop(configured);
        let stderr = root.join("openssl-witness-server.stderr");
        let mut command = Command::new(executable()?);
        command
            .args([
                if faults { "server-faults" } else { "server" },
                "127.0.0.1:0",
            ])
            .arg(root.join("openssl-server-cert"))
            .arg(root.join("openssl-server-key"));
        for path in paths {
            command
                .arg(path.join("witness-tls-cert"))
                .arg(path.join("witness-subject"));
        }
        let mut child = fixture::OwnedChild(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(capture(&stderr)?))
                .spawn()?,
        );
        let input = Arc::new(Mutex::new(Some(child.0.stdin.take().ok_or("host input")?)));
        let mut reader = BufReader::new(child.0.stdout.take().ok_or("host output")?);
        let (ready, announcement) = std::sync::mpsc::sync_channel(1);
        let replies = Arc::clone(&input);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let records = Arc::clone(&captured);
        let unprocessed = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::clone(&unprocessed);
        let drop_advance = Arc::new(AtomicBool::new(false));
        let armed = Arc::clone(&drop_advance);
        let events = Arc::new(Mutex::new(Vec::new()));
        let outcomes = Arc::clone(&events);
        let worker = thread::spawn(move || -> Result<usize> {
            let mut line = String::new();
            (&mut reader).take(96).read_line(&mut line)?;
            let address: SocketAddr = line
                .strip_prefix("LISTEN ")
                .and_then(|v| v.strip_suffix('\n'))
                .ok_or("OpenSSL listener announcement")?
                .parse()?;
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err("OpenSSL listener scope".into());
            }
            ready.send(address)?;
            let mut count = 0;
            loop {
                let mut prefix = [0; 4];
                let first = reader.read(prefix.get_mut(..1).ok_or("prefix slice")?)?;
                if first == 0 {
                    break;
                }
                reader.read_exact(prefix.get_mut(1..).ok_or("prefix tail")?)?;
                if u32::from_be_bytes(prefix) != 3674 {
                    return Err("OpenSSL request frame width".into());
                }
                let mut request = vec![0; 3674];
                reader.read_exact(&mut request)?;
                if count >= 1024 {
                    return Err("OpenSSL reference request capacity".into());
                }
                // The independent TLS process has already received the full frame,
                // authenticated its close and checked the exact certificate/subject.
                // A zero-length IPC instruction is test-only connection loss; it is
                // never a native reply or an empty successful network response.
                if faults && request.get(204) == Some(&2) && armed.swap(false, Ordering::AcqRel) {
                    dropped
                        .lock()
                        .map_err(|_| "OpenSSL dropped request lock")?
                        .push(request);
                    outcomes
                        .lock()
                        .map_err(|_| "OpenSSL outcome lock")?
                        .push(false);
                    let mut input = replies.lock().map_err(|_| "host input poisoned")?;
                    let input = input.as_mut().ok_or("host input closed during fault")?;
                    input.write_all(&0_u32.to_be_bytes())?;
                    input.flush()?;
                    count += 1;
                    continue; // No access to AnchorStore::handle on this request.
                }
                // This is the first store access for each network request. The
                // independent TLS peer has already checked its exact leaf/scope
                // binding and authenticated request end; native signatures and
                // the original durable transaction still govern the command.
                let reply = store
                    .lock()
                    .map_err(|_| "witness store poisoned")?
                    .handle(&request, fixture::now()?)?;
                if reply.len() != 3659 {
                    return Err("native reply frame width".into());
                }
                records
                    .lock()
                    .map_err(|_| "OpenSSL capture lock")?
                    .push(Exchange {
                        request,
                        reply: reply.clone(),
                    });
                outcomes
                    .lock()
                    .map_err(|_| "OpenSSL outcome lock")?
                    .push(true);
                let mut input = replies.lock().map_err(|_| "host input poisoned")?;
                let input = input.as_mut().ok_or("host input closed during request")?;
                input.write_all(&3659_u32.to_be_bytes())?;
                input.write_all(&reply)?;
                input.flush()?;
                count += 1;
            }
            Ok(count)
        });
        let mut host = Self {
            child,
            input,
            worker: Some(worker),
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            stderr,
            captured,
            unprocessed,
            drop_advance,
            events,
        };
        // On a partial/absent announcement Drop reaps the process before it
        // joins the blocked reader; readiness has its own finite deadline.
        host.address = announcement.recv_timeout(Duration::from_secs(5))?;
        Ok(host)
    }
    pub(crate) fn finish(&mut self) -> Result<usize> {
        self.input.lock().map_err(|_| "host input poisoned")?.take();
        let (status, count, text) = self.complete()?;
        if !status.success() {
            return Err(format!("OpenSSL server {status}: {text}").into());
        }
        let events = self.events.lock().map_err(|_| "OpenSSL outcome lock")?;
        if count != events.len()
            || self.drop_advance.load(Ordering::Acquire)
            || !self
                .unprocessed
                .lock()
                .map_err(|_| "OpenSSL dropped request lock")?
                .is_empty()
        {
            return Err("OpenSSL fault or request observation not completed".into());
        }
        let records = self.captured.lock().map_err(|_| "OpenSSL capture lock")?;
        if records.len() != events.iter().filter(|handled| **handled).count()
            || records
                .iter()
                .any(|record| record.request.len() != 3674 || record.reply.len() != 3659)
        {
            return Err("OpenSSL processed frame inventory differs".into());
        }
        if events.iter().all(|handled| *handled) {
            result_lines(&text, "server", count)?;
            return Ok(count);
        }
        let expected = events.iter().enumerate().map(|(i, handled)| format!(
            "OPENSSL_WITNESS_{} role=server tls=1.3 group=X25519MLKEM768 alpn=q-periapt-anchor/1 exchange={}\n",
            if *handled { "OK" } else { "DROPPED" }, i + 1)).collect::<String>();
        if text != expected {
            return Err(format!("OpenSSL server completion scope differs: {text}").into());
        }
        Ok(count)
    }
    pub(crate) fn complete(&mut self) -> Result<(std::process::ExitStatus, usize, String)> {
        let status = fixture::wait(&mut self.child)?;
        let count = self
            .worker
            .take()
            .ok_or("host worker missing")?
            .join()
            .map_err(|_| "host worker panicked")??;
        let text = public_log(&self.stderr)?;
        Ok((status, count, text))
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            // Error cleanup reaps the process before joining its pipe reader.
            match self.child.0.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(error) = self.child.0.kill() {
                        eprintln!("OpenSSL peer cleanup: {error}");
                    }
                    if let Err(error) = self.child.0.wait() {
                        eprintln!("OpenSSL peer reap: {error}");
                    }
                }
                Err(error) => {
                    eprintln!("OpenSSL peer state: {error}");
                    if let Err(error) = self.child.0.kill() {
                        eprintln!("OpenSSL peer cleanup: {error}");
                    }
                    if let Err(error) = self.child.0.wait() {
                        eprintln!("OpenSSL peer reap: {error}");
                    }
                }
            }
            match worker.join() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => eprintln!("OpenSSL host cleanup: {error}"),
                Err(_) => eprintln!("OpenSSL host cleanup panicked"),
            }
        }
    }
}
