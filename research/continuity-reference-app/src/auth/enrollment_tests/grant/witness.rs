// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real framed TCP witness; initial enrollment and G approval stay independent.
use super::*;
use crate::native_device::CredentialRecoveryInputs;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

fn request_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
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

pub(super) struct Server {
    pub(super) store: Arc<Mutex<sdk::AnchorStore>>,
    pub(super) pin: sdk::AnchorPin,
    pub(super) address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<std::result::Result<usize, String>>>,
}
impl Server {
    fn start() -> Result<Self> {
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
                            .handle(&request, crate::enrollment::now()?)?;
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
    fn close(&mut self) -> Result<usize> {
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

#[test]
fn witness_fixture_waits_for_a_request_sent_after_nonblocking_accept() -> Result {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let (start, go) = std::sync::mpsc::channel();
    let sender = thread::spawn(move || -> std::io::Result<()> {
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        go.recv_timeout(Duration::from_secs(3))
            .map_err(std::io::Error::other)?;
        thread::sleep(Duration::from_millis(100));
        socket.write_all(&3674u32.to_be_bytes())?;
        socket.write_all(&[7; 3674])
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut socket, _) = loop {
        if Instant::now() >= deadline {
            return Err("Witness framing accept deadline".into());
        }
        match listener.accept() {
            Ok(value) => break value,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e.into()),
        }
    };
    start.send(())?;
    let received = request_frame(&mut socket);
    sender
        .join()
        .map_err(|_| "Witness framing sender panicked")??;
    assert_eq!(received?, vec![7; 3674]); // Framing evidence only; no crypto claim.
    Ok(())
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

#[test]
fn native_credential_recovery_requires_independent_witness_approval_and_reopens_same_owner(
) -> Result {
    let mut server = Server::start()?;
    let mut c = Case::with_profile(false, Some(&server))?;
    c.host.store.enable_credential_grants()?;
    let issued: IssuedCredentialGrant = serde_json::from_slice(&c.issue()?)?;
    let pin = c.pin()?;
    let current = c.host.enrollment_root(&c.token)?;
    let inputs = CredentialRecoveryInputs {
        approval: &c.input,
        issued: &issued,
        current: &current,
        original_policy: &c.historical,
        policy: &c.policy,
    };
    let open = || {
        NativeDevice::open(
            &c.path.join("device"),
            &c.path.join("wrap.key"),
            c.invitation.clone(),
        )
    };
    assert!(open()?
        .activate_credential_recovery(&inputs, None, None, crate::enrollment::now()?)
        .is_err());
    // G alone cannot grant the independent witness's permission.
    assert!(open()?
        .activate_credential_recovery(
            &inputs,
            Some(server.pin.clone()),
            Some(server.address),
            crate::enrollment::now()?
        )
        .is_err());
    assert!(open()?
        .reconcile_expired_credential_recovery(&issued, &c.policy, crate::enrollment::now()?)
        .is_err());
    let mut owner = open()?;
    assert!(matches!(
        owner.credential_recovery_status()?,
        sdk::CredentialRenewalStatus::Pending { .. }
    ));
    let proposal = owner.prepare_credential_recovery_witness(
        &inputs,
        server.pin.clone(),
        server.address,
        crate::enrollment::now()?,
    )?;
    owner.close();
    let mut owner = open()?;
    assert_eq!(
        proposal,
        owner.prepare_credential_recovery_witness(
            &inputs,
            server.pin.clone(),
            server.address,
            crate::enrollment::now()?
        )?
    );
    owner.close();
    let grant = sdk::VerifiedCredentialRenewal::verify(
        &issued.grant,
        &pin,
        c.input.retained.original_policy.digest,
        crate::enrollment::now()?,
    )?;
    server
        .store
        .lock()
        .map_err(|_| "witness lock")?
        .prepare_credential_renewal(proposal, &grant, &c.policy, crate::enrollment::now()?)?;
    for _ in 0..2 {
        let mut active = open()?.activate_credential_recovery(
            &inputs,
            Some(server.pin.clone()),
            Some(server.address),
            crate::enrollment::now()?,
        )?;
        assert_eq!(active.journal(), c.input.retained.journal);
        active.next_publication()?;
        active.close();
    }
    let mut owner = open()?;
    assert!(matches!(
        owner.credential_recovery_status()?,
        sdk::CredentialRenewalStatus::Committed { .. }
    ));
    owner.close();
    assert!(server.close()? > 0);
    Ok(())
}
