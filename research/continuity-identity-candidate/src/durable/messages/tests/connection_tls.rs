// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::tls_identity::{tls_limits, Identity};
use super::*;
use crate::{
    connection_transport::{
        Actor, Cancellation, ConnectionEndpoint, Consumer, Consumption, Run, RunLimits, Served,
        Submission,
    },
    durable::{
        prekeys::tests::{inventory, Inventory},
        tests::ChildGuard,
    },
};
use q_periapt_rustls::connection::Credentials;
use std::{
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

mod failures;
#[cfg(feature = "control-tls")]
mod lifecycle;
fn limits() -> RunLimits {
    RunLimits {
        exchanges: 8,
        timeout: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(1),
    }
}
fn atomic(path: &Path, name: &str, bytes: &[u8]) {
    let pending = path.join(format!("{name}-pending"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)
        .expect("new private file");
    file.write_all(bytes).expect("write");
    file.sync_all().expect("fsync");
    drop(file);
    fs::rename(pending, path.join(name)).expect("publish complete record");
    fs::File::open(path)
        .expect("directory")
        .sync_all()
        .expect("durable name");
}
struct StoreConsumer {
    path: PathBuf,
    fail: bool,
    unknown_after_commit: bool,
    cancel: Option<Cancellation>,
}
impl Consumer for StoreConsumer {
    fn commit(&mut self, session: [u8; 32], delivery: &CommittedPlaintext) -> io::Result<()> {
        let mut bytes = session.to_vec();
        bytes.extend_from_slice(delivery.message_id().as_bytes());
        bytes.extend_from_slice(delivery.as_bytes());
        let name = format!(
            "application-{}",
            delivery
                .message_id()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let target = self.path.join(&name);
        if target.exists() {
            if fs::read(&target)? != bytes {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(());
        }
        if self.fail {
            return Err(io::ErrorKind::StorageFull.into());
        }
        atomic(&self.path, &name, &bytes);
        if self.unknown_after_commit {
            return Err(io::ErrorKind::Other.into());
        }
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        Ok(())
    }
}
struct Network {
    inventory: Inventory,
    journal: DeviceJournal,
    client_path: PathBuf,
    _dir: tempfile::TempDir,
    client_tls: Identity,
    server_tls: Identity,
    request: InitiationId,
}
impl Network {
    fn new() -> Self {
        let mut inventory = inventory(PrekeyQuality::OneTimeBoth);
        let dir = directory();
        let client_path = dir.path().canonicalize().expect("client path");
        let journal = new_store(&client_path, inventory.peer.initiator_device());
        let client_tls = Identity::new("client.test");
        let server_tls = Identity::new("localhost");
        for (name, data) in [
            (
                "connection-public",
                [inventory.public.0.as_slice(), inventory.public.1.as_slice()].concat(),
            ),
            ("connection-server.der", server_tls.certificate.clone()),
            ("connection-server.key", server_tls.key.to_vec()),
            ("connection-client.der", client_tls.certificate.clone()),
        ] {
            fs::write(inventory.path.join(name), data).expect("private fixture");
        }
        inventory.store.close();
        Self {
            inventory,
            journal,
            client_path,
            _dir: dir,
            client_tls,
            server_tls,
            request: InitiationId::generate().expect("request"),
        }
    }
    fn endpoint(&self) -> ConnectionEndpoint {
        ConnectionEndpoint::client(
            &self.inventory.peer.initiator,
            self.client_tls.credentials(&self.server_tls),
            tls_limits(),
        )
        .expect("client endpoint")
    }
    fn actor(&mut self) -> Actor<'_> {
        Actor {
            journal: &mut self.journal,
            context: &self.inventory.peer.initiator,
            signer: &self.inventory.peer.signer_i,
        }
    }
    fn reopen(&mut self) {
        self.journal.close();
        self.journal = reopen(&self.client_path, self.inventory.peer.initiator_device());
    }
    fn establish(
        &mut self,
        endpoint: &ConnectionEndpoint,
        address: SocketAddr,
        bound: RunLimits,
    ) -> Result<crate::connection_transport::Established, crate::connection_transport::Error> {
        let request = self.request;
        endpoint.establish(
            self.actor(),
            request,
            Run {
                address,
                server_name: "localhost",
                limits: bound,
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
    }
}
fn spawn(n: &Network, generation: u8, cut: &str, operations: usize) -> (ChildGuard, SocketAddr) {
    spawn_at(&n.inventory.path, 2, generation, cut, operations)
}
fn spawn_at(
    path: &Path,
    role: u8,
    generation: u8,
    cut: &str,
    operations: usize,
) -> (ChildGuard, SocketAddr) {
    let log =
        fs::File::create_new(path.join(format!("connection-{generation}.log"))).expect("new log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::messages::tests::connection_tls::connection_tls_peer_child",
                "--nocapture",
            ])
            .env("QPERIAPT_CONNECTION_TLS_DIR", path)
            .env("QPERIAPT_CONNECTION_TLS_ROLE", role.to_string())
            .env("QPERIAPT_CONNECTION_TLS_GENERATION", generation.to_string())
            .env("QPERIAPT_CONNECTION_TLS_CUT", cut)
            .env("QPERIAPT_CONNECTION_TLS_OPERATIONS", operations.to_string())
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let marker = path.join(format!("connection-ready-{generation}"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        assert!(
            child.0.try_wait().expect("child").is_none() && Instant::now() < deadline,
            "{}",
            fs::read_to_string(path.join(format!("connection-{generation}.log"))).expect("log")
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    (
        child,
        fs::read_to_string(marker)
            .expect("address")
            .parse()
            .expect("socket address"),
    )
}
fn wait(n: &Network, child: &mut ChildGuard, generation: u8) {
    wait_at(&n.inventory.path, child, generation);
}
fn wait_at(path: &Path, child: &mut ChildGuard, generation: u8) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait().expect("child") {
            assert!(
                status.success(),
                "{}",
                fs::read_to_string(path.join(format!("connection-{generation}.log"))).expect("log")
            );
            break;
        }
        assert!(Instant::now() < deadline, "server did not terminate");
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(e),
        }
    }
}
#[test]
fn connection_tls_peer_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_CONNECTION_TLS_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let generation: u8 = std::env::var("QPERIAPT_CONNECTION_TLS_GENERATION")?.parse()?;
    let operations: usize = std::env::var("QPERIAPT_CONNECTION_TLS_OPERATIONS")?.parse()?;
    let role: u8 = std::env::var("QPERIAPT_CONNECTION_TLS_ROLE")?.parse()?;
    let mode = std::env::var("QPERIAPT_CONNECTION_TLS_CUT")?;
    let public = fs::read(path.join("connection-public"))?;
    let (reusable, once) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
    let f = crate::bootstrap::tests::fixture_from_public(
        PrekeyQuality::OneTimeBoth,
        Some((reusable.try_into()?, once.try_into()?)),
    );
    let certificate = fs::read(path.join("connection-server.der"))?;
    let key = Zeroizing::new(fs::read(path.join("connection-server.key"))?);
    let peer = fs::read(path.join("connection-client.der"))?;
    let (device, context, signer) = if role == 1 {
        (f.initiator_device(), &f.initiator, &f.signer_i)
    } else {
        (f.local_device(), &f.responder, &f.signer_r)
    };
    if mode == "contender" {
        assert!(matches!(
            DeviceJournal::open(
                &path.join("state.redb"),
                crate::JournalKey::open(&path.join("key"))?,
                device,
                crate::durable::tests::identity(path)
            ),
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        return Ok(());
    }
    let endpoint = ConnectionEndpoint::server(
        context,
        Credentials {
            certificate: &certificate,
            private_key: &key,
            peer_certificate: &peer,
        },
        tls_limits(),
    )?;
    let mut journal = reopen(path, device);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    atomic(
        path,
        &format!("connection-ready-{generation}"),
        listener.local_addr()?.to_string().as_bytes(),
    );
    #[cfg(feature = "control-tls")]
    if mode == "control" {
        let session: [u8; 32] = fs::read(path.join("connection-established"))?
            .try_into()
            .map_err(|_| "session width")?;
        let control = crate::control_transport::ControlEndpoint::server(
            context,
            session,
            Credentials {
                certificate: &certificate,
                private_key: &key,
                peer_certificate: &peer,
            },
            tls_limits(),
        )?;
        for _ in 0..operations {
            control.serve(
                accept(&listener)?,
                crate::control_transport::Session {
                    journal: &mut journal,
                    context,
                    signer,
                },
                limits(),
                &Cancellation::default(),
                || Ok(150),
            )?;
        }
        return Ok(());
    }
    let cancel = Cancellation::default();
    let mut consumer = StoreConsumer {
        path: path.to_path_buf(),
        fail: mode == "fail-application",
        unknown_after_commit: mode == "unknown-application",
        cancel: if mode == "cancel-application" {
            Some(cancel.clone())
        } else {
            None
        },
    };
    for _ in 0..operations {
        let result = endpoint.serve(
            accept(&listener)?,
            Actor {
                journal: &mut journal,
                context,
                signer,
            },
            &mut consumer,
            limits(),
            &cancel,
            || Ok(150),
        );
        match mode.as_str() {
            "fail-application" | "unknown-application" => {
                assert!(matches!(
                    result,
                    Err(crate::connection_transport::Error::Application(_))
                ));
                atomic(
                    path,
                    "expected-application-failure",
                    b"inbox retained without consumption",
                );
                return Ok(());
            }
            "cancel-application" => {
                assert!(matches!(
                    result,
                    Err(crate::connection_transport::Error::Cancelled)
                ));
                atomic(
                    path,
                    "expected-application-cancellation",
                    b"external transaction committed; inbox unconsumed",
                );
                return Ok(());
            }
            _ => {}
        }
        let event = result?;
        if let Served::Established(session) = event {
            let file = path.join("connection-established");
            if file.exists() {
                assert_eq!(fs::read(file)?, session);
            } else {
                atomic(path, "connection-established", &session);
            }
        }
    }
    Ok(())
}
fn readback(n: &Network, session: [u8; 32], message: MessageId, plaintext: &[u8]) {
    let files: Vec<_> = fs::read_dir(&n.inventory.path)
        .expect("dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|x| x.to_string_lossy().starts_with("application-"))
        })
        .collect();
    assert_eq!(files.len(), 1, "one durable external effect");
    let mut expected = session.to_vec();
    expected.extend_from_slice(message.as_bytes());
    expected.extend_from_slice(plaintext);
    assert_eq!(
        fs::read(files.first().expect("application file")).expect("independent disk readback"),
        expected
    );
}
#[test]
fn connection_tls_empty_journals_establish_and_confirm_real_application_consumption() {
    let mut n = Network::new();
    let endpoint = n.endpoint();
    assert!(!n
        .journal
        .image()
        .expect("sender")
        .records
        .values()
        .any(|r| r.kind == RecordKind::Messages));
    let (mut child, address) = spawn(&n, 0, "none", 2);
    let established = n
        .establish(&endpoint, address, limits())
        .expect("actual bootstrap flights");
    assert_eq!(established.exchanges, 2);
    let context = Arc::clone(&n.inventory.peer.initiator);
    let id = n
        .journal
        .next_message_id(&context, established.session, 150)
        .expect("ID");
    let plaintext = b"independent endpoint persisted these authenticated bytes";
    let result = endpoint
        .send(
            n.actor(),
            Submission {
                session: established.session,
                message: id,
                plaintext,
                associated_data: b"reference-connection",
            },
            Run {
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
        .expect("consumption proof");
    assert_eq!(result.consumption, Consumption::Confirmed);
    wait(&n, &mut child, 0);
    readback(&n, established.session, id, plaintext);
    n.reopen();
    assert_eq!(
        n.journal
            .message_status(&context, established.session, id)
            .expect("reconciled ACK"),
        MessageStatus::Acknowledged
    );
    let mut responder = reopen(&n.inventory.path, n.inventory.peer.local_device());
    let (policy, device, _) = n.inventory.peer.responder.inventory_inputs();
    for (ordinal, key) in n.inventory.ids.iter().enumerate() {
        assert_eq!(
            responder
                .prekey_status(policy, device, *key)
                .expect("inventory"),
            if matches!(ordinal, 1 | 3) {
                crate::PrekeyStatus::Consumed
            } else {
                crate::PrekeyStatus::Available
            }
        );
    }
    eprintln!("CONNECTION_TLS_REFERENCE bootstrap_network_exchanges=2 one_time_keys_consumed=2 actual_application_readback=true authenticated_consumption=true");
}

#[test]
fn connection_tls_out_of_order_consumption_remains_pending_until_the_real_prefix_closes() {
    let mut n = Network::new();
    let endpoint = n.endpoint();
    let (mut child, address) = spawn(&n, 0, "none", 1);
    let session = n
        .establish(&endpoint, address, limits())
        .expect("bootstrap")
        .session;
    wait(&n, &mut child, 0);
    let context = Arc::clone(&n.inventory.peer.initiator);
    let first = n
        .journal
        .next_message_id(&context, session, 150)
        .expect("first ID");
    n.journal
        .send_message(
            &context,
            session,
            first,
            b"first delayed input",
            b"ordered",
            150,
        )
        .expect("durable delayed outbox");
    let second = n
        .journal
        .next_message_id(&context, session, 150)
        .expect("second ID");
    let (mut child, address) = spawn(&n, 1, "none", 3);
    for _ in 0..2 {
        let result = endpoint
            .send(
                n.actor(),
                Submission {
                    session,
                    message: second,
                    plaintext: b"second delivered first",
                    associated_data: b"ordered",
                },
                Run {
                    address,
                    server_name: "localhost",
                    limits: limits(),
                    cancel: &Cancellation::default(),
                },
                || Ok(150),
            )
            .expect("real pending prefix");
        assert_eq!(result.consumption, Consumption::PrefixPending);
        assert_eq!(
            n.journal
                .message_status(&context, session, second)
                .expect("not falsely ACKed"),
            MessageStatus::Committed
        );
    }
    let result = endpoint
        .send(
            n.actor(),
            Submission {
                session,
                message: first,
                plaintext: b"first delayed input",
                associated_data: b"ordered",
            },
            Run {
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
        .expect("gap closed");
    assert_eq!(result.consumption, Consumption::Confirmed);
    wait(&n, &mut child, 1);
    assert_eq!(
        n.journal
            .message_status(&context, session, second)
            .expect("real cumulative proof"),
        MessageStatus::Acknowledged
    );
    let count = fs::read_dir(&n.inventory.path)
        .expect("dir")
        .filter(|e| {
            e.as_ref()
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("application-")
        })
        .count();
    assert_eq!(
        count, 2,
        "exactly two durable external effects despite three sends"
    );
}

#[test]
fn connection_tls_invalid_limits_cancel_and_clock_failure_leave_initial_work_absent() {
    let mut n = Network::new();
    let endpoint = n.endpoint();
    let request = n.request;
    let before = n.journal.image().expect("image").digest;
    let address = "127.0.0.1:9"
        .parse()
        .expect("unused peer; no connect is allowed");
    let mut invalid = limits();
    invalid.exchanges = 0;
    let result = endpoint.establish(
        n.actor(),
        request,
        Run {
            address,
            server_name: "localhost",
            limits: invalid,
            cancel: &Cancellation::default(),
        },
        || Err(io::ErrorKind::NotFound.into()),
    );
    assert!(matches!(
        result,
        Err(crate::connection_transport::Error::InvalidOptions)
    ));
    let cancel = Cancellation::default();
    cancel.cancel();
    let result = endpoint.establish(
        n.actor(),
        request,
        Run {
            address,
            server_name: "localhost",
            limits: limits(),
            cancel: &cancel,
        },
        || Err(io::ErrorKind::NotFound.into()),
    );
    assert!(matches!(
        result,
        Err(crate::connection_transport::Error::Cancelled)
    ));
    let result = endpoint.establish(
        n.actor(),
        request,
        Run {
            address,
            server_name: "localhost",
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Err(io::ErrorKind::NotFound.into()),
    );
    assert!(matches!(
        result,
        Err(crate::connection_transport::Error::Clock(_))
    ));
    assert_eq!(
        n.journal.image().expect("same authenticated state").digest,
        before
    );
}
