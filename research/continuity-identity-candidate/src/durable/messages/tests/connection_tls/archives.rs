// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{JournalKey, SessionClosureId, SessionClosureJournal, SessionClosureStatus};

fn session(n: &mut Network) -> [u8; 32] {
    n.journal
        .resume_reply(Arc::clone(&n.inventory.peer.initiator), n.request, 150)
        .expect("original saved bootstrap result")
        .session_id()
}
fn absent(journal: &mut DeviceJournal, context: &BootstrapContext, session: [u8; 32]) {
    assert!(
        matches!(
            journal.session_closure_status(context, session),
            Err(DurableError::Absent)
        ),
        "message state must remain unactivated"
    );
}
fn exited(child: &mut ChildGuard, success: bool) {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if let Some(status) = child.0.try_wait().expect("status") {
            assert_eq!(status.success(), success);
            return;
        }
        assert!(
            Instant::now() < deadline,
            "owned peer did not exit after disconnect"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
// No fixture, policy, VerifiedDevice or BootstrapContext is constructed here.
#[test]
fn connection_tls_archive_cleanup_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_INDEXED_CLEANUP_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let id = crate::durable::tests::identity(path);
    let session: [u8; 32] = fs::read(path.join("cleanup-session"))?
        .try_into()
        .map_err(|_| "session width")?;
    let mut index = SessionArchiveStore::open(&path.join("archives.redb"), id)?;
    let archive = index.get(session)?;
    index.close();
    let mut owner = SessionClosureJournal::open(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key"))?,
        id,
        &archive,
    )?;
    let report = owner.begin()?;
    assert_eq!(report.session, session);
    crate::durable::messages::tests::closure::account(path, &report);
    owner.acknowledge(report.report)?;
    assert_eq!(owner.status()?, SessionClosureStatus::Closed(report.report));
    atomic(path, "cleanup-complete", report.report.as_bytes());
    Ok(())
}
pub(super) fn close_endpoints(n: &mut Network, session: [u8; 32]) {
    n.inventory
        .peer
        .initiator
        .current_policy()
        .expect("fixture policy owner")
        .close();
    n.inventory
        .peer
        .responder
        .current_policy()
        .expect("fixture policy owner")
        .close();
    n.journal.close();
    n.archives.close();
    n.inventory.store.close();
    for path in [&n.client_path, &n.inventory.path] {
        atomic(path, "cleanup-session", &session);
        let log = fs::File::create_new(path.join("indexed-cleanup.log")).expect("log");
        let mut child=ChildGuard(Command::new(std::env::current_exe().expect("exe")).args(["--exact","durable::messages::tests::connection_tls::archives::connection_tls_archive_cleanup_child","--nocapture"])
            .env("QPERIAPT_INDEXED_CLEANUP_DIR",path).stdout(Stdio::from(log.try_clone().expect("log"))).stderr(Stdio::from(log)).spawn().expect("new cleanup process"));
        exited(&mut child, true);
        let id = SessionClosureId::from_trusted_state(
            fs::read(path.join("cleanup-complete"))
                .expect("terminal readback")
                .try_into()
                .expect("ID"),
        )
        .expect("report");
        let mut index = SessionArchiveStore::open(
            &path.join("archives.redb"),
            crate::durable::tests::identity(path),
        )
        .expect("retained index");
        let archive = index.get(session).expect("retained exact archive");
        index.close();
        let mut owner = SessionClosureJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            crate::durable::tests::identity(path),
            &archive,
        )
        .expect("fresh restricted owner");
        assert_eq!(
            owner.status().expect("independent terminal readback"),
            SessionClosureStatus::Closed(id)
        );
    }
    eprintln!("CONNECTION_TLS_INDEXED_CLEANUP endpoints=2 original_contexts_in_child=0 durable_host_reports=2 terminal_readbacks=2");
}
#[test]
fn connection_tls_client_archive_commit_cut_precedes_both_activations_and_recovers() {
    let mut n = Network::new();
    let endpoint = n.endpoint();
    let (mut server, address) = spawn(&n, 0, "none", 1);
    n.journal.close();
    n.archives.close();
    for (name, bytes) in [
        (
            "connection-public",
            fs::read(n.inventory.path.join("connection-public")).expect("public"),
        ),
        (
            "connection-bundle",
            fs::read(n.inventory.path.join("connection-bundle")).expect("bundle"),
        ),
        ("connection-server.der", n.client_tls.certificate.clone()),
        ("connection-server.key", n.client_tls.key.to_vec()),
        ("connection-client.der", n.server_tls.certificate.clone()),
        ("client-address", address.to_string().into_bytes()),
        ("client-request", n.request.as_bytes().to_vec()),
    ] {
        atomic(&n.client_path, name, &bytes);
    }
    let log = fs::File::create_new(n.client_path.join("client-cut.log")).expect("log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("exe"))
            .args([
                "--exact",
                "durable::messages::tests::connection_tls::connection_tls_peer_child",
                "--nocapture",
            ])
            .env("QPERIAPT_CONNECTION_TLS_DIR", &n.client_path)
            .env("QPERIAPT_CONNECTION_TLS_ROLE", "1")
            .env("QPERIAPT_CONNECTION_TLS_GENERATION", "0")
            .env("QPERIAPT_CONNECTION_TLS_CUT", "client-archive")
            .env("QPERIAPT_CONNECTION_TLS_OPERATIONS", "1")
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("actual client process"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !n.client_path.join("cut-ready").exists() {
        assert!(
            child.0.try_wait().expect("client status").is_none() && Instant::now() < deadline,
            "{}",
            fs::read_to_string(n.client_path.join("client-cut.log")).expect("log")
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fs::read_to_string(n.client_path.join("cut-ready")).expect("stage"),
        "client-archive"
    );
    assert!(matches!(
        SessionArchiveStore::open(
            &n.client_path.join("archives.redb"),
            crate::durable::tests::identity(&n.client_path)
        ),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    child.0.kill().expect("kill at actual committed archive");
    assert!(!child.0.wait().expect("reap").success());
    exited(&mut server, false);
    n.reopen();
    let session = session(&mut n);
    assert_eq!(
        fs::read(n.client_path.join("cut-wire")).expect("observed session"),
        session
    );
    n.archives
        .get(session)
        .expect("client archive survived process loss");
    absent(&mut n.journal, &n.inventory.peer.initiator, session);
    let mut peer = reopen(&n.inventory.path, n.inventory.peer.local_device());
    absent(&mut peer, &n.inventory.peer.responder, session);
    peer.close();
    let (mut server, address) = spawn(&n, 1, "none", 1);
    assert_eq!(
        n.establish(&endpoint, address, limits())
            .expect("same saved initiation")
            .session,
        session
    );
    wait(&n, &mut server, 1);
    close_endpoints(&mut n, session);
    eprintln!("CONNECTION_TLS_CLIENT_ARCHIVE_CUT real_process_kill=true before_both_activations=true exact_restart=true");
}
#[test]
fn connection_tls_archive_sync_failures_cannot_activate_either_native_endpoint() {
    let mut baseline = Network::new();
    baseline.archives.close();
    let (index, _, count) = crate::session_archives::tests::fault_index(
        &baseline.client_path.join("archives.redb"),
        baseline.journal.identity().expect("id"),
        false,
    );
    baseline.archives = index;
    let endpoint = baseline.endpoint();
    let (mut peer, address) = spawn(&baseline, 0, "measure-archive", 1);
    baseline
        .establish(&endpoint, address, limits())
        .expect("measure actual connection commits");
    wait(&baseline, &mut peer, 0);
    let client_barriers = count.load(Ordering::SeqCst);
    let server_barriers = u64::from_be_bytes(
        fs::read(baseline.inventory.path.join("archive-barriers"))
            .expect("measured server count")
            .try_into()
            .expect("count width"),
    ) as usize;
    assert_eq!((client_barriers, server_barriers), (2, 2));
    for server_fault in [false, true] {
        let barriers = if server_fault {
            server_barriers
        } else {
            client_barriers
        };
        for cut in 1..=barriers {
            for after in [false, true] {
                let mut n = Network::new();
                let endpoint = n.endpoint();
                if !server_fault {
                    n.archives.close();
                    let (index, remaining, _) = crate::session_archives::tests::fault_index(
                        &n.client_path.join("archives.redb"),
                        n.journal.identity().expect("id"),
                        after,
                    );
                    remaining.store(cut, Ordering::SeqCst);
                    n.archives = index;
                }
                let mode = if server_fault {
                    format!("archive-sync-{cut}-{after}")
                } else {
                    "none".to_owned()
                };
                let (mut peer, address) = spawn(&n, 0, &mode, 1);
                let result = n.establish(&endpoint, address, limits());
                if server_fault {
                    assert!(result.is_err());
                    wait(&n, &mut peer, 0);
                    assert!(n.inventory.path.join("expected-archive-failure").is_file());
                } else {
                    let original = match result {
                        Err(crate::connection_transport::Error::Archive(e)) => Ok(e),
                        other => Err(format!("unexpected connection outcome: {other:?}")),
                    }
                    .expect("exact archive error boundary");
                    let failure = Err(original);
                    crate::durable::tests::assert_sync_failure::<()>(failure, after);
                    exited(&mut peer, false);
                }
                let session = session(&mut n);
                absent(&mut n.journal, &n.inventory.peer.initiator, session);
                let mut server = reopen(&n.inventory.path, n.inventory.peer.local_device());
                absent(&mut server, &n.inventory.peer.responder, session);
                server.close();
                n.reopen();
                let (mut peer, address) = spawn(&n, 1, "none", 1);
                assert_eq!(
                    n.establish(&endpoint, address, limits())
                        .expect("exact retry after index recovery")
                        .session,
                    session
                );
                wait(&n, &mut peer, 1);
                n.archives.get(session).expect("client archive");
                let mut server_index = SessionArchiveStore::open(
                    &n.inventory.path.join("archives.redb"),
                    crate::durable::tests::identity(&n.inventory.path),
                )
                .expect("server index");
                server_index.get(session).expect("server archive");
            }
        }
        eprintln!("CONNECTION_TLS_ARCHIVE_SYNC server={server_fault} barriers={barriers} before_after_faults={}",barriers*2);
    }
}
#[test]
fn connection_tls_archive_commit_cancellation_and_deadline_never_report_activation() {
    for mode in ["cancel-server-archive", "deadline-server-archive"] {
        let mut n = Network::new();
        let endpoint = n.endpoint();
        let (mut peer, address) = spawn(&n, 0, mode, 1);
        assert!(n.establish(&endpoint, address, limits()).is_err());
        wait(&n, &mut peer, 0);
        let session = session(&mut n);
        assert_eq!(
            fs::read(n.inventory.path.join("archive-boundary")).expect("actual committed boundary"),
            session
        );
        absent(&mut n.journal, &n.inventory.peer.initiator, session);
        let mut server = reopen(&n.inventory.path, n.inventory.peer.local_device());
        absent(&mut server, &n.inventory.peer.responder, session);
        server.close();
        let mut index = SessionArchiveStore::open(
            &n.inventory.path.join("archives.redb"),
            crate::durable::tests::identity(&n.inventory.path),
        )
        .expect("durable index");
        index.get(session).expect("committed archive");
        index.close();
        n.reopen();
        let (mut peer, address) = spawn(&n, 1, "none", 1);
        assert_eq!(
            n.establish(&endpoint, address, limits())
                .expect("explicit new invocation with original ID")
                .session,
            session
        );
        wait(&n, &mut peer, 1);
        eprintln!("CONNECTION_TLS_ARCHIVE_BOUNDARY mode={mode} archive_committed=true activated_before_retry=false");
    }
}

#[test]
fn connection_tls_missing_or_modified_archives_block_data_before_delivery() {
    use crate::session_archives::tests::rewrite_archive;
    for remove in [false, true] {
        let mut n = Network::new();
        let endpoint = n.endpoint();
        let (mut peer, address) = spawn(&n, 0, "none", 1);
        let session = n
            .establish(&endpoint, address, limits())
            .expect("complete connection")
            .session;
        wait(&n, &mut peer, 0);
        let context = Arc::clone(&n.inventory.peer.initiator);
        let message = n
            .journal
            .next_message_id(&context, session, 150)
            .expect("ID");
        let original = n
            .archives
            .get(session)
            .expect("original authenticated archive")
            .as_bytes()
            .to_vec();
        n.archives.close();
        let mut corrupt = original.clone();
        *corrupt.last_mut().expect("MAC") ^= 1;
        rewrite_archive(
            &n.client_path.join("archives.redb"),
            session,
            if remove { None } else { Some(&corrupt) },
        );
        n.archives = SessionArchiveStore::open(
            &n.client_path.join("archives.redb"),
            n.journal.identity().expect("ID"),
        )
        .expect("public index grammar");
        let before = n.journal.image().expect("client before").digest;
        let attempt = endpoint.send(
            n.actor(),
            Submission {
                session,
                message,
                plaintext: b"indexed exact retry",
                associated_data: b"",
            },
            Run {
                address: "127.0.0.1:9".parse().expect("no network allowed"),
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        );
        assert!(matches!(
            attempt,
            Err(crate::connection_transport::Error::Archive(
                DurableError::Absent | DurableError::Authentication
            ))
        ));
        assert_eq!(n.journal.image().expect("client unchanged").digest, before);
        n.archives.close();
        rewrite_archive(
            &n.client_path.join("archives.redb"),
            session,
            Some(&original),
        );
        n.reopen();
        let mut peer_index = SessionArchiveStore::open(
            &n.inventory.path.join("archives.redb"),
            crate::durable::tests::identity(&n.inventory.path),
        )
        .expect("original peer index");
        let original = peer_index
            .get(session)
            .expect("peer archive")
            .as_bytes()
            .to_vec();
        peer_index.close();
        let mut corrupt = original.clone();
        *corrupt.last_mut().expect("MAC") ^= 1;
        rewrite_archive(
            &n.inventory.path.join("archives.redb"),
            session,
            if remove { None } else { Some(&corrupt) },
        );
        let mut receiver = reopen(&n.inventory.path, n.inventory.peer.local_device());
        let before = receiver.image().expect("before").digest;
        receiver.close();
        let (mut peer, address) = spawn(&n, 1, "invalid-archive", 1);
        let attempt = endpoint.send(
            n.actor(),
            Submission {
                session,
                message,
                plaintext: b"indexed exact retry",
                associated_data: b"",
            },
            Run {
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        );
        assert!(attempt.is_err());
        wait(&n, &mut peer, 1);
        let mut receiver = reopen(&n.inventory.path, n.inventory.peer.local_device());
        assert_eq!(receiver.image().expect("no inbox mutation").digest, before);
        receiver.close();
        assert!(fs::read_dir(&n.inventory.path)
            .expect("effects")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("application-")));
        assert_eq!(
            n.journal
                .message_status(&context, session, message)
                .expect("unknown remote outcome"),
            MessageStatus::Committed
        );
        rewrite_archive(
            &n.inventory.path.join("archives.redb"),
            session,
            Some(&original),
        );
        let (mut peer, address) = spawn(&n, 2, "none", 1);
        let delivered = endpoint
            .send(
                n.actor(),
                Submission {
                    session,
                    message,
                    plaintext: b"indexed exact retry",
                    associated_data: b"",
                },
                Run {
                    address,
                    server_name: "localhost",
                    limits: limits(),
                    cancel: &Cancellation::default(),
                },
                || Ok(150),
            )
            .expect("same input after explicit metadata restoration");
        assert_eq!(delivered.consumption, Consumption::Confirmed);
        wait(&n, &mut peer, 2);
        readback(&n, session, message, b"indexed exact retry");
        eprintln!("CONNECTION_TLS_ARCHIVE_DATA_GATE missing={remove} client_mutation_before_repair=false server_inbox_before_repair=false same_message_recovered=true");
    }
}
