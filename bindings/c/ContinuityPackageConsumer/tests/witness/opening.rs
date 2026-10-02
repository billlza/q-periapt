// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real C initialization cancellation, without a detached constructor worker.
use super::*;

fn cancelled(output: &str) -> Result<u64> {
    let ms = output
        .strip_prefix("prepared-cancelled:218:")
        .and_then(|text| text.strip_suffix('\n'))
        .ok_or("constructor cancellation receipt")?
        .parse::<u64>()?;
    if ms >= 1000 {
        return Err("constructor cancellation exceeded observation bound".into());
    }
    Ok(ms)
}
fn prepare(
    path: &Path,
    label: &str,
    mode: &str,
    kind: &str,
    address: Option<SocketAddr>,
    carrier: &str,
) -> Result<String> {
    finish(
        start_carrier(path, label, mode, &[kind.to_owned()], address, carrier)?,
        0,
    )
}

fn stalled_tls(path: &Path, prefix: &str) -> Result<(SocketAddr, thread::JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let stalled = listener.local_addr()?;
    let held_path = path.to_path_buf();
    let prefix = prefix.to_owned();
    let worker = thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut header = [0; 5];
        stream.read_exact(&mut header)?;
        if header[0] != 22 || header[1] != 3 || u16::from_be_bytes([header[3], header[4]]) == 0 {
            return Err("expected actual TLS handshake record".into());
        }
        fixture::store(&held_path, &format!("{prefix}-held"), b"1")?;
        let mut received = header.to_vec();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            received.extend_from_slice(buffer.get(..count).ok_or("TLS receive length")?);
            if received.len() > 16384 {
                return Err("unexpected TLS hello size".into());
            }
        }
        fixture::store(&held_path, &format!("{prefix}-client-hello"), &received)?;
        fixture::store(&held_path, &format!("{prefix}-closed"), b"1")?;
        Ok(())
    });
    Ok((stalled, worker))
}

#[test]
fn c_prepared_constructors_cancel_network_admission_and_release_original_owners() -> Result<()> {
    let mut witness = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let left = &setup.initiator;
    let right = &setup.responder;
    let root = left.parent().ok_or("opening evidence root")?;
    let address = witness.configured.address;
    let before = witness.captured.lock().map_err(|_| "capture lock")?.len();
    for (kind, number) in [("operational", 1), ("recovery", 2)] {
        for (label, endpoint) in [("local", None), ("tcp", Some(address))] {
            assert_eq!(
                prepare(
                    left,
                    &format!("opening-{label}-pre-{kind}"),
                    "opening-pre-cancel",
                    kind,
                    endpoint,
                    "--witness"
                )?,
                format!("prepared-pre-cancel:{number}\n")
            );
        }
    }
    assert_eq!(
        witness.captured.lock().map_err(|_| "capture lock")?.len(),
        before
    );
    for (kind, number) in [("operational", 1), ("recovery", 2)] {
        assert_eq!(
            prepare(
                left,
                &format!("opening-tcp-ready-{kind}"),
                "opening-prepare",
                kind,
                Some(address),
                "--witness"
            )?,
            format!("prepared-open:{number}\n")
        );
    }
    let marker = left.join("opening-tcp-held");
    witness.hold_next_reply(marker.clone())?;
    let tcp_ms = cancelled(&finish(
        start(
            left,
            "opening-tcp-cancel",
            "opening-cancel",
            &[
                "operational".into(),
                marker.to_str().ok_or("marker path")?.into(),
            ],
            Some(address),
        )?,
        0,
    )?)?;
    // Reopening the same installation demonstrates that the failed constructor's
    // native file/policy owners were dropped; no different lineage is provisioned.
    assert_eq!(
        prepare(
            left,
            "opening-tcp-reopen",
            "opening-prepare",
            "operational",
            Some(address),
            "--witness"
        )?,
        "prepared-open:1\n"
    );
    witness.join()?;
    let records = witness.captured.lock().map_err(|_| "capture lock")?;
    let lost = records
        .iter()
        .filter(|record| !record.delivered)
        .collect::<Vec<_>>();
    assert_eq!(lost.len(), 1);
    assert_eq!(
        lost.first().ok_or("missing held query")?.reply.get(204),
        Some(&1)
    ); // Observed query, no advance.
    let mut transcript = Vec::new();
    for record in records.iter() {
        transcript.push(u8::from(record.delivered));
        transcript.extend_from_slice(&record.request);
        transcript.extend_from_slice(&record.reply);
    }
    let exchanges = records.len();
    fixture::store(root, "opening-witness-transcript", &transcript)?;
    drop(records);

    let mut tls = tls::TlsWitness::start(Arc::clone(&witness.configured.store), [left, right])?;
    for (kind, number) in [("operational", 1), ("recovery", 2)] {
        assert_eq!(
            prepare(
                left,
                &format!("opening-tls-pre-{kind}"),
                "opening-pre-cancel",
                kind,
                Some(tls.address),
                "--witness-tls"
            )?,
            format!("prepared-pre-cancel:{number}\n")
        );
        assert_eq!(
            prepare(
                left,
                &format!("opening-tls-ready-{kind}"),
                "opening-prepare",
                kind,
                Some(tls.address),
                "--witness-tls"
            )?,
            format!("prepared-open:{number}\n")
        );
    }
    // Real ClientHello and a bounded owned receiver, without a TLS mock success.
    let (stalled, worker) = stalled_tls(left, "opening-tls")?;
    let marker = left.join("opening-tls-held");
    let pending = start_carrier(
        left,
        "opening-tls-cancel",
        "opening-cancel",
        &[
            "operational".into(),
            marker.to_str().ok_or("TLS marker path")?.into(),
        ],
        Some(stalled),
        "--witness-tls",
    );
    // Join this owned bounded server on success and failure; never leave a thread
    // accessing a fixture that has gone out of scope.
    let result = pending.and_then(|process| finish(process, 0));
    let closed = worker.join().map_err(|_| "TLS hold worker panicked")?;
    if let Err(error) = closed {
        return Err(format!("TLS hold worker failed: {error}; C result: {result:?}").into());
    }
    let tls_ms = cancelled(&result?)?;
    assert_eq!(
        prepare(
            left,
            "opening-tls-reopen",
            "opening-prepare",
            "operational",
            Some(tls.address),
            "--witness-tls"
        )?,
        "prepared-open:1\n"
    );
    assert!(tls.finish()?.is_empty());
    let report = format!(concat!("{{\"schema_version\":2,\"language\":\"{}\",\"completed\":true,\"tcp_cancel_ms\":{},\"tls_cancel_ms\":{},",
        "\"tcp_exchanges\":{},\"pre_cancel_cases\":6,\"snapshot_open_cases\":6,",
        "\"failed_handles_closed\":true,\"same_installation_reopened\":true,",
        "\"tcp_socket_closed\":true,\"tls_socket_closed\":true,\"release_claim_eligible\":false}}\n"),
        installed_language()?, tcp_ms, tls_ms, exchanges);
    fixture::store(root, "c-opening-public-result.json", report.as_bytes())?;
    Ok(())
}

#[test]
fn restored_session_constructors_keep_required_witness_and_cancel_partial_admission() -> Result<()>
{
    let mut witness = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let left = &setup.initiator;
    let right = &setup.responder;
    let root = left.parent().ok_or("restore opening evidence root")?;
    let endpoint = witness.configured.address;
    let (receiver, address) = server(
        right,
        "restore-bootstrap-server",
        "bootstrap",
        None,
        endpoint,
    )?;
    let session = id(run(
        left,
        "restore-bootstrap-client",
        "connect",
        &[
            address.to_string(),
            fixture::hex(p::InitiationId::generate()?.as_bytes()),
        ],
        Some(endpoint),
        0,
    )?)?;
    let served = finish(receiver, 0)?;
    assert!(served.contains(&format!("served:1:0:0:0\n{session}\n{}\n", "0".repeat(64))));
    for path in [left, right] {
        fixture::store(path, "restore-selected-session", &bytes(&session)?)?;
    }
    let selected = |label: &str, mode: &str, tail: &[String], address, carrier| -> Result<String> {
        finish(
            start_selected(right, label, mode, tail, address, carrier, Some(&session))?,
            0,
        )
    };
    let before = witness.captured.lock().map_err(|_| "capture lock")?.len();
    for (label, address) in [("local", None), ("tcp", Some(endpoint))] {
        assert_eq!(
            selected(
                &format!("restore-opening-{label}-pre"),
                "opening-pre-cancel",
                &["operational".into()],
                address,
                "--witness"
            )?,
            "prepared-pre-cancel:1\n"
        );
    }
    assert_eq!(
        witness.captured.lock().map_err(|_| "capture lock")?.len(),
        before
    );
    assert_eq!(
        selected(
            "restore-opening-missing",
            "reject-open",
            &[],
            None,
            "--witness"
        )?,
        "rejected:216\n"
    );
    let original = fixture::array::<32>(right, "witness-id")?;
    fs::write(
        right.join("witness-id"),
        p::AnchorIdentity::generate()?.as_bytes(),
    )?;
    assert_eq!(
        selected(
            "restore-opening-wrong-pin",
            "reject-open",
            &[],
            Some(endpoint),
            "--witness"
        )?,
        "rejected:211\n"
    );
    fs::write(right.join("witness-id"), original)?;
    witness.arm(2)?;
    assert_eq!(
        selected(
            "restore-opening-bad-signature",
            "reject-open",
            &[],
            Some(endpoint),
            "--witness"
        )?,
        "rejected:218\n"
    );
    assert_eq!(
        selected(
            "restore-opening-tcp-ready",
            "opening-prepare",
            &["operational".into()],
            Some(endpoint),
            "--witness"
        )?,
        "prepared-open:1\n"
    );
    let marker = right.join("restore-opening-tcp-held");
    witness.hold_next_reply(marker.clone())?;
    let tcp_ms = cancelled(&selected(
        "restore-opening-tcp-cancel",
        "opening-cancel",
        &[
            "operational".into(),
            marker.to_str().ok_or("marker")?.into(),
        ],
        Some(endpoint),
        "--witness",
    )?)?;
    assert_eq!(
        selected(
            "restore-opening-tcp-reopen",
            "opening-prepare",
            &["operational".into()],
            Some(endpoint),
            "--witness"
        )?,
        "prepared-open:1\n"
    );
    witness.join()?;
    let records = witness.captured.lock().map_err(|_| "capture lock")?;
    let lost = records
        .iter()
        .filter(|row| !row.delivered)
        .collect::<Vec<_>>();
    assert_eq!(lost.len(), 1);
    assert_eq!(lost.first().ok_or("lost query")?.reply.get(204), Some(&1));
    let exchanges = records.len();
    let mut transcript = Vec::new();
    for row in records.iter() {
        transcript.push(u8::from(row.delivered));
        transcript.extend_from_slice(&row.request);
        transcript.extend_from_slice(&row.reply);
    }
    fixture::store(root, "restore-opening-witness-transcript", &transcript)?;
    drop(records);
    let mut tls = tls::TlsWitness::start(Arc::clone(&witness.configured.store), [left, right])?;
    assert_eq!(
        selected(
            "restore-opening-tls-pre",
            "opening-pre-cancel",
            &["operational".into()],
            Some(tls.address),
            "--witness-tls"
        )?,
        "prepared-pre-cancel:1\n"
    );
    assert_eq!(
        selected(
            "restore-opening-tls-ready",
            "opening-prepare",
            &["operational".into()],
            Some(tls.address),
            "--witness-tls"
        )?,
        "prepared-open:1\n"
    );
    let (stalled, worker) = stalled_tls(right, "restore-opening-tls")?;
    let marker = right.join("restore-opening-tls-held");
    let result = selected(
        "restore-opening-tls-cancel",
        "opening-cancel",
        &[
            "operational".into(),
            marker.to_str().ok_or("marker")?.into(),
        ],
        Some(stalled),
        "--witness-tls",
    );
    let closed = worker
        .join()
        .map_err(|_| "restore TLS hold worker panicked")?;
    if let Err(error) = closed {
        return Err(format!("restore TLS receiver: {error}; constructor: {result:?}").into());
    }
    let tls_ms = cancelled(&result?)?;
    assert_eq!(
        selected(
            "restore-opening-tls-reopen",
            "opening-prepare",
            &["operational".into()],
            Some(tls.address),
            "--witness-tls"
        )?,
        "prepared-open:1\n"
    );
    assert!(tls.finish()?.is_empty());
    let report = format!(concat!("{{\"schema_version\":1,\"language\":\"{}\",\"session\":\"{}\",\"local_role\":2,",
        "\"tcp_cancel_ms\":{},\"tls_cancel_ms\":{},\"tcp_exchanges\":{},\"pre_cancel_cases\":3,\"snapshot_open_cases\":4,",
        "\"missing_witness_refused\":true,\"wrong_pin_refused\":true,\"bad_signature_refused\":true,",
        "\"failed_handles_closed\":true,\"same_session_reopened\":true,\"release_claim_eligible\":false}}\n"),
        installed_language()?, session, tcp_ms, tls_ms, exchanges);
    fixture::store(
        root,
        "c-restore-opening-public-result.json",
        report.as_bytes(),
    )?;
    Ok(())
}
