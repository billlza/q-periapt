// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    io::{self, Read, Write},
    net::TcpListener,
    path::Path,
    sync::mpsc,
    thread,
};

struct Control {
    listener: TcpListener,
    expected: [u8; 72],
    marker: PathBuf,
    prefix: PathBuf,
    tls: bool,
    process_exit: Option<mpsc::Receiver<()>>,
}
impl Control {
    fn serve(self) -> Result<Vec<u8>> {
        self.listener.set_nonblocking(true)?;
        let until = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match self.listener.accept() {
                Ok((socket, peer)) if peer.ip().is_loopback() => break socket,
                Ok(_) => return Err("nonlocal cancellation control peer".into()),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => return Err(error.into()),
            }
        };
        // Darwin can inherit O_NONBLOCK from the listener. The accepted control
        // exchange uses bounded blocking reads, independent of sender timing.
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut received = [0; 72];
        socket.read_exact(&mut received)?;
        assert_eq!(
            received, self.expected,
            "control must identify the original proposal"
        );
        let until = Instant::now() + Duration::from_millis(2500);
        loop {
            match fs::read(&self.marker) {
                Ok(bytes) if bytes == b"1" => break,
                Ok(_) => return Err("Query barrier bytes differ".into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < until => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => return Err(error.into()),
            }
        }
        let prefix = fixture::read(
            self.prefix.parent().ok_or("prefix parent")?,
            self.prefix
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("prefix name")?,
            8192,
        )?;
        assert!(!prefix.is_empty() && prefix.len() < 3659);
        if !self.tls {
            assert_eq!(prefix.len(), 1804);
            assert_eq!(prefix.get(..4), Some(&3659_u32.to_be_bytes()[..]));
            assert_eq!(prefix.get(208), Some(&1));
        }
        // The response prefix exists before permission to call cancel is sent.
        socket.write_all(&[1])?;
        socket.flush()?;
        let mut observed = [0; 1];
        socket.read_exact(&mut observed)?;
        let process_cut = self.process_exit.is_some();
        if let Some(exit) = self.process_exit {
            assert_eq!(observed, [4], "process cut must acknowledge the held Query");
            // Only this acknowledged cut connection may terminate without a
            // normal cancellation result. A timeout is never process loss.
            match socket.read(&mut [0]) {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                other => return Err(format!("cut control did not disconnect: {other:?}").into()),
            }
            exit.recv_timeout(Duration::from_secs(3))?;
        } else {
            assert_eq!(
                observed,
                [2],
                "release requires the actual native cancellation result"
            );
        }
        if self.tls {
            let released = self.marker.with_extension("released");
            fixture::publish_marker(
                released.parent().ok_or("release parent")?,
                released
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("release name")?,
            )?;
        }
        let mut transcript = received.to_vec();
        if process_cut {
            // EOF/RST plus the independently reaped process, not EOF alone.
            transcript.extend_from_slice(&[1, 4, 0, 77]);
        } else {
            socket.write_all(&[3])?;
            socket.flush()?;
            transcript.extend_from_slice(&[1, observed[0], 3]);
        }
        Ok(transcript)
    }
}

pub(super) fn start_control(
    base: &Path,
    inputs: &Path,
    transport: &transport::Carrier,
    witness: &witness::Witness,
    original: &Request,
    process_exit: Option<mpsc::Receiver<()>>,
) -> Result<(thread::JoinHandle<Result<Vec<u8>>>, PathBuf)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut token = [0; 32];
    getrandom::fill(&mut token).map_err(io::Error::other)?;
    if token.iter().all(|byte| *byte == 0) {
        return Err("zero cancellation control token".into());
    }
    retain(
        &inputs.join("cancel-control-address"),
        listener.local_addr()?.to_string().as_bytes(),
    )?;
    retain(&inputs.join("cancel-control-token"), &token)?;
    let mut expected = [0; 72];
    expected
        .get_mut(..8)
        .ok_or("magic")?
        .copy_from_slice(b"QPCCAN01");
    expected
        .get_mut(8..40)
        .ok_or("token")?
        .copy_from_slice(&token);
    expected
        .get_mut(40..)
        .ok_or("binding")?
        .copy_from_slice(&original.proposal.binding());
    let marker = base.join("pending-query-held");
    let (prefix, tls) = transport.hold_query(witness, &marker)?;
    let control = Control {
        listener,
        expected,
        marker,
        prefix: prefix.clone(),
        tls,
        process_exit,
    };
    let worker = thread::spawn(move || control.serve());
    Ok((worker, prefix))
}

pub(super) fn exercise(
    base: &Path,
    inputs: &Path,
    transport: &transport::Carrier,
    witness: &witness::Witness,
    original: &Request,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    let before = transport.captures(witness)?.len();
    let before_image =
        crate::witness_tls_faults::snapshot(&witness._directory.path().join("witness.redb"))?;
    let (worker, prefix) = start_control(base, inputs, transport, witness, original, None)?;
    let outcome = run("pending-confirm-inflight", "query-cancelled");
    let gate = match worker.join() {
        Ok(result) => result,
        Err(_) => Err("cancellation control panicked".into()),
    };
    let (outcome, control) = match (outcome, gate) {
        (Ok(outcome), Ok(control)) => (outcome, control),
        (Err(client), Err(gate)) => {
            return Err(format!("cancellation client: {client}; control: {gate}").into())
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    assert_eq!(outcome, 218_u32.to_be_bytes());
    assert!(
        before_image
            == crate::witness_tls_faults::snapshot(
                &witness._directory.path().join("witness.redb")
            )?
    );
    let until = Instant::now() + Duration::from_secs(1);
    let records = loop {
        let records = transport.captures(witness)?;
        if records.len() == before + 1 {
            break records;
        }
        if records.len() > before + 1 || Instant::now() >= until {
            return Err("withheld Query observation count".into());
        }
        thread::sleep(Duration::from_millis(2));
    };
    let record = records.get(before).ok_or("withheld Query")?;
    assert_eq!(record.request.get(204), Some(&1));
    assert_eq!(record.reply.get(204), Some(&1));
    assert!(!record.delivered);
    let mut transcript = vec![0];
    transcript.extend_from_slice(&record.request);
    transcript.extend_from_slice(&record.reply);
    retain(&base.join("query-cancel-transcript"), &transcript)?;
    retain(&base.join("query-cancel-control"), &control)?;
    retain(&base.join("query-cancel-prefix"), &fs::read(prefix)?)?;
    retain(&base.join("query-cancel-store-unchanged"), &[1])?;
    let restored = Request::parse(&run("pending-request", "pending-after-inflight")?)?;
    assert_eq!(restored.proposal, original.proposal);
    assert_eq!(restored.metadata, original.metadata);
    Ok(())
}
