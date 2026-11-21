// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::thread::{self, JoinHandle};

#[derive(Clone, Copy)]
pub(super) struct Observation {
    pub command: [u8; 32],
    pub attempt: [u8; 32],
    pub head: p::AnchorHead,
    pub outcome: p::AnchorOutcome,
    pub dropped: bool,
}

pub(super) struct Server {
    pub configured: WitnessFixture,
    drop_next: Arc<AtomicBool>,
    halt: Arc<AtomicBool>,
    rows: Arc<Mutex<Vec<Observation>>>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl Server {
    pub(super) fn start(dir: &Path) -> Result<Self> {
        let store = Arc::new(Mutex::new(p::AnchorStore::provision(
            &dir.join("witness.redb"),
            p::JournalKey::provision(&dir.join("witness.key"))?,
            p::AnchorSigningKey::generate()?,
            p::AnchorIdentity::generate()?,
        )?));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let configured = WitnessFixture {
            store: Arc::clone(&store),
            address,
        };
        let pin = configured.pin()?;
        let rows = Arc::new(Mutex::new(Vec::new()));
        let halt = Arc::new(AtomicBool::new(false));
        let drop_next = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&rows);
        let stop = Arc::clone(&halt);
        let fault = Arc::clone(&drop_next);
        let worker = thread::spawn(move || -> Result<()> {
            loop {
                let (mut stream, _) = listener.accept()?;
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let mut length = [0; 4];
                stream.read_exact(&mut length)?;
                let size = u32::from_be_bytes(length) as usize;
                if !(1..=16384).contains(&size) {
                    return Err("request length".into());
                }
                let mut request = vec![0; size];
                stream.read_exact(&mut request)?;
                let reply = store
                    .lock()
                    .map_err(|_| "witness lock")?
                    .handle(&request, now()?)?;
                let (verified, attempt) = pin.stage4_observe(&request, &reply)?;
                let outcome = verified.outcome();
                let dropped =
                    outcome == p::AnchorOutcome::Advanced && fault.swap(false, Ordering::SeqCst);
                observed
                    .lock()
                    .map_err(|_| "observation lock")?
                    .push(Observation {
                        outcome,
                        attempt,
                        command: verified.command_id(),
                        head: verified.observed_head(),
                        dropped,
                    });
                if !dropped {
                    stream.write_all(&u32::try_from(reply.len())?.to_be_bytes())?;
                    stream.write_all(&reply)?;
                }
            }
        });
        Ok(Self {
            configured,
            drop_next,
            halt,
            rows,
            worker: Some(worker),
        })
    }

    pub(super) fn arm(&self) -> usize {
        assert!(!self.drop_next.swap(true, Ordering::SeqCst));
        self.rows.lock().expect("observations").len()
    }

    pub(super) fn check_reconciliation(&self, start: usize) -> Result<(Observation, Observation)> {
        let rows = self.rows.lock().map_err(|_| "observations")?;
        let relevant = rows.get(start..).ok_or("start beyond exchange log")?;
        let lost: Vec<_> = relevant.iter().filter(|r| r.dropped).collect();
        let [lost] = lost.as_slice() else {
            return Err("expected exactly one lost durable acknowledgement".into());
        };
        assert_eq!(lost.outcome, p::AnchorOutcome::Advanced);
        let same: Vec<_> = relevant
            .iter()
            .filter(|r| r.command == lost.command)
            .collect();
        assert_eq!(
            same.iter()
                .filter(|r| r.outcome == p::AnchorOutcome::Advanced)
                .count(),
            1
        );
        let exact = same
            .iter()
            .find(|r| r.outcome == p::AnchorOutcome::AlreadyAppliedExact)
            .ok_or("original mutation was never reconciled")?;
        assert_ne!(lost.attempt, exact.attempt);
        assert_eq!(lost.head, exact.head);
        Ok((**lost, **exact))
    }

    pub(super) fn stop(mut self) -> Result<()> {
        self.halt.store(true, Ordering::SeqCst);
        TcpStream::connect_timeout(&self.configured.address, Duration::from_secs(2))?;
        self.worker
            .take()
            .ok_or("missing witness worker")?
            .join()
            .map_err(|_| "witness worker panic")?
    }
}

pub(super) fn describe(phase: u8, records: (Observation, Observation)) -> String {
    use std::fmt::Write;
    fn hex(x: [u8; 32]) -> String {
        x.iter().map(|b| format!("{b:02x}")).collect()
    }
    let mut out = String::new();
    for row in [records.0, records.1] {
        writeln!(
            out,
            "{phase} {:?} {} {} {} {} {} {}",
            row.outcome,
            row.dropped,
            hex(row.command),
            hex(row.attempt),
            row.head.fence(),
            row.head.revision(),
            hex(row.head.digest())
        )
        .expect("write String");
    }
    out
}
