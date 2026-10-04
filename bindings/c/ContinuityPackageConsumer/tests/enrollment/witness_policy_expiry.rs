// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original signed policy expiry, with live SDK and live successor credentials.
//! Applied originates in the selected foreign process, killed after the real
//! witness commit and before result delivery; a fresh process recovers after expiry.
use super::witness_credential_renewal::{
    expected, image_digest, pending_journal, provision_renewal, public_file,
};
use super::*;
use p::AnchorTransport;
use q_periapt_rustls::standard::MutualTlsClient;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use sha3::{Digest, Sha3_256};
use std::{
    io,
    net::TcpListener,
    os::unix::process::ExitStatusExt,
    process::{Child, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const TEST_POLICY_SECONDS: u64 = 120;
const MATERIALS: &[&str] = &[
    "enrollment-root",
    "enrollment-intent",
    "enrollment-request",
    "enrollment-reopened-request",
    "grant-certificate",
    "grant-roster",
    "trusted-account",
    "trusted-roster-version",
    "trusted-roster-digest",
    "family",
    "policy-root",
    "policy-version",
    "policy-digest",
    "protocol-policy",
    "witness-id",
    "witness-public",
    "witness-subject",
    "enrollment-genesis-subject",
    "enrollment-genesis-digest",
    "credential-renewal",
    "credential-operation",
    "credential-statement",
    "renewal-version",
    "renewal-digest",
    "credential-proposal",
    "credential-proposal-original",
    "expiry-image-digests",
    "expiry-sdk-binding",
    "expiry-observations",
    "expiry-witness-transcript",
    "expiry-tcp-transcript",
    "expiry-withheld-request",
    "expiry-withheld-reply",
    "expiry-setup-status-request",
    "expiry-setup-status-reply",
    "expiry-commit-cut-observations",
    "enrollment-policy-refusal-before-recovery",
    "enrollment-policy-refusal",
];
const LABELS: &[&str] = &[
    "key",
    "create",
    "request",
    "request-retry",
    "accept",
    "storage",
    "expiry-original-active",
    "expiry-original-status",
    "expiry-stage",
    "expiry-prepare",
    "expiry-pending-status",
    "expiry-prepare-reopened",
    "expiry-activation-before",
    "expiry-history",
    "expiry-transition",
    "expiry-retry",
    "expiry-terminal-history",
    "expiry-activation-after",
    "expiry-final-status",
    "expiry-commit-cut",
];

fn transport(path: &Path, endpoint: Endpoint) -> Result<Box<dyn AnchorTransport>> {
    if !endpoint.tls {
        return Ok(Box::new(p::AnchorTcpTransport::new(endpoint.address)));
    }
    let peer = fixture::read(path, "witness-tls-peer", 8192)?;
    let certificate = fixture::read(path, "witness-tls-cert", 8192)?;
    let secret = zeroize::Zeroizing::new(fixture::read(path, "witness-tls-key", 8192)?);
    let name = ServerName::try_from(String::from_utf8(fixture::read(
        path,
        "witness-tls-name",
        128,
    )?)?)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(peer.clone()))?;
    let key = PrivateKeyDer::try_from(secret.as_slice())?.clone_key();
    let config = MutualTlsClient::new(roots, vec![CertificateDer::from(certificate)], key)?;
    Ok(Box::new(p::anchor_tls::AnchorTlsTransport::new(
        endpoint.address,
        name,
        peer,
        config,
        p::Cancellation::default(),
    )?))
}
fn enrollment_paths(path: &Path) -> Result<p::EnrollmentPaths> {
    Ok(p::EnrollmentPaths::new(
        &path.join("wrap.key"),
        &path.join("signer.key"),
        &path.join("enrollment.redb"),
        p::InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )?,
    )?)
}
pub(super) fn policy_pin(path: &Path) -> Result<p::PolicyPin> {
    Ok(p::PolicyPin::new(
        fixture::array(path, "family")?,
        p::PublicKey::decode(&fixture::read(path, "policy-root", 8192)?)?,
        p::PolicyCheckpoint::from_trusted_state(
            u64::from_be_bytes(fixture::array(path, "policy-version")?),
            fixture::array(path, "policy-digest")?,
        )?,
    )?)
}
fn commitment(domain: &[u8], value: &[u8]) -> io::Result<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(
        u64::try_from(domain.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    h.update(domain);
    h.update(
        u64::try_from(value.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    h.update(value);
    Ok(h.finalize().into())
}
fn validate_commit_exchange(
    proposal: p::AnchorCredentialRenewalProposal,
    request: &[u8],
    reply: &[u8],
) -> io::Result<()> {
    let mut op = vec![5];
    op.extend_from_slice(&proposal.binding());
    op.extend_from_slice(&[0; 64]);
    let mut command_scope = proposal.witness_binding().to_vec();
    command_scope.extend_from_slice(&proposal.subject().to_bytes());
    command_scope.extend_from_slice(&op);
    let command = commitment(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", &command_scope)?;
    let body = request.get(4..301).ok_or(io::ErrorKind::InvalidData)?;
    let attempt = commitment(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", body)?;
    let target = proposal.target_head();
    let mut head = target.fence().to_be_bytes().to_vec();
    head.extend_from_slice(&target.revision().to_be_bytes());
    head.extend_from_slice(&target.digest());
    if request.len() != 3674
        || reply.len() != 3659
        || request.get(..4) != Some(297u32.to_be_bytes().as_slice())
        || request.get(4..12) != Some(b"QPANRQ01")
        || request.get(12..44) != Some(proposal.witness_binding().as_slice())
        || request.get(44..140) != Some(proposal.subject().to_bytes().as_slice())
        || request.get(140..172) != Some(command.as_slice())
        || request.get(204..301) != Some(op.as_slice())
        || reply.get(..4) != Some(282u32.to_be_bytes().as_slice())
        || reply.get(4..12) != Some(b"QPANRS01")
        || reply.get(12..140) != request.get(12..140)
        || reply.get(140..172) != Some(attempt.as_slice())
        || reply.get(172..204) != Some(command.as_slice())
        || reply.get(204) != Some(&8)
        || reply.get(205..253) != Some(head.as_slice())
        || reply.get(253) != Some(&1)
        || reply.get(254..286) != Some(command.as_slice())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected original Commit cut",
        ));
    }
    Ok(())
}

struct HeldCommit {
    proposal: p::AnchorCredentialRenewalProposal,
    marker: PathBuf,
    released: Arc<AtomicBool>,
}
struct Release(Arc<AtomicBool>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct CommitTlsWitness {
    address: SocketAddr,
    admitted: Arc<AtomicUsize>,
    records: Arc<Mutex<Vec<witness::Capture>>>,
    hold: Arc<Mutex<Option<HeldCommit>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl CommitTlsWitness {
    fn start(store: Arc<Mutex<p::AnchorStore>>, path: &Path) -> Result<Self> {
        let configured = witness_tls::provision([path])?;
        let server = configured.native;
        drop((configured.certificate, configured.key));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let admitted = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&admitted);
        let records = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&records);
        let hold: Arc<Mutex<Option<HeldCommit>>> = Arc::new(Mutex::new(None));
        let pending = Arc::clone(&hold);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || -> Result<()> {
            while !stopping.load(Ordering::Acquire) {
                let mut front = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                let deadline = Instant::now() + Duration::from_secs(3);
                let (reply, record) = witness_tls_relay::receive_reply(
                    &mut front,
                    &server,
                    &store,
                    deadline,
                    &mut || {
                        calls.fetch_add(1, Ordering::AcqRel);
                        fixture::now().map_err(io::Error::other)
                    },
                )?;
                // The native endpoint has authenticated and durably handled the
                // exact request. The relay has retained its encrypted reply.
                let selected = if record.request().get(204) == Some(&5) {
                    pending.lock().map_err(|_| "TLS hold lock")?.take()
                } else {
                    None
                };
                let delivered = selected.is_none();
                if let Some(held) = selected {
                    validate_commit_exchange(held.proposal, record.request(), record.reply())?;
                    let path = held.marker.parent().ok_or("TLS marker parent")?;
                    fixture::store(
                        path,
                        "expiry-encrypted-reply-bytes",
                        &u64::try_from(reply.len())?.to_be_bytes(),
                    )?;
                    fixture::publish_marker(
                        path,
                        held.marker
                            .file_name()
                            .and_then(|s| s.to_str())
                            .ok_or("TLS marker name")?,
                    )?;
                    // receive_reply joined and stopped its request reader. Only
                    // the parent that has reaped SIGKILL may release this hold;
                    // local read shutdown is not evidence of peer termination.
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !held.released.load(Ordering::Acquire) {
                        if Instant::now() >= deadline {
                            return Err("TLS Commit hold expired".into());
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                }
                {
                    let mut rows = captured.lock().map_err(|_| "TLS capture lock")?;
                    if rows.len() >= 4096 {
                        return Err("TLS Commit capture capacity".into());
                    }
                    rows.push(witness::Capture {
                        request: record.request().to_vec(),
                        reply: record.reply().to_vec(),
                        delivered,
                    });
                }
                if delivered {
                    witness_tls_relay::write(&mut front, &reply, deadline)?;
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            admitted,
            records,
            hold,
            stop,
            worker: Some(worker),
        })
    }
    fn arm(
        &self,
        proposal: p::AnchorCredentialRenewalProposal,
        marker: PathBuf,
    ) -> Result<Release> {
        let mut saved = self.hold.lock().map_err(|_| "TLS hold lock")?;
        if saved.is_some() {
            return Err("unconsumed TLS Commit hold".into());
        }
        let released = Arc::new(AtomicBool::new(false));
        *saved = Some(HeldCommit {
            proposal,
            marker,
            released: Arc::clone(&released),
        });
        Ok(Release(released))
    }
    fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .ok_or("missing TLS Commit worker")?
            .join()
            .map_err(|_| "TLS Commit worker panicked")??;
        if self.hold.lock().map_err(|_| "TLS hold lock")?.is_some() {
            return Err("unconsumed TLS Commit hold".into());
        }
        if self.records.lock().map_err(|_| "TLS capture lock")?.len()
            != self.admitted.load(Ordering::Acquire)
        {
            return Err("TLS Commit admission accounting differs".into());
        }
        Ok(())
    }
}
impl Drop for CommitTlsWitness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => eprintln!("TLS Commit witness was not explicitly finished"),
                Ok(Err(error)) => eprintln!("TLS Commit witness cleanup: {error}"),
                Err(_) => eprintln!("TLS Commit witness cleanup panicked"),
            }
        }
    }
}
struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(e) => eprintln!("Commit owner cleanup status: {e}"),
        }
        if let Err(e) = self.0.kill() {
            eprintln!("Commit owner cleanup kill: {e}");
        }
        if let Err(e) = self.0.wait() {
            eprintln!("Commit owner cleanup reap: {e}");
        }
    }
}

fn apply_without_local_recovery(
    registration: &Registration,
    endpoint: Endpoint,
    pin: &p::AnchorPin,
    witness: &witness::Witness,
    tls: Option<&CommitTlsWitness>,
    proposal: p::AnchorCredentialRenewalProposal,
) -> Result<()> {
    let path = &registration.path;
    let before = pending_journal(path)?;
    let marker = path.join("expiry-commit-ready");
    let release = if let Some(server) = tls {
        Some(server.arm(proposal, marker.clone())?)
    } else {
        let mut held = witness.hold_marker.lock().map_err(|_| "TCP hold lock")?;
        if held.replace(marker.clone()).is_some() {
            return Err("unconsumed TCP Commit hold".into());
        }
        drop(held);
        witness.arm(5)?;
        None
    };
    let stdout = fs::File::create(path.join("witness-enrollment-expiry-commit-cut.stdout"))?;
    let stderr = fs::File::create(path.join("witness-enrollment-expiry-commit-cut.stderr"))?;
    let mut child = ChildOwner(
        Command::new(executable()?)
            .args(arguments(path, "credential-witness-commit", Some(endpoint)))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(40);
    while !marker.is_file() {
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "foreign Commit missed barrier: {}",
                String::from_utf8_lossy(&public_file(
                    path,
                    "witness-enrollment-expiry-commit-cut.stderr",
                    65536
                )?)
            )
            .into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    child.0.kill()?;
    let killed = child.0.wait()?;
    assert_eq!(killed.signal(), Some(9));
    for suffix in ["stdout", "stderr"] {
        assert!(public_file(
            path,
            &format!("witness-enrollment-expiry-commit-cut.{suffix}"),
            65536
        )?
        .is_empty());
    }
    drop(release);
    let mut observed = b"QPCECK01".to_vec();
    observed.extend_from_slice(&[u8::from(endpoint.tls), 9, 1, 0]);
    observed.extend_from_slice(&fixture::now()?.to_be_bytes());
    let encrypted = if endpoint.tls {
        u64::from_be_bytes(fixture::array(path, "expiry-encrypted-reply-bytes")?)
    } else {
        0
    };
    assert_eq!(encrypted > 0, endpoint.tls);
    observed.extend_from_slice(&encrypted.to_be_bytes());
    fixture::store(path, "expiry-commit-cut-observations", &observed)?;
    assert_eq!(pending_journal(path)?, before);
    // Observe with the original protected signer, independently of the failed
    // owner. Enrollment reconciliation would install/clean the target here.
    let mut observer =
        p::DeviceEnrollment::open(enrollment_paths(path)?, registration.intent.clone())?;
    let id = observer.identity()?;
    assert_eq!(id.as_bytes(), &registration.accepted.signer);
    assert_eq!(
        observer.credential_renewal_status()?,
        p::CredentialRenewalStatus::Pending {
            operation: proposal.operation(),
            statement: proposal.statement(),
        }
    );
    let key = p::JournalKey::open(&path.join("wrap.key"))?;
    let signer = p::DeviceSigningKey::open(&path.join("signer.key"), &key, id)?;
    let request = p::AnchorRequest::new(
        pin,
        proposal.subject(),
        p::AnchorOperation::credential_renewal_status(&proposal),
        &signer,
    )?;
    let wire = transport(path, endpoint)?
        .exchange(request.as_bytes(), Instant::now() + Duration::from_secs(3))?;
    assert_eq!(
        pin.verify_reply(&request, &wire)?
            .credential_renewal_state(&proposal)?,
        p::AnchorCredentialRenewalState::Applied
    );
    fixture::store(path, "expiry-setup-status-request", request.as_bytes())?;
    fixture::store(path, "expiry-setup-status-reply", &wire)?;
    drop(signer);
    drop(key);
    observer.close();
    assert_eq!(pending_journal(path)?, before);
    let rows = if let Some(server) = tls {
        server.records.lock().map_err(|_| "TLS cut records")?
    } else {
        witness.captured.lock().map_err(|_| "TCP cut records")?
    };
    let lost = rows.iter().filter(|r| !r.delivered).collect::<Vec<_>>();
    assert_eq!(lost.len(), 1);
    let cut = lost.first().ok_or("missing foreign Commit cut")?;
    validate_commit_exchange(proposal, &cut.request, &cut.reply)?;
    if !endpoint.tls {
        let mut prefix = 3659u32.to_be_bytes().to_vec();
        prefix.extend_from_slice(cut.reply.get(..1800).ok_or("Commit prefix")?);
        assert_eq!(
            fixture::read(path, "witness-cancelled-prefix", 8192)?,
            prefix
        );
    }
    fixture::store(path, "expiry-withheld-request", &cut.request)?;
    fixture::store(path, "expiry-withheld-reply", &cut.reply)?;
    Ok(())
}

struct Trace<'a> {
    witness: &'a witness::Witness,
    tls: Option<&'a CommitTlsWitness>,
    subject: p::AnchorSubject,
    started: Instant,
    points: Vec<(&'static str, u64, u64, u64)>,
}
impl Trace<'_> {
    fn mark(&mut self, label: &'static str) -> Result<()> {
        let count = if let Some(tls) = self.tls {
            tls.admitted.load(Ordering::Acquire)
        } else {
            self.witness
                .captured
                .lock()
                .map_err(|_| "capture lock")?
                .iter()
                .filter(|c| c.request.get(44..140) == Some(self.subject.to_bytes().as_slice()))
                .count()
        };
        self.points.push((
            label,
            fixture::now()?,
            u64::try_from(self.started.elapsed().as_millis())?,
            u64::try_from(count)?,
        ));
        Ok(())
    }
    fn encode(
        &self,
        policy: p::Validity,
        credential: p::Validity,
        applied: bool,
    ) -> Result<Vec<u8>> {
        let mut bytes = b"QPCEPX01".to_vec();
        for value in [
            policy.from(),
            policy.until(),
            credential.from(),
            credential.until(),
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.push(u8::from(applied));
        bytes.push(u8::try_from(self.points.len())?);
        for (label, time, elapsed, count) in &self.points {
            bytes.push(u8::try_from(label.len())?);
            bytes.extend_from_slice(label.as_bytes());
            for value in [time, elapsed, count] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        Ok(bytes)
    }
}
pub(super) fn expired_authority(
    path: &Path,
    pin: &p::PolicyPin,
    historical: &p::HistoricalSessionPolicy,
    target: &p::AccountPin,
) -> Result<u64> {
    let now = fixture::now()?;
    assert!(now >= historical.validity().until());
    let mut sdk = fixture::sdk(path)?;
    let runtime = sdk.runtime()?;
    assert!(runtime.is_enabled()?);
    assert_eq!(runtime.policy_binding()?, historical.sdk_binding());
    let wire = fixture::read(path, "protocol-policy", 8192)?;
    assert!(matches!(
        pin.verify(&wire, runtime, now),
        Err(p::Error::Validity)
    ));
    assert_eq!(
        pin.verify_historical(&wire)?.checkpoint(),
        historical.checkpoint()
    );
    p::VerifiedCredentialRenewal::verify(
        &fixture::read(path, "credential-renewal", 65536)?,
        target,
        historical.checkpoint().digest(),
        now,
    )?;
    sdk.close();
    Ok(now)
}
struct ExpiredAuthority<'a> {
    path: &'a Path,
    endpoint: Endpoint,
    pin: &'a p::PolicyPin,
    historical: &'a p::HistoricalSessionPolicy,
    target: &'a p::AccountPin,
}
impl ExpiredAuthority<'_> {
    fn run(
        &self,
        label: &'static str,
        mode: &str,
        expected: &str,
        trace: &mut Trace<'_>,
    ) -> Result<()> {
        expired_authority(self.path, self.pin, self.historical, self.target)?;
        trace.mark(label)?;
        let mut args = arguments(self.path, mode, Some(self.endpoint));
        if mode == "activate-error" {
            args.push("104".into());
        }
        assert_eq!(run(self.path, label, &args)?, expected);
        expired_authority(self.path, self.pin, self.historical, self.target)?;
        trace.mark(label)
    }
}

fn export(path: &Path, output: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(output)?;
    for name in MATERIALS {
        fixture::store(output, name, &public_file(path, name, 32 * 1024 * 1024)?)?;
    }
    for label in LABELS {
        for suffix in ["stdout", "stderr"] {
            let name = format!("witness-enrollment-{label}.{suffix}");
            fixture::store(output, &name, &public_file(path, &name, 65536)?)?;
        }
    }
    Ok(())
}

fn exercise(tls: bool, applied: bool, public: Option<PathBuf>) -> Result<String> {
    let mut witness = witness::Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let registration = prepare_with_policy_lifetime(&setup, &witness, Some(TEST_POLICY_SECONDS))?;
    let path = &registration.path;
    let mut tls_witness = if tls {
        Some(CommitTlsWitness::start(
            Arc::clone(&witness.configured.store),
            path,
        )?)
    } else {
        None
    };
    let endpoint = Endpoint {
        address: tls_witness
            .as_ref()
            .map_or(witness.configured.address, |w| w.address),
        tls,
    };
    let mut trace = Trace {
        witness: &witness,
        tls: tls_witness.as_ref(),
        subject: registration.subject,
        started: Instant::now(),
        points: Vec::new(),
    };
    run(
        path,
        "expiry-original-active",
        &arguments(path, "activate", Some(endpoint)),
    )?;
    let active = state(&run(
        path,
        "expiry-original-status",
        &arguments(path, "status", Some(endpoint)),
    )?)?;
    let original = pending_journal(path)?;
    let (proof, target, credential_validity) = provision_renewal(&registration)?;
    let pin = policy_pin(path)?;
    let historical = pin.verify_historical(&fixture::read(path, "protocol-policy", 8192)?)?;
    let immutable = [
        "family",
        "policy-root",
        "policy-version",
        "policy-digest",
        "protocol-policy",
        "credential-renewal",
    ]
    .into_iter()
    .map(|name| Ok((name, fixture::read(path, name, 65536)?)))
    .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        run(
            path,
            "expiry-stage",
            &arguments(path, "credential-stage", Some(endpoint))
        )?,
        expected(&proof, 1)
    );
    assert_eq!(
        run(
            path,
            "expiry-prepare",
            &arguments(path, "credential-witness-prepare", Some(endpoint))
        )?,
        "credential-witness-prepared\n"
    );
    let proposal_bytes = fixture::read(path, "credential-proposal", 296)?;
    fixture::store(path, "credential-proposal-original", &proposal_bytes)?;
    let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&proposal_bytes)?;
    assert_eq!(proposal.subject(), registration.subject);
    assert_eq!(proposal.operation(), proof.operation());
    assert_eq!(proposal.statement(), proof.statement_digest());
    let pending = pending_journal(path)?;
    assert_eq!(pending.0, original.0);
    assert!(pending.1.is_some());
    let mut sdk = fixture::sdk(path)?;
    let policy = fixture::protocol_policy(path, &sdk)?;
    let witness_pin = {
        let mut store = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?;
        store.prepare_credential_renewal(proposal, &proof, &policy, fixture::now()?)?;
        store.pin()?
    };
    policy.close();
    sdk.close();
    if applied {
        apply_without_local_recovery(
            &registration,
            endpoint,
            &witness_pin,
            &witness,
            tls_witness.as_ref(),
            proposal,
        )?;
    } else {
        for name in [
            "expiry-withheld-request",
            "expiry-withheld-reply",
            "expiry-setup-status-request",
            "expiry-setup-status-reply",
            "expiry-commit-cut-observations",
            "witness-enrollment-expiry-commit-cut.stdout",
            "witness-enrollment-expiry-commit-cut.stderr",
        ] {
            fixture::store(path, name, &[])?;
        }
    }
    assert_eq!(pending_journal(path)?, pending);
    assert_eq!(
        run(
            path,
            "expiry-pending-status",
            &arguments(path, "credential-status", Some(endpoint))
        )?,
        expected(&proof, 1)
    );
    trace.mark("prepared")?;
    assert!(
        fixture::now()? < historical.validity().until(),
        "setup missed original signed validity"
    );
    let waiting = Instant::now();
    while fixture::now()? < historical.validity().until() {
        if waiting.elapsed() > Duration::from_secs(TEST_POLICY_SECONDS + 5) {
            return Err("bounded real policy-expiry wait exhausted".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let observed = expired_authority(path, &pin, &historical, &target)?;
    assert!(observed < credential_validity.until());
    trace.mark("expired")?;
    let expired = ExpiredAuthority {
        path,
        endpoint,
        pin: &pin,
        historical: &historical,
        target: &target,
    };
    fs::rename(
        path.join("credential-proposal"),
        path.join("credential-proposal-before-expiry"),
    )?;
    expired.run(
        "expiry-prepare-reopened",
        "credential-witness-prepare",
        "credential-witness-prepared\n",
        &mut trace,
    )?;
    assert_eq!(
        fixture::read(path, "credential-proposal", 296)?,
        proposal_bytes
    );
    assert_eq!(pending_journal(path)?, pending);
    expired.run(
        "expiry-activation-before",
        "activate-error",
        "enrollment-activation-refused:104\n",
        &mut trace,
    )?;
    assert_eq!(pending_journal(path)?, pending);
    fs::rename(
        path.join("enrollment-policy-refusal"),
        path.join("enrollment-policy-refusal-before-recovery"),
    )?;
    expired.run(
        "expiry-history",
        "credential-witness-reconcile",
        &expected(&proof, if applied { 2 } else { 1 }),
        &mut trace,
    )?;
    if applied {
        let recovered = pending_journal(path)?;
        assert!(recovered.1.is_none());
        assert_eq!(image_digest(&recovered.0)?, proposal.target_head().digest());
        expired.run(
            "expiry-transition",
            "credential-witness-commit",
            &expected(&proof, 2),
            &mut trace,
        )?;
    } else {
        assert_eq!(pending_journal(path)?, pending);
        expired.run(
            "expiry-transition",
            "credential-witness-commit-policy-expired",
            "credential-witness-commit-refused:104\n",
            &mut trace,
        )?;
        assert_eq!(pending_journal(path)?, pending);
    }
    // Closed's explicit mutation is requested only after a fresh expired Commit
    // refusal; Applied's retry only reads the retained original terminal.
    expired.run(
        "expiry-retry",
        if applied {
            "credential-witness-commit"
        } else {
            "credential-witness-close"
        },
        &expected(&proof, if applied { 2 } else { 4 }),
        &mut trace,
    )?;
    expired.run(
        "expiry-terminal-history",
        "credential-witness-reconcile",
        &expected(&proof, if applied { 2 } else { 4 }),
        &mut trace,
    )?;
    let terminal = pending_journal(path)?;
    assert!(terminal.1.is_none());
    assert_eq!(
        image_digest(&terminal.0)?,
        if applied {
            proposal.target_head().digest()
        } else {
            proposal.expected_head().digest()
        }
    );
    expired.run(
        "expiry-activation-after",
        "activate-error",
        "enrollment-activation-refused:104\n",
        &mut trace,
    )?;
    assert_eq!(
        state(&run(
            path,
            "expiry-final-status",
            &arguments(path, "status", Some(endpoint))
        )?)?,
        active
    );
    assert_eq!(pending_journal(path)?, terminal);
    for (name, bytes) in immutable {
        assert_eq!(fixture::read(path, name, 65536)?, bytes);
    }
    fixture::store(path, "expiry-sdk-binding", &historical.sdk_binding())?;
    fixture::store(
        path,
        "expiry-observations",
        &trace.encode(historical.validity(), credential_validity, applied)?,
    )?;
    let expired_index = usize::try_from(
        trace
            .points
            .iter()
            .find(|p| p.0 == "expired")
            .ok_or("expiry point")?
            .3,
    )?;
    drop(trace);
    let mut tcp_transcript = Vec::new();
    for capture in witness
        .captured
        .lock()
        .map_err(|_| "capture lock")?
        .iter()
        .filter(|c| c.request.get(44..140) == Some(registration.subject.to_bytes().as_slice()))
    {
        tcp_transcript.push(u8::from(capture.delivered));
        tcp_transcript.extend_from_slice(&capture.request);
        tcp_transcript.extend_from_slice(&capture.reply);
    }
    let transcript = if let Some(server) = tls_witness.as_mut() {
        assert!(
            tcp_transcript.is_empty(),
            "TLS recovery used plaintext fallback"
        );
        server.finish()?;
        let records = server.records.lock().map_err(|_| "TLS records poisoned")?;
        assert_eq!(records.len(), server.admitted.load(Ordering::Acquire));
        let mut bytes = Vec::new();
        for record in records.iter() {
            assert_eq!(
                record.request.as_slice().get(44..140),
                Some(registration.subject.to_bytes().as_slice())
            );
            bytes.push(u8::from(record.delivered));
            bytes.extend_from_slice(record.request.as_slice());
            bytes.extend_from_slice(record.reply.as_slice());
        }
        bytes
    } else {
        tcp_transcript.clone()
    };
    fixture::store(path, "expiry-tcp-transcript", &tcp_transcript)?;
    let (records, remainder) = transcript.as_chunks::<7334>();
    assert!(remainder.is_empty());
    assert!(
        records
            .iter()
            .skip(expired_index)
            .all(|r| r.get(205) != Some(&5)),
        "expired recovery sent a new Commit"
    );
    fixture::store(path, "expiry-witness-transcript", &transcript)?;
    let mut images = image_digest(&original.0)?.to_vec();
    images.extend_from_slice(&image_digest(&pending.0)?);
    images.extend_from_slice(&image_digest(&terminal.0)?);
    fixture::store(path, "expiry-image-digests", &images)?;
    witness.join()?;
    let name = format!(
        "{}-{}",
        if tls { "tls" } else { "tcp" },
        if applied { "applied" } else { "closed" }
    );
    if let Some(public) = public {
        export(path, &public.join(&name))?;
    }
    Ok(format!("WITNESSED_POLICY_EXPIRY case={name} policy_until={} observed={observed} credential_until={} sdk_present=true original_policy=true no_new_commit=true foreign_commit_killed={applied}", historical.validity().until(), credential_validity.until()))
}

#[test]
fn original_foreign_owner_recovers_after_real_signed_policy_expiry() -> Result<()> {
    let public = std::env::var_os("QPERIAPT_WITNESSED_POLICY_EXPIRY_EVIDENCE").map(PathBuf::from);
    if let Some(path) = &public {
        if !path.is_absolute() {
            return Err("absolute policy-expiry evidence path required".into());
        }
        q_periapt_host_store::filesystem::OwnedPrivateDirectory::open(
            path.parent().ok_or("evidence parent")?,
        )?;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let mut handles = Vec::new();
    for (tls, applied) in [(false, true), (false, false), (true, true), (true, false)] {
        let output = public.clone();
        handles.push(thread::spawn(move || exercise(tls, applied, output)));
    }
    // Join every independent case even if one fails. No parallel fixture survives
    // a reported result, and wall-clock expiry is shared in time, never backdated.
    let results = handles
        .into_iter()
        .map(|handle| match handle.join() {
            Ok(result) => result,
            Err(_) => {
                Err(io::Error::other("policy-expiry case panicked; see thread diagnostic").into())
            }
        })
        .collect::<Vec<Result<String>>>();
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(report) => println!("{report}"),
            Err(error) => failures.push(error.to_string()),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}
