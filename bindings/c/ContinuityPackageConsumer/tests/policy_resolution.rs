// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signed historical fixtures at explicit past instants; foreign resolution uses
//! the real host clock. Authenticated-row replay models an old retained Pending,
//! not physical power-loss injection or a product repair procedure.
use q_periapt_continuity_identity_candidate as p;
use q_periapt_sig::Signer;
use redb::{ReadableDatabase, ReadableTable};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn store(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(name))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn runtime() -> Result<Arc<q_periapt_sdk::Runtime>> {
    let policy=b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let (mut key, public) = q_periapt_backends::MlDsa65::generate([82; 32]);
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    let result = q_periapt_backends::MlDsa65.sign(
        &key,
        &q_periapt_policy::policy_signature_message(policy),
        &[83; 32],
        &mut signature,
    );
    key.zeroize();
    result.map_err(|e| format!("SDK policy signing: {e:?}"))?;
    Ok(Arc::new(q_periapt_sdk::Runtime::from_signed_policy(
        policy,
        &signature,
        &public,
        None,
        q_periapt_sdk::Limits::default(),
    )?))
}
struct Document {
    root: Vec<u8>,
    family: [u8; 32],
    checkpoint: p::PolicyCheckpoint,
    wire: Vec<u8>,
}
impl Document {
    fn files(&self) -> [(&'static str, Vec<u8>); 5] {
        [
            ("policy-root", self.root.clone()),
            ("family", self.family.to_vec()),
            (
                "policy-version",
                self.checkpoint.version().to_be_bytes().to_vec(),
            ),
            ("policy-digest", self.checkpoint.digest().to_vec()),
            ("protocol-policy", self.wire.clone()),
        ]
    }
    fn publish(&self, path: &Path) -> Result<()> {
        for (name, bytes) in self.files() {
            store(path, name, &bytes)?;
        }
        Ok(())
    }
    fn replace(&self, path: &Path) -> Result<()> {
        for (name, bytes) in self.files() {
            fs::write(path.join(name), bytes)?;
        }
        Ok(())
    }
}
fn policy(
    root: &p::PolicySigningKey,
    runtime: &Arc<q_periapt_sdk::Runtime>,
    version: u64,
    from: u64,
    until: u64,
    at: u64,
) -> Result<(Document, p::VerifiedSessionPolicy)> {
    let issued = root.issue_session_policy(
        runtime,
        p::SessionPolicyParameters::new(
            version,
            p::Validity::new(from, until)?,
            p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
            p::AnchorRequirement::local_only(),
            p::ApplicationSendBudget::new(1024)?,
        )?,
    )?;
    let verified = p::PolicyPin::new(
        root.policy_family()?,
        root.public_key()?,
        issued.checkpoint(),
    )?
    .verify(issued.as_bytes(), Arc::clone(runtime), at)?;
    Ok((
        Document {
            root: root.public_key()?.encode(),
            family: verified.family(),
            checkpoint: issued.checkpoint(),
            wire: issued.as_bytes().to_vec(),
        },
        verified,
    ))
}
fn row(path: &Path) -> Result<Vec<u8>> {
    let db =
        q_periapt_host_store::filesystem::open_private_database(&path.join("enrollment.redb"))?;
    let tx = db.begin_read()?;
    let table = tx.open_table(redb::TableDefinition::<&str, &[u8]>::new(
        "continuity_enrollment_v1",
    ))?;
    let value = table.get("enrollment")?.ok_or("original enrollment row")?;
    Ok(value.value().to_vec())
}
fn replace_row(path: &Path, bytes: &[u8]) -> Result<()> {
    let db =
        q_periapt_host_store::filesystem::open_private_database(&path.join("enrollment.redb"))?;
    let mut tx = db.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    {
        let mut table = tx.open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "continuity_enrollment_v1",
        ))?;
        table.insert("enrollment", bytes)?;
    }
    tx.commit()?;
    Ok(())
}
fn journal_rows(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let db = q_periapt_host_store::filesystem::open_private_database(&path.join("journal.redb"))?;
    let tx = db.begin_read()?;
    let table = tx.open_table(redb::TableDefinition::<&str, &[u8]>::new(
        "continuity_device_candidate_v21",
    ))?;
    table
        .iter()?
        .map(|entry| {
            let (k, v) = entry?;
            Ok((k.value().to_owned(), v.value().to_vec()))
        })
        .collect()
}
fn approve(
    root: &p::RootSigningKey,
    issuer: &p::PolicySigningKey,
    request: &p::PolicyRenewalRequest,
    original: &p::HistoricalSessionPolicy,
    previous: &p::HistoricalSessionPolicy,
    target: &p::VerifiedSessionPolicy,
    at: u64,
) -> Result<p::VerifiedPolicyRenewal> {
    let materials = request.materials(original, previous, target);
    let statement = p::PolicyRenewalStatement::new(request.scope(), &materials, at)?;
    Ok(p::VerifiedPolicyRenewal::verify(
        &root.approve_policy_renewal(&statement)?,
        &issuer.approve_policy_renewal(&statement)?,
        request.scope(),
        &materials,
        at,
    )?)
}
struct ActualPolicy {
    config: Vec<u8>,
    operation: p::PolicyRenewalId,
    statement: [u8; 32],
    document: Document,
}
#[derive(PartialEq, Eq)]
struct AssetSnapshot {
    wrapping_hash: [u8; 32],
    signer_hash: [u8; 32],
    journal_rows: Vec<(String, Vec<u8>)>,
}
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    paths: p::EnrollmentPaths,
    intent: p::EnrollmentIntent,
    original: p::VerifiedDevice,
    journal: p::JournalIdentity,
    operation: p::PolicyRenewalId,
    statement: [u8; 32],
    target: p::PolicyCheckpoint,
    head: p::RosterCheckpoint,
    phase: u32,
    reason: u32,
    actual: Option<ActualPolicy>,
    kind: String,
}
impl Fixture {
    fn new(kind: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().canonicalize()?;
        let n = now()?;
        let at = n.checked_sub(800).ok_or("clock before fixture interval")?;
        let from = n - 1000;
        let runtime = runtime()?;
        let issuer = p::PolicySigningKey::generate()?;
        let (p0doc, p0) = policy(&issuer, &runtime, 1, from, n - 400, at)?;
        p0doc.publish(&path)?;
        let target_expired =
            kind == "expired-policy" || kind.starts_with("committed-") || kind == "higher-policy";
        let (p1doc, p1) = policy(
            &issuer,
            &runtime,
            2,
            from,
            if target_expired { n - 200 } else { n + 600 },
            at,
        )?;
        let target_dir = path.join("independent-sdk");
        fs::create_dir(&target_dir)?;
        fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o700))?;
        p1doc.publish(&target_dir)?;
        let root = p::RootSigningKey::generate()?;
        let validity = p::Validity::new(
            from,
            if kind == "expired-credential" {
                n - 100
            } else {
                n + 600
            },
        )?;
        let intent = p::EnrollmentIntent::new(
            root.public_key()?,
            p::DeviceDescription::new([7; 16], 1, p0.family(), validity)?,
        );
        let paths = p::EnrollmentPaths::new(
            &path.join("wrap.key"),
            &path.join("signer.key"),
            &path.join("enrollment.redb"),
            p::InstallationPaths::new(
                &path.join("installation.redb"),
                &path.join("journal.redb"),
                &path.join("archives.redb"),
            )?,
        )?;
        drop(p::JournalKey::provision(&path.join("wrap.key"))?);
        let mut enrollment = p::DeviceEnrollment::provision(paths.clone(), intent.clone())?;
        let request = enrollment.request(at)?;
        let verified = p::VerifiedEnrollmentRequest::verify(&request, &intent, at)?;
        let certificate = root.issue_enrollment(&verified, at)?;
        let roster = root.issue_roster(
            1,
            p::Validity::new(
                from,
                if kind == "expired-roster" {
                    n - 100
                } else {
                    n + 600
                },
            )?,
            &[root.roster_entry(&certificate)?],
        )?;
        let pin = |checkpoint| {
            p::AccountPin::new(
                root.account_id()?,
                root.public_key()?,
                checkpoint,
                p0.family(),
            )
        };
        let journal = enrollment.accept(
            &certificate,
            roster.as_bytes(),
            &pin(roster.checkpoint())?,
            &p0,
            at,
        )?;
        enrollment.prepare(&p0, at)?;
        let mut owner = enrollment.activate(&p0, at, None)?;
        let original = owner.parts()?.2.clone();
        owner.close();
        let open = || p::DeviceEnrollment::open(paths.clone(), intent.clone());
        let operation = p::PolicyRenewalId::generate()?;
        let requested = open()?.policy_renewal_request(operation, p0.historical())?;
        let approval = approve(
            &root,
            &issuer,
            &requested,
            p0.historical(),
            p0.historical(),
            &p1,
            n - 700,
        )?;
        open()?.stage_policy_renewal(&approval, operation, p0.historical(), &p1, n - 700)?;
        let pending = row(&path)?;
        let mut actual = None;
        if kind.starts_with("committed-") || kind == "higher-policy" {
            assert!(matches!(
                open()?.reconcile_policy_renewal(p0.historical(), &p1, n - 650)?,
                p::PolicyRenewalStatus::Committed { .. }
            ));
            if kind == "higher-policy" {
                let (p2doc, p2) = policy(&issuer, &runtime, 3, from, n + 900, n - 550)?;
                let operation2 = p::PolicyRenewalId::generate()?;
                let requested2 = open()?.policy_renewal_request(operation2, p0.historical())?;
                let approval2 = approve(
                    &root,
                    &issuer,
                    &requested2,
                    p0.historical(),
                    p1.historical(),
                    &p2,
                    n - 550,
                )?;
                open()?.stage_policy_renewal(
                    &approval2,
                    operation2,
                    p0.historical(),
                    &p2,
                    n - 550,
                )?;
                assert!(matches!(
                    open()?.reconcile_policy_renewal(p0.historical(), &p2, n - 540)?,
                    p::PolicyRenewalStatus::Committed { .. }
                ));
                actual = Some(ActualPolicy {
                    config: row(&path)?,
                    operation: operation2,
                    statement: approval2.statement_digest(),
                    document: p2doc,
                });
                p2.close();
            }
            replace_row(&path, &pending)?;
        }
        let advanced = matches!(
            kind,
            "advanced-roster"
                | "revoked"
                | "generation"
                | "committed-advanced"
                | "committed-revoked"
                | "committed-generation"
        );
        let mut head = roster.checkpoint();
        if advanced {
            let entries = if kind.ends_with("revoked") {
                vec![]
            } else if kind.ends_with("generation") {
                let replacement = root.issue_device(
                    p::DeviceDescription::new(
                        [7; 16],
                        2,
                        p0.family(),
                        p::Validity::new(from, n + 900)?,
                    )?,
                    verified.public_key().clone(),
                )?;
                vec![root.roster_entry(&replacement)?]
            } else {
                vec![root.roster_entry(&certificate)?]
            };
            let next = root.issue_roster(2, p::Validity::new(n - 900, n + 900)?, &entries)?;
            let mut j = p::DeviceJournal::open(
                &path.join("journal.redb"),
                p::JournalKey::open(&path.join("wrap.key"))?,
                &original,
                journal,
            )?;
            j.install_roster(
                &pin(next.checkpoint())?.verify_roster(next.as_bytes(), n - 600)?,
                n - 600,
            )?;
            j.close();
            head = next.checkpoint();
        }
        let (phase, reason) = if kind.starts_with("committed-") {
            (2, 0)
        } else if advanced {
            (3, 2)
        } else {
            (3, 1)
        };
        store(&path, "enrollment-root", &root.public_key()?.encode())?;
        let mut intent_bytes = vec![7; 16];
        intent_bytes.extend_from_slice(&1u64.to_be_bytes());
        intent_bytes.extend_from_slice(&p0.family());
        intent_bytes.extend_from_slice(&validity.from().to_be_bytes());
        intent_bytes.extend_from_slice(&validity.until().to_be_bytes());
        store(&path, "enrollment-intent", &intent_bytes)?;
        store(&path, "independent-operation", operation.as_bytes())?;
        store(&path, "independent-statement", &approval.statement_digest())?;
        if kind == "wrong-target" {
            let (wrong, verified) = policy(&issuer, &runtime, 3, from, n + 900, at)?;
            wrong.replace(&target_dir)?;
            verified.close();
        }
        if kind == "wrong-operation" {
            fs::write(
                path.join("independent-operation"),
                p::PolicyRenewalId::generate()?.as_bytes(),
            )?;
        }
        if kind == "wrong-statement" {
            let mut wrong = approval.statement_digest();
            *wrong.first_mut().ok_or("statement width")? ^= 1;
            fs::write(path.join("independent-statement"), wrong)?;
        }
        fs::rename(path.join("signer.key"), path.join("signer-held.key"))?;
        p1.close();
        p0.close();
        runtime.close();
        Ok(Self {
            _directory: directory,
            path,
            paths,
            intent,
            original,
            journal,
            operation,
            statement: approval.statement_digest(),
            target: p1doc.checkpoint,
            head,
            phase,
            reason,
            actual,
            kind: kind.into(),
        })
    }
    fn run(&self, mode: &str) -> Result<String> {
        let executable = PathBuf::from(
            std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("select exact foreign client")?,
        );
        if !executable.is_absolute() || !executable.is_file() {
            return Err("foreign client path".into());
        }
        let output = Command::new(executable)
            .arg(format!("enrollment-independent-policy-{mode}"))
            .arg(&self.path)
            .output()?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(format!(
                "foreign {} {mode}: {}; {}",
                self.kind,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }
    fn assets(&self) -> Result<AssetSnapshot> {
        use sha3::{Digest, Sha3_256};
        assert!(!self.path.join("signer.key").exists());
        for dir in [&self.path, &self.path.join("independent-sdk")] {
            for name in ["sdk.redb", "sdk-policy", "tls-cert", "tls-key"] {
                assert!(
                    !dir.join(name).exists(),
                    "historical fixture acquired operational inputs"
                );
            }
        }
        let mut j = p::DeviceJournal::open(
            &self.path.join("journal.redb"),
            p::JournalKey::open(&self.path.join("wrap.key"))?,
            &self.original,
            self.journal,
        )?;
        assert_eq!(j.identity()?, self.journal);
        assert_eq!(j.roster_checkpoint(self.original.account_id())?, self.head);
        j.close();
        Ok(AssetSnapshot {
            wrapping_hash: Sha3_256::digest(fs::read(self.path.join("wrap.key"))?).into(),
            signer_hash: Sha3_256::digest(fs::read(self.path.join("signer-held.key"))?).into(),
            journal_rows: journal_rows(&self.path)?,
        })
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn expected(
    phase: u32,
    reason: u32,
    operation: p::PolicyRenewalId,
    statement: [u8; 32],
    target: p::PolicyCheckpoint,
    head: Option<p::RosterCheckpoint>,
    at: u64,
) -> String {
    let (version, digest) = head.map_or((0, [0; 32]), |h| (h.version(), h.digest()));
    format!(
        "{phase}\n{reason}\n{}\n{}\n{}\n{}\n{version}\n{}\n{at}\n",
        hex(operation.as_bytes()),
        hex(&statement),
        target.version(),
        hex(&target.digest()),
        hex(&digest)
    )
}
#[test]
fn foreign_policy_resolution_preserves_exact_outcomes_and_original_observation() -> Result<()> {
    for kind in [
        "expired-policy",
        "expired-credential",
        "expired-roster",
        "advanced-roster",
        "revoked",
        "generation",
        "committed-expired",
        "committed-advanced",
        "committed-revoked",
        "committed-generation",
    ] {
        let f = Fixture::new(kind)?;
        let assets = f.assets()?;
        let earliest = now()?;
        let output = f.run("resolve")?;
        let at = output
            .lines()
            .nth(8)
            .ok_or("observation time")?
            .parse::<u64>()?;
        if f.phase == 3 {
            assert!(
                at >= earliest && at <= now()?,
                "first observation outside invocation"
            );
        } else {
            assert_eq!(at, 0);
        }
        let expected = expected(
            f.phase,
            f.reason,
            f.operation,
            f.statement,
            f.target,
            if f.phase == 3 { Some(f.head) } else { None },
            at,
        );
        assert_eq!(
            output, expected,
            "{kind} resolved another target or outcome"
        );
        assert_eq!(f.run("status")?, expected);
        if f.phase == 3 {
            let waited = Instant::now();
            while now()? <= at {
                if waited.elapsed() >= Duration::from_secs(3) {
                    return Err("host clock did not pass original observation".into());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        assert_eq!(
            f.run("resolve")?,
            expected,
            "retry changed original observation"
        );
        let status = p::DeviceEnrollment::open(f.paths.clone(), f.intent.clone())?
            .policy_renewal_status()?;
        let native = if f.phase == 2 {
            p::PolicyRenewalStatus::Committed {
                operation: f.operation,
                statement: f.statement,
                target: f.target,
            }
        } else {
            p::PolicyRenewalStatus::AbandonedUncommitted {
                operation: f.operation,
                statement: f.statement,
                target: f.target,
                reason: if f.reason == 1 {
                    p::PolicyRenewalAbandonment::Expired
                } else {
                    p::PolicyRenewalAbandonment::RosterAdvanced
                },
                observed_roster: f.head,
                observed_at: at,
            }
        };
        assert_eq!(status, native);
        assert!(
            f.assets()? == assets,
            "resolution changed original keys or already-acknowledged journal"
        );
    }
    eprintln!("FOREIGN_POLICY_OUTCOMES cases=10 exact_original=true real_signed_history=true prior_commit_wins=true honest_abandonment=true exact_retry_time=true later_wall_clock=true no_runtime_tls_signer=true original_assets=true");
    Ok(())
}
#[test]
fn foreign_policy_resolution_refusals_never_invent_no_commit_or_replace_pending() -> Result<()> {
    for (kind, mode, code) in [
        ("live", "resolve-pending", 215),
        ("wrong-operation", "resolve-conflict", 211),
        ("wrong-statement", "resolve-conflict", 211),
        ("wrong-target", "resolve-scope", 103),
        ("expired-policy", "resolve-cancelled", 302),
        ("higher-policy", "resolve-conflict", 211),
    ] {
        let f = Fixture::new(kind)?;
        let before = row(&f.path)?;
        let assets = f.assets()?;
        assert_eq!(
            f.run(mode)?,
            if code == 215 {
                "pending-unresolved:215\n".into()
            } else {
                format!("policy-resolve-refused:{code}\n")
            }
        );
        assert!(
            row(&f.path)? == before,
            "refused resolution changed original Pending"
        );
        assert_eq!(
            f.run("status")?,
            expected(1, 0, f.operation, f.statement, f.target, None, 0)
        );
        assert!(
            f.assets()? == assets,
            "refusal changed original keys or journal"
        );
        if let Some(actual) = &f.actual {
            // Fixture-only control: restore the authentic actual P2 configuration,
            // not a proposed SDK rollback repair. Actual P2 history must still read.
            replace_row(&f.path, &actual.config)?;
            fs::write(
                f.path.join("independent-operation"),
                actual.operation.as_bytes(),
            )?;
            fs::write(f.path.join("independent-statement"), actual.statement)?;
            actual.document.replace(&f.path.join("independent-sdk"))?;
            assert_eq!(
                f.run("resolve")?,
                expected(
                    2,
                    0,
                    actual.operation,
                    actual.statement,
                    actual.document.checkpoint,
                    None,
                    0
                )
            );
            assert!(
                f.assets()? == assets,
                "actual policy history changed original journal"
            );
        }
    }
    eprintln!("FOREIGN_POLICY_REFUSALS cases=6 live_target=true exact_original_inputs=true cancellation=true later_actual_policy_not_no_commit=true original_pending=true actual_p2_control=true");
    Ok(())
}
