// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real foreign processes recover original signed native history using public APIs.
use q_periapt_continuity_identity_candidate as p;
use q_periapt_sig::Signer;
use redb::ReadableDatabase;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn store(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn runtime() -> Arc<q_periapt_sdk::Runtime> {
    let policy=b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let (mut secret, public) = q_periapt_backends::MlDsa65::generate([80; 32]);
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    let signed = q_periapt_backends::MlDsa65.sign(
        &secret,
        &q_periapt_policy::policy_signature_message(policy),
        &[81; 32],
        &mut signature,
    );
    secret.zeroize();
    signed.expect("actual SDK policy signature");
    Arc::new(
        q_periapt_sdk::Runtime::from_signed_policy(
            policy,
            &signature,
            &public,
            None,
            q_periapt_sdk::Limits::default(),
        )
        .expect("real runtime"),
    )
}
fn cp_bytes(cp: p::RosterCheckpoint) -> Vec<u8> {
    let mut out = cp.version().to_be_bytes().to_vec();
    out.extend_from_slice(&cp.digest());
    out
}
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    paths: p::EnrollmentPaths,
    intent: p::EnrollmentIntent,
    original: p::VerifiedDevice,
    journal: p::JournalIdentity,
    previous: p::RosterCheckpoint,
    target: p::RosterCheckpoint,
    observed: p::RosterCheckpoint,
    outcome: u32,
    phase: u32,
}
impl Fixture {
    fn new(kind: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().canonicalize()?;
        let at = now()?;
        let past = at - 200;
        let runtime = runtime();
        let policy_root = p::PolicySigningKey::generate()?;
        let signed = policy_root.issue_session_policy(
            &runtime,
            p::SessionPolicyParameters::new(
                1,
                p::Validity::new(at - 300, at - 50)?,
                p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
                p::AnchorRequirement::local_only(),
                p::ApplicationSendBudget::new(1024)?,
            )?,
        )?;
        let policy = p::PolicyPin::new(
            policy_root.policy_family()?,
            policy_root.public_key()?,
            signed.checkpoint(),
        )?
        .verify(signed.as_bytes(), Arc::clone(&runtime), past)?;
        for (name, bytes) in [
            ("family", policy.family().to_vec()),
            ("policy-root", policy_root.public_key()?.encode()),
            (
                "policy-version",
                signed.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("policy-digest", signed.checkpoint().digest().to_vec()),
            ("protocol-policy", signed.as_bytes().to_vec()),
        ] {
            store(&path, name, &bytes)?;
        }
        let root = p::RootSigningKey::generate()?;
        let validity = p::Validity::new(at - 300, at + 600)?;
        let description = p::DeviceDescription::new([7; 16], 1, policy.family(), validity)?;
        let intent = p::EnrollmentIntent::new(root.public_key()?, description);
        let installation = p::InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )?;
        let paths = p::EnrollmentPaths::new(
            &path.join("wrap.key"),
            &path.join("signer.key"),
            &path.join("enrollment.redb"),
            installation.clone(),
        )?;
        drop(p::JournalKey::provision(&path.join("wrap.key"))?);
        let mut enrollment = p::DeviceEnrollment::provision(paths.clone(), intent.clone())?;
        let wire = enrollment.request(past)?;
        let request = p::VerifiedEnrollmentRequest::verify(&wire, &intent, past)?;
        let certificate = root.issue_enrollment(&request, past)?;
        let entry = root.roster_entry(&certificate)?;
        let initial = root.issue_roster(1, p::Validity::new(at - 300, at + 600)?, &[entry])?;
        let pin =
            |cp| p::AccountPin::new(root.account_id()?, root.public_key()?, cp, policy.family());
        let initial_pin = pin(initial.checkpoint())?;
        let journal = enrollment.accept(
            &certificate,
            initial.as_bytes(),
            &initial_pin,
            &policy,
            past,
        )?;
        enrollment.prepare(&policy, past)?;
        let mut owner = enrollment.activate(&policy, past, None)?;
        let original = owner.parts()?.2.clone();
        owner.close();
        let target = root.issue_roster(
            2,
            p::Validity::new(at - 250, if kind == "live" { at + 600 } else { at - 100 })?,
            &[root.roster_entry(&certificate)?],
        )?;
        p::DeviceEnrollment::open(paths.clone(), intent.clone())?.refresh_roster(
            initial.checkpoint(),
            target.as_bytes(),
            &pin(target.checkpoint())?,
            &policy,
            past,
        )?;
        let mut j = p::DeviceJournal::open(
            &path.join("journal.redb"),
            p::JournalKey::open(&path.join("wrap.key"))?,
            &original,
            journal,
        )?;
        if matches!(kind, "committed" | "committed-then-higher") {
            j.install_roster(
                &pin(target.checkpoint())?.verify_roster(target.as_bytes(), past + 5)?,
                past + 5,
            )?;
        }
        let (outcome, phase) = match kind {
            "expired" | "live" => (2, 5),
            "committed" => (1, 5),
            "same-version" | "skipped" | "committed-then-higher" => {
                let next = root.issue_roster(
                    if kind == "same-version" { 2 } else { 3 },
                    p::Validity::new(at - 240, at + 600)?,
                    &[root.roster_entry(&certificate)?],
                )?;
                j.install_roster(
                    &pin(next.checkpoint())?.verify_roster(next.as_bytes(), past + 10)?,
                    past + 10,
                )?;
                (if kind == "same-version" { 3 } else { 4 }, 5)
            }
            "revoked" | "generation" => {
                let replacement = root.issue_device(
                    p::DeviceDescription::new([7; 16], 2, policy.family(), validity)?,
                    request.public_key().clone(),
                )?;
                let entries = if kind == "generation" {
                    vec![root.roster_entry(&replacement)?]
                } else {
                    Vec::new()
                };
                let next = root.issue_roster(3, p::Validity::new(at - 240, at + 600)?, &entries)?;
                j.install_roster(
                    &pin(next.checkpoint())?.verify_roster(next.as_bytes(), past + 10)?,
                    past + 10,
                )?;
                (4, 7)
            }
            _ => return Err("unknown fixture kind".into()),
        };
        let observed = j.roster_checkpoint(original.account_id())?;
        j.close();
        store(&path, "trusted-root", &root.public_key()?.encode())?;
        store(&path, "trusted-device", &[7; 16])?;
        store(&path, "trusted-generation", &1u64.to_be_bytes())?;
        let mut times = validity.from().to_be_bytes().to_vec();
        times.extend_from_slice(&validity.until().to_be_bytes());
        store(&path, "trusted-validity", &times)?;
        store(&path, "roster-previous", &cp_bytes(initial.checkpoint()))?;
        store(&path, "roster-target", &cp_bytes(target.checkpoint()))?;
        fs::rename(path.join("signer.key"), path.join("signer-held.key"))?;
        policy.close();
        runtime.close();
        Ok(Self {
            _directory: directory,
            path,
            paths,
            intent,
            original,
            journal,
            previous: initial.checkpoint(),
            target: target.checkpoint(),
            observed,
            outcome,
            phase,
        })
    }
    fn row(&self) -> Result<Vec<u8>> {
        let db = q_periapt_host_store::filesystem::open_private_database(
            &self.path.join("enrollment.redb"),
        )?;
        let tx = db.begin_read()?;
        let table = tx.open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "continuity_enrollment_v1",
        ))?;
        let row = table.get("enrollment")?.ok_or("missing original record")?;
        Ok(row.value().to_vec())
    }
    fn check_assets(&self, wrapping: &[u8], signer: &[u8]) -> Result<()> {
        assert!(
            fs::read(self.path.join("wrap.key"))? == wrapping,
            "wrapping key changed"
        );
        assert!(
            fs::read(self.path.join("signer-held.key"))? == signer,
            "private signer changed"
        );
        assert!(
            !self.path.join("signer.key").exists(),
            "signer was recreated"
        );
        assert!(
            !self.path.join("sdk-policy").exists() && !self.path.join("tls-ca").exists(),
            "metadata recovery created runtime/TLS inputs"
        );
        let mut journal = p::DeviceJournal::open(
            &self.path.join("journal.redb"),
            p::JournalKey::open(&self.path.join("wrap.key"))?,
            &self.original,
            self.journal,
        )?;
        assert_eq!(journal.identity()?, self.journal);
        assert_eq!(
            journal.roster_checkpoint(self.original.account_id())?,
            self.observed
        );
        journal.close();
        Ok(())
    }
    fn run(&self, mode: &str) -> Result<String> {
        let executable = PathBuf::from(
            std::env::var_os("QPERIAPT_ROSTER_RESOLUTION_CLIENT")
                .ok_or("select exact foreign client")?,
        );
        if !executable.is_absolute() || !executable.is_file() {
            return Err("foreign client path".into());
        }
        let output = Command::new(executable)
            .arg(&self.path)
            .arg(mode)
            .output()?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(format!(
                "foreign {mode}: {}; {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn cross_language_outcomes_preserve_unknown_history_and_exact_original_retry() -> Result<()> {
    for kind in [
        "expired",
        "committed",
        "same-version",
        "skipped",
        "committed-then-higher",
        "revoked",
        "generation",
    ] {
        let f = Fixture::new(kind)?;
        let wrapping = fs::read(f.path.join("wrap.key"))?;
        let signer = fs::read(f.path.join("signer-held.key"))?;
        let earliest = now()?;
        let output = f.run("resolve")?;
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 10);
        let expected = [
            f.outcome.to_string(),
            hex(f.journal.as_bytes()),
            f.previous.version().to_string(),
            hex(&f.previous.digest()),
            f.target.version().to_string(),
            hex(&f.target.digest()),
            f.observed.version().to_string(),
            hex(&f.observed.digest()),
        ];
        assert_eq!(
            lines.get(..8),
            Some(
                expected
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice()
            )
        );
        let observed_at: u64 = lines.get(8).ok_or("observation time")?.parse()?;
        assert!(observed_at >= earliest && observed_at <= now()?);
        assert_eq!(lines.get(9), Some(&f.phase.to_string().as_str()));
        assert_eq!(
            f.run("resolve")?,
            output,
            "repeat must preserve original observation"
        );
        let mut enrollment = p::DeviceEnrollment::open(f.paths.clone(), f.intent.clone())?;
        let status = enrollment.status()?;
        if f.phase == 7 {
            assert!(
                matches!(status,p::EnrollmentStatus::RosterResolved(r) if r.outcome==p::RosterRefreshOutcome::SupersededUnknown&&r.observed==f.observed)
            );
        } else {
            assert_eq!(status, p::EnrollmentStatus::Active(f.journal));
        }
        enrollment.close();
        f.check_assets(&wrapping, &signer)?;
    }
    eprintln!("FOREIGN_ROSTER_OUTCOMES cases=7 exact_retry=true no_runtime_tls_signer=true honest_unknown=true original_journal=true");
    Ok(())
}
#[test]
fn cross_language_failures_do_not_publish_or_replace_original_pending() -> Result<()> {
    for (kind, mode, code) in [
        ("expired", "wrong-target", 211),
        ("live", "live", 215),
        ("expired", "cancel", 302),
    ] {
        let f = Fixture::new(kind)?;
        let before = f.row()?;
        let wrapping = fs::read(f.path.join("wrap.key"))?;
        let signer = fs::read(f.path.join("signer-held.key"))?;
        assert_eq!(f.run(mode)?, format!("rejected:{code}\n"));
        assert!(
            f.row()? == before,
            "failed/cancelled resolver replaced original intent"
        );
        f.check_assets(&wrapping, &signer)?;
    }
    eprintln!("FOREIGN_ROSTER_FAILURES wrong_original=true live_target=true cancellation=true original_pending=true");
    Ok(())
}
#[test]
fn c_pointer_argument_failure_keeps_output_and_original_owner() -> Result<()> {
    let f = Fixture::new("expired")?;
    let before = f.row()?;
    assert_eq!(f.run("arguments")?, "rejected:1\n");
    assert!(f.row()? == before, "argument error changed original intent");
    Ok(())
}
