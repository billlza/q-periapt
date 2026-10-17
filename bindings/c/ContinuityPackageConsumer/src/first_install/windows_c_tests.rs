//! Execute the installed C client in another process; never call its ABI through Rust.
use super::windows_tests::fixture::{sdk_policy, Case};
use super::*;
use q_periapt_sig::Signer;
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().expect("C child status").is_none() {
            self.0.kill().expect("stop owned C child");
            self.0.wait().expect("reap owned C child");
        }
    }
}
fn run(
    c: &Case,
    source: &Path,
    mode: &str,
    trust: &str,
    label: &str,
    expected: &str,
    success: bool,
) -> TestResult<()> {
    let client = PathBuf::from(
        std::env::var_os("QPC_FIRST_USE_CLIENT").ok_or("installed C client is required")?,
    );
    let stdout = c.root.join(format!("{label}.stdout"));
    let stderr = c.root.join(format!("{label}.stderr"));
    let mut child = OwnedChild(
        Command::new(client)
            .args([mode, trust])
            .arg(source)
            .arg(&c.target)
            .arg(c.root.join(format!("{label}.output")))
            .stdout(Stdio::from(fs::File::create_new(&stdout)?))
            .stderr(Stdio::from(fs::File::create_new(&stderr)?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(format!("C client deadline: {label}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = fs::read_to_string(stdout)?;
    let err = fs::read_to_string(stderr)?;
    assert_eq!(
        status.code(),
        Some(if success { 0 } else { 1 }),
        "{label}: {err}"
    );
    if success {
        assert!(err.is_empty(), "{label}: {err}");
        assert_eq!(out.trim(), expected);
    } else {
        assert!(out.is_empty(), "failure printed success: {label}");
        assert!(err.starts_with("configuration status 500: "), "{err}");
        assert!(err.contains(expected), "{label}: {err}");
    }
    eprintln!(
        "WINDOWS_INSTALLED_C_FIRST_USE case={label} trust={trust} exit={} expected=true",
        status.code().ok_or("exit status")?
    );
    Ok(())
}
#[test]
fn installed_c_first_use_reopens_original_inputs_and_preserves_refused_state() -> TestResult<()> {
    for recoverable in [false, true] {
        let mut c = Case::new()?;
        let source = c.root.join("c-inputs");
        let mut recovery = None;
        if recoverable {
            let (key, public) = q_periapt_backends::MlDsa65::generate([61; 32]);
            let key = Zeroizing::new(key);
            let trust = PolicyRecoveryTrust::new([62; 32], &c.input.sdk.root, &public)?;
            let mut proof = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
            q_periapt_backends::MlDsa65
                .sign(
                    key.as_ref(),
                    &trust.enrollment_message(),
                    &[63; 32],
                    &mut proof,
                )
                .map_err(|error| io::Error::other(format!("recovery fixture signing: {error}")))?;
            c.input.sdk = SdkConfiguration::new_recoverable(
                &c.input.sdk.policy,
                &c.input.sdk.signature,
                &trust,
                &proof,
            )?;
            recovery = Some((public, proof));
        }
        publish_private_directory(&source, |path| {
            for (name, bytes) in c.input.fields() {
                publish_private_bytes(&path.join(name), bytes)?;
            }
            if let Some((root, proof)) = &recovery {
                publish_private_bytes(&path.join("recovery-root"), root)?;
                publish_private_bytes(&path.join("recovery-scope"), &[62; 32])?;
                publish_private_bytes(&path.join("recovery-enrollment"), proof)?;
            }
            Ok::<_, PrivatePublicationError>(())
        })?;
        let trust = if recoverable { "recoverable" } else { "fixed" };
        run(
            &c,
            &source,
            "policy-target-create",
            trust,
            "create",
            "QPC_CONFIGURATION_POLICY_TARGET",
            true,
        )?;
        c.assert_inputs()?;
        let original_key = Zeroizing::new(fs::read(c.target.join("wrap.key"))?);
        run(
            &c,
            &source,
            "configuration-reconcile",
            trust,
            "reconcile",
            "QPC_CONFIGURATION_RECONCILED",
            true,
        )?;
        run(
            &c,
            &source,
            "configuration-open",
            trust,
            "open",
            "QPC_CONFIGURATION_OPENED",
            true,
        )?;
        run(
            &c,
            &source,
            "policy-target-create",
            trust,
            "duplicate",
            "configuration publication failed",
            false,
        )?;
        let mut held = c.input.reconcile(&c.target)?;
        run(
            &c,
            &source,
            "configuration-reconcile",
            trust,
            "busy",
            "SDK policy store admission failed",
            false,
        )?;
        held.close();
        fs::rename(c.target.join("wrap.key"), c.root.join("retained.key"))?;
        run(
            &c,
            &source,
            "configuration-reconcile",
            trust,
            "missing",
            "installation key admission failed",
            false,
        )?;
        assert!(!c.target.join("wrap.key").exists());
        assert!(
            fs::read(c.root.join("retained.key"))? == *original_key,
            "retained key changed"
        );
        fs::rename(c.root.join("retained.key"), c.target.join("wrap.key"))?;
        let mut store = c.input.reconcile(&c.target)?;
        let previous = store.runtime()?.trusted_state();
        let (policy, signature, _) = sdk_policy(2)?;
        store.replace_policy(previous, &policy, &signature)?;
        store.close();
        run(
            &c,
            &source,
            "configuration-reconcile",
            trust,
            "advanced",
            "original first-install configuration differs",
            false,
        )?;
        let mut current = c.input.sdk.open(&c.target.join("sdk.redb"))?;
        assert_eq!(current.runtime()?.trusted_state().version(), 2);
        current.close();
        assert!(
            fs::read(c.target.join("wrap.key"))? == *original_key,
            "original key changed"
        );
        c.assert_inputs()?;
    }
    Ok(())
}
