//! Real signed original inputs retained independently of the destination directory.
use super::*;
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_sig::Signer;

pub(in crate::first_install) fn sdk_policy(version: u32) -> TestResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (key, public) = MlDsa65::generate([91; 32]);
    let policy = format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"ML-KEM-768\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n").into_bytes();
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &key,
            &q_periapt_policy::policy_signature_message(&policy),
            &[19; 32],
            &mut signature,
        )
        .map_err(|error| io::Error::other(format!("fixture signing: {error}")))?;
    Ok((policy, signature, public.to_vec()))
}
fn input() -> TestResult<FirstInstallConfiguration> {
    let (policy, signature, root) = sdk_policy(1)?;
    let runtime = Runtime::from_signed_policy(&policy, &signature, &root, None, Limits::default())?;
    let authority = p::PolicySigningKey::generate()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let issued = authority.issue_session_policy(
        &runtime,
        p::SessionPolicyParameters::new(
            1,
            p::Validity::new(now.saturating_sub(1), now.checked_add(3600).ok_or("clock")?)?,
            p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
            p::AnchorRequirement::local_only(),
            p::ApplicationSendBudget::new(1024)?,
        )?,
    )?;
    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let result = FirstInstallConfiguration::new(
        SdkConfiguration::new(&policy, &signature, &root)?,
        ProtocolConfiguration::new(
            authority.policy_family()?,
            &authority.public_key()?.encode(),
            issued.checkpoint(),
            issued.as_bytes(),
        )?,
        TlsConfiguration::new(tls.cert.der().as_ref(), &tls.signing_key.serialize_der())?,
    );
    runtime.close();
    Ok(result)
}

pub(in crate::first_install) struct Case {
    pub(in crate::first_install) root: PathBuf,
    pub(in crate::first_install) target: PathBuf,
    pub(in crate::first_install) input: FirstInstallConfiguration,
}
impl Case {
    pub(in crate::first_install) fn new() -> TestResult<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = PathBuf::from(
            std::env::var_os("QPC_FIRST_USE_ROOT").ok_or("missing owned Windows test root")?,
        );
        OwnedPrivateDirectory::open(&parent)?;
        let root = parent.join(format!(
            "case-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        publish_private_directory(&root, |_| Ok::<_, PrivatePublicationError>(()))?;
        let input = input()?;
        publish_private_directory(&root.join("request"), |path| {
            for (name, bytes) in input.fields() {
                publish_private_bytes(&path.join(name), bytes)?;
            }
            Ok::<_, PrivatePublicationError>(())
        })?;
        Ok(Self {
            target: root.join("installation"),
            root,
            input,
        })
    }
    pub(in crate::first_install) fn assert_inputs(&self) -> TestResult<()> {
        for (name, expected) in self.input.fields() {
            assert!(
                fs::read(self.target.join(name))? == expected,
                "original input changed: {name}"
            );
        }
        Ok(())
    }
    pub(in crate::first_install) fn staged(&self) -> TestResult<Vec<PathBuf>> {
        Ok(fs::read_dir(&self.root)?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".private-tree-")
            })
            .map(|entry| entry.path())
            .collect())
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove only owned first-use fixture");
    }
}
pub(in crate::first_install) fn load(request: &Path) -> TestResult<FirstInstallConfiguration> {
    let read = |name| fs::read(request.join(name));
    Ok(FirstInstallConfiguration::new(
        SdkConfiguration::new(
            &read("sdk-policy")?,
            &read("sdk-signature")?,
            &read("sdk-root")?,
        )?,
        ProtocolConfiguration::new(
            read("family")?.try_into().map_err(|_| "family width")?,
            &read("policy-root")?,
            p::PolicyCheckpoint::from_trusted_state(
                u64::from_be_bytes(
                    read("policy-version")?
                        .try_into()
                        .map_err(|_| "version width")?,
                ),
                read("policy-digest")?
                    .try_into()
                    .map_err(|_| "digest width")?,
            )?,
            &read("protocol-policy")?,
        )?,
        TlsConfiguration::new(&read("tls-cert")?, &read("tls-key")?)?,
    ))
}
