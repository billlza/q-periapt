// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent control-plane setup; the child executable owns every root operation.
use super::*;
use q_periapt_continuity_c_consumer::first_install::{
    FirstInstallConfiguration, ProtocolConfiguration, SdkConfiguration, TlsConfiguration,
};

pub(super) struct Account {
    pub(super) path: PathBuf,
    pub(super) paths: p::EnrollmentPaths,
    pub(super) intent: p::EnrollmentIntent,
    pub(super) root: p::RootSigningKey,
    pub(super) credential: p::VerifiedDevice,
    pub(super) certificate: Vec<u8>,
    pub(super) roster: Vec<u8>,
    pub(super) genesis: p::AnchorGenesis,
}
pub(super) enum ClientLanguage {
    C,
    Swift,
    Kotlin,
}
impl ClientLanguage {
    pub(super) fn selected() -> Result<Self> {
        match std::env::var("QPC_ROOT_CLIENT_LANGUAGE").as_deref() {
            Ok("C") | Err(std::env::VarError::NotPresent) => Ok(Self::C),
            Ok("Swift") => Ok(Self::Swift),
            Ok("Kotlin") => Ok(Self::Kotlin),
            _ => Err("unknown installed root client language".into()),
        }
    }
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::C => "C",
            Self::Swift => "Swift",
            Self::Kotlin => "Kotlin",
        }
    }
}
pub(super) enum Recovery {
    Original,
    Transition(Box<p::ManagedAccountRootTransition>),
    Adoption(Box<p::ManagedAccountRootAdoption>),
}
pub(super) struct Case {
    language: ClientLanguage,
    pub(super) recovery: Recovery,
    pub(super) original_target: [u8; 32],
    pub(super) sdk: q_periapt_host_store::PolicyStore,
    pub(super) policy: std::sync::Arc<p::VerifiedSessionPolicy>,
    pub(super) pin: p::AnchorPin,
    pub(super) old: Account,
    pub(super) target: Account,
    pub(super) registry_path: PathBuf,
    pub(super) identity: p::AccountAuthorityIdentity,
    pub(super) checkpoint: p::AccountAuthorityCheckpoint,
    pub(super) plan: p::AnchorAccountReplacementPlan,
    pub(super) public: PathBuf,
    // Private directories outlive every SDK/store owner that can hold them.
    pub(super) witness: witness::Witness,
    pub(super) reference: fixture::Setup,
}
impl Case {
    pub(super) fn new(path: &Path, transition: bool, language: ClientLanguage) -> Result<Self> {
        let witness = witness::Witness::start()?;
        let reference = fixture::setup_with_witness(Some(&witness.configured))?;
        let sdk = fixture::sdk(&reference.initiator)?;
        let policy = fixture::protocol_policy(&reference.initiator, &sdk)?;
        let pin = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?
            .pin()?;
        let configuration = configuration(&reference.initiator)?;
        let old = account(&path.join("original"), &configuration, &policy, &pin)?;
        let original_target = account(&path.join("target"), &configuration, &policy, &pin)?;
        let registry_path = path.join("registry");
        fixture::create_private_directory(&registry_path)?;
        let identity = p::AccountAuthorityIdentity::generate()?;
        let mut registry = p::AccountAuthorityStore::provision(
            &registry_path.join("authority.redb"),
            p::JournalKey::provision(&registry_path.join("authority.key"))?,
            identity,
            policy.family(),
            pin.clone(),
        )?;
        let checkpoint = registry.associate(
            p::ApplicationAccountId::from_trusted_state([151; 32])?,
            &old.credential,
        )?;
        registry.close();
        let plan = {
            let mut store = witness.configured.store.lock().map_err(|_| "witness")?;
            store.enroll(&old.genesis, &old.credential, &policy, fixture::now()?)?;
            let request = p::AnchorAccountFreezeRequest::from_trusted_state(
                p::AnchorAccountFreezeId::from_trusted_state([152; 32])?,
                old.root.public_key()?,
                &pin,
            )?;
            store.account_replacement_plan(
                p::AnchorAccountReplacementId::from_trusted_state([153; 32])?,
                request,
                &original_target.genesis,
                &original_target.credential,
                &policy,
                fixture::now()?,
            )?
        };
        let original_target_id = original_target.credential.account_id();
        let target = if transition {
            account(&path.join("next-target"), &configuration, &policy, &pin)?
        } else {
            original_target
        };
        let public = path.join("public");
        fixture::create_private_directory(&public)?;
        for (name, wire) in [
            ("registry-id", identity.as_bytes().to_vec()),
            ("family", policy.family().to_vec()),
            ("witness-id", pin.identity().as_bytes().to_vec()),
            ("witness-public", pin.public_key().encode()),
            ("application", checkpoint.application().as_bytes().to_vec()),
            ("account", checkpoint.account().to_vec()),
            ("revision", checkpoint.revision().to_be_bytes().to_vec()),
            ("approved-plan", plan.to_bytes()?),
            ("target-account", target.credential.account_id().to_vec()),
            ("original-target-account", original_target_id.to_vec()),
            (
                "original-roster-version",
                old.credential
                    .roster()
                    .checkpoint()
                    .version()
                    .to_be_bytes()
                    .to_vec(),
            ),
            (
                "original-roster-digest",
                old.credential.roster().checkpoint().digest().to_vec(),
            ),
            (
                "target-roster-version",
                target
                    .credential
                    .roster()
                    .checkpoint()
                    .version()
                    .to_be_bytes()
                    .to_vec(),
            ),
            (
                "target-roster-digest",
                target.credential.roster().checkpoint().digest().to_vec(),
            ),
        ] {
            fixture::store(&public, name, &wire)?;
        }
        fixture::store(&public, "client-language", language.name().as_bytes())?;
        Ok(Self {
            language,
            recovery: Recovery::Original,
            original_target: original_target_id,
            witness,
            reference,
            sdk,
            policy,
            pin,
            old,
            target,
            registry_path,
            identity,
            checkpoint,
            plan,
            public,
        })
    }
    pub(super) fn registry(&self) -> Result<p::AccountAuthorityStore> {
        Ok(p::AccountAuthorityStore::open(
            &self.registry_path.join("authority.redb"),
            p::JournalKey::open(&self.registry_path.join("authority.key"))?,
            self.identity,
            self.policy.family(),
            self.pin.clone(),
        )?)
    }
    pub(super) fn records_pthread_stacks(&self) -> bool {
        !matches!(self.language, ClientLanguage::Kotlin)
    }
    pub(super) fn cut_output(&self, mode: &str) -> String {
        match self.language {
            ClientLanguage::Kotlin => format!("root-cut-ready:{mode}\n"),
            ClientLanguage::C | ClientLanguage::Swift => String::new(),
        }
    }
    pub(super) fn cut_ready(&self, mode: &str, stdout: &Path) -> Result<bool> {
        let expected = self.cut_output(mode);
        if expected.is_empty() {
            return Ok(true);
        }
        // The JVM host publishes records with a temporary second hard link.
        // Its explicit flush follows removal of that link and directory sync;
        // keep the private-file reader's single-link requirement unchanged.
        let bytes = fs::read(stdout)?;
        Ok(bytes.ends_with(expected.as_bytes()))
    }
    pub(super) fn command_mode(&self, mode: &str) -> String {
        let selected = match self.recovery {
            Recovery::Original => mode.to_owned(),
            Recovery::Transition(_) => format!("transition:{mode}"),
            Recovery::Adoption(_) => format!("adoption:{mode}"),
        };
        match self.language {
            ClientLanguage::C => selected,
            ClientLanguage::Swift | ClientLanguage::Kotlin => format!("root:{selected}"),
        }
    }
    pub(super) fn resume(&self) -> Result<p::ManagedAccountRootReplacement> {
        let registry = self.registry()?;
        Ok(match &self.recovery {
            Recovery::Original => p::ManagedAccountRootReplacement::resume_original(
                registry,
                self.checkpoint,
                self.plan.clone(),
                self.old.paths.clone(),
                self.old.intent.clone(),
                self.pin.clone(),
            )?,
            Recovery::Transition(approved) => p::ManagedAccountRootReplacement::resume_transition(
                registry,
                self.checkpoint,
                self.old.paths.clone(),
                self.old.intent.clone(),
                self.pin.clone(),
                approved,
            )?,
            Recovery::Adoption(approved) => p::ManagedAccountRootReplacement::resume_adoption(
                registry,
                self.checkpoint,
                self.old.paths.clone(),
                self.old.intent.clone(),
                self.pin.clone(),
                approved,
            )?,
        })
    }
}
fn configuration(path: &Path) -> Result<FirstInstallConfiguration> {
    Ok(FirstInstallConfiguration::new(
        SdkConfiguration::new(
            &fixture::read(path, "sdk-policy", 65536)?,
            &fixture::read(path, "sdk-signature", 8192)?,
            &fixture::read(path, "sdk-root", 8192)?,
        )?,
        ProtocolConfiguration::new(
            fixture::array(path, "family")?,
            &fixture::read(path, "policy-root", 8192)?,
            p::PolicyCheckpoint::from_trusted_state(
                u64::from_be_bytes(fixture::array(path, "policy-version")?),
                fixture::array(path, "policy-digest")?,
            )?,
            &fixture::read(path, "protocol-policy", 8192)?,
        )?,
        TlsConfiguration::new(
            &fixture::read(path, "tls-cert", 8192)?,
            &fixture::read(path, "tls-key", 8192)?,
        )?,
    ))
}
fn account(
    path: &Path,
    configuration: &FirstInstallConfiguration,
    policy: &p::VerifiedSessionPolicy,
    pin: &p::AnchorPin,
) -> Result<Account> {
    configuration.provision(path)?.close();
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
    let root = p::RootSigningKey::generate()?;
    let now = fixture::now()?;
    let validity = p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
    let intent = p::EnrollmentIntent::new(
        root.public_key()?,
        p::DeviceDescription::new([154; 16], 1, policy.family(), validity)?,
    );
    let mut owner = p::DeviceEnrollment::provision(paths.clone(), intent.clone())?;
    let request = p::VerifiedEnrollmentRequest::verify(&owner.request(now)?, &intent, now)?;
    let certificate = root.issue_enrollment(&request, now)?;
    let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
    let account_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        policy.family(),
    )?;
    let credential = account_pin.verify_device(&certificate, roster.as_bytes(), now)?;
    owner.accept(&certificate, roster.as_bytes(), &account_pin, policy, now)?;
    let genesis = match owner.prepare(policy, now)? {
        p::InstallationPreparation::RequiresEnrollment(g) => g,
        _ => return Err("required witness absent".into()),
    };
    owner.close();
    let mut wire = Vec::new();
    wire.extend_from_slice(&[154; 16]);
    wire.extend_from_slice(&1u64.to_be_bytes());
    wire.extend_from_slice(&policy.family());
    wire.extend_from_slice(&validity.from().to_be_bytes());
    wire.extend_from_slice(&validity.until().to_be_bytes());
    fixture::store(path, "enrollment-root", &root.public_key()?.encode())?;
    fixture::store(path, "enrollment-intent", &wire)?;
    fixture::store(path, "witness-id", pin.identity().as_bytes())?;
    fixture::store(path, "witness-public", &pin.public_key().encode())?;
    Ok(Account {
        path: path.to_owned(),
        paths,
        intent,
        root,
        credential,
        certificate,
        roster: roster.as_bytes().to_vec(),
        genesis,
    })
}
