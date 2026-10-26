// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original device enrollment before credential-dependent installation creation.
use crate::{
    codec::Decoder,
    crypto::{digest, envelope, open_envelope, Purpose},
    durable::{storage, transaction},
    installation::{admit, validate_paths},
    AccountPin, AnchorClient, AnchorPin, AnchorTransport, DeviceDescription, DeviceInstallation,
    DeviceService, DeviceSigningKey, DurableError, Error, InstallationPaths,
    InstallationPreparation, JournalIdentity, JournalKey, PublicKey, RootSigningKey,
    RosterCheckpoint, SigningKeyId, VerifiedDevice, VerifiedSessionPolicy, PUBLIC_KEY_BYTES,
};
use hmac::{Hmac, Mac};
#[cfg(all(test, unix))]
use q_periapt_host_store::filesystem::open_private_database;
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use sha2::Sha256;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_enrollment_v1");
const REQUEST_BODY: usize = 8 + 32 + 32 + 16 + 8 + 16 + 32 + PUBLIC_KEY_BYTES;
const MAX_IMAGE: usize = 24 * 1024;
const MAX_RENEWAL_IMAGE: usize = 128 * 1024;
const MAX_PREINSTALLATION_IMAGE: usize = 192 * 1024;
mod public_admission;
pub use public_admission::EnrollmentPublicAdmission;
mod preinstallation;
use preinstallation::Preparation;
pub use preinstallation::{
    EnrollmentExtensionApproval, EnrollmentExtensionInputs, EnrollmentExtensionStatus,
    EnrollmentPreparationStatus,
};
mod account_authority;
mod account_root;
pub use account_root::{AccountRootEnrollmentRecovery, AccountRootEnrollmentState};
mod managed_root;
pub use managed_root::{
    ManagedAccountRootAdoption, ManagedAccountRootReplacement, ManagedAccountRootTransition,
};
mod pending_recovery;
mod policy_renewal;
mod recovery;
mod renewal;
pub use recovery::EnrollmentRecovery;
mod retirement;
pub use retirement::{RetiredDeviceEnrollment, SigningFileErasureState};
mod roster_refresh;
mod roster_resolution;
mod witness_handoff;
pub(crate) use policy_renewal::{EnrollmentPolicyCompletion, PersistedPolicyTerminal};
use policy_renewal::{PolicyDeviceBinding, RetainedPolicyRenewal};
pub use policy_renewal::{
    PolicyRenewalAbandonment, PolicyRenewalRequest, PolicyRenewalStatus,
    WitnessedPolicyRenewalDisposition, WitnessedPolicyRenewalProgress,
};
use renewal::LocalRenewal;
pub(crate) use renewal::PersistedRenewalTerminal;
pub use renewal::{CredentialRenewalRequest, CredentialRenewalStatus};
pub(crate) use roster_refresh::PersistedRosterTerminal;
pub use roster_refresh::{WitnessedRosterRefreshDisposition, WitnessedRosterRefreshProgress};
pub use roster_resolution::{RosterRefreshOutcome, RosterRefreshResolution};

#[cfg(all(test, unix))]
mod tests;

/// Independently approved account root and exact requested device metadata.
/// Obtain these through the application's trusted enrollment channel. A request
/// proving possession of a device key does not grant account membership.
#[derive(Clone)]
pub struct EnrollmentIntent {
    root: PublicKey,
    description: DeviceDescription,
}
impl EnrollmentIntent {
    /// Bind the account root and exact device/generation/family/validity grant.
    pub fn new(root: PublicKey, description: DeviceDescription) -> Self {
        Self { root, description }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::identity::account_id(&self.root));
        out.extend_from_slice(&self.description.id);
        out.extend_from_slice(&self.description.generation.to_be_bytes());
        self.description.validity.encode(out);
        out.extend_from_slice(&self.description.family);
    }
    fn verify_device(&self, device: &VerifiedDevice) -> Result<(), Error> {
        if device.authority_key != self.root || device.description != self.description {
            return Err(Error::Scope);
        }
        Ok(())
    }
}

/// Dual-signature proof of possession for one exact independently approved intent.
/// Verification is not user authentication, account authorization or roster freshness.
pub struct VerifiedEnrollmentRequest {
    intent: EnrollmentIntent,
    identity: SigningKeyId,
    public: PublicKey,
}
impl VerifiedEnrollmentRequest {
    /// Authenticate bounded qperiapt-enrollment/1 bytes against independent inputs.
    pub fn verify(wire: &[u8], intent: &EnrollmentIntent, now: u64) -> Result<Self, Error> {
        intent.description.validity.check(now)?;
        let proof = authenticate_enrollment_proof(wire, intent)?;
        Ok(Self {
            intent: intent.clone(),
            identity: proof.identity,
            public: proof.public,
        })
    }
    /// Authenticate a fresh generation under an independently approved intent.
    /// The predecessor may be expired historical identity evidence; it grants no
    /// permission to replace itself. The host must separately authorize the
    /// account operation and compare its actual current roster at commit.
    pub fn verify_replacement(
        wire: &[u8],
        intent: &EnrollmentIntent,
        previous: &VerifiedDevice,
        now: u64,
    ) -> Result<Self, Error> {
        let request = Self::verify(wire, intent, now)?;
        if intent.root != previous.authority_key
            || intent.description.id != previous.description.id
            || intent.description.family != previous.description.family
            || intent.description.generation <= previous.description.generation
            || request.public.shares_component(&previous.key)
        {
            return Err(Error::Scope);
        }
        Ok(request)
    }
    /// Original precommitted signing-owner identity, suitable for scoped request deduplication.
    pub fn identity(&self) -> SigningKeyId {
        self.identity
    }
    /// Public key proved by both signatures; no private-key material is returned.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

// Signature and exact historical scope only. This private result cannot be
// passed to RootSigningKey::issue_enrollment as current authorization.
struct EnrollmentProof {
    identity: SigningKeyId,
    public: PublicKey,
}
fn authenticate_enrollment_proof(
    wire: &[u8],
    intent: &EnrollmentIntent,
) -> Result<EnrollmentProof, Error> {
    let (body, signature) = open_envelope(wire)?;
    if body.len() != REQUEST_BODY {
        return Err(Error::Encoding);
    }
    let mut d = Decoder::new(body);
    if d.array::<8>()? != *b"QPENRQ01" {
        return Err(Error::Encoding);
    }
    let identity = SigningKeyId::from_trusted_state(d.array()?)?;
    let mut expected = Vec::new();
    intent.encode(&mut expected);
    if d.take(expected.len())? != expected {
        return Err(Error::Scope);
    }
    let public = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
    d.finish()?;
    if public.shares_component(&intent.root) {
        return Err(Error::Scope);
    }
    public.verify(Purpose::EnrollmentRequest, body, signature)?;
    Ok(EnrollmentProof { identity, public })
}
impl RootSigningKey {
    /// Issue the exact approved credential after authenticating the enrollment
    /// request. The host must separately authorize the account/user operation and
    /// commit its current roster; this method never treats possession as membership.
    pub fn issue_enrollment(
        &self,
        request: &VerifiedEnrollmentRequest,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        request.intent.description.validity.check(now)?;
        if self.public_key()? != request.intent.root {
            return Err(Error::Scope);
        }
        self.issue_device(request.intent.description.clone(), request.public.clone())
    }
}

/// File-backed enrollment and its original downstream installation. Keep the
/// existing wrapping-key file and enrollment record outside journal backups.
#[derive(Clone)]
pub struct EnrollmentPaths {
    wrapping: PathBuf,
    signer: PathBuf,
    configuration: PathBuf,
    installation: InstallationPaths,
}
impl EnrollmentPaths {
    /// Bind six distinct canonical absolute paths. `wrapping` must already have
    /// been explicitly provisioned; neither opening nor any error creates a key.
    pub fn new(
        wrapping: &Path,
        signer: &Path,
        configuration: &Path,
        installation: InstallationPaths,
    ) -> Result<Self, DurableError> {
        let mut files = vec![wrapping, signer, configuration];
        files.extend(installation.files());
        validate_paths(&files)?;
        Ok(Self {
            wrapping: wrapping.into(),
            signer: signer.into(),
            configuration: configuration.into(),
            installation,
        })
    }
    fn binding(
        &self,
        key: &JournalKey,
        intent: &EnrollmentIntent,
    ) -> Result<[u8; 32], DurableError> {
        let mut body = Vec::new();
        for path in [&self.wrapping, &self.signer, &self.configuration] {
            let bytes = path.to_str().ok_or(DurableError::PrivateFile)?.as_bytes();
            body.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            body.extend_from_slice(bytes);
        }
        body.extend_from_slice(&self.installation.binding()?);
        body.extend_from_slice(&key.installation_binding());
        body.extend_from_slice(&intent.root.encode());
        intent.encode(&mut body);
        Ok(digest(b"Q-PERIAPT-CONTINUITY-ENROLLMENT-SCOPE/v1", &body))
    }
}

/// Durable enrollment progress. These observations grant no traffic permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentStatus {
    /// Original intent exists; no signed request has been released.
    Preparing,
    /// Exact signed request is committed and may have been sent.
    Requested,
    /// Credential, roster, policy and original future journal identity are committed.
    Accepted(JournalIdentity),
    /// Original activation was requested; retry activation, never child preparation.
    Activating(JournalIdentity),
    /// An original service may have operated; missing children cannot be recreated.
    Active(JournalIdentity),
    /// A current same-credential roster is retained, but its original journal
    /// must still reconcile the exact update before any service can be released.
    Refreshing {
        /// Original journal; never replace it to finish this update.
        journal: JournalIdentity,
        /// Original expected journal roster before this update.
        previous: RosterCheckpoint,
        /// Exact independently admitted update target.
        next: RosterCheckpoint,
    },
    /// The original refresh has a retained result, but the actual roster cannot
    /// supply a valid snapshot for this credential. No owner may be released.
    RosterResolved(RosterRefreshResolution),
}

#[derive(Clone)]
struct Admission {
    certificate: Vec<u8>,
    roster: Vec<u8>,
    checkpoint: RosterCheckpoint,
    policy: [u8; 32],
    journal: JournalIdentity,
}
impl Admission {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        field(out, &self.certificate)?;
        field(out, &self.roster)?;
        out.extend_from_slice(&self.checkpoint.version().to_be_bytes());
        out.extend_from_slice(&self.checkpoint.digest());
        out.extend_from_slice(&self.policy);
        out.extend_from_slice(self.journal.as_bytes());
        Ok(())
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let certificate = take(d)?;
        let roster = take(d)?;
        let checkpoint = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let policy = d.array()?;
        crate::codec::nonzero(&policy)?;
        let journal = JournalIdentity::from_trusted_state(d.array()?)?;
        Ok(Self {
            certificate,
            roster,
            checkpoint,
            policy,
            journal,
        })
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum AdmissionPhase {
    Accepted,
    Activating,
    Active,
    Refreshing { previous: RosterCheckpoint },
    RosterResolved { observed: RosterCheckpoint },
}
enum Phase {
    Preparing,
    Requested(Vec<u8>),
    Accepted {
        request: Vec<u8>,
        admission: Admission,
        stage: AdmissionPhase,
    },
}
struct Image {
    identity: SigningKeyId,
    phase: Phase,
    renewal: Option<LocalRenewal>,
    policy_pending: Option<RetainedPolicyRenewal>,
    policy_completed: Option<RetainedPolicyRenewal>,
    policy_device_binding: PolicyDeviceBinding,
    policy_resolution: Option<policy_renewal::RetainedPolicyResolution>,
    roster_resolution: Option<roster_resolution::RetainedRosterResolution>,
    policy_witness: Option<policy_renewal::WitnessPolicy>,
    roster_witness: Option<roster_refresh::WitnessRoster>,
    preparation: Option<Preparation>,
}
impl Image {
    fn require_roster_retired(&self) -> Result<(), DurableError> {
        if self.roster_witness.as_ref().is_some_and(|r| !r.retired()) {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }

    fn check_time_floor(&self, now: u64) -> Result<(), DurableError> {
        if let Some(resolution) = &self.roster_resolution {
            resolution.check_time(now)?;
        }
        if let Some(resolution) = &self.policy_resolution {
            resolution.check_time(now)?;
        }
        if let Some(renewal) = &self.renewal {
            renewal.policy_time_floor(now)?;
        }
        Ok(())
    }
    fn witnessed_credential_after_policy(&self) -> bool {
        self.policy_device_binding == PolicyDeviceBinding::CredentialRenewal
            && self.policy_witness.is_some()
            && self.renewal.as_ref().is_some_and(LocalRenewal::witnessed)
    }
    fn require_no_policy_renewal(&self) -> Result<(), DurableError> {
        self.require_roster_retired()?;
        if self.policy_pending.is_some() || self.policy_completed.is_some() {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
    fn require_credential_policy_retired(&self) -> Result<(), DurableError> {
        self.require_roster_retired()?;
        if self.policy_completed.is_none() {
            return self.require_no_policy_renewal();
        }
        if self.policy_pending.is_some()
            || self.policy_witness.is_none()
            || !self.policy_coordination_retired()
        {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
    fn validate_policy_phase(&self) -> Result<(), DurableError> {
        if let Some(r) = &self.roster_witness {
            r.validate(self)?;
        }
        if let Some(witness) = &self.policy_witness {
            witness.validate(self)?;
        }
        roster_resolution::validate_phase(self)?;
        if let Some(resolution) = &self.policy_resolution {
            resolution.validate(self)?;
        }
        if self.policy_device_binding == PolicyDeviceBinding::CredentialRenewal
            && (self.renewal.is_none()
                || (self.renewal.as_ref().is_some_and(LocalRenewal::witnessed)
                    && self.policy_witness.is_none()))
        {
            return Err(DurableError::Corrupt);
        }
        if self.policy_device_binding != PolicyDeviceBinding::Exact
            && self.policy_completed.is_none()
        {
            return Err(DurableError::Corrupt);
        }
        let valid_phase = match self.phase {
            Phase::Accepted {
                stage: AdmissionPhase::Active,
                ..
            } => true,
            Phase::Accepted {
                stage: AdmissionPhase::Refreshing { .. } | AdmissionPhase::RosterResolved { .. },
                ..
            } => {
                self.policy_device_binding != PolicyDeviceBinding::Exact
                    && self.policy_completed.is_some()
                    && self.policy_pending.is_none()
                    && self
                        .renewal
                        .as_ref()
                        .is_none_or(|r| !r.has_pending_credential())
            }
            _ => false,
        };
        if (self.policy_pending.is_some() || self.policy_completed.is_some())
            && (!valid_phase
                || self.renewal.as_ref().is_some_and(|r| {
                    if self.policy_device_binding == PolicyDeviceBinding::CredentialRenewal {
                        !r.permits_policy_credential(self.policy_pending.is_some())
                    } else {
                        !r.permits_policy_pending()
                    }
                }))
        {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
}
struct Active {
    database: Database,
    key: JournalKey,
}

/// Exclusive, authenticated original enrollment transaction. `provision` is an
/// explicit first-use decision. Reopen published unknown results; only the original
/// never-active first-use intent can retry an absent unpublished configuration.
/// Partial formal files fail closed and are never deleted or replaced.
pub struct DeviceEnrollment {
    storage: crate::storage::Storage,
    active: Option<Active>,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    binding: [u8; 32],
    account_authority: Option<crate::JournalAccountAuthority>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Commit original intent before dependent signer creation or request release.
    /// Existing signer or installation children cannot be adopted as a new intent.
    pub async fn provision(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        Self::provision_with_storage(crate::storage::Storage::native()?, paths, intent).await
    }
    pub(crate) async fn provision_with_storage(
        store: crate::storage::Storage,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        let key = store.open_key(&paths.wrapping).await?;
        for path in std::iter::once(paths.signer.as_path()).chain(paths.installation.files()) {
            if !store.missing(path).await? {
                return Err(DurableError::Conflict);
            }
        }
        let binding = paths.binding(&key, &intent)?;
        let image = Image {
            identity: SigningKeyId::generate()?,
            phase: Phase::Preparing,
            renewal: None,
            policy_pending: None,
            policy_completed: None,
            policy_device_binding: PolicyDeviceBinding::Exact,
            policy_resolution: None,
            roster_resolution: None,
            policy_witness: None,
            roster_witness: None,
            preparation: None,
        };
        let bytes = encode(&key, binding, &image)?;
        let database = store
            .provision_database(&paths.configuration, |database| {
                write_with_selection(database, &key, binding, &bytes)?;
                #[cfg(all(test, unix))]
                tests::initial_boundary("after-commit");
                Ok::<_, DurableError>(())
            })
            .await?;
        #[cfg(all(test, unix))]
        tests::after_commit(&bytes);
        let mut owner = Self {
            storage: store,
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
            account_authority: None,
        };
        owner.image()?;
        Ok(owner)
    }
    /// Reopen the original record, key, approved scope and paths. Never infer first
    /// use from missing, corrupt, busy, authentication or permission errors.
    pub async fn open(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        Self::open_with_storage(crate::storage::Storage::native()?, paths, intent).await
    }
    pub(crate) async fn open_with_storage(
        store: crate::storage::Storage,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        let mut owner = Self::open_original_storage_with_storage(store, paths, intent).await?;
        owner.image()?;
        Ok(owner)
    }
    // Storage admission only. Restricted callers must authenticate their own
    // retained lifecycle state before returning an owner; never expose this raw open.
    async fn open_original_storage(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        Self::open_original_storage_with_storage(crate::storage::Storage::native()?, paths, intent)
            .await
    }
    async fn open_original_storage_with_storage(
        store: crate::storage::Storage,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        let key = store.open_key(&paths.wrapping).await?;
        let binding = paths.binding(&key, &intent)?;
        let database = store.open_database(&paths.configuration).await?;
        Ok(Self {
            storage: store,
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
            account_authority: None,
        })
    }
    /// Original request/signing-file identity, independent of network responses.
    pub fn identity(&mut self) -> Result<SigningKeyId, DurableError> {
        Ok(self.image()?.identity)
    }
    /// Read authenticated original progress without reviving expired authority.
    pub fn status(&mut self) -> Result<EnrollmentStatus, DurableError> {
        let image = self.image()?;
        Ok(match image.phase {
            Phase::Preparing => EnrollmentStatus::Preparing,
            Phase::Requested(_) => EnrollmentStatus::Requested,
            Phase::Accepted {
                admission, stage, ..
            } => match stage {
                AdmissionPhase::Accepted => EnrollmentStatus::Accepted(admission.journal),
                AdmissionPhase::Activating => EnrollmentStatus::Activating(admission.journal),
                AdmissionPhase::Active => EnrollmentStatus::Active(admission.journal),
                AdmissionPhase::Refreshing { previous } => EnrollmentStatus::Refreshing {
                    journal: admission.journal,
                    previous,
                    next: admission.checkpoint,
                },
                AdmissionPhase::RosterResolved { .. } => EnrollmentStatus::RosterResolved(
                    image
                        .roster_resolution
                        .as_ref()
                        .ok_or(DurableError::Corrupt)?
                        .result(),
                ),
            },
        })
    }
    /// Release the lease and erase the held wrapping owner. Closing is idempotent.
    pub fn close(&mut self) {
        self.active = None;
    }
    fn image(&mut self) -> Result<Image, DurableError> {
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let image = load(&active.database, &active.key, self.binding)?;
            self.validate_preparation(&image)?;
            self.validate_roster_resolution(&image)?;
            self.validate_witness_roster(&image)?;
            self.validate_policy_pending(&image)?;
            Ok(image)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    // Existing credential/roster flows must not bypass an independent policy
    // intent. Metadata reads use image() so a Pending can always be reopened.
    fn image_without_policy_renewal(&mut self) -> Result<Image, DurableError> {
        let result = (|| {
            let image = self.image()?;
            image.require_no_policy_renewal()?;
            Ok(image)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn save(&mut self, image: &Image) -> Result<(), DurableError> {
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let bytes = encode(&active.key, self.binding, image)?;
            write_with_selection(&active.database, &active.key, self.binding, &bytes)?;
            #[cfg(all(test, unix))]
            tests::after_commit(&bytes);
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn key(&self) -> Result<JournalKey, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let key = self.storage.open_key(&self.paths.wrapping).await?;
        if key.installation_binding() != active.key.installation_binding() {
            return Err(DurableError::Conflict);
        }
        Ok(key)
    }
    async fn signer(
        &self,
        identity: SigningKeyId,
        creating: bool,
    ) -> Result<DeviceSigningKey, DurableError> {
        let key = self.key().await?;
        if creating && self.storage.missing(&self.paths.signer).await? {
            self.storage
                .provision_signer(&self.paths.signer, &key, identity)
                .await
        } else {
            self.storage
                .open_signer(&self.paths.signer, &key, identity)
                .await
        }
    }
    /// Create/reopen the exact original signer, commit its complete signed request,
    /// then release bytes. Restart/retry returns the identical committed request.
    pub async fn request(&mut self, now: u64) -> Result<Vec<u8>, DurableError> {
        let result = self.request_attempt(now).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn request_attempt(&mut self, now: u64) -> Result<Vec<u8>, DurableError> {
        self.intent.description.validity.check(now)?;
        let mut image = self.image()?;
        let signer = self
            .signer(image.identity, matches!(image.phase, Phase::Preparing))
            .await?;
        let wire = match &image.phase {
            Phase::Preparing => {
                let mut body = b"QPENRQ01".to_vec();
                body.extend_from_slice(image.identity.as_bytes());
                self.intent.encode(&mut body);
                body.extend_from_slice(&signer.public_key()?.encode());
                let wire = envelope(&body, &signer.sign(Purpose::EnrollmentRequest, &body)?)?;
                // Refuse shared components or invalid scope before persistence/release.
                VerifiedEnrollmentRequest::verify(&wire, &self.intent, now)?;
                image.phase = Phase::Requested(wire.clone());
                self.save(&image)?;
                wire
            }
            Phase::Requested(wire) | Phase::Accepted { request: wire, .. } => wire.clone(),
        };
        let request = VerifiedEnrollmentRequest::verify(&wire, &self.intent, now)?;
        if request.identity != image.identity || request.public != signer.public_key()? {
            return Err(DurableError::Conflict);
        }
        Ok(wire)
    }
    /// Admit the response under an independently obtained CURRENT account/roster
    /// pin and live verified policy. The same signer and exact approved metadata
    /// must match. Commit acceptance and one future journal ID before installation.
    /// An already accepted target is read back, never replaced by another response.
    pub async fn accept(
        &mut self,
        certificate: &[u8],
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<JournalIdentity, DurableError> {
        let result = self
            .accept_attempt(certificate, roster, pin, policy, now)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn accept_attempt(
        &mut self,
        certificate: &[u8],
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<JournalIdentity, DurableError> {
        let mut image = self.image_without_policy_renewal()?;
        if image
            .preparation
            .as_ref()
            .is_some_and(|p| p.extension.is_some())
        {
            return Err(DurableError::Conflict);
        }
        if image.renewal.is_some() {
            return Err(DurableError::Conflict);
        }
        let request = match &image.phase {
            Phase::Preparing => return Err(Error::State.into()),
            Phase::Requested(wire) | Phase::Accepted { request: wire, .. } => wire,
        };
        let original = VerifiedEnrollmentRequest::verify(request, &self.intent, now)?;
        let device = pin.verify_device(certificate, roster, now)?;
        self.intent.verify_device(&device)?;
        self.signer(image.identity, false)
            .await?
            .check_device(&device)?;
        if original.identity != image.identity || original.public != device.key {
            return Err(Error::Scope.into());
        }
        admit(&device, policy, now)?;
        if let Phase::Accepted { admission, .. } = &image.phase {
            if admission.checkpoint != device.roster().checkpoint()
                || admission.policy != policy.checkpoint().digest()
            {
                return Err(DurableError::Conflict);
            }
            let saved = pin.verify_device(&admission.certificate, &admission.roster, now)?;
            if saved.credential_digest() != device.credential_digest() {
                return Err(DurableError::Conflict);
            }
            return Ok(admission.journal);
        }
        let journal = JournalIdentity::generate()?;
        for path in self.paths.installation.files() {
            if !self.storage.missing(path).await? {
                return Err(DurableError::Conflict);
            }
        }
        image.phase = Phase::Accepted {
            request: request.clone(),
            admission: Admission {
                certificate: certificate.to_vec(),
                roster: roster.to_vec(),
                checkpoint: device.roster().checkpoint(),
                policy: policy.checkpoint().digest(),
                journal,
            },
            stage: AdmissionPhase::Accepted,
        };
        image.preparation = Some(Preparation::new(policy.checkpoint()));
        self.save(&image)?;
        Ok(journal)
    }

    /// Retain an independently authorized CURRENT roster for the same original
    /// credential, key, root and policy. `previous` is an expected checkpoint,
    /// never authority. The original credential/intent must still be valid.
    ///
    /// Success reports durable registration progress, not an operational service:
    /// Refreshing requires `activate` to reconcile the original journal first.
    /// After policy-only adoption, pass its current target policy and use
    /// `activate_policy_renewal` to reconcile the same original installation.
    /// An exact retry preserves the original target bytes; a different pending
    /// target is refused. Errors close this owner. Reopen the original enrollment
    /// after an unknown commit; never use `accept` or provisioning as a fallback.
    pub async fn refresh_roster(
        &mut self,
        previous: RosterCheckpoint,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrollmentStatus, DurableError> {
        let result = self
            .refresh_roster_attempt(previous, roster, pin, policy, now)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn refresh_roster_attempt(
        &mut self,
        previous: RosterCheckpoint,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrollmentStatus, DurableError> {
        let mut image = self.image()?;
        image.check_time_floor(now)?;
        if image.roster_witness.is_some() {
            return Err(DurableError::Conflict);
        }
        if image.policy_completed.is_some() {
            return self
                .refresh_policy_roster(image, previous, roster, pin, policy, now)
                .await;
        }
        image.require_no_policy_renewal()?;
        if image.renewal.is_some() {
            return self
                .refresh_renewed_roster(image, previous, roster, pin, policy, now)
                .await;
        }
        if matches!(
            &image.phase,
            Phase::Accepted {
                stage: AdmissionPhase::Accepted,
                ..
            }
        ) {
            return self
                .refresh_unprepared_roster(image, previous, roster, pin, policy, now)
                .await;
        }
        let expected_intent = self.installation_intent(&image)?;
        let Phase::Accepted {
            request,
            admission,
            stage,
        } = &mut image.phase
        else {
            return Err(Error::State.into());
        };
        if !matches!(
            *stage,
            AdmissionPhase::Active
                | AdmissionPhase::Refreshing { .. }
                | AdmissionPhase::RosterResolved { .. }
        ) {
            return Err(Error::State.into());
        }
        if admission.policy != policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        // The old roster may be expired. The authenticated enrollment record
        // supplies its expected identity, never a renewed authorization grant.
        let device = pin.verify_device(&admission.certificate, roster, now)?;
        expected_intent.verify_device(&device)?;
        let original = authenticate_enrollment_proof(request, &self.intent)?;
        if original.identity != image.identity || original.public != device.key {
            return Err(DurableError::Conflict);
        }
        self.signer(image.identity, false)
            .await?
            .check_device(&device)?;
        admit(&device, policy, now)?;
        let next = device.roster().checkpoint();
        if next.version() <= previous.version() {
            return Err(Error::Checkpoint.into());
        }
        match *stage {
            AdmissionPhase::Refreshing { previous: expected }
                if expected == previous && admission.checkpoint == next => {}
            AdmissionPhase::Active if admission.checkpoint == next => {}
            AdmissionPhase::Active if admission.checkpoint == previous => {
                admission.roster = roster.to_vec();
                admission.checkpoint = next;
                *stage = AdmissionPhase::Refreshing { previous };
                self.save(&image)?;
            }
            AdmissionPhase::RosterResolved { observed } if observed == previous => {
                admission.roster = roster.to_vec();
                admission.checkpoint = next;
                *stage = AdmissionPhase::Refreshing { previous };
                self.save(&image)?;
            }
            _ => return Err(DurableError::Conflict),
        }
        admit(&device, policy, now)?;
        self.status()
    }

    async fn admitted(
        &self,
        image: &Image,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
        image.check_time_floor(now)?;
        image.require_reconciled_roster()?;
        image.require_no_policy_renewal()?;
        if image.renewal.is_some() {
            return self.admitted_renewed(image, policy, now).await;
        }
        let Phase::Accepted {
            request, admission, ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        if admission.policy != policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        let pin = AccountPin::new(
            crate::identity::account_id(&self.intent.root),
            self.intent.root.clone(),
            admission.checkpoint,
            self.intent.description.family,
        )?;
        let device = pin.verify_device(&admission.certificate, &admission.roster, now)?;
        let original = authenticate_enrollment_proof(request, &self.intent)?;
        if original.identity != image.identity || original.public != device.key {
            return Err(DurableError::Conflict);
        }
        self.installation_intent(image)?.verify_device(&device)?;
        self.signer(image.identity, false)
            .await?
            .check_device(&device)?;
        admit(&device, policy, now)?;
        Ok(device)
    }
    async fn installation(
        &self,
        image: &Image,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        create: bool,
    ) -> Result<DeviceInstallation, DurableError> {
        let Phase::Accepted {
            admission, stage, ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        let key = self.key().await?;
        let paths = self.paths.installation.clone();
        let config = paths
            .files()
            .first()
            .copied()
            .ok_or(DurableError::Corrupt)?;
        let owner = if create
            && *stage == AdmissionPhase::Accepted
            && self.storage.missing(config).await?
        {
            DeviceInstallation::provision_with_identity(
                self.storage.clone(),
                paths,
                &key,
                device,
                policy,
                now,
                admission.journal,
            )
            .await?
        } else {
            DeviceInstallation::open_with_storage(
                self.storage.clone(),
                paths,
                &key,
                device,
                policy,
                now,
            )
            .await?
        };
        if owner.identity()? != admission.journal {
            return Err(DurableError::Conflict);
        }
        Ok(owner)
    }
    /// Prepare original empty children through the existing installation contract.
    /// Required-witness genesis is returned for explicit independent enrollment.
    pub async fn prepare(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, DurableError> {
        let result = self.prepare_attempt(policy, now).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn prepare_attempt(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, DurableError> {
        let mut image = self.image_without_policy_renewal()?;
        if !matches!(
            image.phase,
            Phase::Accepted {
                stage: AdmissionPhase::Accepted,
                ..
            }
        ) {
            return Err(Error::State.into());
        }
        let device = self.admitted(&image, policy, now).await?;
        self.select_installation(&mut image)?;
        self.installation(&image, &device, policy, now, true)
            .await?
            .prepare(self.key().await?, &device, policy, now)
            .await
    }

    /// Construct the required witness client from the original controlled signer,
    /// using the independently pinned witness and explicit carrier. The admitted
    /// policy must require this exact pin; a local-only or changed pin is refused.
    pub async fn anchor_client(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let result = self
            .anchor_client_attempt(policy, now, pin, transport, timeout)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn anchor_client_attempt(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let image = self.image_without_policy_renewal()?;
        self.check_witness_client(None)?;
        let device = self.admitted(&image, policy, now).await?;
        if policy.anchor_requirement().binding() != Some(pin.binding()) {
            return Err(Error::Scope.into());
        }
        let client = AnchorClient::new(
            pin,
            self.signer(image.identity, false).await?,
            transport,
            timeout,
        )?;
        admit(&device, policy, now)?;
        Ok(client)
    }

    /// Activate/reopen the original prepared installation. Persist Active before
    /// releasing the service/signing owners. Missing required witness never falls
    /// back to local protection. Unknown results require original enrollment open.
    pub async fn activate(
        mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<EnrolledDevice, DurableError> {
        let mut image = self.image_without_policy_renewal()?;
        self.check_witness_client(anchor.as_ref())?;
        if image.renewal.is_some() {
            return self.activate_renewed(image, policy, now, anchor).await;
        }
        let device = self.admitted(&image, policy, now).await?;
        let signer = self.signer(image.identity, false).await?;
        self.select_installation(&mut image)?;
        let mut installation = self
            .installation(&image, &device, policy, now, false)
            .await?;
        let Phase::Accepted { stage, .. } = &mut image.phase else {
            return Err(Error::State.into());
        };
        if *stage == AdmissionPhase::Accepted {
            if installation.status()? != crate::InstallationStatus::Creating {
                return Err(DurableError::Conflict);
            }
            for path in self.paths.installation.files().into_iter().skip(1) {
                if self.storage.missing(path).await? {
                    return Err(Error::State.into());
                }
            }
            *stage = AdmissionPhase::Activating;
            // Activating is itself a permanent selection boundary. When no
            // extension was adopted, the extra preinstallation marker has no
            // remaining purpose; retain the established legacy state contract.
            // Extension history must remain because it defines the installation's
            // original credential while the enrollment intent stays immutable.
            if image
                .preparation
                .as_ref()
                .is_some_and(|p| p.extension.is_none())
            {
                image.preparation = None;
            }
            self.save(&image)?;
        } else if matches!(
            *stage,
            AdmissionPhase::Active | AdmissionPhase::Refreshing { .. }
        ) && installation.status()? != crate::InstallationStatus::Active
        {
            return Err(DurableError::Conflict);
        }
        let mut service = installation
            .activate_admitted(
                self.key().await?,
                &device,
                policy,
                now,
                crate::installation::InstallationAdmission {
                    anchor,
                    account: self.account_authority.clone(),
                },
            )
            .await?;
        let Phase::Accepted {
            stage, admission, ..
        } = &mut image.phase
        else {
            return Err(Error::State.into());
        };
        // Opening an anchored journal first reconciles its ORIGINAL pending
        // command. Compare the resulting checkpoint, not a pre-recovery snapshot.
        let journal = service.stores()?.0;
        let current = journal.roster_checkpoint(device.account_id()).await?;
        if let AdmissionPhase::Refreshing { previous } = *stage {
            if current != admission.checkpoint && current != previous {
                return Err(DurableError::Conflict);
            }
            let installed = journal.install_roster(device.roster(), now).await?;
            if installed != admission.checkpoint {
                return Err(DurableError::Conflict);
            }
            #[cfg(all(test, unix))]
            tests::after_roster_journal_commit();
        } else if current != admission.checkpoint {
            return Err(DurableError::Conflict);
        }
        if *stage != AdmissionPhase::Active {
            *stage = AdmissionPhase::Active;
            self.save(&image)?;
        }
        // Enrollment adds a durability boundary after installation activation.
        // Recheck local and independently witnessed authority at actual release.
        service
            .stores()?
            .0
            .check_enrollment_authority(&device, policy, now)
            .await?;
        admit(&device, policy, now)?;
        Ok(EnrolledDevice {
            active: Some(Box::new(EnrolledOwners {
                enrollment: self,
                service,
                signer,
                device,
            })),
        })
    }
}

struct EnrolledOwners {
    enrollment: DeviceEnrollment,
    service: DeviceService,
    signer: DeviceSigningKey,
    device: VerifiedDevice,
}
/// Controlled result of original enrollment and installation activation. This
/// composes the existing service and signer, not a second traffic implementation.
pub struct EnrolledDevice {
    // Keep the exclusive aggregate behind one owned allocation. Moving the
    // public handle through continuation Result values must not copy the
    // service, signer and verified identity into each caller's stack frame.
    active: Option<Box<EnrolledOwners>>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Historical original renewal outcome; current service admission is separate.
    pub fn credential_renewal_status(&mut self) -> Result<CredentialRenewalStatus, DurableError> {
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .credential_renewal_status()
    }
    /// Historical independent policy outcome; current traffic admission is separate.
    pub fn policy_renewal_status(&mut self) -> Result<PolicyRenewalStatus, DurableError> {
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .policy_renewal_status()
    }
    /// Retained independent policy terminal and original witness cleanup status.
    pub fn witnessed_policy_renewal_progress(
        &mut self,
    ) -> Result<Option<WitnessedPolicyRenewalProgress>, DurableError> {
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .witnessed_policy_renewal_progress()
    }
    /// Read retained enrollment progress; this observation grants no traffic authority.
    pub fn enrollment_status(&mut self) -> Result<EnrollmentStatus, DurableError> {
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .status()
    }
    /// Original roster coordination metadata; it grants no new traffic authority.
    pub fn witnessed_roster_refresh_progress(
        &mut self,
    ) -> Result<Option<WitnessedRosterRefreshProgress>, DurableError> {
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .witnessed_roster_refresh_progress()
    }
    /// Borrow the existing service, original signer and verified local identity.
    /// Peer preparation, current roster/policy and durable traffic checks still apply.
    pub fn parts(
        &mut self,
    ) -> Result<(&mut DeviceService, &DeviceSigningKey, &VerifiedDevice), DurableError> {
        let active = self.active.as_mut().ok_or(DurableError::Closed)?;
        // Retaining this owner keeps the original registration lease and key alive.
        active
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        Ok((&mut active.service, &active.signer, &active.device))
    }
    /// Observe the next original publication ID through this registered owner.
    pub async fn next_prekey_publication_id(
        &mut self,
    ) -> Result<crate::PrekeyPublicationId, DurableError> {
        self.parts()?
            .0
            .stores()?
            .0
            .next_prekey_publication_id()
            .await
    }
    /// Read original publication metadata; this does not release public keys.
    pub async fn prekey_publication_status(
        &mut self,
        id: crate::PrekeyPublicationId,
    ) -> Result<crate::PrekeyPublicationStatus, DurableError> {
        self.parts()?
            .0
            .stores()?
            .0
            .prekey_publication_status(id)
            .await
    }
    /// Prepare/recover one advertisement without borrowing the controlled signer
    /// or composing inventory steps. The verified policy and current trusted
    /// clock are still required; the journal rechecks all durable authority.
    pub async fn prepare_prekey_publication(
        &mut self,
        id: crate::PrekeyPublicationId,
        plan: &crate::PrekeyPublicationPlan,
        policy: &VerifiedSessionPolicy,
        run: crate::PrekeyPublicationRun<'_>,
        clock: impl FnMut() -> std::io::Result<u64>,
    ) -> Result<crate::PreparedPrekeyPublication, crate::PrekeyPublicationError> {
        let (service, signer, device) = self.parts()?;
        service
            .stores()?
            .0
            .prepare_prekey_publication(
                crate::PrekeyPublicationRequest {
                    id,
                    plan,
                    policy,
                    device,
                    signer,
                },
                run,
                clock,
            )
            .await
    }
    /// Acknowledge local public-artifact retirement, without revoking inventory.
    pub async fn retire_prekey_publication(
        &mut self,
        id: crate::PrekeyPublicationId,
        artifact: [u8; 32],
    ) -> Result<crate::PrekeyPublicationStatus, DurableError> {
        self.parts()?
            .0
            .stores()?
            .0
            .retire_prekey_publication(id, artifact)
            .await
    }
    /// Abandon a still-reserved original intent without retiring reused members.
    pub async fn abandon_prekey_publication(
        &mut self,
        id: crate::PrekeyPublicationId,
        intent: [u8; 32],
        policy: &VerifiedSessionPolicy,
    ) -> Result<crate::PrekeyPublicationStatus, DurableError> {
        self.parts()?
            .0
            .stores()?
            .0
            .abandon_prekey_publication(id, intent, policy)
            .await
    }
    /// Close service, signing key and enrollment lease. Repeated close is valid.
    pub fn close(&mut self) {
        self.active = None;
    }
}

fn auth(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let derived = key.enrollment_state_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider.into())
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DurableError> {
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(DurableError::Capacity);
    }
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}
fn take(d: &mut Decoder<'_>) -> Result<Vec<u8>, DurableError> {
    let length = usize::from(d.u16()?);
    if length == 0 || length > 8192 {
        return Err(DurableError::Corrupt);
    }
    Ok(d.take(length)?.to_vec())
}
fn credential_history_tag(image: &Image) -> &'static [u8; 8] {
    if image
        .renewal
        .as_ref()
        .is_some_and(LocalRenewal::policy_cancellation)
    {
        b"QPENST08"
    } else if image
        .renewal
        .as_ref()
        .is_some_and(LocalRenewal::policy_coordination)
    {
        b"QPENST07"
    } else if image.renewal.as_ref().is_some_and(LocalRenewal::joint) {
        b"QPENST06"
    } else if image
        .renewal
        .as_ref()
        .is_some_and(LocalRenewal::cancellation)
    {
        b"QPENST05"
    } else if image.renewal.as_ref().is_some_and(LocalRenewal::witnessed) {
        b"QPENST04"
    } else if image.renewal.as_ref().is_some_and(LocalRenewal::extended) {
        b"QPENST03"
    } else if image.renewal.is_some() {
        b"QPENST02"
    } else {
        b"QPENST01"
    }
}
fn encode(key: &JournalKey, binding: [u8; 32], image: &Image) -> Result<Vec<u8>, DurableError> {
    image.validate_policy_phase()?;
    let history_tag = credential_history_tag(image);
    let mut bytes = if image.policy_device_binding == PolicyDeviceBinding::CredentialRenewal {
        b"QPENST12"
    } else if image.policy_device_binding == PolicyDeviceBinding::MonotonicRoster {
        b"QPENST11"
    } else if image.policy_completed.is_some() {
        b"QPENST10"
    } else if image.policy_pending.is_some() {
        b"QPENST09"
    } else {
        history_tag
    }
    .to_vec();
    if image.policy_resolution.is_some() {
        let mut wrapper = b"QPENST13".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image.roster_resolution.is_some() {
        let mut wrapper = b"QPENST14".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image.policy_witness.is_some() {
        let mut wrapper = b"QPENST16".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image.roster_witness.is_some() {
        let mut wrapper = b"QPENST17".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image.witnessed_credential_after_policy() {
        let mut wrapper = b"QPENST18".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image.preparation.is_some() {
        let mut wrapper = b"QPENST19".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    let account = image.renewal.as_ref().filter(|r| r.has_account_extension());
    if account.is_some() {
        let mut wrapper = b"QPENST20".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image
        .roster_witness
        .as_ref()
        .is_some_and(roster_refresh::WitnessRoster::credential_bound)
    {
        let mut wrapper = b"QPENST21".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    if image
        .roster_witness
        .as_ref()
        .is_some_and(roster_refresh::WitnessRoster::continued)
    {
        let mut wrapper = b"QPENST22".to_vec();
        wrapper.extend_from_slice(&bytes);
        bytes = wrapper;
    }
    bytes.extend_from_slice(&binding);
    bytes.extend_from_slice(image.identity.as_bytes());
    match &image.phase {
        Phase::Preparing => bytes.push(0),
        Phase::Requested(request) => {
            bytes.push(1);
            field(&mut bytes, request)?;
        }
        Phase::Accepted {
            request,
            admission,
            stage,
        } => {
            bytes.push(match stage {
                AdmissionPhase::Accepted => 2,
                AdmissionPhase::Activating => 3,
                AdmissionPhase::Active => 4,
                AdmissionPhase::Refreshing { .. } => 5,
                AdmissionPhase::RosterResolved { .. } => 6,
            });
            field(&mut bytes, request)?;
            admission.encode(&mut bytes)?;
            if let AdmissionPhase::Refreshing { previous } = stage {
                bytes.extend_from_slice(&previous.version().to_be_bytes());
                bytes.extend_from_slice(&previous.digest());
            }
            if let AdmissionPhase::RosterResolved { observed } = stage {
                bytes.extend_from_slice(&observed.version().to_be_bytes());
                bytes.extend_from_slice(&observed.digest());
            }
        }
    }
    if image.policy_pending.is_some() || image.policy_completed.is_some() {
        bytes.extend_from_slice(history_tag);
    }
    if let Some(renewal) = &image.renewal {
        renewal.encode(&mut bytes)?;
    }
    if let Some(completed) = &image.policy_completed {
        completed.encode(&mut bytes)?;
        bytes.push(u8::from(image.policy_pending.is_some()));
    }
    if let Some(pending) = &image.policy_pending {
        pending.encode(&mut bytes)?;
    }
    if let Some(resolution) = &image.policy_resolution {
        resolution.encode(&mut bytes)?;
    }
    if let Some(resolution) = &image.roster_resolution {
        resolution.encode(&mut bytes)?;
    }
    if let Some(witness) = &image.policy_witness {
        witness.encode(&mut bytes)?;
    }
    if let Some(r) = &image.roster_witness {
        r.encode(&mut bytes)?;
    }
    if let Some(preparation) = &image.preparation {
        preparation.encode(&mut bytes)?;
    }
    let account_start = bytes.len();
    if let Some(account) = account {
        account.encode_account(&mut bytes)?;
    }
    let account_size = bytes.len() - account_start + if account.is_some() { 8 } else { 0 };
    let mut mac = auth(key)?;
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    let limit = if image.preparation.is_some() {
        MAX_PREINSTALLATION_IMAGE
    } else if image.renewal.is_some()
        || image.policy_pending.is_some()
        || image.policy_completed.is_some()
        || image.policy_resolution.is_some()
        || image.roster_resolution.is_some()
        || image.policy_witness.is_some()
        || image.roster_witness.is_some()
    {
        MAX_RENEWAL_IMAGE
    } else {
        MAX_IMAGE
    };
    if bytes.len() - account_size > limit || bytes.len() > renewal::MAX_ACCOUNT_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(bytes)
}
fn load(database: &Database, key: &JournalKey, binding: [u8; 32]) -> Result<Image, DurableError> {
    let (image, retirement) = load_snapshot(database, key, binding)?;
    if retirement.is_some() {
        return Err(DurableError::Suspended);
    }
    Ok(image)
}
fn load_snapshot(
    database: &Database,
    key: &JournalKey,
    binding: [u8; 32],
) -> Result<(Image, Option<retirement::State>), DurableError> {
    let snapshot = read_snapshot(database, key, binding)?;
    if snapshot.root_replacement.is_some() {
        return Err(DurableError::Suspended);
    }
    Ok((snapshot.image, snapshot.retirement))
}
struct EnrollmentSnapshot {
    image: Image,
    retirement: Option<retirement::State>,
    witness_handoff: Option<witness_handoff::State>,
    // Ordinary activation must not carry the full two-root proposal by value.
    root_replacement: Option<Box<account_root::State>>,
}
fn read_snapshot(
    database: &Database,
    key: &JournalKey,
    binding: [u8; 32],
) -> Result<EnrollmentSnapshot, DurableError> {
    let tx = database.begin_read().map_err(storage)?;
    let tables: Vec<_> = tx.list_tables().map_err(storage)?.collect();
    if tables.len() != 1
        || tables.first().ok_or(DurableError::Corrupt)?.name() != TABLE.name()
        || tx.list_multimap_tables().map_err(storage)?.next().is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = tx.open_table(TABLE).map_err(storage)?;
    let retirement = table
        .get("retirement")
        .map_err(storage)?
        .map(|row| retirement::State::decode(row.value(), key, binding))
        .transpose()?;
    let root_replacement = table
        .get(account_root::ROW)
        .map_err(storage)?
        .map(|row| account_root::State::decode(row.value(), key, binding))
        .transpose()?;
    let witness_row = table.get(witness_handoff::ROW).map_err(storage)?;
    let witness_binding = witness_row
        .as_ref()
        .map(|row| account_root::selection_binding(row.value()));
    let witness_handoff = witness_row
        .map(|row| witness_handoff::State::decode(key, binding, row.value()))
        .transpose()?;
    if table.len().map_err(storage)?
        != 1 + u64::from(retirement.is_some())
            + u64::from(root_replacement.is_some())
            + u64::from(witness_handoff.is_some())
    {
        return Err(DurableError::Corrupt);
    }
    let saved = table
        .get("enrollment")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    let wire = saved.value();
    let image = decode_image(wire, key, binding)?;
    if let Some(state) = &witness_handoff {
        state.check_image(&image)?;
    }
    if let Some(state) = &retirement {
        state.check_image(&image, wire)?;
        if state.requires_account_root() && root_replacement.is_none() {
            return Err(DurableError::Conflict);
        }
    }
    if let Some(state) = &root_replacement {
        state.check_image(&image, wire)?;
        state.check_selection_binding(witness_binding)?;
        if let Some(retirement) = &retirement {
            retirement.check_account_retirement(state)?;
        }
    }
    Ok(EnrollmentSnapshot {
        image,
        retirement,
        witness_handoff,
        root_replacement,
    })
}
fn decode_image(wire: &[u8], key: &JournalKey, binding: [u8; 32]) -> Result<Image, DurableError> {
    if wire.len() < 105 || wire.len() > renewal::MAX_ACCOUNT_IMAGE {
        return Err(DurableError::Corrupt);
    }
    let (body, tag) = wire.split_at(wire.len() - 32);
    let mut mac = auth(key)?;
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| DurableError::Authentication)?;
    let mut d = Decoder::new(body);
    let tag = d.array::<8>()?;
    let roster_continued = tag == *b"QPENST22";
    let tag = if roster_continued {
        d.array::<8>()?
    } else {
        tag
    };
    let roster_credential = tag == *b"QPENST21";
    if roster_continued && !roster_credential {
        return Err(DurableError::Corrupt);
    }
    let tag = if roster_credential {
        d.array::<8>()?
    } else {
        tag
    };
    let has_account = tag == *b"QPENST20";
    let tag = if has_account { d.array::<8>()? } else { tag };
    if !has_account && wire.len() > MAX_PREINSTALLATION_IMAGE {
        return Err(DurableError::Corrupt);
    }
    let has_preparation = tag == *b"QPENST19";
    if !has_account && !has_preparation && wire.len() > MAX_RENEWAL_IMAGE {
        return Err(DurableError::Corrupt);
    }
    let tag = if has_preparation {
        d.array::<8>()?
    } else {
        tag
    };
    let credential_after_policy = tag == *b"QPENST18";
    let tag = if credential_after_policy {
        d.array::<8>()?
    } else {
        tag
    };
    let has_roster_witness = tag == *b"QPENST17";
    let tag = if has_roster_witness {
        d.array::<8>()?
    } else {
        tag
    };
    let completion_metadata = tag == *b"QPENST16";
    let has_policy_witness = completion_metadata || tag == *b"QPENST15";
    let tag = if has_policy_witness {
        d.array::<8>()?
    } else {
        tag
    };
    let has_roster_resolution = tag == *b"QPENST14";
    let tag = if has_roster_resolution {
        d.array::<8>()?
    } else {
        tag
    };
    let has_resolution = tag == *b"QPENST13";
    let tag = if has_resolution { d.array::<8>()? } else { tag };
    if (tag != *b"QPENST01"
        && tag != *b"QPENST02"
        && tag != *b"QPENST03"
        && tag != *b"QPENST04"
        && tag != *b"QPENST05"
        && tag != *b"QPENST06"
        && tag != *b"QPENST07"
        && tag != *b"QPENST08"
        && tag != *b"QPENST09"
        && tag != *b"QPENST10"
        && tag != *b"QPENST11"
        && tag != *b"QPENST12")
        || d.array::<32>()? != binding
        || (!has_preparation
            && !has_roster_witness
            && !has_policy_witness
            && !has_roster_resolution
            && !has_resolution
            && tag == *b"QPENST01"
            && wire.len() > MAX_IMAGE)
    {
        return Err(DurableError::Conflict);
    }
    let identity = SigningKeyId::from_trusted_state(d.array()?)?;
    let phase = match d.array::<1>()? {
        [0] => Phase::Preparing,
        [1] => Phase::Requested(take(&mut d)?),
        [phase @ 2..=6] => {
            let request = take(&mut d)?;
            let admission = Admission::decode(&mut d)?;
            let checkpoint = admission.checkpoint;
            Phase::Accepted {
                request,
                admission,
                stage: match phase {
                    2 => AdmissionPhase::Accepted,
                    3 => AdmissionPhase::Activating,
                    4 => AdmissionPhase::Active,
                    5 => {
                        let previous = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
                        if previous.version() >= checkpoint.version() {
                            return Err(DurableError::Corrupt);
                        }
                        AdmissionPhase::Refreshing { previous }
                    }
                    6 if has_roster_resolution => AdmissionPhase::RosterResolved {
                        observed: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
                    },
                    _ => return Err(DurableError::Corrupt),
                },
            }
        }
        _ => return Err(DurableError::Corrupt),
    };
    let policy_device_binding = if tag == *b"QPENST12" {
        PolicyDeviceBinding::CredentialRenewal
    } else if tag == *b"QPENST11" {
        PolicyDeviceBinding::MonotonicRoster
    } else {
        PolicyDeviceBinding::Exact
    };
    let policy_completion = [*b"QPENST10", *b"QPENST11", *b"QPENST12"].contains(&tag);
    let policy_only = tag == *b"QPENST09" || policy_completion;
    let tag = if policy_only { d.array::<8>()? } else { tag };
    if ![
        *b"QPENST01",
        *b"QPENST02",
        *b"QPENST03",
        *b"QPENST04",
        *b"QPENST05",
        *b"QPENST06",
        *b"QPENST07",
        *b"QPENST08",
    ]
    .contains(&tag)
    {
        return Err(DurableError::Corrupt);
    }
    let mut renewal = if tag == *b"QPENST02"
        || tag == *b"QPENST03"
        || tag == *b"QPENST04"
        || tag == *b"QPENST05"
        || tag == *b"QPENST06"
        || tag == *b"QPENST07"
        || tag == *b"QPENST08"
    {
        if !matches!(
            phase,
            Phase::Accepted {
                stage: AdmissionPhase::Active
                    | AdmissionPhase::Refreshing { .. }
                    | AdmissionPhase::RosterResolved { .. },
                ..
            }
        ) {
            return Err(DurableError::Corrupt);
        }
        Some(LocalRenewal::decode(
            &mut d,
            renewal::RenewalEncoding {
                extended: tag != *b"QPENST02",
                witnessed: tag == *b"QPENST04" || tag == *b"QPENST05",
                cancellation: tag == *b"QPENST05",
                joint: [*b"QPENST06", *b"QPENST07", *b"QPENST08"].contains(&tag),
                policy_coordination: tag == *b"QPENST07" || tag == *b"QPENST08",
                policy_cancellation: tag == *b"QPENST08",
                independent_policy: credential_after_policy,
            },
        )?)
    } else {
        None
    };
    let policy_completed = if policy_completion {
        Some(RetainedPolicyRenewal::decode(&mut d)?)
    } else {
        None
    };
    let has_pending = if policy_completion {
        match d.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(DurableError::Corrupt),
        }
    } else {
        policy_only
    };
    let policy_pending = if has_pending {
        Some(RetainedPolicyRenewal::decode(&mut d)?)
    } else {
        None
    };
    let policy_resolution = if has_resolution {
        Some(policy_renewal::RetainedPolicyResolution::decode(&mut d)?)
    } else {
        None
    };
    let roster_resolution = if has_roster_resolution {
        Some(roster_resolution::RetainedRosterResolution::decode(&mut d)?)
    } else {
        None
    };
    let policy_witness = if has_policy_witness {
        Some(policy_renewal::WitnessPolicy::decode(
            &mut d,
            completion_metadata,
        )?)
    } else {
        None
    };
    let roster_witness = if has_roster_witness {
        Some(roster_refresh::WitnessRoster::decode(
            &mut d,
            roster_credential,
            roster_continued,
        )?)
    } else {
        None
    };
    let preparation = if has_preparation {
        Some(Preparation::decode(&mut d)?)
    } else {
        None
    };
    if has_account {
        let base_size = wire.len() - d.remaining() - 8;
        let base_limit = if has_preparation {
            MAX_PREINSTALLATION_IMAGE
        } else {
            MAX_RENEWAL_IMAGE
        };
        if base_size > base_limit {
            return Err(DurableError::Corrupt);
        }
        renewal
            .as_mut()
            .ok_or(DurableError::Corrupt)?
            .decode_account(&mut d)?;
    }
    d.finish()?;
    let image = Image {
        identity,
        phase,
        renewal,
        policy_pending,
        policy_completed,
        policy_device_binding,
        policy_resolution,
        roster_resolution,
        policy_witness,
        roster_witness,
        preparation,
    };
    image.validate_policy_phase()?;
    if roster_continued
        != image
            .roster_witness
            .as_ref()
            .is_some_and(roster_refresh::WitnessRoster::continued)
    {
        return Err(DurableError::Corrupt);
    }
    if roster_credential
        != image
            .roster_witness
            .as_ref()
            .is_some_and(roster_refresh::WitnessRoster::credential_bound)
    {
        return Err(DurableError::Corrupt);
    }
    if image.witnessed_credential_after_policy() != credential_after_policy {
        return Err(DurableError::Corrupt);
    }
    Ok(image)
}
fn write_with_selection(
    database: &Database,
    key: &JournalKey,
    binding: [u8; 32],
    bytes: &[u8],
) -> Result<(), DurableError> {
    let tx = transaction(database)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if let Some(selected) = table.get(witness_handoff::ROW).map_err(storage)? {
            witness_handoff::State::decode(key, binding, selected.value())?
                .check_image(&decode_image(bytes, key, binding)?)?;
        }
        table.insert("enrollment", bytes).map_err(storage)?;
    }
    #[cfg(all(test, unix))]
    tests::initial_boundary("before-commit");
    tx.commit().map_err(DurableError::CommitUncertain)?;
    Ok(())
}
