// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original device enrollment before credential-dependent installation creation.
use crate::{
    codec::Decoder,
    crypto::{digest, envelope, open_envelope, Purpose},
    durable::{storage, transaction},
    installation::{admit, missing, validate_paths},
    AccountPin, AnchorClient, AnchorPin, AnchorTransport, DeviceDescription, DeviceInstallation,
    DeviceService, DeviceSigningKey, DurableError, Error, InstallationPaths,
    InstallationPreparation, JournalIdentity, JournalKey, PublicKey, RootSigningKey,
    RosterCheckpoint, SigningKeyId, VerifiedDevice, VerifiedSessionPolicy, PUBLIC_KEY_BYTES,
};
use hmac::{Hmac, Mac};
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition, TableHandle};
use sha2::Sha256;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_enrollment_v1");
const REQUEST_BODY: usize = 8 + 32 + 32 + 16 + 8 + 16 + 32 + PUBLIC_KEY_BYTES;
const MAX_IMAGE: usize = 24 * 1024;

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
        Ok(Self {
            intent: intent.clone(),
            identity,
            public,
        })
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
}
struct Admission {
    certificate: Vec<u8>,
    roster: Vec<u8>,
    checkpoint: RosterCheckpoint,
    policy: [u8; 32],
    journal: JournalIdentity,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum AdmissionPhase {
    Accepted = 2,
    Activating = 3,
    Active = 4,
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
}
struct Active {
    database: Database,
    key: JournalKey,
}

/// Exclusive, authenticated original enrollment transaction. `provision` is an
/// explicit first-use decision; use `open` after every interrupted/unknown result.
/// Partial key/configuration files fail closed and are never deleted or replaced.
pub struct DeviceEnrollment {
    active: Option<Active>,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    binding: [u8; 32],
}
impl DeviceEnrollment {
    /// Commit original intent before dependent signer creation or request release.
    /// Existing signer or installation children cannot be adopted as a new intent.
    pub fn provision(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        for path in std::iter::once(paths.signer.as_path()).chain(paths.installation.files()) {
            if !missing(path)? {
                return Err(DurableError::Conflict);
            }
        }
        let binding = paths.binding(&key, &intent)?;
        let image = Image {
            identity: SigningKeyId::generate()?,
            phase: Phase::Preparing,
        };
        let bytes = encode(&key, binding, &image)?;
        let database = provision_private_database(&paths.configuration, |database| {
            write(&database, &bytes)?;
            Ok::<_, DurableError>(database)
        })?;
        let mut owner = Self {
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
        };
        owner.image()?;
        Ok(owner)
    }
    /// Reopen the original record, key, approved scope and paths. Never infer first
    /// use from missing, corrupt, busy, authentication or permission errors.
    pub fn open(paths: EnrollmentPaths, intent: EnrollmentIntent) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        let database = open_private_database(&paths.configuration)?;
        let mut owner = Self {
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
        };
        owner.image()?;
        Ok(owner)
    }
    /// Original request/signing-file identity, independent of network responses.
    pub fn identity(&mut self) -> Result<SigningKeyId, DurableError> {
        Ok(self.image()?.identity)
    }
    /// Read authenticated original progress without reviving expired authority.
    pub fn status(&mut self) -> Result<EnrollmentStatus, DurableError> {
        Ok(match self.image()?.phase {
            Phase::Preparing => EnrollmentStatus::Preparing,
            Phase::Requested(_) => EnrollmentStatus::Requested,
            Phase::Accepted {
                admission, stage, ..
            } => match stage {
                AdmissionPhase::Accepted => EnrollmentStatus::Accepted(admission.journal),
                AdmissionPhase::Activating => EnrollmentStatus::Activating(admission.journal),
                AdmissionPhase::Active => EnrollmentStatus::Active(admission.journal),
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
            load(&active.database, &active.key, self.binding)
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
            write(&active.database, &bytes)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn key(&self) -> Result<JournalKey, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let key = JournalKey::open(&self.paths.wrapping)?;
        if key.installation_binding() != active.key.installation_binding() {
            return Err(DurableError::Conflict);
        }
        Ok(key)
    }
    fn signer(
        &self,
        identity: SigningKeyId,
        creating: bool,
    ) -> Result<DeviceSigningKey, DurableError> {
        let key = self.key()?;
        if creating && missing(&self.paths.signer)? {
            DeviceSigningKey::provision(&self.paths.signer, &key, identity)
        } else {
            DeviceSigningKey::open(&self.paths.signer, &key, identity)
        }
    }
    /// Create/reopen the exact original signer, commit its complete signed request,
    /// then release bytes. Restart/retry returns the identical committed request.
    pub fn request(&mut self, now: u64) -> Result<Vec<u8>, DurableError> {
        let result = (|| {
            self.intent.description.validity.check(now)?;
            let mut image = self.image()?;
            let signer = self.signer(image.identity, matches!(image.phase, Phase::Preparing))?;
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
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Admit the response under an independently obtained CURRENT account/roster
    /// pin and live verified policy. The same signer and exact approved metadata
    /// must match. Commit acceptance and one future journal ID before installation.
    /// An already accepted target is read back, never replaced by another response.
    pub fn accept(
        &mut self,
        certificate: &[u8],
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<JournalIdentity, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            let request = match &image.phase {
                Phase::Preparing => return Err(Error::State.into()),
                Phase::Requested(wire) | Phase::Accepted { request: wire, .. } => wire,
            };
            let original = VerifiedEnrollmentRequest::verify(request, &self.intent, now)?;
            let device = pin.verify_device(certificate, roster, now)?;
            self.intent.verify_device(&device)?;
            self.signer(image.identity, false)?.check_device(&device)?;
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
            self.save(&image)?;
            Ok(journal)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn admitted(
        &self,
        image: &Image,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
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
        let original = VerifiedEnrollmentRequest::verify(request, &self.intent, now)?;
        if original.identity != image.identity || original.public != device.key {
            return Err(DurableError::Conflict);
        }
        self.intent.verify_device(&device)?;
        self.signer(image.identity, false)?.check_device(&device)?;
        admit(&device, policy, now)?;
        Ok(device)
    }
    fn installation(
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
        let key = self.key()?;
        let paths = self.paths.installation.clone();
        let config = paths
            .files()
            .first()
            .copied()
            .ok_or(DurableError::Corrupt)?;
        let owner = if create && *stage == AdmissionPhase::Accepted && missing(config)? {
            DeviceInstallation::provision_with_identity(
                paths,
                &key,
                device,
                policy,
                now,
                admission.journal,
            )?
        } else {
            DeviceInstallation::open(paths, &key, device, policy, now)?
        };
        if owner.identity()? != admission.journal {
            return Err(DurableError::Conflict);
        }
        Ok(owner)
    }
    /// Prepare original empty children through the existing installation contract.
    /// Required-witness genesis is returned for explicit independent enrollment.
    pub fn prepare(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, DurableError> {
        let result = (|| {
            let image = self.image()?;
            if !matches!(
                image.phase,
                Phase::Accepted {
                    stage: AdmissionPhase::Accepted,
                    ..
                }
            ) {
                return Err(Error::State.into());
            }
            let device = self.admitted(&image, policy, now)?;
            self.installation(&image, &device, policy, now, true)?
                .prepare(self.key()?, &device, policy, now)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Construct the required witness client from the original controlled signer,
    /// using the independently pinned witness and explicit carrier. The admitted
    /// policy must require this exact pin; a local-only or changed pin is refused.
    pub fn anchor_client(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let device = self.admitted(&image, policy, now)?;
            if policy.anchor_requirement().binding() != Some(pin.binding()) {
                return Err(Error::Scope.into());
            }
            let client =
                AnchorClient::new(pin, self.signer(image.identity, false)?, transport, timeout)?;
            admit(&device, policy, now)?;
            Ok(client)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Activate/reopen the original prepared installation. Persist Active before
    /// releasing the service/signing owners. Missing required witness never falls
    /// back to local protection. Unknown results require original enrollment open.
    pub fn activate(
        mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<EnrolledDevice, DurableError> {
        let mut image = self.image()?;
        let device = self.admitted(&image, policy, now)?;
        let signer = self.signer(image.identity, false)?;
        let mut installation = self.installation(&image, &device, policy, now, false)?;
        let Phase::Accepted { stage, .. } = &mut image.phase else {
            return Err(Error::State.into());
        };
        if *stage == AdmissionPhase::Accepted {
            if installation.status()? != crate::InstallationStatus::Creating {
                return Err(DurableError::Conflict);
            }
            for path in self.paths.installation.files().into_iter().skip(1) {
                if missing(path)? {
                    return Err(Error::State.into());
                }
            }
            *stage = AdmissionPhase::Activating;
            self.save(&image)?;
        } else if *stage == AdmissionPhase::Active
            && installation.status()? != crate::InstallationStatus::Active
        {
            return Err(DurableError::Conflict);
        }
        let service = installation.activate(self.key()?, &device, policy, now, anchor)?;
        let Phase::Accepted { stage, .. } = &mut image.phase else {
            return Err(Error::State.into());
        };
        if *stage != AdmissionPhase::Active {
            *stage = AdmissionPhase::Active;
            self.save(&image)?;
        }
        // Enrollment adds a durability boundary after installation activation.
        // Recheck live authority at this layer's actual owner-release boundary.
        admit(&device, policy, now)?;
        Ok(EnrolledDevice {
            active: Some(EnrolledOwners {
                enrollment: self,
                service,
                signer,
                device,
            }),
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
    active: Option<EnrolledOwners>,
}
impl EnrolledDevice {
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
fn encode(key: &JournalKey, binding: [u8; 32], image: &Image) -> Result<Vec<u8>, DurableError> {
    let mut bytes = b"QPENST01".to_vec();
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
            bytes.push(*stage as u8);
            field(&mut bytes, request)?;
            field(&mut bytes, &admission.certificate)?;
            field(&mut bytes, &admission.roster)?;
            bytes.extend_from_slice(&admission.checkpoint.version().to_be_bytes());
            bytes.extend_from_slice(&admission.checkpoint.digest());
            bytes.extend_from_slice(&admission.policy);
            bytes.extend_from_slice(admission.journal.as_bytes());
        }
    }
    let mut mac = auth(key)?;
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    if bytes.len() > MAX_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(bytes)
}
fn load(database: &Database, key: &JournalKey, binding: [u8; 32]) -> Result<Image, DurableError> {
    let tx = database.begin_read().map_err(storage)?;
    let tables: Vec<_> = tx.list_tables().map_err(storage)?.collect();
    if tables.len() != 1
        || tables.first().ok_or(DurableError::Corrupt)?.name() != TABLE.name()
        || tx.list_multimap_tables().map_err(storage)?.next().is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = tx.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let saved = table
        .get("enrollment")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    let wire = saved.value();
    if wire.len() < 105 || wire.len() > MAX_IMAGE {
        return Err(DurableError::Corrupt);
    }
    let (body, tag) = wire.split_at(wire.len() - 32);
    let mut mac = auth(key)?;
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| DurableError::Authentication)?;
    let mut d = Decoder::new(body);
    if d.array::<8>()? != *b"QPENST01" || d.array::<32>()? != binding {
        return Err(DurableError::Conflict);
    }
    let identity = SigningKeyId::from_trusted_state(d.array()?)?;
    let phase = match d.array::<1>()? {
        [0] => Phase::Preparing,
        [1] => Phase::Requested(take(&mut d)?),
        [phase @ 2..=4] => {
            let request = take(&mut d)?;
            let certificate = take(&mut d)?;
            let roster = take(&mut d)?;
            let checkpoint = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
            let policy = d.array()?;
            crate::codec::nonzero(&policy)?;
            let journal = JournalIdentity::from_trusted_state(d.array()?)?;
            Phase::Accepted {
                request,
                admission: Admission {
                    certificate,
                    roster,
                    checkpoint,
                    policy,
                    journal,
                },
                stage: match phase {
                    2 => AdmissionPhase::Accepted,
                    3 => AdmissionPhase::Activating,
                    4 => AdmissionPhase::Active,
                    _ => return Err(DurableError::Corrupt),
                },
            }
        }
        _ => return Err(DurableError::Corrupt),
    };
    d.finish()?;
    Ok(Image { identity, phase })
}
fn write(database: &Database, bytes: &[u8]) -> Result<(), DurableError> {
    let tx = transaction(database)?;
    tx.open_table(TABLE)
        .map_err(storage)?
        .insert("enrollment", bytes)
        .map_err(storage)?;
    tx.commit().map_err(DurableError::CommitUncertain)?;
    #[cfg(all(test, unix))]
    tests::after_commit(bytes);
    Ok(())
}
