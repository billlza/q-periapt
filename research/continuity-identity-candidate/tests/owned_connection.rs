// SPDX-License-Identifier: Apache-2.0 OR MIT
//! External consumer of the public installation, identity and TLS contracts.
#![cfg(all(unix, feature = "connection-tls"))]

use p::connection_transport::{
    Actor, Cancellation, ConnectionEndpoint, Consumer, Consumption, Run, RunLimits, Served,
    Submission,
};
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::{
    filesystem::{
        open_private_database, provision_private_file, OwnedPrivateDirectory, PrivateDatabaseError,
    },
    PolicyStore,
};
use q_periapt_rustls::connection::{Credentials, Limits};
use q_periapt_sig::Signer;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[path = "owned_connection/reopen.rs"]
mod reopen;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}
pub(crate) fn store(path: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path)?.sync_all()
}
fn publish_observation(
    path: &Path,
    name: &str,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let mut pending = tempfile::NamedTempFile::new_in(path)?;
    write(pending.as_file_mut())?;
    pending.as_file().sync_all()?;
    pending
        .persist_noclobber(path.join(name))
        .map_err(|error| error.error)?;
    fs::File::open(path)?.sync_all()
}
pub(crate) fn publish_marker(path: &Path, name: &str) -> io::Result<()> {
    publish_observation(path, name, |file| file.write_all(b"1"))
}
fn publish_ready(path: &Path, name: &str, address: SocketAddr) -> io::Result<()> {
    publish_observation(path, name, |file| {
        file.write_all(address.to_string().as_bytes())
    })
}
fn marker_publication_control(path: &Path) -> io::Result<()> {
    let name = "marker-publication-control";
    publish_observation(path, name, |file| {
        // Pause at the actual writer boundary: a concurrent path reader must
        // observe absence both before and after writing the unpublished file.
        assert_eq!(
            fs::read(path.join(name))
                .expect_err("partial marker became visible")
                .kind(),
            io::ErrorKind::NotFound
        );
        file.write_all(b"1")?;
        assert_eq!(
            fs::read(path.join(name))
                .expect_err("unsynced marker became visible")
                .kind(),
            io::ErrorKind::NotFound
        );
        Ok(())
    })?;
    assert_eq!(fs::read(path.join(name))?, b"1");
    assert_eq!(
        publish_marker(path, name)
            .expect_err("marker was replaced")
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(path.join(name))?, b"1");
    Ok(())
}
pub(crate) fn read(path: &Path, name: &str, maximum: usize) -> Result<Vec<u8>> {
    let directory = OwnedPrivateDirectory::open(path)?;
    let file = directory.open_config_file(name, maximum)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("invalid configured file size".into());
    }
    Ok(bytes)
}
pub(crate) fn array<const N: usize>(path: &Path, name: &str) -> Result<[u8; N]> {
    read(path, name, N)?
        .try_into()
        .map_err(|_| "configured width differs".into())
}
fn paths(path: &Path) -> Result<p::InstallationPaths> {
    Ok(p::InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("journal.redb"),
        &path.join("archives.redb"),
    )?)
}
fn key(path: &Path) -> Result<p::JournalKey> {
    Ok(p::JournalKey::open(&path.join("wrap.key"))?)
}
fn role(path: &Path) -> Result<p::BootstrapRole> {
    match array::<1>(path, "role")? {
        [1] => Ok(p::BootstrapRole::Initiator),
        [2] => Ok(p::BootstrapRole::Responder),
        _ => Err("unknown configured bootstrap role".into()),
    }
}
pub(crate) fn limits() -> RunLimits {
    RunLimits {
        exchanges: 8,
        timeout: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(1),
        outer_deadline: None,
    }
}
pub(crate) fn tls_limits() -> Limits {
    Limits {
        max_connections: 1,
        handshake_ms: 10_000,
        request_ms: 10_000,
        idle_ms: 10_000,
    }
}

pub(crate) struct SdkIssuer {
    key: Zeroizing<[u8; q_periapt_backends::ML_DSA_65_SK_LEN]>,
    public: [u8; q_periapt_backends::ML_DSA_65_VK_LEN],
}
impl SdkIssuer {
    fn new() -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut())?;
        let (key, public) = q_periapt_backends::MlDsa65::generate(*seed);
        Ok(Self {
            key: Zeroizing::new(key),
            public,
        })
    }
    pub(crate) fn policy(&self, revision: u64, enabled: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        let kems = if enabled {
            "[\"ML-KEM-768\",\"X25519\"]"
        } else {
            "[\"ML-KEM-1024\",\"X25519\"]"
        };
        let text = format!("schema_version=1\npolicy_version={revision}\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems={kems}\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n").into_bytes();
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(randomness.as_mut())?;
        let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
        q_periapt_backends::MlDsa65
            .sign(
                self.key.as_ref(),
                &q_periapt_policy::policy_signature_message(&text),
                randomness.as_ref(),
                &mut signature,
            )
            .map_err(|e| io::Error::other(format!("SDK policy signing failed: {e:?}")))?;
        Ok((text, signature))
    }
}
pub(crate) fn sdk(path: &Path) -> Result<PolicyStore> {
    Ok(PolicyStore::open_configured(
        &path.join("sdk.redb"),
        &read(path, "sdk-policy", 4096)?,
        &read(path, "sdk-signature", 8192)?,
        &read(path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?)
}
fn protocol_policy(path: &Path, store: &PolicyStore) -> Result<Arc<p::VerifiedSessionPolicy>> {
    let checkpoint = p::PolicyCheckpoint::from_trusted_state(
        u64::from_be_bytes(array(path, "policy-version")?),
        array(path, "policy-digest")?,
    )?;
    let pin = p::PolicyPin::new(
        array(path, "family")?,
        p::PublicKey::decode(&read(path, "policy-root", 8192)?)?,
        checkpoint,
    )?;
    Ok(Arc::new(pin.verify(
        &read(path, "protocol-policy", 8192)?,
        store.runtime()?,
        now()?,
    )?))
}
fn account(path: &Path, label: &str) -> Result<p::AccountPin> {
    Ok(p::AccountPin::new(
        array(path, &format!("{label}-account"))?,
        p::PublicKey::decode(&read(path, &format!("{label}-root"), 8192)?)?,
        p::RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(array(path, &format!("{label}-roster-version"))?),
            array(path, &format!("{label}-roster-digest"))?,
        )?,
        array(path, "family")?,
    )?)
}
fn with_bundle<T>(
    path: &Path,
    check: impl FnOnce(p::BootstrapBundle, p::BootstrapRequirements<'_>) -> Result<T>,
) -> Result<T> {
    let i = account(path, "initiator")?;
    let r = account(path, "responder")?;
    let requirements = p::BootstrapRequirements {
        initiator: p::ExpectedDevice::new(
            &i,
            array(path, "initiator-device")?,
            u64::from_be_bytes(array(path, "initiator-generation")?),
        )?,
        responder: p::ExpectedDevice::new(
            &r,
            array(path, "responder-device")?,
            u64::from_be_bytes(array(path, "responder-generation")?),
        )?,
        quality: p::PrekeyQuality::OneTimeBoth,
        directory: p::DirectoryExpectation::from_trusted_state(array(path, "directory")?)?,
    };
    let bundle = p::BootstrapBundle::from_bytes(&read(
        path,
        "bootstrap.bundle",
        p::MAX_BOOTSTRAP_BUNDLE_BYTES,
    )?)?;
    check(bundle, requirements)
}
fn context(path: &Path, sdk: &PolicyStore, at: u64) -> Result<Arc<p::BootstrapContext>> {
    let policy = protocol_policy(path, sdk)?;
    let context = with_bundle(path, |bundle, requirements| {
        Ok(Arc::new(bundle.verify(
            Arc::clone(&policy),
            requirements,
            at,
        )?))
    })?;
    assert!(std::ptr::eq(Arc::as_ptr(&policy), context.policy()));
    assert_eq!(
        context.device(p::BootstrapRole::Initiator).device_id(),
        array::<16>(path, "initiator-device")?
    );
    assert_eq!(
        context.device(p::BootstrapRole::Responder).device_id(),
        array::<16>(path, "responder-device")?
    );
    Ok(context)
}

pub(crate) struct Peer {
    pub(crate) service: p::DeviceService,
    pub(crate) signer: p::DeviceSigningKey,
    pub(crate) context: Arc<p::BootstrapContext>,
    policy_store: PolicyStore,
    certificate: Vec<u8>,
    tls_key: Zeroizing<Vec<u8>>,
    peer_certificate: Vec<u8>,
    pub(crate) peer_name: String,
}
impl Peer {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        Self::open_with_witness(path, None)
    }
    pub(crate) fn open_with_witness(path: &Path, witness: Option<&WitnessFixture>) -> Result<Self> {
        Self::open_at_with_witness(path, witness, now()?)
    }
    pub(crate) fn open_at_with_witness(
        path: &Path,
        witness: Option<&WitnessFixture>,
        at: u64,
    ) -> Result<Self> {
        let policy_store = sdk(path)?;
        let context = context(path, &policy_store, at)?;
        let role = role(path)?;
        let device = context.device(role);
        let key = key(path)?;
        let id = p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?;
        let signer = p::DeviceSigningKey::open(&path.join("signer.key"), &key, id)?;
        let owner = p::DeviceInstallation::open(paths(path)?, &key, device, context.policy(), at)?;
        let anchor = witness.map(|value| value.client(path)).transpose()?;
        let service = owner.activate(key, device, context.policy(), at, anchor)?;
        Ok(Self {
            service,
            signer,
            context,
            policy_store,
            certificate: read(path, "tls-cert", 8192)?,
            tls_key: Zeroizing::new(read(path, "tls-key", 8192)?),
            peer_certificate: read(path, "tls-peer", 8192)?,
            peer_name: String::from_utf8(read(path, "tls-peer-name", 128)?)?,
        })
    }
    pub(crate) fn credentials(&self) -> Credentials<'_> {
        Credentials {
            certificate: &self.certificate,
            private_key: &self.tls_key,
            peer_certificate: &self.peer_certificate,
        }
    }
    pub(crate) fn actor(&mut self) -> Result<Actor<'_>> {
        let (journal, archives) = self.service.stores()?;
        Ok(Actor {
            journal,
            archives,
            context: &self.context,
            signer: &self.signer,
        })
    }
    pub(crate) fn close(&mut self) {
        self.service.close();
        self.signer.close();
        self.context.policy().close();
        self.policy_store.close();
    }
}

pub(crate) struct Setup {
    _directory: Option<tempfile::TempDir>,
    pub(crate) initiator: PathBuf,
    pub(crate) responder: PathBuf,
    pub(crate) issuer: SdkIssuer,
}
pub(crate) fn setup() -> Result<Setup> {
    setup_with_witness(None)
}
/// Qualification-only explicit real witness store and socket, not incoming trust.
pub(crate) struct WitnessFixture {
    pub(crate) store: Arc<std::sync::Mutex<p::AnchorStore>>,
    pub(crate) address: SocketAddr,
}
impl WitnessFixture {
    fn pin(&self) -> Result<p::AnchorPin> {
        Ok(self
            .store
            .lock()
            .map_err(|_| "witness store poisoned")?
            .pin()?)
    }
    pub(crate) fn client(&self, path: &Path) -> Result<p::AnchorClient> {
        let key = key(path)?;
        let signer = p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key,
            p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?,
        )?;
        Ok(p::AnchorClient::new(
            self.pin()?,
            signer,
            Box::new(p::AnchorTcpTransport::new(self.address)),
            Duration::from_secs(3),
        )?)
    }
}
pub(crate) fn setup_with_witness(witness: Option<&WitnessFixture>) -> Result<Setup> {
    setup_with_advertisement(witness, None)
}
fn setup_with_advertisement(
    witness: Option<&WitnessFixture>,
    advertisement_seconds: Option<u64>,
) -> Result<Setup> {
    setup_with_time(witness, advertisement_seconds, None)
}
pub(crate) fn setup_with_time(
    witness: Option<&WitnessFixture>,
    advertisement_seconds: Option<u64>,
    at: Option<u64>,
) -> Result<Setup> {
    Ok(setup_devices(witness, advertisement_seconds, at, false)?.0)
}

/// Build the ordinary pair or two independently credentialed account recipients.
pub(crate) fn setup_devices(
    witness: Option<&WitnessFixture>,
    advertisement_seconds: Option<u64>,
    at: Option<u64>,
    multi: bool,
) -> Result<(Setup, Option<PathBuf>)> {
    let (dir, root) = if let Some(path) = std::env::var_os("QPERIAPT_PUBLIC_SERVICE_EVIDENCE") {
        let mut path = PathBuf::from(path);
        if advertisement_seconds.is_some() || multi {
            let mut name = path.file_name().ok_or("evidence filename")?.to_os_string();
            name.push(if multi { "-account" } else { "-session-reopen" });
            path.set_file_name(name);
        }
        if !path.is_absolute() {
            return Err("reference evidence path must be absolute".into());
        }
        OwnedPrivateDirectory::open(path.parent().ok_or("evidence parent")?)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        (None, path.canonicalize()?)
    } else {
        let dir = tempfile::Builder::new()
            .prefix("continuity-public-service-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = dir.path().canonicalize()?;
        (Some(dir), path)
    };
    let left = root.join("initiator");
    let right = root.join("responder");
    let extra = multi.then(|| root.join("responder-2"));
    let mut all_paths = vec![&left, &right];
    all_paths.extend(extra.iter());
    for path in &all_paths {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let issuer = SdkIssuer::new()?;
    let (policy, signature) = issuer.policy(1, true)?;
    let mut stores = Vec::new();
    let mut signing = Vec::new();
    for (index, path) in all_paths.iter().enumerate() {
        let role = if index == 0 { 1u8 } else { 2u8 };
        store(path, "sdk-policy", &policy)?;
        store(path, "sdk-signature", &signature)?;
        store(path, "sdk-root", &issuer.public)?;
        store(path, "role", &[role])?;
        stores.push(PolicyStore::provision(
            &path.join("sdk.redb"),
            &policy,
            &signature,
            &issuer.public,
            q_periapt_sdk::Limits::default(),
        )?);
        let key = p::JournalKey::provision(&path.join("wrap.key"))?;
        let id = p::SigningKeyId::generate()?;
        store(path, "signer-id", id.as_bytes())?;
        signing.push(p::DeviceSigningKey::provision(
            &path.join("signer.key"),
            &key,
            id,
        )?);
    }
    let time = match at {
        Some(value) => value,
        None => now()?,
    };
    let validity = p::Validity::new(
        time.saturating_sub(1),
        time.checked_add(3600).ok_or("clock overflow")?,
    )?;
    let advertisement = match advertisement_seconds {
        Some(seconds) => p::Validity::new(
            validity.from(),
            time.checked_add(seconds).ok_or("advertisement overflow")?,
        )?,
        None => validity,
    };
    if advertisement.until() > validity.until() {
        return Err("advertisement exceeds credential".into());
    }
    let mut authority = p::PolicySigningKey::generate()?;
    let sdk = stores.first().ok_or("SDK owner")?.runtime()?;
    let issued = authority.issue_session_policy(
        &sdk,
        p::SessionPolicyParameters::new(
            1,
            validity,
            p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
            match witness {
                Some(witness) => p::AnchorRequirement::required(&witness.pin()?),
                None => p::AnchorRequirement::local_only(),
            },
            p::ApplicationSendBudget::new(1024)?,
        )?,
    )?;
    let family = authority.policy_family()?;
    for path in &all_paths {
        if let Some(witness) = witness {
            let pin = witness.pin()?;
            store(path, "witness-id", pin.identity().as_bytes())?;
            store(path, "witness-public", &pin.public_key().encode())?;
        }
        for (name, bytes) in [
            ("family", family.to_vec()),
            ("policy-root", authority.public_key()?.encode()),
            (
                "policy-version",
                issued.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("policy-digest", issued.checkpoint().digest().to_vec()),
            ("protocol-policy", issued.as_bytes().to_vec()),
            ("directory", vec![99; 32]),
        ] {
            store(path, name, &bytes)?;
        }
    }
    authority.close();
    let mut devices = Vec::new();
    let mut credentials = Vec::new();
    let mut rosters = Vec::new();
    for group in [0..1, 1..all_paths.len()] {
        let mut root = p::RootSigningKey::generate()?;
        let mut certificates = Vec::new();
        for ordinal in group.clone() {
            certificates.push(root.issue_device(
                p::DeviceDescription::new([u8::try_from(ordinal + 1)?; 16], 1, family, validity)?,
                signing.get(ordinal).ok_or("signer")?.public_key()?,
            )?);
        }
        let entries = certificates
            .iter()
            .map(|certificate| root.roster_entry(certificate))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let roster = root.issue_roster(1, validity, &entries)?;
        let pin = p::AccountPin::new(
            root.account_id()?,
            root.public_key()?,
            roster.checkpoint(),
            family,
        )?;
        for (ordinal, certificate) in group.zip(certificates) {
            let path = all_paths.get(ordinal).ok_or("local path")?;
            let device_id = [u8::try_from(ordinal + 1)?; 16];
            devices.push(pin.verify_device(&certificate, roster.as_bytes(), time)?);
            for (name, bytes) in [
                ("account", root.account_id()?.to_vec()),
                ("root", root.public_key()?.encode()),
                (
                    "roster-version",
                    roster.checkpoint().version().to_be_bytes().to_vec(),
                ),
                ("roster-digest", roster.checkpoint().digest().to_vec()),
                ("device", device_id.to_vec()),
                ("generation", 1u64.to_be_bytes().to_vec()),
                ("certificate", certificate.clone()),
                ("roster", roster.as_bytes().to_vec()),
            ] {
                store(path, &format!("local-{name}"), &bytes)?;
            }
            credentials.push(certificate);
            rosters.push(roster.as_bytes().to_vec());
        }
        root.close();
    }
    let mut peers = Vec::new();
    for index in 1..all_paths.len() {
        let peer = if multi {
            let path = left.join(format!("peer-{}", index - 1));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            path
        } else {
            left.clone()
        };
        let responder = all_paths.get(index).ok_or("responder path")?;
        for (label, source) in [("initiator", &left), ("responder", *responder)] {
            for name in [
                "account",
                "root",
                "roster-version",
                "roster-digest",
                "device",
                "generation",
            ] {
                let bytes = read(source, &format!("local-{name}"), 8192)?;
                for destination in [&peer, *responder] {
                    store(destination, &format!("{label}-{name}"), &bytes)?;
                }
            }
        }
        if multi {
            store(&peer, "directory", &[99; 32])?;
        }
        peers.push(peer);
    }
    let mut services = Vec::new();
    for (index, path) in all_paths.iter().enumerate() {
        let wrapping = key(path)?;
        let policy = protocol_policy(path, stores.get(index).ok_or("SDK owner")?)?;
        let device = devices.get(index).ok_or("device")?;
        let mut install =
            p::DeviceInstallation::provision(paths(path)?, &wrapping, device, &policy, time)?;
        match (witness, install.prepare(wrapping, device, &policy, time)?) {
            (None, p::InstallationPreparation::Local) => {}
            (Some(witness), p::InstallationPreparation::RequiresEnrollment(genesis)) => {
                // Retain the operator's original enrollment scope for TLS peer
                // authorization; never infer that scope from an incoming request.
                store(path, "witness-subject", &genesis.subject().to_bytes())?;
                witness
                    .store
                    .lock()
                    .map_err(|_| "witness enrollment lock poisoned")?
                    .enroll(&genesis, device, &policy, time)?;
            }
            _ => return Err("installation changed the requested witness profile".into()),
        }
        let anchor = witness.map(|witness| witness.client(path)).transpose()?;
        services.push(install.activate(key(path)?, device, &policy, time, anchor)?);
    }
    if advertisement_seconds.is_some() {
        for path in &all_paths {
            store(
                path,
                "reopen-test-time",
                &advertisement.until().to_be_bytes(),
            )?;
        }
    }
    let mut identities = Vec::new();
    for (index, path) in all_paths.iter().enumerate() {
        let name = if index == 0 {
            "initiator.test"
        } else {
            "responder.test"
        };
        let tls = rcgen::generate_simple_self_signed(vec![name.into()])?;
        store(path, "tls-cert", tls.cert.der())?;
        store(
            path,
            "tls-key",
            &Zeroizing::new(tls.signing_key.serialize_der()),
        )?;
        identities.push(tls);
    }
    for (index, responder) in all_paths.iter().enumerate().skip(1) {
        let peer = peers.get(index - 1).ok_or("sender peer")?;
        let server_device = devices.get(index).ok_or("responder")?;
        let server_policy = protocol_policy(responder, stores.get(index).ok_or("responder SDK")?)?;
        let mut leaves = Vec::new();
        for (leaf_index, kind) in [
            p::LeafKind::SignedClassical,
            p::LeafKind::OneTimeClassical,
            p::LeafKind::LastResortPq,
            p::LeafKind::OneTimePq,
        ]
        .into_iter()
        .enumerate()
        {
            let request = p::PrekeyId::from_trusted_state([u8::try_from(leaf_index + 1)?; 32])?;
            leaves.push(
                services
                    .get_mut(index)
                    .ok_or("server service")?
                    .stores()?
                    .0
                    .generate_prekey(
                        &server_policy,
                        server_device,
                        request,
                        kind,
                        advertisement,
                        time,
                    )?,
            );
        }
        let manifest = signing
            .get(index)
            .ok_or("responder signer")?
            .issue_manifest(
                server_device,
                p::ManifestContext::new(
                    1,
                    sdk.trusted_state().digest(),
                    p::bootstrap_suite_digest(),
                    [99; 32],
                    advertisement,
                )?,
                &leaves,
            )?;
        let verified = server_device.verify_manifest(manifest.as_bytes(), time)?;
        let mut proofs = BTreeMap::new();
        for index in 0..manifest.leaf_count() {
            let proof = manifest.proof(index)?;
            proofs.insert(
                verified.verify_leaf(&proof, time)?.kind() as u8,
                proof.encode()?,
            );
        }
        let proof = |kind: p::LeafKind| -> Result<&[u8]> {
            Ok(proofs.get(&(kind as u8)).ok_or("required proof")?)
        };
        let bundle = p::BootstrapBundle::from_materials(
            p::PrekeyQuality::OneTimeBoth,
            p::BootstrapMaterials {
                initiator_credential: credentials.first().ok_or("initiator credential")?,
                initiator_roster: rosters.first().ok_or("initiator roster")?.as_slice(),
                responder_credential: credentials.get(index).ok_or("responder credential")?,
                responder_roster: rosters.get(index).ok_or("responder roster")?.as_slice(),
                responder_manifest: manifest.as_bytes(),
                signed_classical: proof(p::LeafKind::SignedClassical)?,
                last_resort_pq: proof(p::LeafKind::LastResortPq)?,
                one_time_classical: Some(proof(p::LeafKind::OneTimeClassical)?),
                one_time_pq: Some(proof(p::LeafKind::OneTimePq)?),
            },
        )?;
        let left_tls = identities.first().ok_or("sender TLS")?;
        let right_tls = identities.get(index).ok_or("receiver TLS")?;
        for (path, remote, name) in [
            (peer, right_tls, "responder.test"),
            (*responder, left_tls, "initiator.test"),
        ] {
            store(path, "bootstrap.bundle", bundle.as_bytes())?;
            store(path, "tls-peer", remote.cert.der())?;
            store(path, "tls-peer-name", name.as_bytes())?;
        }
    }
    for service in &mut services {
        service.close();
    }
    for key in &mut signing {
        key.close();
    }
    for policy in &mut stores {
        policy.close();
    }
    Ok((
        Setup {
            _directory: dir,
            initiator: left,
            responder: right,
            issuer,
        },
        extra,
    ))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn effect(
    path: &Path,
    session: [u8; 32],
    id: p::MessageId,
    plaintext: &[u8],
) -> Result<()> {
    let mut expected = session.to_vec();
    expected.extend_from_slice(id.as_bytes());
    expected.extend_from_slice(plaintext);
    assert_eq!(
        read(path, &format!("application-{}", hex(id.as_bytes())), 65536)?,
        expected
    );
    Ok(())
}
struct Application {
    path: PathBuf,
    mode: String,
}
impl Consumer for Application {
    fn commit(&mut self, session: [u8; 32], delivery: &p::CommittedPlaintext) -> io::Result<()> {
        let name = format!("application-{}", hex(delivery.message_id().as_bytes()));
        let mut bytes = session.to_vec();
        bytes.extend_from_slice(delivery.message_id().as_bytes());
        bytes.extend_from_slice(delivery.as_bytes());
        match fs::symlink_metadata(self.path.join(&name)) {
            Ok(_) => {
                let parent = OwnedPrivateDirectory::open(&self.path).map_err(io::Error::other)?;
                let mut file = parent
                    .open_state_file(std::ffi::OsStr::new(&name))
                    .map_err(io::Error::other)?;
                let mut existing = Vec::new();
                Read::by_ref(&mut file)
                    .take(65537)
                    .read_to_end(&mut existing)?;
                if existing != bytes {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                file.sync_all()?;
                parent.sync_entries().map_err(io::Error::other)?;
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        provision_private_file(&self.path.join(&name), io::Error::other, |mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        })?;
        if self.mode == "crash-after-application" {
            std::process::exit(77);
        }
        Ok(())
    }
}
pub(crate) struct OwnedChild(pub(crate) Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        if let Err(e) = self.0.kill() {
            eprintln!("owned peer termination failed: {e}");
        }
        if let Err(e) = self.0.wait() {
            eprintln!("owned peer reap failed: {e}");
        }
    }
}
pub(crate) fn wait(child: &mut OwnedChild) -> Result<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("peer process did not finish within deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn child(path: &Path, attempt: u8, mode: &str) -> Result<OwnedChild> {
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join(format!("peer-{attempt}.log")))?;
    // The same archive-shipped workload can be included as a consumer fixture
    // module. Derive the real harness name rather than running an empty filter.
    let process_test = module_path!().split_once("::").map_or_else(
        || "service_peer_process".to_owned(),
        |(_, module)| format!("{module}::service_peer_process"),
    );
    Ok(OwnedChild(
        Command::new(std::env::current_exe()?)
            .args(["--exact", &process_test, "--nocapture"])
            .env("QPERIAPT_PUBLIC_SERVICE_ROOT", path)
            .env("QPERIAPT_PUBLIC_SERVICE_ATTEMPT", attempt.to_string())
            .env("QPERIAPT_PUBLIC_SERVICE_MODE", mode)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    ))
}
pub(crate) fn spawn(path: &Path, attempt: u8, mode: &str) -> Result<(OwnedChild, SocketAddr)> {
    let mut child = child(path, attempt, mode)?;
    let marker = path.join(format!("ready-{attempt}"));
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match fs::read_to_string(&marker) {
            Ok(address) => return Ok((child, address.parse()?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "peer readiness failed: {}",
                fs::read_to_string(path.join(format!("peer-{attempt}.log")))?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(crate) fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(e),
        }
    }
}

#[test]
fn service_peer_process() -> Result<()> {
    let Some(root) = std::env::var_os("QPERIAPT_PUBLIC_SERVICE_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let attempt: u8 = std::env::var("QPERIAPT_PUBLIC_SERVICE_ATTEMPT")?.parse()?;
    let mode = std::env::var("QPERIAPT_PUBLIC_SERVICE_MODE")?;
    if mode == "contender" || mode == "recovery-contender" {
        let files: &[&str] = if mode == "contender" {
            &[
                "sdk.redb",
                "installation.redb",
                "journal.redb",
                "archives.redb",
            ]
        } else {
            &["installation.redb", "journal.redb", "archives.redb"]
        };
        for name in files {
            assert!(
                matches!(
                    open_private_database(&root.join(name)),
                    Err(PrivateDatabaseError::Busy)
                ),
                "lease {name}"
            );
        }
        return Ok(());
    }
    if mode == "cleanup-freeze" || mode == "cleanup-finish" || mode == "cleanup-verify" {
        let session = array(root, "session")?;
        let mut recovery = p::InstallationRecovery::open(paths(root)?, key(root)?)?;
        if mode == "cleanup-verify" {
            assert!(recovery.session_ids()?.is_empty());
            let archive =
                p::SessionClosureArchive::from_bytes(&read(root, "closure-archive", 1024)?)?;
            let mut owner = recovery.open_session_from_archive(&archive, None)?;
            let report = p::SessionClosureId::from_trusted_state(array(root, "closure-id")?)?;
            assert_eq!(
                owner.stores()?.0.status()?,
                p::SessionClosureStatus::Closed(report)
            );
            store(root, "cleanup-verified", report.as_bytes())?;
            return Ok(());
        }
        assert_eq!(recovery.session_ids()?, vec![session]);
        let mut owner = recovery.open_session(session, None)?;
        if mode == "cleanup-freeze" {
            let mut contender = child(root, 91, "recovery-contender")?;
            assert!(wait(&mut contender)?.success());
        }
        let (journal, index) = owner.stores()?;
        if mode == "cleanup-freeze" {
            store(root, "closure-archive", index.get(session)?.as_bytes())?;
        }
        let report = journal.begin()?;
        assert_eq!(report.session, session);
        let accounting = format!("{report:?}\n").into_bytes();
        if mode == "cleanup-freeze" {
            store(root, "closure-report", &accounting)?;
            store(root, "closure-id", report.report.as_bytes())?;
            std::process::exit(77);
        }
        assert_eq!(read(root, "closure-report", 65536)?, accounting);
        assert_eq!(array::<32>(root, "closure-id")?, *report.report.as_bytes());
        journal.acknowledge(report.report)?;
        assert_eq!(
            journal.status()?,
            p::SessionClosureStatus::Closed(report.report)
        );
        assert!(index.retire_closed(journal, report.report)?);
        assert!(!index.retire_closed(journal, report.report)?);
        assert!(index.session_ids()?.is_empty());
        owner.close();
        assert!(matches!(owner.stores(), Err(p::DurableError::Closed)));
        store(root, "cleanup-complete", report.report.as_bytes())?;
        return Ok(());
    }
    if mode == "reopen-application" {
        return reopen::serve_reopened(root, attempt);
    }
    if let Some(application_mode) = mode.strip_prefix("restore-current-") {
        if !matches!(application_mode, "application" | "crash-after-application") {
            return Err("unknown current-clock restore scenario".into());
        }
        return reopen::serve_restored_current(root, attempt, application_mode);
    }
    let mut peer = Peer::open(root)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = ConnectionEndpoint::server(&peer.context, peer.credentials(), tls_limits())?;
    publish_ready(root, &format!("ready-{attempt}"), listener.local_addr()?)?;
    #[cfg(feature = "control-tls")]
    if mode == "rekey" {
        let session = array(root, "session")?;
        let control = p::control_transport::ControlEndpoint::server(
            &peer.context,
            session,
            peer.credentials(),
            tls_limits(),
        )?;
        let (journal, _) = peer.service.stores()?;
        control.serve(
            accept(&listener)?,
            p::control_transport::Session {
                journal,
                context: &peer.context,
                signer: &peer.signer,
            },
            limits(),
            &Cancellation::default(),
            now,
        )?;
        return Ok(());
    }
    if !matches!(
        mode.as_str(),
        "bootstrap" | "application" | "crash-after-application"
    ) {
        return Err("unknown peer operation".into());
    }
    let mut app = Application {
        path: root.into(),
        mode,
    };
    let result = endpoint.serve(
        accept(&listener)?,
        peer.actor()?,
        &mut app,
        limits(),
        &Cancellation::default(),
        now,
    )?;
    if let Served::Established(session) = result {
        store(root, "session", &session)?;
    }
    peer.close();
    Ok(())
}

pub(crate) fn send(
    peer: &mut Peer,
    endpoint: &ConnectionEndpoint,
    address: SocketAddr,
    session: [u8; 32],
    id: p::MessageId,
    bytes: &[u8],
) -> Result<p::connection_transport::Delivered> {
    let name = peer.peer_name.clone();
    Ok(endpoint.send(
        peer.actor()?,
        Submission {
            session,
            message: id,
            plaintext: bytes,
            associated_data: b"owned-service",
        },
        Run {
            address,
            server_name: &name,
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        now,
    )?)
}

#[test]
fn owned_services_connect_restart_rekey_and_reconcile_unknown_delivery() -> Result<()> {
    let s = setup()?;
    marker_publication_control(&s.initiator)?;
    eprintln!("PUBLIC_SERVICE_STAGE enrollment_complete");
    fs::write(s.initiator.join("role"), [2])?;
    let wrong_role = match Peer::open(&s.initiator) {
        Ok(_) => return Err("peer device metadata granted the local installation".into()),
        Err(error) => error,
    };
    assert!(matches!(
        wrong_role.downcast_ref::<p::DurableError>(),
        Some(p::DurableError::Conflict)
    ));
    fs::write(s.initiator.join("role"), [1])?;
    let mut client = Peer::open(&s.initiator)?;
    let endpoint = ConnectionEndpoint::client(&client.context, client.credentials(), tls_limits())?;
    let (mut server, address) = spawn(&s.responder, 0, "bootstrap")?;
    for path in [&s.initiator, &s.responder] {
        let mut contender = child(path, 90, "contender")?;
        assert!(
            wait(&mut contender)?.success(),
            "{}",
            String::from_utf8(read(path, "peer-90.log", 65536)?)?
        );
    }
    let name = client.peer_name.clone();
    let request = p::InitiationId::generate()?;
    store(&s.initiator, "initiation", request.as_bytes())?;
    let established = endpoint.establish(
        client.actor()?,
        request,
        Run {
            address,
            server_name: &name,
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        now,
    )?;
    assert!(wait(&mut server)?.success());
    assert_eq!(array::<32>(&s.responder, "session")?, established.session);
    store(&s.initiator, "session", &established.session)?;
    eprintln!("PUBLIC_SERVICE_STAGE bootstrap_complete");
    let context = Arc::clone(&client.context);
    let id = client
        .service
        .stores()?
        .0
        .next_message_id(&context, established.session, now()?)?;
    store(&s.initiator, "uncertain-message", id.as_bytes())?;
    let (mut server, address) = spawn(&s.responder, 1, "crash-after-application")?;
    assert!(send(
        &mut client,
        &endpoint,
        address,
        established.session,
        id,
        b"persisted before process exit"
    )
    .is_err());
    assert_eq!(wait(&mut server)?.code(), Some(77));
    effect(
        &s.responder,
        established.session,
        id,
        b"persisted before process exit",
    )?;
    assert_eq!(
        client
            .service
            .stores()?
            .0
            .message_status(&context, established.session, id)?,
        p::MessageStatus::Committed
    );
    client.close();
    client = Peer::open(&s.initiator)?;
    let endpoint = ConnectionEndpoint::client(&client.context, client.credentials(), tls_limits())?;
    let saved = p::MessageId::from_trusted_state(array(&s.initiator, "uncertain-message")?)?;
    assert_eq!(saved, id);
    let (mut server, address) = spawn(&s.responder, 2, "application")?;
    let delivered = send(
        &mut client,
        &endpoint,
        address,
        established.session,
        saved,
        b"persisted before process exit",
    )?;
    assert_eq!(delivered.consumption, Consumption::Confirmed);
    assert!(wait(&mut server)?.success());
    effect(
        &s.responder,
        established.session,
        saved,
        b"persisted before process exit",
    )?;
    assert_eq!(
        client
            .service
            .stores()?
            .0
            .message_status(&client.context, established.session, saved)?,
        p::MessageStatus::Acknowledged
    );
    eprintln!("PUBLIC_SERVICE_STAGE unknown_delivery_reconciled");
    #[cfg(feature = "control-tls")]
    {
        let (mut server, address) = spawn(&s.responder, 3, "rekey")?;
        let control = p::control_transport::ControlEndpoint::client(
            &client.context,
            established.session,
            client.credentials(),
            tls_limits(),
        )?;
        let (journal, _) = client.service.stores()?;
        let result = control.run(
            p::control_transport::Session {
                journal,
                context: &client.context,
                signer: &client.signer,
            },
            p::control_transport::Run {
                target: 1,
                address,
                server_name: &client.peer_name,
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            now,
        )?;
        assert_eq!(result.epoch, 1);
        assert!(wait(&mut server)?.success());
    }
    client.close();
    let network_rekeys = u8::from(cfg!(feature = "control-tls"));
    eprintln!("PUBLIC_SERVICE_STAGE restart_complete network_rekeys={network_rekeys}");
    let (mut receiver, address) = spawn(&s.initiator, 4, "application")?;
    let mut sender = Peer::open(&s.responder)?;
    let reverse = ConnectionEndpoint::client(&sender.context, sender.credentials(), tls_limits())?;
    let id =
        sender
            .service
            .stores()?
            .0
            .next_message_id(&sender.context, established.session, now()?)?;
    let delivered = send(
        &mut sender,
        &reverse,
        address,
        established.session,
        id,
        b"reverse after original installation restart",
    )?;
    assert_eq!(delivered.consumption, Consumption::Confirmed);
    assert!(wait(&mut receiver)?.success());
    effect(
        &s.initiator,
        established.session,
        id,
        b"reverse after original installation restart",
    )?;
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let next =
        sender
            .service
            .stores()?
            .0
            .next_message_id(&sender.context, established.session, now()?)?;
    assert!(matches!(
        reverse.send(
            sender.actor()?,
            Submission {
                session: established.session,
                message: next,
                plaintext: b"cancelled",
                associated_data: b"owned-service"
            },
            Run {
                address,
                server_name: "initiator.test",
                limits: limits(),
                cancel: &cancelled
            },
            now
        ),
        Err(p::connection_transport::Error::Cancelled)
    ));
    assert_eq!(
        sender
            .service
            .stores()?
            .0
            .message_status(&sender.context, established.session, next)?,
        p::MessageStatus::Absent
    );
    let prior = sender.policy_store.runtime()?.trusted_state();
    eprintln!("PUBLIC_SERVICE_STAGE reverse_delivery_and_cancellation_complete");
    let (revoked, signature) = s.issuer.policy(2, false)?;
    sender
        .policy_store
        .replace_policy(prior, &revoked, &signature)?;
    assert!(!sender.policy_store.runtime()?.is_enabled()?);
    assert!(matches!(
        sender
            .service
            .stores()?
            .0
            .next_message_id(&sender.context, established.session, now()?),
        Err(p::DurableError::Protocol(p::Error::Runtime(
            q_periapt_sdk::Error::Closed
        )))
    ));
    sender.close();
    assert!(matches!(
        sender
            .context
            .policy()
            .check_mode(p::PrekeyQuality::OneTimeBoth, now()?),
        Err(p::Error::Closed)
    ));
    let reopened = match Peer::open(&s.responder) {
        Ok(_) => return Err("old policy config reopened a revoked service".into()),
        Err(error) => error,
    };
    assert!(matches!(
        reopened.downcast_ref::<q_periapt_host_store::StoreError>(),
        Some(q_periapt_host_store::StoreError::Policy(
            q_periapt_sdk::Error::PolicyDenied
        ))
    ));
    let mut cleanup = child(&s.responder, 5, "cleanup-freeze")?;
    assert_eq!(wait(&mut cleanup)?.code(), Some(77));
    let retained_report = array::<32>(&s.responder, "closure-id")?;
    let mut cleanup = child(&s.responder, 6, "cleanup-finish")?;
    assert!(wait(&mut cleanup)?.success());
    assert_eq!(
        array::<32>(&s.responder, "cleanup-complete")?,
        retained_report
    );
    let mut cleanup = child(&s.responder, 7, "cleanup-verify")?;
    assert!(wait(&mut cleanup)?.success());
    assert_eq!(
        array::<32>(&s.responder, "cleanup-verified")?,
        retained_report
    );
    assert!(
        p::InstallationRecovery::open(paths(&s.responder)?, key(&s.responder)?)?
            .session_ids()?
            .is_empty()
    );
    let receipt = format!("{{\"session\":\"{}\",\"forward_message\":\"{}\",\"reverse_message\":\"{}\",\"network_rekeys\":{network_rekeys},\"independent_readbacks\":3,\"exclusive_leases_checked\":8,\"unknown_delivery_reconciled\":true,\"durable_sdk_revocation\":true,\"cleanup_after_revocation\":true,\"cleanup_exclusive_leases_checked\":3}}\n",
        hex(&established.session),hex(saved.as_bytes()),hex(id.as_bytes()));
    store(
        s.initiator.parent().ok_or("reference root")?,
        "public-result.json",
        receipt.as_bytes(),
    )?;
    eprintln!("OWNED_SERVICE_PUBLIC_REFERENCE processes=true local_private_signers=true persistent_sdk_policy=true unknown_commit_reconciled=true independent_readbacks=3 bidirectional=true network_rekeys={network_rekeys} exclusive_leases_checked=8 pre_cancel_refused=true durable_revocation=true");
    Ok(())
}
