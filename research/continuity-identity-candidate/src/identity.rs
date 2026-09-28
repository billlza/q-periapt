// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{
    codec::{generation, nonzero, Decoder},
    crypto::{digest, envelope, open_envelope, Purpose},
    Error, PublicKey, RootSigningKey, PUBLIC_KEY_BYTES,
};

/// Maximum active device generations in one candidate roster.
pub const MAX_DEVICES: usize = 32;
const CERTIFICATE_TAG: &[u8; 8] = b"QPCERT01";
const ROSTER_TAG: &[u8; 8] = b"QPROST01";

/// A checked, half-open interval evaluated against independently trusted time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    pub(crate) from: u64,
    pub(crate) until: u64,
}
impl Validity {
    /// Inclusive beginning of the signed interval.
    pub fn from(self) -> u64 {
        self.from
    }
    /// Exclusive end of the signed interval.
    pub fn until(self) -> u64 {
        self.until
    }
    /// Construct a finite nonempty interval `[from, until)`.
    pub fn new(from: u64, until: u64) -> Result<Self, Error> {
        if from >= until || until == u64::MAX {
            return Err(Error::Validity);
        }
        Ok(Self { from, until })
    }
    pub(crate) fn check(self, trusted_time: u64) -> Result<(), Error> {
        if self.from <= trusted_time && trusted_time < self.until {
            Ok(())
        } else {
            Err(Error::Validity)
        }
    }
    pub(crate) fn contains(self, other: Self) -> bool {
        self.from <= other.from && other.until <= self.until
    }
    pub(crate) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.from.to_be_bytes());
        out.extend_from_slice(&self.until.to_be_bytes());
    }
    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Self::new(decoder.u64()?, decoder.u64()?)
    }
}

/// Enrollment metadata chosen by the account authority, not a network verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceDescription {
    pub(crate) id: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) family: [u8; 32],
    pub(crate) validity: Validity,
}
impl DeviceDescription {
    /// Construct checked metadata for one distinct device generation.
    pub fn new(
        id: [u8; 16],
        device_generation: u64,
        policy_family: [u8; 32],
        validity: Validity,
    ) -> Result<Self, Error> {
        nonzero(&id)?;
        generation(device_generation)?;
        nonzero(&policy_family)?;
        Ok(Self {
            id,
            generation: device_generation,
            family: policy_family,
            validity,
        })
    }
}

/// Expected checkpoint supplied by enrollment or protected host state.
///
/// These public values alone are not an authenticated receipt or rollback anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterCheckpoint {
    version: u64,
    digest: [u8; 32],
}
impl RosterCheckpoint {
    /// Reconstruct an independently retained expectation; network data must not select it.
    pub fn from_trusted_state(version: u64, digest: [u8; 32]) -> Result<Self, Error> {
        generation(version)?;
        nonzero(&digest)?;
        Ok(Self { version, digest })
    }
    /// Monotonic roster version expected by this pin.
    pub fn version(self) -> u64 {
        self.version
    }
    /// Digest of the complete canonical roster body, excluding randomized signatures.
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Device membership derived only from a credential signed by this account root.
#[derive(Clone, Debug)]
pub struct RosterEntry {
    account: [u8; 32],
    id: [u8; 16],
    generation: u64,
    certificate: [u8; 32],
}

/// A signed roster and the exact checkpoint its issuer may provision.
pub struct IssuedRoster {
    wire: Vec<u8>,
    checkpoint: RosterCheckpoint,
}
impl IssuedRoster {
    /// Signed canonical bytes for distribution.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Exact issuer checkpoint; provisioning its freshness remains a host responsibility.
    pub fn checkpoint(&self) -> RosterCheckpoint {
        self.checkpoint
    }
}

struct Credential {
    account: [u8; 32],
    description: DeviceDescription,
    key: PublicKey,
}
impl Credential {
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(112 + PUBLIC_KEY_BYTES);
        body.extend_from_slice(CERTIFICATE_TAG);
        body.extend_from_slice(&self.account);
        body.extend_from_slice(&self.description.id);
        body.extend_from_slice(&self.description.generation.to_be_bytes());
        self.description.validity.encode(&mut body);
        body.extend_from_slice(&self.description.family);
        body.extend_from_slice(&self.key.encode());
        body
    }
    fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(body);
        if decoder.array::<8>()? != *CERTIFICATE_TAG {
            return Err(Error::Encoding);
        }
        let account = decoder.array()?;
        nonzero(&account)?;
        let id = decoder.array()?;
        let generation = decoder.u64()?;
        let validity = Validity::decode(&mut decoder)?;
        let family = decoder.array()?;
        let description = DeviceDescription::new(id, generation, family, validity)?;
        let key = PublicKey::decode(decoder.take(PUBLIC_KEY_BYTES)?)?;
        decoder.finish()?;
        Ok(Self {
            account,
            description,
            key,
        })
    }
}

fn account_id(root: &PublicKey) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", &root.encode())
}
fn certificate_digest(body: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", body)
}
fn roster_digest(body: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", body)
}

impl RootSigningKey {
    /// Self-certifying account identifier for this candidate key profile.
    pub fn account_id(&self) -> Result<[u8; 32], Error> {
        Ok(account_id(&self.public_key()?))
    }

    /// Authorize one independent device key pair under the account root.
    pub fn issue_device(
        &self,
        description: DeviceDescription,
        key: PublicKey,
    ) -> Result<Vec<u8>, Error> {
        let root = self.public_key()?;
        if root.shares_component(&key) {
            return Err(Error::Scope);
        }
        let body = Credential {
            account: account_id(&root),
            description,
            key,
        }
        .encode();
        envelope(&body, &self.sign(Purpose::Credential, &body)?)
    }

    /// Verify one account-issued credential before selecting it for a roster.
    pub fn roster_entry(&self, certificate: &[u8]) -> Result<RosterEntry, Error> {
        let root = self.public_key()?;
        let (body, signature) = open_envelope(certificate)?;
        root.verify(Purpose::Credential, body, signature)?;
        let credential = Credential::decode(body)?;
        if credential.account != account_id(&root) || root.shares_component(&credential.key) {
            return Err(Error::Scope);
        }
        Ok(RosterEntry {
            account: credential.account,
            id: credential.description.id,
            generation: credential.description.generation,
            certificate: certificate_digest(body),
        })
    }

    /// Issue one canonical roster; zero entries explicitly revokes all devices.
    pub fn issue_roster(
        &self,
        version: u64,
        validity: Validity,
        entries: &[RosterEntry],
    ) -> Result<IssuedRoster, Error> {
        generation(version)?;
        if entries.len() > MAX_DEVICES {
            return Err(Error::Capacity);
        }
        let account = self.account_id()?;
        let mut entries = entries.to_vec();
        entries.sort_by_key(|entry| entry.id);
        let mut previous = None;
        let mut body = Vec::with_capacity(66 + entries.len() * 56);
        body.extend_from_slice(ROSTER_TAG);
        body.extend_from_slice(&account);
        body.extend_from_slice(&version.to_be_bytes());
        validity.encode(&mut body);
        let count = u16::try_from(entries.len()).map_err(|_| Error::Capacity)?;
        body.extend_from_slice(&count.to_be_bytes());
        for entry in entries {
            if entry.account != account || previous == Some(entry.id) {
                return Err(Error::Scope);
            }
            previous = Some(entry.id);
            body.extend_from_slice(&entry.id);
            body.extend_from_slice(&entry.generation.to_be_bytes());
            body.extend_from_slice(&entry.certificate);
        }
        let checkpoint = RosterCheckpoint::from_trusted_state(version, roster_digest(&body))?;
        let wire = envelope(&body, &self.sign(Purpose::Roster, &body)?)?;
        Ok(IssuedRoster { wire, checkpoint })
    }
}

/// Independently provisioned root and exact roster expectation.
///
/// This type performs signature and binding checks. Persistence, monotonic
/// checkpoint advancement, witness availability and trusted time are host duties;
/// accepting a pin from the same untrusted message does not authenticate its sender.
pub struct AccountPin {
    account: [u8; 32],
    root: PublicKey,
    checkpoint: RosterCheckpoint,
    family: [u8; 32],
}
impl AccountPin {
    /// Provision one expected account, root, roster checkpoint and policy family.
    pub fn new(
        expected_account: [u8; 32],
        root: PublicKey,
        checkpoint: RosterCheckpoint,
        family: [u8; 32],
    ) -> Result<Self, Error> {
        nonzero(&family)?;
        if expected_account != account_id(&root) {
            return Err(Error::Scope);
        }
        Ok(Self {
            account: expected_account,
            root,
            checkpoint,
            family,
        })
    }

    /// Verify both signatures, the exact roster, membership, device generation and time.
    /// This result alone does not authorize bootstrap, plaintext release or prekey consumption.
    pub fn verify_device(
        &self,
        certificate: &[u8],
        roster: &[u8],
        trusted_time: u64,
    ) -> Result<VerifiedDevice, Error> {
        let (body, signature) = open_envelope(certificate)?;
        self.root.verify(Purpose::Credential, body, signature)?;
        let credential = Credential::decode(body)?;
        if credential.account != self.account
            || credential.description.family != self.family
            || self.root.shares_component(&credential.key)
        {
            return Err(Error::Scope);
        }
        credential.description.validity.check(trusted_time)?;
        let certificate = certificate_digest(body);
        let (body, signature) = open_envelope(roster)?;
        self.root.verify(Purpose::Roster, body, signature)?;
        let mut decoder = Decoder::new(body);
        if decoder.array::<8>()? != *ROSTER_TAG {
            return Err(Error::Encoding);
        }
        if decoder.array::<32>()? != self.account {
            return Err(Error::Scope);
        }
        let version = decoder.u64()?;
        if RosterCheckpoint::from_trusted_state(version, roster_digest(body))? != self.checkpoint {
            return Err(Error::Checkpoint);
        }
        let roster_validity = Validity::decode(&mut decoder)?;
        roster_validity.check(trusted_time)?;
        let count = usize::from(decoder.u16()?);
        if count > MAX_DEVICES {
            return Err(Error::Capacity);
        }
        let mut previous = None;
        let mut matched = false;
        for _ in 0..count {
            let id = decoder.array::<16>()?;
            nonzero(&id)?;
            if previous.is_some_and(|previous| previous >= id) {
                return Err(Error::Encoding);
            }
            previous = Some(id);
            let device_generation = decoder.u64()?;
            generation(device_generation)?;
            let digest = decoder.array::<32>()?;
            nonzero(&digest)?;
            if id == credential.description.id
                && device_generation == credential.description.generation
                && digest == certificate
            {
                matched = true;
            }
        }
        decoder.finish()?;
        if !matched {
            return Err(Error::Scope);
        }
        let mut authority = Vec::with_capacity(104);
        authority.extend_from_slice(&self.account);
        authority.extend_from_slice(&self.checkpoint.version.to_be_bytes());
        authority.extend_from_slice(&self.checkpoint.digest);
        authority.extend_from_slice(&self.family);
        Ok(VerifiedDevice {
            account: self.account,
            description: credential.description,
            key: credential.key,
            certificate,
            checkpoint: self.checkpoint,
            roster_validity,
            authority: digest(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", &authority),
        })
    }
}

/// Actual verified account-to-device chain under one exact independently retained pin.
///
/// The service must recheck `authority_binding()` at its eventual transaction fence.
/// A retained value does not automatically track later revocation or time advancement.
pub struct VerifiedDevice {
    pub(crate) account: [u8; 32],
    pub(crate) description: DeviceDescription,
    pub(crate) key: PublicKey,
    pub(crate) certificate: [u8; 32],
    pub(crate) checkpoint: RosterCheckpoint,
    pub(crate) roster_validity: Validity,
    authority: [u8; 32],
}
impl VerifiedDevice {
    /// Account identifier authenticated under the provisioned root.
    pub fn account_id(&self) -> [u8; 32] {
        self.account
    }
    /// Device identifier, independent of its generation.
    pub fn device_id(&self) -> [u8; 16] {
        self.description.id
    }
    /// Exact authenticated device generation.
    pub fn generation(&self) -> u64 {
        self.description.generation
    }
    /// Public authority checkpoint binding for a later repository recheck.
    pub fn authority_binding(&self) -> [u8; 32] {
        self.authority
    }
    /// Canonical signed credential body digest.
    pub fn credential_digest(&self) -> [u8; 32] {
        self.certificate
    }
}
