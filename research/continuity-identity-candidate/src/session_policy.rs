// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{
    codec::{generation, nonzero, Decoder},
    crypto::{digest, envelope, open_envelope, Purpose},
    Error, PolicySigningKey, PrekeyQuality, PublicKey, Validity, VerifiedDevice,
};
use q_periapt_sdk::Runtime;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

const POLICY_TAG: &[u8; 8] = b"QPSESP01";
const POLICY_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-SESSION-POLICY-CANDIDATE/v1";
const FAMILY_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-POLICY-AUTHORITY-CANDIDATE/v1";

/// Fixed candidate protocol profile, separate from the SDK KEM suite and ABI.
/// The digest is metadata for this candidate, not a frozen product identifier.
pub fn bootstrap_suite_digest() -> [u8; 32] {
    digest(
        b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-SUITE-CANDIDATE/v1",
        b"ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256",
    )
}

/// Exactly the signed prekey-mode permissions, with no implicit fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedPrekeyModes(u8);
impl AllowedPrekeyModes {
    /// Construct an explicit set. Empty disables all new bootstraps; duplicates fail.
    pub fn new(modes: &[PrekeyQuality]) -> Result<Self, Error> {
        let mut bits = 0;
        for mode in modes {
            let bit = 1 << (*mode as u8 - 1);
            if bits & bit != 0 {
                return Err(Error::Encoding);
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }
    /// Whether this authenticated set permits exactly this two-leg mode.
    pub fn permits(self, quality: PrekeyQuality) -> bool {
        self.0 & (1 << (quality as u8 - 1)) != 0
    }
    fn decode(bits: u8) -> Result<Self, Error> {
        if bits & !0x0f != 0 {
            return Err(Error::Encoding);
        }
        Ok(Self(bits))
    }
}

/// Issuer-selected version, time window and explicit bootstrap permissions.
pub struct SessionPolicyParameters {
    version: u64,
    validity: Validity,
    modes: AllowedPrekeyModes,
}
impl SessionPolicyParameters {
    /// Validate the content revision. Its durable monotonic issuance is a host duty.
    pub fn new(version: u64, validity: Validity, modes: AllowedPrekeyModes) -> Result<Self, Error> {
        generation(version)?;
        Ok(Self {
            version,
            validity,
            modes,
        })
    }
}

/// Independently retained exact protocol-policy expectation, not an anchor receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyCheckpoint {
    version: u64,
    digest: [u8; 32],
}
impl PolicyCheckpoint {
    /// Load trusted configuration/state; the incoming policy must not select this value.
    pub fn from_trusted_state(version: u64, digest: [u8; 32]) -> Result<Self, Error> {
        generation(version)?;
        nonzero(&digest)?;
        Ok(Self { version, digest })
    }
    /// Exact expected version.
    pub fn version(self) -> u64 {
        self.version
    }
    /// Canonical body digest, excluding randomized signatures.
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Public signed protocol policy and the exact checkpoint the issuer may provision.
pub struct IssuedSessionPolicy {
    wire: Vec<u8>,
    checkpoint: PolicyCheckpoint,
}
impl IssuedSessionPolicy {
    /// Canonical signed envelope for distribution.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Exact checkpoint; independent authenticated provisioning remains required.
    pub fn checkpoint(&self) -> PolicyCheckpoint {
        self.checkpoint
    }
}

impl PolicySigningKey {
    /// Policy-authority family bound by account-issued device credentials.
    pub fn policy_family(&self) -> Result<[u8; 32], Error> {
        Ok(digest(FAMILY_DOMAIN, &self.public_key()?.encode()))
    }
    /// Sign the fixed protocol profile bound to an actual verified SDK runtime.
    /// No unsigned algorithm decision or caller-supplied SDK digest is accepted.
    pub fn issue_session_policy(
        &self,
        runtime: &Runtime,
        parameters: SessionPolicyParameters,
    ) -> Result<IssuedSessionPolicy, Error> {
        let sdk = runtime.policy_binding()?;
        // A disabled SDK runtime may be bound only by a disabling protocol policy.
        if parameters.modes.0 != 0 && !runtime.is_enabled()? {
            return Err(Error::PolicyDenied);
        }
        let mut body = Vec::with_capacity(165);
        body.extend_from_slice(POLICY_TAG);
        body.extend_from_slice(&self.policy_family()?);
        body.extend_from_slice(&parameters.version.to_be_bytes());
        parameters.validity.encode(&mut body);
        body.extend_from_slice(&bootstrap_suite_digest());
        body.extend_from_slice(&sdk);
        body.push(parameters.modes.0);
        let checkpoint =
            PolicyCheckpoint::from_trusted_state(parameters.version, digest(POLICY_DOMAIN, &body))?;
        let wire = envelope(&body, &self.sign(Purpose::SessionPolicy, &body)?)?;
        Ok(IssuedSessionPolicy { wire, checkpoint })
    }
}

/// Expected protocol-policy authority and checkpoint, provisioned independently.
pub struct PolicyPin {
    family: [u8; 32],
    root: PublicKey,
    checkpoint: PolicyCheckpoint,
}
impl PolicyPin {
    /// Require the expected family to match this exact policy-authority key pair.
    pub fn new(
        expected_family: [u8; 32],
        root: PublicKey,
        checkpoint: PolicyCheckpoint,
    ) -> Result<Self, Error> {
        nonzero(&expected_family)?;
        if expected_family != digest(FAMILY_DOMAIN, &root.encode()) {
            return Err(Error::Scope);
        }
        Ok(Self {
            family: expected_family,
            root,
            checkpoint,
        })
    }
    /// Verify both signatures, the exact checkpoint, profile, time and SDK binding.
    /// This does not establish directory consistency or durable policy installation.
    pub fn verify(
        &self,
        wire: &[u8],
        runtime: Arc<Runtime>,
        trusted_time: u64,
    ) -> Result<VerifiedSessionPolicy, Error> {
        let (body, signature) = open_envelope(wire)?;
        self.root.verify(Purpose::SessionPolicy, body, signature)?;
        let mut decoder = Decoder::new(body);
        if decoder.array::<8>()? != *POLICY_TAG || decoder.array::<32>()? != self.family {
            return Err(Error::Scope);
        }
        let version = decoder.u64()?;
        let checkpoint =
            PolicyCheckpoint::from_trusted_state(version, digest(POLICY_DOMAIN, body))?;
        if checkpoint != self.checkpoint {
            return Err(Error::Checkpoint);
        }
        let validity = Validity::decode(&mut decoder)?;
        validity.check(trusted_time)?;
        if decoder.array::<32>()? != bootstrap_suite_digest() {
            return Err(Error::Scope);
        }
        let sdk = decoder.array::<68>()?;
        if sdk != runtime.policy_binding()? {
            return Err(Error::Scope);
        }
        let [modes] = decoder.array()?;
        let modes = AllowedPrekeyModes::decode(modes)?;
        decoder.finish()?;
        if modes.0 != 0 && !runtime.is_enabled()? {
            return Err(Error::PolicyDenied);
        }
        Ok(VerifiedSessionPolicy {
            runtime,
            family: self.family,
            checkpoint,
            validity,
            modes,
            sdk,
            closed: AtomicBool::new(false),
            signer: self.root.clone(),
        })
    }
}

/// Actual authenticated protocol policy, bound to one verified runtime lifetime.
pub struct VerifiedSessionPolicy {
    pub(crate) runtime: Arc<Runtime>,
    family: [u8; 32],
    checkpoint: PolicyCheckpoint,
    validity: Validity,
    modes: AllowedPrekeyModes,
    sdk: [u8; 68],
    closed: AtomicBool,
    signer: PublicKey,
}
impl VerifiedSessionPolicy {
    pub(crate) fn check_device(&self, device: &VerifiedDevice, now: u64) -> Result<(), Error> {
        if device.description.family != self.family {
            return Err(Error::Scope);
        }
        self.check_external_signer(&device.key)?;
        device.description.validity.check(now)?;
        device.roster_validity.check(now)
    }
    pub(crate) fn check_external_signer(&self, key: &PublicKey) -> Result<(), Error> {
        if key.shares_component(&self.signer) {
            return Err(Error::Scope);
        }
        let public = key.encode();
        let pq = public
            .get(..q_periapt_backends::ML_DSA_65_VK_LEN)
            .ok_or(Error::Encoding)?;
        let pq_digest: [u8; 32] = Sha256::digest(pq).into();
        if self.sdk.starts_with(&pq_digest) {
            return Err(Error::Scope);
        }
        Ok(())
    }
    /// Close this protocol-policy instance without changing other SDK applications.
    /// Durable policy replacement and other instances still require host coordination.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
    /// Account/device enrollment policy family.
    pub fn family(&self) -> [u8; 32] {
        self.family
    }
    /// Exact protocol-policy version and digest for a later transaction fence.
    pub fn checkpoint(&self) -> PolicyCheckpoint {
        self.checkpoint
    }
    /// Complete signed time window.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// Underlying SDK authority, content version and digest.
    pub fn sdk_binding(&self) -> [u8; 68] {
        self.sdk
    }
    /// Exact signed mode permissions. Reading them alone is not an admission lease.
    pub fn allowed_modes(&self) -> AllowedPrekeyModes {
        self.modes
    }
    /// Check mode, time and current runtime lifetime at an operation boundary.
    /// The service must separately recheck durable policy/roster/directory authority.
    pub fn check_mode(&self, quality: PrekeyQuality, trusted_time: u64) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        self.validity.check(trusted_time)?;
        if !self.modes.permits(quality) || !self.runtime.is_enabled()? {
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }
}
