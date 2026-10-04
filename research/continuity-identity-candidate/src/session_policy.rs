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

const POLICY_TAG: &[u8; 8] = b"QPSESP03";
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

/// Explicit signed local-persistence or pinned-witness requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorRequirement(Option<[u8; 32]>);
impl AnchorRequirement {
    /// Explicit commit-order-only profile, with no rollback-anchor assurance.
    pub fn local_only() -> Self {
        Self(None)
    }
    /// Require this exact independently pinned witness instance and key.
    pub fn required(pin: &crate::AnchorPin) -> Self {
        Self(Some(pin.binding()))
    }
    /// Signed witness binding, or the explicitly selected local-only profile.
    pub fn binding(self) -> Option<[u8; 32]> {
        self.0
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.push(u8::from(self.0.is_some()));
        out.extend_from_slice(&self.0.unwrap_or([0; 32]));
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let [mode] = d.array()?;
        let binding = d.array()?;
        match mode {
            0 if binding == [0; 32] => Ok(Self(None)),
            1 => {
                nonzero(&binding)?;
                Ok(Self(Some(binding)))
            }
            _ => Err(Error::Encoding),
        }
    }
}

/// Explicit signed application-send allowance between local rekey completions.
/// This bounds protocol work, not an adversary's knowledge or recovery time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationSendBudget(std::num::NonZeroU16);
impl ApplicationSendBudget {
    /// Require an explicit nonzero issuer value; there is no runtime default.
    pub fn new(messages: u16) -> Result<Self, Error> {
        std::num::NonZeroU16::new(messages)
            .map(Self)
            .ok_or(Error::Encoding)
    }
    /// Maximum new application slots before the next locally completed rekey.
    pub fn messages(self) -> u16 {
        self.0.get()
    }
}

/// Issuer-selected version, time window, bootstrap modes, anchor and send budget.
pub struct SessionPolicyParameters {
    version: u64,
    validity: Validity,
    modes: AllowedPrekeyModes,
    anchor: AnchorRequirement,
    budget: ApplicationSendBudget,
}
impl SessionPolicyParameters {
    /// Validate the content revision. Its durable monotonic issuance is a host duty.
    pub fn new(
        version: u64,
        validity: Validity,
        modes: AllowedPrekeyModes,
        anchor: AnchorRequirement,
        budget: ApplicationSendBudget,
    ) -> Result<Self, Error> {
        generation(version)?;
        Ok(Self {
            version,
            validity,
            modes,
            anchor,
            budget,
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
        let mut body = Vec::with_capacity(200);
        body.extend_from_slice(POLICY_TAG);
        body.extend_from_slice(&self.policy_family()?);
        body.extend_from_slice(&parameters.version.to_be_bytes());
        parameters.validity.encode(&mut body);
        body.extend_from_slice(&bootstrap_suite_digest());
        body.extend_from_slice(&sdk);
        body.push(parameters.modes.0);
        parameters.anchor.encode(&mut body);
        body.extend_from_slice(&parameters.budget.messages().to_be_bytes());
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
        let historical = self.verify_historical(wire)?;
        historical.validity.check(trusted_time)?;
        if historical.sdk != runtime.policy_binding()? {
            return Err(Error::Scope);
        }
        if historical.modes.0 != 0 && !runtime.is_enabled()? {
            return Err(Error::PolicyDenied);
        }
        Ok(VerifiedSessionPolicy {
            runtime,
            historical,
            closed: AtomicBool::new(false),
        })
    }
    /// Verify exact signed historical metadata under this independently retained
    /// pin, without constructing an SDK runtime or making a current-time claim.
    /// The original installation must separately authenticate the same policy
    /// digest before recovery. This value cannot create work or activate a device.
    pub fn verify_historical(&self, wire: &[u8]) -> Result<HistoricalSessionPolicy, Error> {
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
        if decoder.array::<32>()? != bootstrap_suite_digest() {
            return Err(Error::Scope);
        }
        let sdk = decoder.array::<68>()?;
        q_periapt_policy::TrustedPolicyState::decode(sdk.get(32..).ok_or(Error::Encoding)?)
            .map_err(|_| Error::Scope)?;
        let [modes] = decoder.array()?;
        let modes = AllowedPrekeyModes::decode(modes)?;
        let anchor = AnchorRequirement::decode(&mut decoder)?;
        let budget = ApplicationSendBudget::new(decoder.u16()?)?;
        decoder.finish()?;
        Ok(HistoricalSessionPolicy {
            family: self.family,
            checkpoint,
            validity,
            modes,
            anchor,
            budget,
            sdk,
            signer: self.root.clone(),
        })
    }
}

/// Exact signature-verified protocol-policy metadata for historical recovery.
/// It has no runtime, admission lease or operation-creation interface. Its signed
/// SDK binding is a claim authenticated by the protocol issuer; recovery must
/// also match the original durable installation's policy digest.
///
/// Historical metadata cannot be supplied to operational activation:
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{DeviceEnrollment, HistoricalSessionPolicy};
/// fn activate(enrollment: DeviceEnrollment, historical: &HistoricalSessionPolicy) {
///     let _ = enrollment.activate(historical, 250, None);
/// }
/// ```
#[derive(Clone)]
pub struct HistoricalSessionPolicy {
    family: [u8; 32],
    checkpoint: PolicyCheckpoint,
    validity: Validity,
    modes: AllowedPrekeyModes,
    anchor: AnchorRequirement,
    budget: ApplicationSendBudget,
    sdk: [u8; 68],
    signer: PublicKey,
}
impl AsRef<HistoricalSessionPolicy> for HistoricalSessionPolicy {
    fn as_ref(&self) -> &HistoricalSessionPolicy {
        self
    }
}
/// Actual authenticated protocol policy, bound to one verified runtime lifetime.
pub struct VerifiedSessionPolicy {
    pub(crate) runtime: Arc<Runtime>,
    historical: HistoricalSessionPolicy,
    closed: AtomicBool,
}
impl AsRef<HistoricalSessionPolicy> for VerifiedSessionPolicy {
    fn as_ref(&self) -> &HistoricalSessionPolicy {
        &self.historical
    }
}
impl VerifiedSessionPolicy {
    /// Borrow immutable authenticated metadata. This does not extend the runtime
    /// lifetime or restore a closed/expired policy's permission.
    pub fn historical(&self) -> &HistoricalSessionPolicy {
        &self.historical
    }

    pub(crate) fn check_device(&self, device: &VerifiedDevice, now: u64) -> Result<(), Error> {
        self.check_device_identity(device, now)?;
        device.roster_validity.check(now)
    }
    pub(crate) fn check_device_identity(
        &self,
        device: &VerifiedDevice,
        now: u64,
    ) -> Result<(), Error> {
        if device.description.family != self.historical.family {
            return Err(Error::Scope);
        }
        self.check_external_signer(&device.key)?;
        device.description.validity.check(now)
    }

    /// Close this protocol-policy instance without changing other SDK applications.
    /// Durable policy replacement and other instances still require host coordination.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Check mode, time and current runtime lifetime at an operation boundary.
    /// The service must separately recheck durable policy/roster/directory authority.
    pub fn check_mode(&self, quality: PrekeyQuality, trusted_time: u64) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        self.historical.validity.check(trusted_time)?;
        if !self.historical.modes.permits(quality) || !self.runtime.is_enabled()? {
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }
    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn application_send_budget(&self) -> ApplicationSendBudget {
        self.historical.application_send_budget()
    }

    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn anchor_requirement(&self) -> AnchorRequirement {
        self.historical.anchor_requirement()
    }

    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn family(&self) -> [u8; 32] {
        self.historical.family()
    }

    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn checkpoint(&self) -> PolicyCheckpoint {
        self.historical.checkpoint()
    }

    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn validity(&self) -> Validity {
        self.historical.validity()
    }

    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn sdk_binding(&self) -> [u8; 68] {
        self.historical.sdk_binding()
    }

    /// Authenticated immutable metadata; current admission is checked separately.
    pub fn allowed_modes(&self) -> AllowedPrekeyModes {
        self.historical.allowed_modes()
    }

    pub(crate) fn check_external_signer(&self, key: &PublicKey) -> Result<(), Error> {
        self.historical.check_external_signer(key)
    }
}

impl HistoricalSessionPolicy {
    /// Authenticated immutable send bound; reading it grants no message permission.
    pub fn application_send_budget(&self) -> ApplicationSendBudget {
        self.budget
    }
    /// Exact signed requirement. Reading it does not refresh policy authority or time.
    pub fn anchor_requirement(&self) -> AnchorRequirement {
        self.anchor
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
}
