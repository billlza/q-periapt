// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Owned ContextBound SDK. Product randomness comes from the platform CSPRNG;
//! policies are verified at construction, never accepted as serialized decisions.
//! The host must pin its trust root and atomically persist `trusted_state()`
//! before using a runtime. This in-process API cannot protect against a malicious
//! host, rollbacks of host storage, or previously exported protocol secrets.
//!
//! Calls are synchronous. Borrowing keeps key storage alive through each call;
//! cancellation of an outer task must not detach a native call from its owner.
//! Runtime close revokes new operations. Already admitted operations may finish.
//! Key close requires exclusive access, erases its storage, and returns its quota.

mod purpose;
pub use purpose::{DerivedKey, KeyPurpose, MAX_PROTOCOL_LABEL_BYTES};
/// Explicit professional key transfer; never the product key-generation default.
pub mod expert;
mod policy_update;
pub use policy_update::PolicyUpdate;

use q_periapt_backends::{
    MlDsa65, MlKem768, PreparedMlKem768Key, StreamingSha3_256Xof, DEFAULT_SUITE_ID,
    ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN, ML_KEM_768_CT_LEN, ML_KEM_768_KEYGEN_SEED_LEN,
    ML_KEM_768_PK_LEN, X25519,
};
use q_periapt_core::{Profile, Secret, ZeroizingBytes, MAX_APPLICATION_CONTEXT_BYTES};
use q_periapt_kem::{HybridKem, PqCiphertext, TradCiphertext, TradPublicKey, TradSecretKey};
use q_periapt_policy::{
    AuthenticatedResolvedSuite, HybridSuite, Policy, PolicyResolutionError, TrustedPolicyState,
    MAX_SIGNED_POLICY_BYTES,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

/// Canonical public-key encoding: ML-KEM-768 public key followed by X25519.
pub const PUBLIC_KEY_LEN: usize = ML_KEM_768_PK_LEN + 32;
/// Canonical ciphertext encoding: ML-KEM-768 ciphertext followed by X25519.
pub const CIPHERTEXT_LEN: usize = ML_KEM_768_CT_LEN + 32;

/// Public failure classification. Invalid PQ ciphertexts still use implicit rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Object has been explicitly closed or its runtime dropped/closed.
    Closed,
    /// Invalid public buffer length or context exceeding 64 KiB.
    InvalidLength,
    /// Signature, policy, suite, rollback or equivocation check failed.
    PolicyDenied,
    /// Public key share was invalid or non-contributory.
    InvalidKeyShare,
    /// Platform cryptographic randomness is unavailable.
    Entropy,
    /// Per-runtime live-key or in-flight operation budget was exhausted.
    ResourceLimit,
    /// Invalid runtime limits.
    InvalidLimits,
    /// Unknown purpose code or non-printable-ASCII protocol label.
    InvalidPurpose,
    /// Unsupported private-key representation or failed key-consistency checks.
    InvalidPrivateKey,
    /// Opaque local key/provider failure.
    Backend,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "object is closed",
            Self::InvalidLength => "invalid input length",
            Self::PolicyDenied => "policy denied",
            Self::InvalidKeyShare => "invalid public key share",
            Self::Entropy => "platform entropy unavailable",
            Self::ResourceLimit => "runtime resource limit reached",
            Self::InvalidLimits => "invalid runtime limits",
            Self::InvalidPurpose => "invalid key purpose or protocol label",
            Self::InvalidPrivateKey => "invalid private-key encoding or consistency",
            Self::Backend => "local cryptographic provider failure",
        })
    }
}
impl std::error::Error for Error {}

impl From<q_periapt_core::Error> for Error {
    fn from(error: q_periapt_core::Error) -> Self {
        match error {
            q_periapt_core::Error::InvalidLength => Self::InvalidLength,
            q_periapt_core::Error::InvalidKeyShare => Self::InvalidKeyShare,
            q_periapt_core::Error::PolicyDenied => Self::PolicyDenied,
            _ => Self::Backend,
        }
    }
}

/// Per-runtime admission bounds. They do not reserve memory or prevent process OOM.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrently retained key owners (1..=1024).
    pub max_live_keys: usize,
    /// Concurrent synchronous KEM operations (1..=64).
    pub max_in_flight: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_live_keys: 32,
            max_in_flight: 4,
        }
    }
}

enum Configuration {
    Enabled(AuthenticatedResolvedSuite),
    Disabled(TrustedPolicyState),
}
impl Configuration {
    fn trusted_state(&self) -> TrustedPolicyState {
        match self {
            Self::Enabled(decision) => decision.trusted_state(),
            Self::Disabled(state) => *state,
        }
    }
}

struct State {
    configuration: Configuration,
    digest: [u8; 32],
    trust_root_digest: [u8; 32],
    trust_root: Arc<[u8; ML_DSA_65_VK_LEN]>,
    closed: AtomicBool,
    keys: AtomicUsize,
    operations: AtomicUsize,
    limits: Limits,
}

struct Operation<'a>(&'a AtomicUsize);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn reserve(counter: &AtomicUsize, limit: usize) -> Result<(), Error> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return Err(Error::ResourceLimit);
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}
impl State {
    fn ensure_open(&self) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn begin_control(&self) -> Result<Operation<'_>, Error> {
        self.ensure_open()?;
        reserve(&self.operations, self.limits.max_in_flight)?;
        let lease = Operation(&self.operations);
        // The successful open check is the operation admission point. Closing
        // after it allows this operation to finish; subsequent checks fail.
        self.ensure_open()?;
        Ok(lease)
    }
    fn begin(&self) -> Result<Operation<'_>, Error> {
        let lease = self.begin_control()?;
        if matches!(self.configuration, Configuration::Disabled(_)) {
            return Err(Error::PolicyDenied);
        }
        Ok(lease)
    }
    fn kem(&self) -> Result<HybridKem<'_, MlKem768, X25519, StreamingSha3_256Xof>, Error> {
        let Configuration::Enabled(decision) = self.configuration else {
            return Err(Error::PolicyDenied);
        };
        HybridKem::new_policy_bound(
            &MlKem768,
            &X25519,
            DEFAULT_SUITE_ID,
            decision.resolved().policy_version(),
            &self.digest,
        )
        .map_err(Into::into)
    }
}

/// Immutable verified configuration and resource/lifecycle owner.
/// No constructor accepts an unsigned policy or a 40-byte decision.
pub struct Runtime {
    state: Arc<State>,
}

impl Runtime {
    /// Verify an ML-DSA-65 policy and resolve the fixed ContextBound suite.
    /// `last_trusted` is supplied by trusted host storage, not by a peer.
    /// A valid policy that excludes this suite/profile creates a disabled runtime:
    /// check `is_enabled()`. Key operations fail with `PolicyDenied`, but its state
    /// can be persisted and a future signed update can re-enable operations. This
    /// allows revocation to survive process restart without restoring old rights.
    pub fn from_signed_policy(
        toml: &[u8],
        signature: &[u8],
        trust_root: &[u8],
        last_trusted: Option<&TrustedPolicyState>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if !(1..=MAX_SIGNED_POLICY_BYTES).contains(&toml.len())
            || signature.len() != ML_DSA_65_SIG_LEN
            || trust_root.len() != ML_DSA_65_VK_LEN
        {
            return Err(Error::InvalidLength);
        }
        if !(1..=1024).contains(&limits.max_live_keys) || !(1..=64).contains(&limits.max_in_flight)
        {
            return Err(Error::InvalidLimits);
        }
        let policy =
            Policy::load_signed_monotonic(&MlDsa65, trust_root, toml, signature, last_trusted)
                .map_err(|_| Error::PolicyDenied)?;
        let configuration = match policy.resolve_suite(&[HybridSuite::MlKem768X25519]) {
            Ok(decision) if decision.resolved().profile() == Profile::ContextBound => {
                Configuration::Enabled(decision)
            }
            Ok(_) | Err(PolicyResolutionError::NoSupportedSuite) => {
                Configuration::Disabled(policy.trusted_state())
            }
            // Only the explicit, authenticated absence of a supported suite is
            // an installable disabled state. Future resolution failures are errors.
            Err(_) => return Err(Error::PolicyDenied),
        };
        Ok(Self {
            state: Arc::new(State {
                configuration,
                digest: policy.trusted_state().digest(),
                trust_root_digest: Sha256::digest(trust_root).into(),
                trust_root: Arc::new(trust_root.try_into().map_err(|_| Error::InvalidLength)?),
                closed: AtomicBool::new(false),
                keys: AtomicUsize::new(0),
                operations: AtomicUsize::new(0),
                limits,
            }),
        })
    }

    /// Exact state to atomically persist before accepting this runtime for use.
    pub fn trusted_state(&self) -> TrustedPolicyState {
        self.state.configuration.trusted_state()
    }

    /// Public application-policy identity: SHA-256(pinned root) followed by the
    /// 36-byte trusted state. This is descriptive metadata, never an authority
    /// token. A transport must separately authenticate and bind any peer claim.
    /// Closed runtimes reject access; disabled policies retain their identity.
    pub fn policy_binding(&self) -> Result<[u8; 68], Error> {
        self.state.ensure_open()?;
        let mut binding = [0; 68];
        let (root, state) = binding.split_at_mut(32);
        root.copy_from_slice(&self.state.trust_root_digest);
        state.copy_from_slice(&self.trusted_state().encode());
        Ok(binding)
    }

    /// Whether the authenticated policy permits this SDK's fixed suite/profile.
    /// This is configuration information, not a lease across concurrent close.
    pub fn is_enabled(&self) -> Result<bool, Error> {
        self.state.ensure_open()?;
        Ok(matches!(
            self.state.configuration,
            Configuration::Enabled(_)
        ))
    }

    /// Revoke future operations, including through keys created by this runtime.
    /// Existing key storage is wiped when its key owner is closed or dropped;
    /// closing the runtime does not wait for previously admitted operations.
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
    }

    /// Generate an owned hybrid key with platform randomness. No secret-key export.
    pub fn generate_key(&self) -> Result<HybridKey, Error> {
        self.generate_with(|out| getrandom::fill(out).map_err(|_| Error::Entropy))
    }

    fn generate_with(
        &self,
        mut rng: impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<HybridKey, Error> {
        let _operation = self.state.begin()?;
        reserve(&self.state.keys, self.state.limits.max_live_keys)?;
        let key_lease = KeyLease(Arc::clone(&self.state));
        let mut seed = ZeroizingBytes::<ML_KEM_768_KEYGEN_SEED_LEN>::zeroed();
        let mut traditional = Box::new(ZeroizingBytes::<32>::zeroed());
        rng(seed.as_mut_bytes())?;
        rng(traditional.as_mut_bytes())?;
        let pq = MlKem768::prepare(seed.as_bytes())?;
        let public = PublicKey {
            pq: *pq.encapsulation_key(),
            traditional: X25519::public_key(traditional.as_bytes()),
        };
        Ok(HybridKey {
            material: Some(KeyMaterial {
                pq,
                traditional,
                public,
                lease: key_lease,
            }),
        })
    }

    /// Encapsulate with platform randomness and the authenticated policy context.
    pub fn encapsulate(
        &self,
        peer: &PublicKey,
        application_context: &[u8],
    ) -> Result<Encapsulation, Error> {
        self.encapsulate_with(peer, application_context, |out| {
            getrandom::fill(out).map_err(|_| Error::Entropy)
        })
    }

    fn encapsulate_with(
        &self,
        peer: &PublicKey,
        context: &[u8],
        mut rng: impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<Encapsulation, Error> {
        let _operation = self.state.begin()?;
        check_context(context)?;
        let mut coins = ZeroizingBytes::<32>::zeroed();
        let mut scalar = ZeroizingBytes::<32>::zeroed();
        rng(coins.as_mut_bytes())?;
        rng(scalar.as_mut_bytes())?;
        let mut ciphertext = Ciphertext {
            pq: [0; ML_KEM_768_CT_LEN],
            traditional: [0; 32],
        };
        let secret = self.state.kem()?.encapsulate(
            &peer.pq,
            &peer.traditional,
            context,
            coins.as_bytes(),
            scalar.as_bytes(),
            &mut ciphertext.pq,
            &mut ciphertext.traditional,
        )?;
        Ok(Encapsulation {
            ciphertext,
            secret: SharedSecret {
                inner: Some(secret),
                state: Arc::clone(&self.state),
            },
        })
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.close();
    }
}

struct KeyLease(Arc<State>);
impl Drop for KeyLease {
    fn drop(&mut self) {
        self.0.keys.fetch_sub(1, Ordering::AcqRel);
    }
}
struct KeyMaterial {
    pq: PreparedMlKem768Key,
    traditional: Box<ZeroizingBytes<32>>,
    public: PublicKey,
    lease: KeyLease,
}

/// Non-cloneable hybrid key tied to its verified runtime and paired public key.
///
/// ```compile_fail
/// use q_periapt_sdk::HybridKey;
/// fn copy_private_key(key: &HybridKey) -> HybridKey { key.clone() }
/// ```
pub struct HybridKey {
    material: Option<KeyMaterial>,
}
impl HybridKey {
    /// Return only public bytes. Closed/revoked objects reject access.
    pub fn public_key(&self) -> Result<&PublicKey, Error> {
        let material = self.material.as_ref().ok_or(Error::Closed)?;
        material.lease.0.ensure_open()?;
        Ok(&material.public)
    }
    /// Decapsulate without accepting private keys or unrelated paired public keys.
    pub fn decapsulate(
        &self,
        ciphertext: &Ciphertext,
        application_context: &[u8],
    ) -> Result<SharedSecret, Error> {
        let material = self.material.as_ref().ok_or(Error::Closed)?;
        let _operation = material.lease.0.begin()?;
        check_context(application_context)?;
        let secret = material.lease.0.kem()?.decapsulate_prepared(
            &material.pq,
            PqCiphertext::new(&ciphertext.pq),
            TradSecretKey::new(material.traditional.as_bytes()),
            TradCiphertext::new(&ciphertext.traditional),
            TradPublicKey::new(&material.public.traditional),
            application_context,
        )?;
        Ok(SharedSecret {
            inner: Some(secret),
            state: Arc::clone(&material.lease.0),
        })
    }
    /// Erase key storage and release its slot. Repeated close is harmless.
    /// Exclusive borrowing prevents disposal during a synchronous native call.
    pub fn close(&mut self) {
        self.material = None;
    }
}

fn check_context(context: &[u8]) -> Result<(), Error> {
    if context.len() > MAX_APPLICATION_CONTEXT_BYTES {
        Err(Error::InvalidLength)
    } else {
        Ok(())
    }
}

/// Public hybrid encapsulation key. Parsing checks framing; KEM operations check validity.
#[derive(Clone)]
pub struct PublicKey {
    pq: [u8; ML_KEM_768_PK_LEN],
    traditional: [u8; 32],
}
impl PublicKey {
    /// Decode exactly 1216 public bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let (pq, traditional) = bytes.split_at(ML_KEM_768_PK_LEN);
        Ok(Self {
            pq: pq.try_into().map_err(|_| Error::InvalidLength)?,
            traditional: traditional.try_into().map_err(|_| Error::InvalidLength)?,
        })
    }
    /// Encode public bytes; this never exports a private key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut bytes = [0; PUBLIC_KEY_LEN];
        let (pq, traditional) = bytes.split_at_mut(ML_KEM_768_PK_LEN);
        pq.copy_from_slice(&self.pq);
        traditional.copy_from_slice(&self.traditional);
        bytes
    }
}

/// Public hybrid ciphertext. Correct-length invalid PQ ciphertexts are not rejected here.
#[derive(Clone)]
pub struct Ciphertext {
    pq: [u8; ML_KEM_768_CT_LEN],
    traditional: [u8; 32],
}
impl Ciphertext {
    /// Decode exactly 1120 ciphertext bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CIPHERTEXT_LEN {
            return Err(Error::InvalidLength);
        }
        let (pq, traditional) = bytes.split_at(ML_KEM_768_CT_LEN);
        Ok(Self {
            pq: pq.try_into().map_err(|_| Error::InvalidLength)?,
            traditional: traditional.try_into().map_err(|_| Error::InvalidLength)?,
        })
    }
    /// Encode public bytes.
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_LEN] {
        let mut bytes = [0; CIPHERTEXT_LEN];
        let (pq, traditional) = bytes.split_at_mut(ML_KEM_768_CT_LEN);
        pq.copy_from_slice(&self.pq);
        traditional.copy_from_slice(&self.traditional);
        bytes
    }
}

/// Encapsulation result; shared secret ownership is explicit.
pub struct Encapsulation {
    /// Public ciphertext to send to the recipient.
    pub ciphertext: Ciphertext,
    /// Owned combined secret, without a raw-byte getter.
    pub secret: SharedSecret,
}

/// Non-cloneable combined-secret owner. This is not an authenticated session.
pub struct SharedSecret {
    inner: Option<Secret>,
    state: Arc<State>,
}
impl SharedSecret {
    /// Explicitly copy the combined secret for a reviewed external protocol/KDF.
    /// The recipient owns this copy and its erasure. No application KDF, peer
    /// authentication, key confirmation or session protocol is implied.
    pub fn export_for_protocol(&self) -> Result<ZeroizingBytes<32>, Error> {
        self.state.ensure_open()?;
        let secret = self.inner.as_ref().ok_or(Error::Closed)?;
        let mut output = ZeroizingBytes::zeroed();
        output.as_mut_bytes().copy_from_slice(secret.as_bytes());
        Ok(output)
    }
    /// Erase this owner. Previously exported copies remain the caller's responsibility.
    pub fn close(&mut self) {
        self.inner = None;
    }
}

#[cfg(test)]
mod tests;
