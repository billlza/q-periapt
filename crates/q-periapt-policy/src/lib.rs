#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-policy
//!
//! Crypto-agility engine. The whole point: **algorithm choices live in policy,
//! not in business code**. Applications ask the policy "is this algorithm/profile
//! allowed?", "does it meet the downgrade floor?", and "which combiner profile?"
//! instead of naming concrete algorithms inline. Migration (L3 → L5 or
//! deprecating an algorithm) becomes a config change, and a minimum
//! NIST level gives **downgrade protection**.
//!
//! **Signed-policy verification** ([`Policy::load_signed`]) authenticates a policy
//! file against a trusted key before trusting it — so a tampered policy cannot
//! silently weaken the suite — using an injected [`q_periapt_sig::Verifier`]
//! (SLH-DSA for a long-term root) with fail-closed semantics. Plain TOML loading is
//! [`Policy::from_toml`]. The signature covers the exact policy bytes, so there is
//! no canonical-encoding ambiguity.

use core::num::NonZeroU32;

use q_periapt_core::Profile;
use q_periapt_sig::Verifier;
use sha3::{Digest, Sha3_256};

/// Domain separation for detached signatures over policy documents.
pub const SIGNED_POLICY_DOMAIN: &[u8] = b"Q-PERIAPT-SIGNED-POLICY/v1";

/// Maximum signed-policy document size accepted before signature verification
/// or TOML parsing. Current policies are tiny; this prevents untrusted inputs
/// from driving unbounded message and parser allocation.
pub const MAX_SIGNED_POLICY_BYTES: usize = 64 * 1024;

/// Construct the canonical message signed by policy publishers and verified by
/// [`Policy::load_signed`]. The domain and fixed-width length prevent a policy
/// signature from being replayed as a signature in another protocol.
#[must_use]
pub fn policy_signature_message(toml: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNED_POLICY_DOMAIN.len() + 8 + toml.len());
    message.extend_from_slice(SIGNED_POLICY_DOMAIN);
    message.extend_from_slice(&(toml.len() as u64).to_be_bytes());
    message.extend_from_slice(toml);
    message
}

/// A concrete hybrid KEM suite understood by the policy engine.
///
/// This is deliberately a closed enum rather than caller-provided strings plus a
/// claimed security level.  A caller therefore cannot describe ML-KEM-768 as an
/// L5 primitive and trick the downgrade-floor comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HybridSuite {
    /// ML-KEM-768 with X25519 (NIST level 3).
    MlKem768X25519 = 1,
    /// ML-KEM-1024 with X25519 (NIST level 5).
    MlKem1024X25519 = 2,
}

impl HybridSuite {
    /// Stable suite identifier bound by the context-bound combiner.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::MlKem768X25519 => "ML-KEM-768+X25519",
            Self::MlKem1024X25519 => "ML-KEM-1024+X25519",
        }
    }

    /// Post-quantum component identifier.
    #[must_use]
    pub const fn pq_kem(self) -> &'static str {
        match self {
            Self::MlKem768X25519 => "ML-KEM-768",
            Self::MlKem1024X25519 => "ML-KEM-1024",
        }
    }

    /// Traditional component identifier.
    #[must_use]
    pub const fn traditional_kem(self) -> &'static str {
        "X25519"
    }

    /// NIST security level of the post-quantum component.
    #[must_use]
    pub const fn nist_level(self) -> u8 {
        match self {
            Self::MlKem768X25519 => 3,
            Self::MlKem1024X25519 => 5,
        }
    }

    /// Stable one-byte code used by language bindings.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode a stable one-byte suite code.
    ///
    /// Code `3` is a permanent tombstone for the incompatible pre-standard
    /// PQClean HQC suite. It must never be reinterpreted as FIPS 207 HQC.
    #[must_use]
    pub const fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::MlKem768X25519),
            2 => Some(Self::MlKem1024X25519),
            _ => None,
        }
    }

    const fn compat_xwing_safe(self) -> bool {
        matches!(self, Self::MlKem768X25519)
    }
}

/// Secret-key representation selected together with the suite and profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyFormat {
    /// Expanded/importable decapsulation key; requires the context-bound profile.
    Expanded = 1,
    /// Seed-derived X-Wing decapsulation key.
    SeedDerived = 2,
}

impl KeyFormat {
    /// Stable one-byte code used by language bindings.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode a stable one-byte key-format code.
    #[must_use]
    pub const fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Expanded),
            2 => Some(Self::SeedDerived),
            _ => None,
        }
    }
}

/// Atomic output of policy resolution.
///
/// Its fields are private so safe Rust callers cannot independently substitute a
/// profile, suite, key representation, or policy version after the policy engine
/// has made its decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedSuite {
    suite: HybridSuite,
    profile: Profile,
    key_format: KeyFormat,
    policy_version: NonZeroU32,
}

/// Persisted identity of the last accepted signed policy.
///
/// Version alone is insufficient: accepting two different signed documents with
/// the same version makes rollback/equivocation state ambiguous. The digest is
/// SHA3-256 over the exact signed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedPolicyState {
    version: NonZeroU32,
    digest: [u8; 32],
}

impl TrustedPolicyState {
    /// Length of the canonical state encoding (`version_be || digest`).
    pub const ENCODED_LEN: usize = 36;

    /// Construct persisted state from a non-zero version and exact-byte digest.
    pub fn new(version: u32, digest: [u8; 32]) -> Result<Self, PolicyError> {
        let version = NonZeroU32::new(version).ok_or(PolicyError::InvalidTrustedState)?;
        Ok(Self { version, digest })
    }

    /// Monotonic policy version.
    #[must_use]
    pub const fn version(self) -> u32 {
        self.version.get()
    }

    /// SHA3-256 digest of the exact signed policy bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Canonical portable encoding (`u32` big-endian version followed by digest).
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0u8; Self::ENCODED_LEN];
        encoded[..4].copy_from_slice(&self.version().to_be_bytes());
        encoded[4..].copy_from_slice(&self.digest);
        encoded
    }

    /// Decode the canonical portable state encoding.
    pub fn decode(encoded: &[u8]) -> Result<Self, PolicyError> {
        let encoded: &[u8; Self::ENCODED_LEN] = encoded
            .try_into()
            .map_err(|_| PolicyError::InvalidTrustedState)?;
        let version = u32::from_be_bytes(
            encoded[..4]
                .try_into()
                .map_err(|_| PolicyError::InvalidTrustedState)?,
        );
        let digest = encoded[4..]
            .try_into()
            .map_err(|_| PolicyError::InvalidTrustedState)?;
        Self::new(version, digest)
    }
}

/// A policy whose exact source bytes were authenticated under a trusted key.
///
/// Keeping this distinct from [`Policy`] prevents safe Rust APIs from confusing
/// an unsigned local configuration with a trust-boundary decision.
#[derive(Clone, Debug)]
pub struct AuthenticatedPolicy {
    policy: Policy,
    state: TrustedPolicyState,
}

/// Atomic suite decision plus the exact-byte identity of the signed policy that
/// authorized it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedResolvedSuite {
    resolved: ResolvedSuite,
    state: TrustedPolicyState,
}

impl AuthenticatedResolvedSuite {
    /// Concrete suite/profile/key-format/version decision.
    #[must_use]
    pub const fn resolved(self) -> ResolvedSuite {
        self.resolved
    }

    /// Exact signed-policy state that authorized the decision.
    #[must_use]
    pub const fn trusted_state(self) -> TrustedPolicyState {
        self.state
    }
}

impl AuthenticatedPolicy {
    /// Borrow the validated policy contents.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// State callers must persist after acceptance for rollback/equivocation checks.
    #[must_use]
    pub const fn trusted_state(&self) -> TrustedPolicyState {
        self.state
    }

    /// Resolve the authenticated policy against concrete local suites.
    pub fn resolve_suite(
        &self,
        locally_supported: &[HybridSuite],
    ) -> Result<AuthenticatedResolvedSuite, PolicyResolutionError> {
        let resolved = self.policy.resolve_suite(locally_supported)?;
        Ok(AuthenticatedResolvedSuite {
            resolved,
            state: self.state,
        })
    }
}

impl ResolvedSuite {
    /// Selected concrete hybrid suite.
    #[must_use]
    pub const fn suite(self) -> HybridSuite {
        self.suite
    }

    /// Selected combiner profile.
    #[must_use]
    pub const fn profile(self) -> Profile {
        self.profile
    }

    /// Selected secret-key representation.
    #[must_use]
    pub const fn key_format(self) -> KeyFormat {
        self.key_format
    }

    /// Monotonic policy content version.
    #[must_use]
    pub const fn policy_version(self) -> u32 {
        self.policy_version.get()
    }
}

/// Failure to map a validated policy onto the suites this runtime actually
/// implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyResolutionError {
    /// No locally implemented suite satisfies the allow-list and downgrade floor.
    NoSupportedSuite,
}

impl core::fmt::Display for PolicyResolutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSupportedSuite => {
                f.write_str("no implemented hybrid suite satisfies the active policy")
            }
        }
    }
}

/// NIST claimed security level (1/2/3/5) for a known algorithm id, or `None` if
/// the id is not a leveled post-quantum algorithm (e.g. a traditional partner
/// like `X25519`, or an unknown id).
#[must_use]
pub fn nist_level(id: &str) -> Option<u8> {
    Some(match id {
        "ML-KEM-512" => 1,
        "ML-DSA-44" => 2,
        "ML-KEM-768" | "ML-DSA-65" | "SLH-DSA-SHA2-192s" => 3,
        "ML-KEM-1024" | "ML-DSA-87" | "SLH-DSA-SHA2-256s" => 5,
        "SLH-DSA-SHA2-128s" => 1,
        _ => return None,
    })
}

/// Whether `id` is a recognized *traditional* (non-PQ) component that is
/// allowed to serve as the hybrid partner regardless of the PQ floor.
#[must_use]
pub fn is_traditional(id: &str) -> bool {
    matches!(id, "X25519" | "X448" | "P-256" | "P-384")
}

/// Whether a (post-quantum) KEM is ciphertext-second-preimage-resistant (C2PRI)
/// — the property that lets the fast [`Profile::CompatXWing`] omit its ciphertext
/// from the KDF. This function records only the primitive property. ML-KEM is
/// mapped as C2PRI. Exact backend API/key-format suitability is the
/// separate `HybridSuite::compat_xwing_safe` / `Kem::COMPAT_XWING_SAFE` capability.
#[must_use]
pub fn is_c2pri(id: &str) -> bool {
    matches!(id, "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024")
}

/// An evaluable algorithm policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Monotonic content version. A signed policy with a lower version than the caller's
    /// last-trusted one is a rollback ([`Policy::load_signed_monotonic`]).
    policy_version: NonZeroU32,
    /// Minimum acceptable NIST security level (downgrade floor). Default 3.
    min_nist_level: u8,
    /// Default combiner profile when no stronger requirement applies.
    default_profile: Profile,
    /// Allowed KEM identifiers (e.g. `"ML-KEM-768"`, `"X25519"`).
    allowed_kems: Vec<String>,
    /// Allowed signature identifiers (e.g. `"ML-DSA-65"`, `"SLH-DSA-SHA2-256s"`).
    allowed_sigs: Vec<String>,
    /// Explicitly deprecated identifiers (denied even if otherwise allowed).
    deprecated: Vec<String>,
}

impl Default for Policy {
    /// Default posture: hybrid lattice+traditional at NIST L3, context-bound
    /// profile, ML-DSA-65 + SLH-DSA for roots. Matches
    /// `docs/policy/default.policy.toml`.
    fn default() -> Self {
        Self {
            policy_version: NonZeroU32::MIN,
            min_nist_level: 3,
            default_profile: Profile::ContextBound,
            allowed_kems: vec!["ML-KEM-768".into(), "X25519".into()],
            allowed_sigs: vec!["ML-DSA-65".into(), "SLH-DSA-SHA2-256s".into()],
            deprecated: Vec::new(),
        }
    }
}

impl Policy {
    /// Construct and validate a policy from typed host values.
    ///
    /// This is the only public constructor besides the built-in postures and
    /// TOML loader. It rejects a zero version, an invalid NIST category, unknown
    /// identifiers, duplicate identifiers, and a policy that cannot authorize at
    /// least one PQ KEM, one traditional KEM, and one signature at its floor.
    pub fn try_new(
        policy_version: u32,
        min_nist_level: u8,
        default_profile: Profile,
        allowed_kems: Vec<String>,
        allowed_sigs: Vec<String>,
        deprecated: Vec<String>,
    ) -> Result<Self, PolicyError> {
        let policy_version = NonZeroU32::new(policy_version).ok_or(PolicyError::InvalidVersion)?;
        if !matches!(min_nist_level, 1 | 2 | 3 | 5) {
            return Err(PolicyError::InvalidFloor);
        }
        if has_duplicates(&allowed_kems)
            || has_duplicates(&allowed_sigs)
            || has_duplicates(&deprecated)
        {
            return Err(PolicyError::DuplicateAlgorithm);
        }
        if allowed_kems
            .iter()
            .any(|id| nist_level(id).is_none() && !is_traditional(id))
            || allowed_sigs
                .iter()
                .any(|id| nist_level(id).is_none() || is_traditional(id))
            || deprecated
                .iter()
                .any(|id| nist_level(id).is_none() && !is_traditional(id))
        {
            return Err(PolicyError::UnknownAlgorithm);
        }

        let policy = Self {
            policy_version,
            min_nist_level,
            default_profile,
            allowed_kems,
            allowed_sigs,
            deprecated,
        };
        let has_hybrid_suite = [HybridSuite::MlKem768X25519, HybridSuite::MlKem1024X25519]
            .iter()
            .any(|suite| {
                policy.kem_allowed(suite.pq_kem()) && policy.kem_allowed(suite.traditional_kem())
            });
        let has_signature = policy.allowed_sigs.iter().any(|id| policy.sig_allowed(id));
        if !has_hybrid_suite || !has_signature {
            return Err(PolicyError::Unsatisfiable);
        }
        Ok(policy)
    }

    /// Enhanced posture: NIST L5, context-bound combiner, ML-DSA-87 plus
    /// SLH-DSA-256s. Experimental HQC candidates are not product suites.
    #[must_use]
    pub fn enhanced() -> Self {
        Self {
            policy_version: NonZeroU32::MIN,
            min_nist_level: 5,
            default_profile: Profile::ContextBound,
            allowed_kems: vec!["ML-KEM-1024".into(), "X25519".into()],
            allowed_sigs: vec!["ML-DSA-87".into(), "SLH-DSA-SHA2-256s".into()],
            deprecated: Vec::new(),
        }
    }

    /// Monotonic policy content version.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version.get()
    }

    /// Minimum accepted NIST security category.
    #[must_use]
    pub const fn min_nist_level(&self) -> u8 {
        self.min_nist_level
    }

    /// Configured default combiner profile before suite-specific safety upgrades.
    #[must_use]
    pub const fn default_profile(&self) -> Profile {
        self.default_profile
    }

    /// Configured KEM allow-list in local preference order.
    #[must_use]
    pub fn allowed_kems(&self) -> &[String] {
        &self.allowed_kems
    }

    /// Configured signature allow-list.
    #[must_use]
    pub fn allowed_sigs(&self) -> &[String] {
        &self.allowed_sigs
    }

    /// Explicitly deprecated algorithm identifiers.
    #[must_use]
    pub fn deprecated(&self) -> &[String] {
        &self.deprecated
    }

    /// True iff `id` is explicitly deprecated.
    #[must_use]
    pub fn is_deprecated(&self, id: &str) -> bool {
        self.deprecated.iter().any(|d| d == id)
    }

    /// Whether `id` satisfies the downgrade floor. A leveled PQ algorithm must
    /// meet `min_nist_level`; a recognized traditional partner is allowed; an
    /// unknown id is denied (fail-closed).
    #[must_use]
    pub fn meets_floor(&self, id: &str) -> bool {
        match nist_level(id) {
            Some(level) => level >= self.min_nist_level,
            None => is_traditional(id),
        }
    }

    /// True iff `id` is an allowed KEM: listed, not deprecated, **and** it meets
    /// the downgrade floor. (The floor check is what was missing before — a
    /// below-floor KEM placed in `allowed_kems` is now correctly rejected.)
    #[must_use]
    pub fn kem_allowed(&self, id: &str) -> bool {
        !self.is_deprecated(id) && self.allowed_kems.iter().any(|k| k == id) && self.meets_floor(id)
    }

    /// True iff `id` is an allowed signature algorithm (listed, not deprecated,
    /// meets floor).
    #[must_use]
    pub fn sig_allowed(&self, id: &str) -> bool {
        !self.is_deprecated(id) && self.allowed_sigs.iter().any(|s| s == id) && self.meets_floor(id)
    }

    /// Whether any allowed PQ KEM lacks a locally mapped C2PRI capability, which
    /// forces the stronger context-bound combiner for safety.
    #[must_use]
    fn requires_context_bound(&self) -> bool {
        self.allowed_kems
            .iter()
            .any(|k| self.kem_allowed(k) && nist_level(k).is_some() && !is_c2pri(k))
    }

    /// Resolve this policy against the exact suites compiled into a caller.
    ///
    /// The result is one atomic [`ResolvedSuite`], not a profile string plus
    /// caller-controlled metadata. Selection maximizes the NIST level and then
    /// follows this policy's KEM preference order, independent of peer/local list
    /// ordering. A suite is eligible only when both of its components are
    /// allowed. `CompatXWing` is automatically upgraded to `ContextBound` for a
    /// suite/key format that is not byte-compatible with X-Wing.
    pub fn resolve_suite(
        &self,
        locally_supported: &[HybridSuite],
    ) -> Result<ResolvedSuite, PolicyResolutionError> {
        let preference = |id: &str| {
            self.allowed_kems
                .iter()
                .position(|candidate| candidate == id)
                .unwrap_or(usize::MAX)
        };
        let suite = locally_supported
            .iter()
            .copied()
            .filter(|suite| {
                self.kem_allowed(suite.pq_kem()) && self.kem_allowed(suite.traditional_kem())
            })
            .max_by_key(|suite| {
                (
                    suite.nist_level(),
                    core::cmp::Reverse(preference(suite.pq_kem())),
                )
            })
            .ok_or(PolicyResolutionError::NoSupportedSuite)?;

        let profile = if self.requires_context_bound()
            || (self.default_profile == Profile::CompatXWing && !suite.compat_xwing_safe())
        {
            Profile::ContextBound
        } else {
            self.default_profile
        };
        let key_format = match profile {
            Profile::ContextBound => KeyFormat::Expanded,
            Profile::CompatXWing => KeyFormat::SeedDerived,
        };
        Ok(ResolvedSuite {
            suite,
            profile,
            key_format,
            policy_version: self.policy_version,
        })
    }
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values.iter().take(index).any(|prior| prior == value))
}

/// The only policy `schema_version` this build understands.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Errors from loading or authenticating an algorithm policy. These are host-side
/// configuration faults (not side-channel-sensitive), so — unlike the deliberately
/// coarse [`q_periapt_core::Error`] — they are descriptive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PolicyError {
    /// The exact signed policy exceeded [`MAX_SIGNED_POLICY_BYTES`].
    PolicyTooLarge,
    /// Not valid UTF-8 / TOML, or a field had the wrong type or was missing.
    Malformed,
    /// `policy_version` was zero. Signed and unsigned policy files must carry a
    /// non-zero monotonic version; silently defaulting a missing version to zero
    /// would disable meaningful rollback state.
    InvalidVersion,
    /// `min_nist_level` was not one of the defined NIST categories 1, 2, 3, or 5.
    InvalidFloor,
    /// An allow-list or deprecation entry names an algorithm this build does not know.
    UnknownAlgorithm,
    /// An allow-list or deprecation list contains the same identifier more than once.
    DuplicateAlgorithm,
    /// After floor/deprecation checks the policy has no complete hybrid suite or
    /// no usable signature algorithm.
    Unsatisfiable,
    /// A caller-supplied persisted policy state was malformed or had version zero.
    InvalidTrustedState,
    /// `schema_version` is not one this build understands.
    UnsupportedSchema,
    /// `default_profile` was not a recognized combiner profile.
    UnknownProfile,
    /// The detached signature did not verify under the trusted key. **Fail-closed:**
    /// the policy is rejected; callers must not trust attacker-influenced data.
    SignatureInvalid,
    /// The signing key's algorithm is weaker than the floor the policy asserts (e.g. an
    /// L1 root signing an L5 policy) — the trust anchor must be at least as strong as the
    /// posture it authorizes.
    WeakSigner,
    /// The policy's `policy_version` is older than the caller's last-trusted version — a
    /// rollback/replay of a previously-valid but now-superseded policy.
    Rollback,
    /// A different signed policy reused the already-trusted version number.
    Equivocation,
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PolicyError::PolicyTooLarge => "signed policy exceeds the configured byte limit",
            PolicyError::Malformed => "malformed policy file",
            PolicyError::InvalidVersion => "policy_version must be non-zero",
            PolicyError::InvalidFloor => "min_nist_level must be 1, 2, 3, or 5",
            PolicyError::UnknownAlgorithm => "policy contains an unknown algorithm identifier",
            PolicyError::DuplicateAlgorithm => "policy contains a duplicate algorithm identifier",
            PolicyError::Unsatisfiable => {
                "policy cannot authorize a complete hybrid suite and signature"
            }
            PolicyError::InvalidTrustedState => "malformed trusted policy state",
            PolicyError::UnsupportedSchema => "unsupported policy schema_version",
            PolicyError::UnknownProfile => "unknown default_profile",
            PolicyError::SignatureInvalid => "policy signature did not verify",
            PolicyError::WeakSigner => "signing key weaker than the policy's floor",
            PolicyError::Rollback => "policy version older than last-trusted (rollback)",
            PolicyError::Equivocation => "different signed policy reused the last-trusted version",
        })
    }
}

/// Wire schema of a `*.policy.toml` file (`docs/policy/default.policy.toml`).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema_version: u32,
    /// Non-zero monotonic content version used for rollback protection.
    policy_version: u32,
    min_nist_level: u8,
    default_profile: String,
    allowed_kems: Vec<String>,
    allowed_sigs: Vec<String>,
    deprecated: Vec<String>,
}

impl Policy {
    /// Parse and validate a policy from TOML text (see
    /// `docs/policy/default.policy.toml`). This does **not** authenticate the
    /// source — use [`Policy::load_signed`] whenever the policy may have crossed a
    /// trust boundary.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let f: PolicyFile = toml::from_str(text).map_err(|_| PolicyError::Malformed)?;
        if f.schema_version != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedSchema);
        }
        let default_profile = match f.default_profile.as_str() {
            "CompatXWing" => Profile::CompatXWing,
            "ContextBound" => Profile::ContextBound,
            _ => return Err(PolicyError::UnknownProfile),
        };
        Self::try_new(
            f.policy_version,
            f.min_nist_level,
            default_profile,
            f.allowed_kems,
            f.allowed_sigs,
            f.deprecated,
        )
    }

    /// Load a policy **only if** a detached signature over the exact policy bytes
    /// verifies under a trusted verification key — downgrade protection applied to
    /// the policy *itself*, so a tampered policy cannot silently weaken the suite.
    ///
    /// The `verifier` is injected (typically SLH-DSA for a long-term root, per the
    /// suite's trust-anchor design), keeping this crate backend-agnostic. The
    /// signature covers a domain-separated, length-prefixed representation of
    /// the raw `toml` bytes — no canonical-encoding ambiguity.
    /// **Fail-closed:** any signature or parse failure is an `Err`; the caller
    /// must reject the policy and abort the policy-controlled operation. This
    /// crate deliberately provides no success-looking fallback policy API.
    pub fn load_signed<V: Verifier>(
        verifier: &V,
        verification_key: &[u8],
        toml: &[u8],
        signature: &[u8],
    ) -> Result<AuthenticatedPolicy, PolicyError> {
        if toml.len() > MAX_SIGNED_POLICY_BYTES {
            return Err(PolicyError::PolicyTooLarge);
        }
        let signed_message = policy_signature_message(toml);
        verifier
            .verify(verification_key, &signed_message, signature)
            .map_err(|_| PolicyError::SignatureInvalid)?;
        let text = core::str::from_utf8(toml).map_err(|_| PolicyError::Malformed)?;
        let policy = Self::from_toml(text)?;
        // The trust anchor must be at least as strong as the posture it authorizes: an L1
        // root must not be able to sign an L5 policy. Bind the signer's strength to the floor.
        if verifier.algorithm().nist_level() < policy.min_nist_level() {
            return Err(PolicyError::WeakSigner);
        }
        let digest: [u8; 32] = Sha3_256::digest(toml).into();
        let state = TrustedPolicyState {
            version: policy.policy_version,
            digest,
        };
        Ok(AuthenticatedPolicy { policy, state })
    }

    /// Like [`Policy::load_signed`] but additionally compares the exact signed-byte
    /// identity with an optional previously persisted state.
    ///
    /// A lower version is a rollback. Reusing the same version for different
    /// policy bytes is equivocation and is also rejected. Re-applying the exact
    /// same signed policy is idempotent. Callers must atomically persist the
    /// returned [`AuthenticatedPolicy::trusted_state`] after acceptance.
    pub fn load_signed_monotonic<V: Verifier>(
        verifier: &V,
        verification_key: &[u8],
        toml: &[u8],
        signature: &[u8],
        last_trusted: Option<&TrustedPolicyState>,
    ) -> Result<AuthenticatedPolicy, PolicyError> {
        let authenticated = Self::load_signed(verifier, verification_key, toml, signature)?;
        if let Some(last) = last_trusted {
            let current = authenticated.trusted_state();
            if current.version < last.version {
                return Err(PolicyError::Rollback);
            }
            if current.version == last.version && current.digest != last.digest {
                return Err(PolicyError::Equivocation);
            }
        }
        Ok(authenticated)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use core::cell::Cell;

    use super::*;

    struct RecordingVerifier {
        called: Cell<bool>,
    }

    impl q_periapt_sig::Verifier for RecordingVerifier {
        fn algorithm(&self) -> q_periapt_sig::SigAlg {
            q_periapt_sig::SigAlg::MlDsa65
        }

        fn verify(
            &self,
            _pk: &[u8],
            _msg: &[u8],
            _sig: &[u8],
        ) -> Result<(), q_periapt_core::Error> {
            self.called.set(true);
            Err(q_periapt_core::Error::Backend)
        }
    }

    #[test]
    fn oversized_signed_policy_fails_before_verification_or_parsing() {
        let oversized = vec![b'x'; MAX_SIGNED_POLICY_BYTES + 1];
        let verifier = RecordingVerifier {
            called: Cell::new(false),
        };
        assert_eq!(
            Policy::load_signed(&verifier, &[], &oversized, &[]).unwrap_err(),
            PolicyError::PolicyTooLarge
        );
        assert!(!verifier.called.get(), "oversized input reached verifier");
    }

    #[test]
    fn floor_rejects_below_level_kem() {
        let p = Policy::default(); // floor = L3
                                   // ML-KEM-512 is L1: listed-or-not, it must fail the floor.
        assert!(!p.meets_floor("ML-KEM-512"));
        assert!(p.meets_floor("ML-KEM-768"));
        assert!(p.meets_floor("X25519")); // traditional partner allowed
        assert!(!p.meets_floor("RSA-2048")); // unknown -> fail-closed
    }

    #[test]
    fn enhanced_floor_rejects_mlkem768() {
        let p = Policy::enhanced(); // floor = L5
        assert!(
            !p.kem_allowed("ML-KEM-768"),
            "L3 KEM must not pass an L5 floor"
        );
        // The full enhanced KEM pair (ML-KEM-1024 + X25519) that the enhanced
        // HybridKem<MlKem1024, X25519> relies on must both pass the L5 posture.
        assert!(p.kem_allowed("ML-KEM-1024"));
        assert!(
            p.kem_allowed("X25519"),
            "enhanced suite's traditional partner must pass the floor"
        );
    }

    #[test]
    fn deprecation_overrides_allow_list() {
        let p = Policy::try_new(
            1,
            3,
            Profile::ContextBound,
            vec!["ML-KEM-768".into(), "X25519".into()],
            vec!["ML-DSA-65".into()],
            vec!["ML-KEM-768".into()],
        )
        .unwrap_err();
        assert_eq!(p, PolicyError::Unsatisfiable);

        let mut p = Policy::default();
        assert!(p.kem_allowed("ML-KEM-768"));
        p.deprecated.push("ML-KEM-768".into());
        assert!(!p.kem_allowed("ML-KEM-768"));
    }

    #[test]
    fn suite_without_compat_capability_forces_context_bound() {
        let compat_requested_for_l5 = Policy {
            default_profile: Profile::CompatXWing,
            ..Policy::enhanced()
        };
        assert_eq!(
            compat_requested_for_l5
                .resolve_suite(&[HybridSuite::MlKem1024X25519])
                .unwrap()
                .profile(),
            Profile::ContextBound,
            "a suite without an X-Wing-safe key-format mapping must override CompatXWing"
        );
    }

    #[test]
    fn retired_hqc_suite_and_identifiers_fail_closed() {
        assert_eq!(HybridSuite::from_u8(3), None);
        assert_eq!(nist_level("HQC-128"), None);
        assert_eq!(nist_level("HQC-192"), None);
        assert_eq!(nist_level("HQC-256"), None);
        assert_eq!(
            Policy::try_new(
                2,
                5,
                Profile::ContextBound,
                vec!["HQC-256".into(), "X25519".into()],
                vec!["ML-DSA-87".into()],
                Vec::new(),
            )
            .unwrap_err(),
            PolicyError::UnknownAlgorithm,
            "pre-standard HQC policies require explicit migration and re-signing"
        );
    }

    #[test]
    fn resolve_suite_is_atomic_deterministic_and_fail_closed() {
        let default = Policy::default()
            .resolve_suite(&[HybridSuite::MlKem1024X25519, HybridSuite::MlKem768X25519])
            .unwrap();
        assert_eq!(default.suite(), HybridSuite::MlKem768X25519);
        assert_eq!(default.profile(), Profile::ContextBound);
        assert_eq!(default.key_format(), KeyFormat::Expanded);
        assert_eq!(default.policy_version(), 1);

        let enhanced = Policy::enhanced()
            .resolve_suite(&[HybridSuite::MlKem768X25519, HybridSuite::MlKem1024X25519])
            .unwrap();
        assert_eq!(enhanced.suite(), HybridSuite::MlKem1024X25519);
        assert_eq!(enhanced.profile(), Profile::ContextBound);

        assert_eq!(
            Policy::enhanced()
                .resolve_suite(&[HybridSuite::MlKem768X25519])
                .unwrap_err(),
            PolicyResolutionError::NoSupportedSuite
        );
    }

    #[test]
    fn nist_level_table_agrees_with_sigalg() {
        // The policy `nist_level` id->level table and `q-periapt-sig`'s `SigAlg::nist_level`
        // are hand-maintained in separate crates; this guard fails CI if they ever diverge.
        use q_periapt_sig::SigAlg;
        for a in [
            SigAlg::MlDsa44,
            SigAlg::MlDsa65,
            SigAlg::MlDsa87,
            SigAlg::SlhDsaSha2_128s,
            SigAlg::SlhDsaSha2_192s,
            SigAlg::SlhDsaSha2_256s,
        ] {
            assert_eq!(
                nist_level(a.id()),
                Some(a.nist_level()),
                "policy/SigAlg NIST-level drift for {}",
                a.id()
            );
        }
    }
}

#[cfg(test)]
mod load_tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
    use q_periapt_sig::Signer;

    const POLICY: &str = "schema_version = 1\n\
        policy_version = 1\n\
        min_nist_level = 3\n\
        default_profile = \"ContextBound\"\n\
        allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
        allowed_sigs = [\"ML-DSA-65\", \"SLH-DSA-SHA2-256s\"]\n\
        deprecated = []\n";

    #[test]
    fn from_toml_parses_and_enforces() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert_eq!(p.min_nist_level(), 3);
        assert_eq!(p.default_profile(), Profile::ContextBound);
        assert!(p.kem_allowed("ML-KEM-768"));
        assert!(p.sig_allowed("ML-DSA-65"));
        assert!(!p.kem_allowed("ML-KEM-512")); // below floor
    }

    #[test]
    fn from_toml_rejects_bad_schema_and_profile() {
        let bad_schema = POLICY.replace("schema_version = 1", "schema_version = 2");
        assert_eq!(
            Policy::from_toml(&bad_schema).unwrap_err(),
            PolicyError::UnsupportedSchema
        );
        let bad_profile = POLICY.replace("ContextBound", "Nonsense");
        assert_eq!(
            Policy::from_toml(&bad_profile).unwrap_err(),
            PolicyError::UnknownProfile
        );
        assert_eq!(
            Policy::from_toml("not = valid = toml").unwrap_err(),
            PolicyError::Malformed
        );
    }

    #[test]
    fn signed_load_accepts_valid_and_fails_closed() {
        // Sign the exact policy bytes with a root key. The mechanism is
        // verifier-agnostic (ML-DSA-65 here for fast tests; SLH-DSA is the intended
        // production root) — load_signed only trusts an authenticated policy.
        let (sk, vk) = MlDsa65::generate([9u8; 32]);
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let message = policy_signature_message(POLICY.as_bytes());
        let n = MlDsa65.sign(&sk, &message, &[0u8; 32], &mut sig).unwrap();
        let sig = &sig[..n];

        // Authentic policy loads.
        let p = Policy::load_signed(&MlDsa65, &vk, POLICY.as_bytes(), sig).unwrap();
        assert_eq!(p.policy().default_profile(), Profile::ContextBound);
        assert_eq!(p.trusted_state().version(), 1);

        // One flipped byte in the body → rejected.
        let mut tampered = POLICY.as_bytes().to_vec();
        tampered[20] ^= 1;
        assert_eq!(
            Policy::load_signed(&MlDsa65, &vk, &tampered, sig).unwrap_err(),
            PolicyError::SignatureInvalid
        );

        // Wrong trust key → rejected.
        let (_, other_vk) = MlDsa65::generate([1u8; 32]);
        assert_eq!(
            Policy::load_signed(&MlDsa65, &other_vk, POLICY.as_bytes(), sig).unwrap_err(),
            PolicyError::SignatureInvalid
        );

        // There is no fallback posture: authentication failure remains an error.
        assert_eq!(
            Policy::load_signed(&MlDsa65, &other_vk, POLICY.as_bytes(), sig).unwrap_err(),
            PolicyError::SignatureInvalid
        );
    }

    // ---- audit hardening: floor validation, signer-strength binding, rollback ----

    /// Sign `text` with a fresh ML-DSA-65 (L3) root, returning `(verification_key, signature)`.
    fn sign_with_root(text: &str, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = MlDsa65::generate([seed; 32]);
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let message = policy_signature_message(text.as_bytes());
        let n = MlDsa65.sign(&sk, &message, &[0u8; 32], &mut sig).unwrap();
        (vk.to_vec(), sig[..n].to_vec())
    }

    #[test]
    fn from_toml_rejects_invalid_floor() {
        // 0 would silently disable the downgrade floor; 4 is not a real NIST category.
        for bad in ["min_nist_level = 0", "min_nist_level = 4"] {
            let t = POLICY.replace("min_nist_level = 3", bad);
            assert_eq!(
                Policy::from_toml(&t).unwrap_err(),
                PolicyError::InvalidFloor
            );
        }
    }

    #[test]
    fn from_toml_requires_version_and_rejects_unknown_fields() {
        let missing_version = POLICY.replace("policy_version = 1\n", "");
        assert_eq!(
            Policy::from_toml(&missing_version).unwrap_err(),
            PolicyError::Malformed
        );
        let zero_version = POLICY.replace("policy_version = 1", "policy_version = 0");
        assert_eq!(
            Policy::from_toml(&zero_version).unwrap_err(),
            PolicyError::InvalidVersion
        );
        let misspelled = POLICY.replace("deprecated = []", "depreacted = []");
        assert_eq!(
            Policy::from_toml(&misspelled).unwrap_err(),
            PolicyError::Malformed
        );
    }

    #[test]
    fn signed_load_rejects_signer_weaker_than_floor() {
        // An L5 policy signed by an L3 root (ML-DSA-65) must be refused — the trust anchor
        // must be at least as strong as the posture it authorizes.
        let l5 = POLICY
            .replace("min_nist_level = 3", "min_nist_level = 5")
            .replace("ML-KEM-768", "ML-KEM-1024");
        let (vk, sig) = sign_with_root(&l5, 7);
        assert_eq!(
            Policy::load_signed(&MlDsa65, &vk, l5.as_bytes(), &sig).unwrap_err(),
            PolicyError::WeakSigner
        );
        // The same policy at floor 3 (signer is also L3) loads fine.
        let (vk3, sig3) = sign_with_root(POLICY, 7);
        assert!(Policy::load_signed(&MlDsa65, &vk3, POLICY.as_bytes(), &sig3).is_ok());
    }

    #[test]
    fn signed_load_monotonic_rejects_rollback() {
        // A validly-signed policy at version 2.
        let v2 = POLICY.replace("policy_version = 1", "policy_version = 2");
        let (vk, sig) = sign_with_root(&v2, 5);
        let loaded =
            Policy::load_signed_monotonic(&MlDsa65, &vk, v2.as_bytes(), &sig, None).unwrap();
        let same = loaded.trusted_state();
        // Exact re-apply is idempotent.
        assert!(
            Policy::load_signed_monotonic(&MlDsa65, &vk, v2.as_bytes(), &sig, Some(&same)).is_ok()
        );
        // Re-installing an older version than the last-trusted one (3) is a rollback.
        let newer_state = TrustedPolicyState::new(3, [3u8; 32]).unwrap();
        assert_eq!(
            Policy::load_signed_monotonic(&MlDsa65, &vk, v2.as_bytes(), &sig, Some(&newer_state))
                .unwrap_err(),
            PolicyError::Rollback
        );

        // A different validly-signed body may not reuse version 2.
        let v2_different = v2.replace("ContextBound", "CompatXWing");
        let (vk_different, sig_different) = sign_with_root(&v2_different, 6);
        assert_eq!(
            Policy::load_signed_monotonic(
                &MlDsa65,
                &vk_different,
                v2_different.as_bytes(),
                &sig_different,
                Some(&same)
            )
            .unwrap_err(),
            PolicyError::Equivocation
        );

        assert_eq!(TrustedPolicyState::decode(&same.encode()).unwrap(), same);
    }
}
