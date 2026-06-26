#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-policy
//!
//! Crypto-agility engine. The whole point: **algorithm choices live in policy,
//! not in business code**. Applications ask the policy "is this algorithm/profile
//! allowed?", "does it meet the downgrade floor?", and "which combiner profile?"
//! instead of naming concrete algorithms inline. Migration (L3 → L5, enabling the
//! HQC backup, deprecating an algorithm) becomes a config change, and a minimum
//! NIST level gives **downgrade protection**.
//!
//! **Signed-policy verification** ([`Policy::load_signed`]) authenticates a policy
//! file against a trusted key before trusting it — so a tampered policy cannot
//! silently weaken the suite — using an injected [`q_periapt_sig::Verifier`]
//! (SLH-DSA for a long-term root) with fail-closed semantics. Plain TOML loading is
//! [`Policy::from_toml`]. The signature covers the exact policy bytes, so there is
//! no canonical-encoding ambiguity.

use q_periapt_core::Profile;
use q_periapt_sig::Verifier;

/// NIST claimed security level (1/2/3/5) for a known algorithm id, or `None` if
/// the id is not a leveled post-quantum algorithm (e.g. a traditional partner
/// like `X25519`, or an unknown id).
#[must_use]
pub fn nist_level(id: &str) -> Option<u8> {
    Some(match id {
        "ML-KEM-512" | "HQC-128" => 1,
        "ML-DSA-44" => 2,
        "ML-KEM-768" | "HQC-192" | "ML-DSA-65" | "SLH-DSA-SHA2-192s" => 3,
        "ML-KEM-1024" | "HQC-256" | "ML-DSA-87" | "SLH-DSA-SHA2-256s" => 5,
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
/// from the KDF. ML-KEM is C2PRI; HQC (as wired here) is not.
#[must_use]
pub fn is_c2pri(id: &str) -> bool {
    matches!(id, "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024")
}

/// An evaluable algorithm policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Monotonic content version. A signed policy with a lower version than the caller's
    /// last-trusted one is a rollback ([`Policy::load_signed_monotonic`]).
    pub policy_version: u32,
    /// Minimum acceptable NIST security level (downgrade floor). Default 3.
    pub min_nist_level: u8,
    /// Default combiner profile when no stronger requirement applies.
    pub default_profile: Profile,
    /// Allowed KEM identifiers (e.g. `"ML-KEM-768"`, `"X25519"`, `"HQC-256"`).
    pub allowed_kems: Vec<String>,
    /// Allowed signature identifiers (e.g. `"ML-DSA-65"`, `"SLH-DSA-SHA2-256s"`).
    pub allowed_sigs: Vec<String>,
    /// Explicitly deprecated identifiers (denied even if otherwise allowed).
    pub deprecated: Vec<String>,
}

impl Default for Policy {
    /// Default posture: hybrid lattice+traditional at NIST L3, fast
    /// (X-Wing-compatible) profile, ML-DSA-65 + SLH-DSA for roots. Matches
    /// `docs/policy/default.policy.toml`.
    fn default() -> Self {
        Self {
            policy_version: 1,
            min_nist_level: 3,
            default_profile: Profile::CompatXWing,
            allowed_kems: vec!["ML-KEM-768".into(), "X25519".into()],
            allowed_sigs: vec!["ML-DSA-65".into(), "SLH-DSA-SHA2-256s".into()],
            deprecated: Vec::new(),
        }
    }
}

impl Policy {
    /// Enhanced posture: NIST L5, context-bound combiner, code-based (HQC) backup
    /// for assumption diversity, ML-DSA-87 + SLH-DSA-256s.
    #[must_use]
    pub fn enhanced() -> Self {
        Self {
            policy_version: 1,
            min_nist_level: 5,
            default_profile: Profile::ContextBound,
            allowed_kems: vec!["ML-KEM-1024".into(), "X25519".into(), "HQC-256".into()],
            allowed_sigs: vec!["ML-DSA-87".into(), "SLH-DSA-SHA2-256s".into()],
            deprecated: Vec::new(),
        }
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

    /// Whether any allowed PQ KEM is non-C2PRI (e.g. HQC), which forces the
    /// stronger context-bound combiner for safety.
    #[must_use]
    pub fn requires_context_bound(&self) -> bool {
        self.allowed_kems
            .iter()
            .any(|k| nist_level(k).is_some() && !is_c2pri(k))
    }

    /// The combiner profile to actually use: [`Profile::ContextBound`] whenever a
    /// non-C2PRI KEM is in play (overriding `default_profile`), else the default.
    #[must_use]
    pub fn select_profile(&self) -> Profile {
        if self.requires_context_bound() {
            Profile::ContextBound
        } else {
            self.default_profile
        }
    }

    /// Negotiate a PQ KEM against a peer's offered list, enforcing the floor.
    ///
    /// Returns the strongest (highest NIST level) KEM that is both allowed by
    /// this policy and offered by the peer, or [`q_periapt_core::Error::PolicyDenied`]
    /// if the peer offers nothing acceptable — i.e. a downgrade attempt aborts
    /// rather than silently selecting a weak suite.
    ///
    /// Among equal-NIST-level candidates the choice is broken **deterministically by
    /// this policy's own preference** — the position in [`allowed_kems`](Self::allowed_kems),
    /// earlier = more preferred — so the selection cannot be steered by the order in
    /// which the peer lists its offers.
    pub fn negotiate_kem<'p>(
        &self,
        peer_offered: &[&'p str],
    ) -> Result<&'p str, q_periapt_core::Error> {
        let preference = |id: &str| {
            self.allowed_kems
                .iter()
                .position(|k| k.as_str() == id)
                .unwrap_or(usize::MAX)
        };
        peer_offered
            .iter()
            .copied()
            .filter(|id| self.kem_allowed(id) && nist_level(id).is_some())
            // Maximize (NIST level, then policy preference). `Reverse(rank)` turns the
            // earliest allow-list entry into the maximum, and the key is unique per id,
            // so the result does not depend on `peer_offered`'s ordering.
            .max_by_key(|id| {
                (
                    nist_level(id).unwrap_or(0),
                    core::cmp::Reverse(preference(id)),
                )
            })
            .ok_or(q_periapt_core::Error::PolicyDenied)
    }
}

/// The only policy `schema_version` this build understands.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Errors from loading or authenticating an algorithm policy. These are host-side
/// configuration faults (not side-channel-sensitive), so — unlike the deliberately
/// coarse [`q_periapt_core::Error`] — they are descriptive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PolicyError {
    /// Not valid UTF-8 / TOML, or a field had the wrong type or was missing.
    Malformed,
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
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PolicyError::Malformed => "malformed policy file",
            PolicyError::UnsupportedSchema => "unsupported policy schema_version",
            PolicyError::UnknownProfile => "unknown default_profile",
            PolicyError::SignatureInvalid => "policy signature did not verify",
            PolicyError::WeakSigner => "signing key weaker than the policy's floor",
            PolicyError::Rollback => "policy version older than last-trusted (rollback)",
        })
    }
}

/// Wire schema of a `*.policy.toml` file (`docs/policy/default.policy.toml`).
#[derive(serde::Deserialize)]
struct PolicyFile {
    schema_version: u32,
    /// Monotonic content version (rollback protection). Optional for unsigned/legacy files;
    /// signed deployments should always set it so [`Policy::load_signed_monotonic`] is meaningful.
    #[serde(default)]
    policy_version: u32,
    min_nist_level: u8,
    default_profile: String,
    allowed_kems: Vec<String>,
    allowed_sigs: Vec<String>,
    #[serde(default)]
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
        // The downgrade floor must be a real NIST category; reject `min_nist_level = 0`
        // (which would silently disable the floor) and the non-existent level 4.
        if !matches!(f.min_nist_level, 1 | 2 | 3 | 5) {
            return Err(PolicyError::Malformed);
        }
        let default_profile = match f.default_profile.as_str() {
            "CompatXWing" => Profile::CompatXWing,
            "ContextBound" => Profile::ContextBound,
            _ => return Err(PolicyError::UnknownProfile),
        };
        Ok(Self {
            policy_version: f.policy_version,
            min_nist_level: f.min_nist_level,
            default_profile,
            allowed_kems: f.allowed_kems,
            allowed_sigs: f.allowed_sigs,
            deprecated: f.deprecated,
        })
    }

    /// Load a policy **only if** a detached signature over the exact policy bytes
    /// verifies under a trusted verification key — downgrade protection applied to
    /// the policy *itself*, so a tampered policy cannot silently weaken the suite.
    ///
    /// The `verifier` is injected (typically SLH-DSA for a long-term root, per the
    /// suite's trust-anchor design), keeping this crate backend-agnostic. The
    /// signature covers the raw `toml` bytes — no canonical-encoding ambiguity.
    /// **Fail-closed:** any signature or parse failure is an `Err`; the caller
    /// decides whether to abort (recommended) or fall back via
    /// [`Policy::load_signed_or_failsafe`].
    pub fn load_signed<V: Verifier>(
        verifier: &V,
        verification_key: &[u8],
        toml: &[u8],
        signature: &[u8],
    ) -> Result<Self, PolicyError> {
        verifier
            .verify(verification_key, toml, signature)
            .map_err(|_| PolicyError::SignatureInvalid)?;
        let text = core::str::from_utf8(toml).map_err(|_| PolicyError::Malformed)?;
        let policy = Self::from_toml(text)?;
        // The trust anchor must be at least as strong as the posture it authorizes: an L1
        // root must not be able to sign an L5 policy. Bind the signer's strength to the floor.
        if verifier.algorithm().nist_level() < policy.min_nist_level {
            return Err(PolicyError::WeakSigner);
        }
        Ok(policy)
    }

    /// Like [`Policy::load_signed`] but additionally rejects a policy whose `policy_version`
    /// is **older** than `last_trusted_version` — rollback/replay protection. A validly-signed
    /// but superseded policy (e.g. one that predates a security tightening) must not be
    /// re-installable. Callers persist the last accepted version and pass it here; the same
    /// version is accepted (idempotent re-apply), only a strictly-older one is refused.
    pub fn load_signed_monotonic<V: Verifier>(
        verifier: &V,
        verification_key: &[u8],
        toml: &[u8],
        signature: &[u8],
        last_trusted_version: u32,
    ) -> Result<Self, PolicyError> {
        let policy = Self::load_signed(verifier, verification_key, toml, signature)?;
        if policy.policy_version < last_trusted_version {
            return Err(PolicyError::Rollback);
        }
        Ok(policy)
    }

    /// Like [`Policy::load_signed`] but **fail-closed to the conservative compiled-in
    /// default** ([`Policy::enhanced`]: L5 + `ContextBound`) on any failure, returning
    /// the offending [`PolicyError`] alongside it. For availability-critical callers
    /// that must keep running under the *strongest* posture rather than abort — a
    /// genuine deployment must log the error: an unauthenticated or malformed policy
    /// is a security event, not a routine fallback.
    #[must_use]
    pub fn load_signed_or_failsafe<V: Verifier>(
        verifier: &V,
        verification_key: &[u8],
        toml: &[u8],
        signature: &[u8],
    ) -> (Self, Option<PolicyError>) {
        match Self::load_signed(verifier, verification_key, toml, signature) {
            Ok(p) => (p, None),
            Err(e) => (Self::enhanced(), Some(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

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
        let mut p = Policy::default();
        assert!(p.kem_allowed("ML-KEM-768"));
        p.deprecated.push("ML-KEM-768".into());
        assert!(!p.kem_allowed("ML-KEM-768"));
    }

    #[test]
    fn non_c2pri_forces_context_bound() {
        assert_eq!(Policy::default().select_profile(), Profile::CompatXWing);
        // enhanced has HQC-256 (non-C2PRI) -> must force ContextBound.
        assert!(Policy::enhanced().requires_context_bound());
        assert_eq!(Policy::enhanced().select_profile(), Profile::ContextBound);
    }

    #[test]
    fn negotiate_prefers_strongest_and_aborts_on_downgrade() {
        let p = Policy::enhanced(); // allows ML-KEM-1024, X25519, HQC-256; floor L5
                                    // Peer offers a weak + a strong option: must pick the strongest allowed.
        let chosen = p.negotiate_kem(&["ML-KEM-512", "ML-KEM-1024"]).unwrap();
        assert_eq!(chosen, "ML-KEM-1024");
        // Peer offers only below-floor / disallowed options: must abort.
        assert!(p.negotiate_kem(&["ML-KEM-512", "ML-KEM-768"]).is_err());
    }

    #[test]
    fn negotiate_tie_break_is_deterministic_not_peer_steerable() {
        // enhanced() lists both ML-KEM-1024 and HQC-256 at NIST L5, with ML-KEM-1024
        // first in allowed_kems. The choice must follow OUR preference regardless of the
        // order the peer offers them in.
        let p = Policy::enhanced();
        assert_eq!(
            p.negotiate_kem(&["HQC-256", "ML-KEM-1024"]).unwrap(),
            "ML-KEM-1024"
        );
        assert_eq!(
            p.negotiate_kem(&["ML-KEM-1024", "HQC-256"]).unwrap(),
            "ML-KEM-1024"
        );
    }

    #[test]
    fn negotiate_kem_aborts_at_empty_boundaries() {
        // The downgrade chokepoint must fail closed at every empty/stripped boundary.
        // (i) Empty offer: nothing to select.
        assert!(Policy::enhanced().negotiate_kem(&[]).is_err());
        // (ii) Empty allow-list: every candidate is filtered out, for any offer.
        let no_kems = Policy {
            allowed_kems: Vec::new(),
            ..Policy::enhanced()
        };
        assert!(no_kems.negotiate_kem(&["ML-KEM-1024", "X25519"]).is_err());
        // (iii) Offer of only unrecognized ids (no NIST level): filtered out, abort.
        assert!(Policy::enhanced()
            .negotiate_kem(&["BOGUS-KEM", "totally-made-up"])
            .is_err());
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
        min_nist_level = 3\n\
        default_profile = \"CompatXWing\"\n\
        allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
        allowed_sigs = [\"ML-DSA-65\", \"SLH-DSA-SHA2-256s\"]\n\
        deprecated = []\n";

    #[test]
    fn from_toml_parses_and_enforces() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert_eq!(p.min_nist_level, 3);
        assert_eq!(p.default_profile, Profile::CompatXWing);
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
        let bad_profile = POLICY.replace("CompatXWing", "Nonsense");
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
        let n = MlDsa65
            .sign(&sk, POLICY.as_bytes(), &[0u8; 32], &mut sig)
            .unwrap();
        let sig = &sig[..n];

        // Authentic policy loads.
        let p = Policy::load_signed(&MlDsa65, &vk, POLICY.as_bytes(), sig).unwrap();
        assert_eq!(p.default_profile, Profile::CompatXWing);

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

        // Fail-closed fallback yields the strongest posture + reports the fault.
        let (fp, err) =
            Policy::load_signed_or_failsafe(&MlDsa65, &other_vk, POLICY.as_bytes(), sig);
        assert_eq!(fp.select_profile(), Profile::ContextBound);
        assert_eq!(fp.min_nist_level, 5);
        assert_eq!(err, Some(PolicyError::SignatureInvalid));
    }

    // ---- audit hardening: floor validation, signer-strength binding, rollback ----

    /// Sign `text` with a fresh ML-DSA-65 (L3) root, returning `(verification_key, signature)`.
    fn sign_with_root(text: &str, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = MlDsa65::generate([seed; 32]);
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let n = MlDsa65.sign(&sk, text.as_bytes(), &[0u8; 32], &mut sig).unwrap();
        (vk.to_vec(), sig[..n].to_vec())
    }

    #[test]
    fn from_toml_rejects_invalid_floor() {
        // 0 would silently disable the downgrade floor; 4 is not a real NIST category.
        for bad in ["min_nist_level = 0", "min_nist_level = 4"] {
            let t = POLICY.replace("min_nist_level = 3", bad);
            assert_eq!(Policy::from_toml(&t).unwrap_err(), PolicyError::Malformed);
        }
    }

    #[test]
    fn signed_load_rejects_signer_weaker_than_floor() {
        // An L5 policy signed by an L3 root (ML-DSA-65) must be refused — the trust anchor
        // must be at least as strong as the posture it authorizes.
        let l5 = POLICY.replace("min_nist_level = 3", "min_nist_level = 5");
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
        let v2 = POLICY.replace("schema_version = 1\n", "schema_version = 1\npolicy_version = 2\n");
        let (vk, sig) = sign_with_root(&v2, 5);
        // Same or newer than last-trusted is accepted (idempotent re-apply / upgrade).
        assert!(Policy::load_signed_monotonic(&MlDsa65, &vk, v2.as_bytes(), &sig, 2).is_ok());
        assert!(Policy::load_signed_monotonic(&MlDsa65, &vk, v2.as_bytes(), &sig, 1).is_ok());
        // Re-installing an older version than the last-trusted one (3) is a rollback → refused.
        assert_eq!(
            Policy::load_signed_monotonic(&MlDsa65, &vk, v2.as_bytes(), &sig, 3).unwrap_err(),
            PolicyError::Rollback
        );
    }
}
