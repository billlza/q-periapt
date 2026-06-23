#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # pqt-policy
//!
//! Crypto-agility engine. The whole point: **algorithm choices live in policy,
//! not in business code**. Applications ask the policy "is this algorithm/profile
//! allowed?", "does it meet the downgrade floor?", and "which combiner profile?"
//! instead of naming concrete algorithms inline. Migration (L3 → L5, enabling the
//! HQC backup, deprecating an algorithm) becomes a config change, and a minimum
//! NIST level gives **downgrade protection**.
//!
//! Signed-policy verification (SLH-DSA over a canonical encoding, fail-closed to a
//! conservative compiled-in default) is tracked in `docs/ROADMAP.md` and depends
//! on a real `pqt-sig` backend; this module implements the in-memory model and
//! the *enforcement* logic, which are the security-relevant parts.

use pqt_core::Profile;

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
    /// this policy and offered by the peer, or [`pqt_core::Error::PolicyDenied`]
    /// if the peer offers nothing acceptable — i.e. a downgrade attempt aborts
    /// rather than silently selecting a weak suite.
    pub fn negotiate_kem<'p>(&self, peer_offered: &[&'p str]) -> Result<&'p str, pqt_core::Error> {
        peer_offered
            .iter()
            .copied()
            .filter(|id| self.kem_allowed(id) && nist_level(id).is_some())
            .max_by_key(|id| nist_level(id).unwrap_or(0))
            .ok_or(pqt_core::Error::PolicyDenied)
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
        assert!(p.kem_allowed("ML-KEM-1024"));
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
}
