#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-sig
//!
//! Signature layer for the PQ/T hybrid suite.
//!
//! - **ML-DSA-65 / ML-DSA-87** (FIPS 204) for general-purpose signatures.
//! - **SLH-DSA** (FIPS 205, hash-based) for the most conservative trust anchors:
//!   roots, firmware, and long-term signatures, where large/slow signatures are
//!   an acceptable trade for minimal assumptions.
//!
//! Backends (`fips204` for ML-DSA, `fips205` for SLH-DSA) are wired into
//! `q-periapt-backends` behind cargo features; this crate defines the algorithm-agnostic
//! trait surface that the policy layer and FFI build on. (RustCrypto `ml-dsa` appears only
//! as a `[dev-dependencies]` differential cross-check, not as a shipped backend.)

use q_periapt_core::Error;

/// Signature algorithms recognized by the suite. The policy layer maps these to
/// backends and decides which are permitted — business code never hardcodes one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SigAlg {
    /// ML-DSA-44 (FIPS 204), NIST level 2. Smallest ML-DSA parameter set.
    MlDsa44,
    /// ML-DSA-65 (FIPS 204), NIST level 3. General-purpose default.
    MlDsa65,
    /// ML-DSA-87 (FIPS 204), NIST level 5. Enhanced mode.
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205). Small/slow, conservative; roots/firmware.
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-192s (FIPS 205). Level 3, conservative long-term.
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-256s (FIPS 205). Level 5, most conservative.
    SlhDsaSha2_256s,
}

impl SigAlg {
    /// Stable string identifier (matches policy files and CBOM entries).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            SigAlg::MlDsa44 => "ML-DSA-44",
            SigAlg::MlDsa65 => "ML-DSA-65",
            SigAlg::MlDsa87 => "ML-DSA-87",
            SigAlg::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            SigAlg::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            SigAlg::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        }
    }

    /// Claimed NIST security level (1/2/3/5).
    #[must_use]
    pub fn nist_level(self) -> u8 {
        match self {
            SigAlg::MlDsa44 => 2,
            SigAlg::MlDsa65 | SigAlg::SlhDsaSha2_192s => 3,
            SigAlg::MlDsa87 | SigAlg::SlhDsaSha2_256s => 5,
            SigAlg::SlhDsaSha2_128s => 1,
        }
    }
}

/// Produces signatures.
///
/// Implementations must document their secret-dependent timing boundary. ML-DSA uses
/// rejection sampling, so its signer does not have a strict fixed-time contract; callers
/// must not expose signing as an attacker-amplifiable timing oracle. Verification operates
/// only on public inputs and is the product ABI's policy-authentication path.
pub trait Signer {
    /// Algorithm this signer implements.
    fn algorithm(&self) -> SigAlg;
    /// Sign `msg` with `sk`, writing into `out_sig`; returns the signature length.
    ///
    /// `randomness` is the signing nonce (caller-provided so the operation is
    /// deterministic — KAT-able — and `no_std`, with no internal RNG): 32 bytes
    /// for ML-DSA hedged signing; pass all-zero for deterministic signing.
    fn sign(
        &self,
        sk: &[u8],
        msg: &[u8],
        randomness: &[u8],
        out_sig: &mut [u8],
    ) -> Result<usize, Error>;
}

/// Verifies signatures.
pub trait Verifier {
    /// Algorithm this verifier implements.
    fn algorithm(&self) -> SigAlg;
    /// Verify `sig` over `msg` under `pk`. `Ok(())` iff valid.
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_and_ids() {
        assert_eq!(SigAlg::MlDsa65.nist_level(), 3);
        assert_eq!(SigAlg::MlDsa87.nist_level(), 5);
        assert_eq!(SigAlg::SlhDsaSha2_256s.id(), "SLH-DSA-SHA2-256s");
    }
}
