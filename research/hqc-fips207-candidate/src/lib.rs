#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Isolated, non-production adapters for the HQC v5 FIPS 207 draft candidate.
//!
//! This crate is a shadow research lane. It is not a Q-Periapt wire suite, has
//! no suite code, is not part of the production workspace, and must not be used
//! as an ABI 1 or ABI 2 dependency. In particular, it does not reuse historical
//! suite code `3`.
//!
//! The upstream primitive describes itself as tracking FIPS 207. That is an
//! upstream target claim, not evidence of an official publication: as of
//! 2026-07-12, the official NIST FIPS 207 IPD publication endpoint is
//! unavailable and NIST still describes the standard as forthcoming. Public
//! names here therefore say `DRAFT-CANDIDATE`, never `IPD` or final `FIPS`.
//!
//! Each adapter implements [`q_periapt_core::Kem`] with strict input/output
//! lengths and deterministic caller-provided key-generation and encapsulation
//! randomness. Both compatibility capabilities remain `false`, confining the
//! candidate to [`q_periapt_core::Profile::ContextBound`].

use hqc_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, HqcKem};
use q_periapt_core::{Error, Kem, ZeroizingBytes};

/// Stable research-family label. This is an algorithm-family label, not a wire
/// suite identifier or numeric suite code.
pub const CANDIDATE_FAMILY_ID: &str = "HQC-V5-FIPS207-DRAFT-CANDIDATE/hqc-kem-0.1.0-rc.0";

/// Deterministic key-generation seed length shared by all candidate parameter
/// sets.
pub const KEYGEN_SEED_LEN: usize = 32;

/// Salt length used by deterministic encapsulation for every candidate
/// parameter set.
pub const ENCAPS_SALT_LEN: usize = 16;

/// Shared-secret length produced by every candidate parameter set.
pub const SHARED_SECRET_LEN: usize = 32;

#[inline]
fn require_exact(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength)
    }
}

macro_rules! define_hqc_candidate {
    (
        $name:ident,
        $params:ty,
        $algorithm:literal,
        pk = $pk:literal,
        sk = $sk:literal,
        ct = $ct:literal,
        message = $message:literal,
        randomness = $randomness:literal
    ) => {
        #[doc = concat!(
                            $algorithm,
                    " shadow adapter. This is a non-production HQC v5 FIPS 207 draft candidate."
                        )]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Encapsulation-key (public-key) length in bytes.
            pub const PK_LEN: usize = $pk;
            /// Decapsulation-key (secret-key) length in bytes.
            pub const SK_LEN: usize = $sk;
            /// Ciphertext length in bytes.
            pub const CT_LEN: usize = $ct;
            /// Deterministic encapsulation message length in bytes.
            pub const MESSAGE_LEN: usize = $message;
            /// Caller-provided deterministic encapsulation randomness length.
            /// The layout is `message || salt`, where the salt is 16 bytes.
            pub const ENCAPS_RANDOMNESS_LEN: usize = $randomness;
            /// Shared-secret length in bytes.
            pub const SS_LEN: usize = SHARED_SECRET_LEN;

            /// Deterministically generate `(decapsulation_key, encapsulation_key)`
            /// from a 32-byte seed.
            #[must_use]
            pub fn generate(
                seed: [u8; KEYGEN_SEED_LEN],
            ) -> ([u8; Self::SK_LEN], [u8; Self::PK_LEN]) {
                let seed = ZeroizingBytes::from_bytes(seed);
                let (encapsulation_key, decapsulation_key) =
                    HqcKem::<$params>::generate_key_deterministic(seed.as_bytes());
                let mut sk = [0u8; Self::SK_LEN];
                let mut pk = [0u8; Self::PK_LEN];
                sk.copy_from_slice(decapsulation_key.as_ref());
                pk.copy_from_slice(encapsulation_key.as_ref());
                (sk, pk)
            }
        }

        impl Kem for $name {
            // No candidate-specific C2PRI proof is claimed at this research
            // boundary. ContextBound binds every component ciphertext and key.
            const C2PRI: bool = false;
            // This key API is not the seed-derived X-Wing key format.
            const COMPAT_XWING_SAFE: bool = false;

            fn algorithm(&self) -> &'static str {
                $algorithm
            }

            fn encapsulate(
                &self,
                pk: &[u8],
                randomness: &[u8],
                ct: &mut [u8],
                ss: &mut [u8],
            ) -> Result<(), Error> {
                // Validate every public boundary before doing expensive work or
                // mutating either caller-owned output.
                require_exact(pk.len(), Self::PK_LEN)?;
                require_exact(randomness.len(), Self::ENCAPS_RANDOMNESS_LEN)?;
                require_exact(ct.len(), Self::CT_LEN)?;
                require_exact(ss.len(), Self::SS_LEN)?;

                let public =
                    EncapsulationKey::<$params>::try_from(pk).map_err(|_| Error::Backend)?;
                let (message, salt_bytes) = randomness.split_at(Self::MESSAGE_LEN);
                let salt =
                    <&[u8; ENCAPS_SALT_LEN]>::try_from(salt_bytes).map_err(|_| Error::Backend)?;
                let (ciphertext, shared_secret) = public
                    .encapsulate_deterministic(message, salt)
                    .map_err(|_| Error::Backend)?;

                ct.copy_from_slice(ciphertext.as_ref());
                ss.copy_from_slice(shared_secret.as_ref());
                Ok(())
            }

            fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
                // Length is the only public rejection. Any same-length corrupt
                // ciphertext reaches the upstream implicit-rejection path.
                require_exact(sk.len(), Self::SK_LEN)?;
                require_exact(ct.len(), Self::CT_LEN)?;
                require_exact(ss.len(), Self::SS_LEN)?;

                let private =
                    DecapsulationKey::<$params>::try_from(sk).map_err(|_| Error::Backend)?;
                let ciphertext = Ciphertext::<$params>::try_from(ct).map_err(|_| Error::Backend)?;
                let shared_secret = private.decapsulate(&ciphertext);
                ss.copy_from_slice(shared_secret.as_ref());
                Ok(())
            }
        }
    };
}

define_hqc_candidate!(
    Hqc128Fips207DraftCandidate,
    hqc_kem::Hqc128Params,
    "HQC-128-V5-FIPS207-DRAFT-CANDIDATE",
    pk = 2241,
    sk = 2321,
    ct = 4433,
    message = 16,
    randomness = 32
);

define_hqc_candidate!(
    Hqc192Fips207DraftCandidate,
    hqc_kem::Hqc192Params,
    "HQC-192-V5-FIPS207-DRAFT-CANDIDATE",
    pk = 4514,
    sk = 4602,
    ct = 8978,
    message = 24,
    randomness = 40
);

define_hqc_candidate!(
    Hqc256Fips207DraftCandidate,
    hqc_kem::Hqc256Params,
    "HQC-256-V5-FIPS207-DRAFT-CANDIDATE",
    pk = 7237,
    sk = 7333,
    ct = 14421,
    message = 32,
    randomness = 48
);
