//! FIPS 204 ML-DSA adapters.
//!
//! The product ABI uses verification for signed policy documents. Signing remains
//! available to Rust callers for research and tooling, but the upstream production
//! signing loop has the rejection-sampling timing exception required by ML-DSA and
//! is not covered by the former libcrux/hax source-level assurance claim.

use super::{to_arr, to_zeroizing, write_exact};
use fips204::{
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    traits::{
        KeyGen as Fips204KeyGen, SerDes as Fips204SerDes, Signer as Fips204Signer,
        Verifier as Fips204Verifier,
    },
    Ph,
};
use q_periapt_core::{Error, ZeroizingBytes};
use q_periapt_sig::{SigAlg, Signer, Verifier};

#[inline]
fn validate_context(context: &[u8]) -> Result<(), Error> {
    if context.len() > usize::from(u8::MAX) {
        return Err(Error::InvalidLength);
    }
    Ok(())
}

/// Validate the packed `s1 || s2` portion of an expanded ML-DSA signing key before
/// handing it to the backend. FIPS 204 requires each small coefficient to be in
/// `[-eta, eta]`; rejecting unused bit patterns here prevents a non-canonical byte
/// string from being expanded into out-of-range secret coefficients.
fn validate_small_secret_coefficients(
    signing_key: &[u8],
    eta: u8,
    packed_len: usize,
) -> Result<(), Error> {
    const PREFIX_LEN: usize = 128;
    let packed_end = PREFIX_LEN.checked_add(packed_len).ok_or(Error::Backend)?;
    let packed = signing_key
        .get(PREFIX_LEN..packed_end)
        .ok_or(Error::Backend)?;

    match eta {
        2 => {
            let mut groups = packed.chunks_exact(3);
            for group in &mut groups {
                let [first, second, third] = group else {
                    return Err(Error::Backend);
                };
                let encoded =
                    u32::from(*first) | (u32::from(*second) << 8) | (u32::from(*third) << 16);
                for shift in (0..24).step_by(3) {
                    if ((encoded >> shift) & 0b111) > 4 {
                        return Err(Error::Backend);
                    }
                }
            }
            if !groups.remainder().is_empty() {
                return Err(Error::Backend);
            }
        }
        4 => {
            for byte in packed {
                if (byte & 0x0F) > 8 || (byte >> 4) > 8 {
                    return Err(Error::Backend);
                }
            }
        }
        _ => return Err(Error::Backend),
    }

    Ok(())
}

/// Declares one FIPS 204 parameter-set adapter. Expanded signing keys first pass
/// the adapter's canonical packed-coefficient check and then `fips204`'s decoder;
/// malformed fixed-length encodings fail explicitly.
macro_rules! mldsa_backend {
    (
        $name:ident, $m:ident, $alg:expr,
        $sk_len:ident = $sk:literal,
        $vk_len:ident = $vk:literal,
        $sig_len:ident = $sig:literal,
        $seed_len:ident = $seed:literal,
        $rand_len:ident = $rand:literal,
        $eta:literal,
        $packed_small_len:literal,
        $alg_str:literal,
        $struct_doc:literal
    ) => {
        #[doc = concat!($alg_str, " expanded signing-key length, bytes (FIPS 204).")]
        pub const $sk_len: usize = $sk;
        #[doc = concat!($alg_str, " verification-key length, bytes.")]
        pub const $vk_len: usize = $vk;
        #[doc = concat!($alg_str, " signature length, bytes.")]
        pub const $sig_len: usize = $sig;
        #[doc = concat!($alg_str, " key-generation seed length, bytes.")]
        pub const $seed_len: usize = $seed;
        #[doc = concat!($alg_str, " signing-randomness length, bytes.")]
        pub const $rand_len: usize = $rand;

        #[doc = $struct_doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Deterministically generate a key pair from a 32-byte seed.
            /// Returns `(expanded_signing_key, verification_key)`.
            #[must_use]
            pub fn generate(seed: [u8; $seed_len]) -> ([u8; $sk_len], [u8; $vk_len]) {
                let seed = ZeroizingBytes::from_bytes(seed);
                let (verification_key, signing_key) = $m::KG::keygen_from_seed(seed.as_bytes());
                (signing_key.into_bytes(), verification_key.into_bytes())
            }

            /// External `ML-DSA.Sign` with explicit context and caller randomness.
            /// An all-zero randomness value selects deterministic signing; other
            /// values provide the FIPS 204 hedged variant.
            pub fn sign_ctx(
                &self,
                sk: &[u8],
                msg: &[u8],
                context: &[u8],
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                validate_context(context)?;
                if out_sig.len() != $sig_len {
                    return Err(Error::InvalidLength);
                }
                let sk = to_zeroizing::<$sk_len>(sk)?;
                let randomness = to_zeroizing::<$rand_len>(randomness)?;
                validate_small_secret_coefficients(sk.as_bytes(), $eta, $packed_small_len)?;
                let signing_key =
                    $m::PrivateKey::try_from_bytes(*sk.as_bytes()).map_err(|_| Error::Backend)?;
                let signature = signing_key
                    .try_sign_with_seed(randomness.as_bytes(), msg, context)
                    .map_err(|_| Error::Backend)?;
                write_exact(out_sig, &signature)?;
                Ok($sig_len)
            }

            /// External `ML-DSA.Verify` with an explicit context.
            pub fn verify_ctx(
                &self,
                pk: &[u8],
                msg: &[u8],
                context: &[u8],
                sig: &[u8],
            ) -> Result<(), Error> {
                validate_context(context)?;
                let verification_key = $m::PublicKey::try_from_bytes(to_arr::<$vk_len>(pk)?)
                    .map_err(|_| Error::Backend)?;
                let signature = to_arr::<$sig_len>(sig)?;
                verification_key
                    .verify(msg, &signature, context)
                    .then_some(())
                    .ok_or(Error::Backend)
            }

            /// `HashML-DSA.Sign` using SHAKE128 pre-hashing and explicit context.
            pub fn sign_pre_hashed_shake128(
                &self,
                sk: &[u8],
                msg: &[u8],
                context: &[u8],
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                validate_context(context)?;
                if out_sig.len() != $sig_len {
                    return Err(Error::InvalidLength);
                }
                let sk = to_zeroizing::<$sk_len>(sk)?;
                let randomness = to_zeroizing::<$rand_len>(randomness)?;
                validate_small_secret_coefficients(sk.as_bytes(), $eta, $packed_small_len)?;
                let signing_key =
                    $m::PrivateKey::try_from_bytes(*sk.as_bytes()).map_err(|_| Error::Backend)?;
                let signature = signing_key
                    .try_hash_sign_with_seed(randomness.as_bytes(), msg, context, &Ph::SHAKE128)
                    .map_err(|_| Error::Backend)?;
                write_exact(out_sig, &signature)?;
                Ok($sig_len)
            }

            /// `HashML-DSA.Verify` using SHAKE128 pre-hashing and explicit context.
            pub fn verify_pre_hashed_shake128(
                &self,
                pk: &[u8],
                msg: &[u8],
                context: &[u8],
                sig: &[u8],
            ) -> Result<(), Error> {
                validate_context(context)?;
                let verification_key = $m::PublicKey::try_from_bytes(to_arr::<$vk_len>(pk)?)
                    .map_err(|_| Error::Backend)?;
                let signature = to_arr::<$sig_len>(sig)?;
                verification_key
                    .hash_verify(msg, &signature, context, &Ph::SHAKE128)
                    .then_some(())
                    .ok_or(Error::Backend)
            }
        }

        impl Signer for $name {
            fn algorithm(&self) -> SigAlg {
                $alg
            }

            fn sign(
                &self,
                sk: &[u8],
                msg: &[u8],
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                self.sign_ctx(sk, msg, b"", randomness, out_sig)
            }
        }

        impl Verifier for $name {
            fn algorithm(&self) -> SigAlg {
                $alg
            }

            fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
                self.verify_ctx(pk, msg, b"", sig)
            }
        }
    };
}

mldsa_backend!(
    MlDsa65,
    ml_dsa_65,
    SigAlg::MlDsa65,
    ML_DSA_65_SK_LEN = 4032,
    ML_DSA_65_VK_LEN = 1952,
    ML_DSA_65_SIG_LEN = 3309,
    ML_DSA_65_KEYGEN_SEED_LEN = 32,
    ML_DSA_65_SIGN_RAND_LEN = 32,
    4,
    1408,
    "ML-DSA-65",
    "ML-DSA-65 backend (FIPS 204) via fips204."
);

mldsa_backend!(
    MlDsa87,
    ml_dsa_87,
    SigAlg::MlDsa87,
    ML_DSA_87_SK_LEN = 4896,
    ML_DSA_87_VK_LEN = 2592,
    ML_DSA_87_SIG_LEN = 4627,
    ML_DSA_87_KEYGEN_SEED_LEN = 32,
    ML_DSA_87_SIGN_RAND_LEN = 32,
    2,
    1440,
    "ML-DSA-87",
    "ML-DSA-87 backend (FIPS 204, NIST level 5) via fips204."
);

mldsa_backend!(
    MlDsa44,
    ml_dsa_44,
    SigAlg::MlDsa44,
    ML_DSA_44_SK_LEN = 2560,
    ML_DSA_44_VK_LEN = 1312,
    ML_DSA_44_SIG_LEN = 2420,
    ML_DSA_44_KEYGEN_SEED_LEN = 32,
    ML_DSA_44_SIGN_RAND_LEN = 32,
    2,
    768,
    "ML-DSA-44",
    "ML-DSA-44 backend (FIPS 204, NIST level 2) via fips204."
);
