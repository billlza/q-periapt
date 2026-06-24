#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-backends
//!
//! Vetted primitive backends wired into the `q-periapt-core` traits:
//! - **ML-KEM** (FIPS 203) via `libcrux-ml-kem` (HACL*-derived, constant-time), C2PRI ⇒
//!   usable with the fast `CompatXWing` profile: [`MlKem512`], [`MlKem768`], [`MlKem1024`].
//! - **ML-DSA** (FIPS 204) via `libcrux-ml-dsa`: [`MlDsa44`], [`MlDsa65`], [`MlDsa87`]
//!   (the `impl_mldsa_modes!` surface also adds context/hedged + SHAKE-128 pre-hash +
//!   internal-interface signing, for ACVP conformance).
//! - [`X25519`] — X25519 ECDH-as-KEM via `x25519-dalek`, deterministic from a 32-byte
//!   scalar (non-C2PRI ⇒ `ContextBound` only, enforced by `q-periapt-kem`).
//! - [`Sha3_256Xof`] — the combiner XOF (SHA3-256).
//! - Off by default (cargo features): `slh-dsa` ⇒ `SlhDsaSha2_128s`/`_192s`/`_256s`
//!   (FIPS 205, via `fips205`); `hqc` ⇒ `Hqc128`/`Hqc192`/`Hqc256` (via `pqcrypto-hqc`).
//!
//! This is the only crate that touches real cryptographic primitives; the
//! security-critical composition stays in the dependency-free `q-periapt-core`.

use libcrux_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use libcrux_ml_kem::{mlkem1024, mlkem512, mlkem768};
use q_periapt_core::{Error, Kem, Xof256, SHARED_SECRET_LEN};
use q_periapt_sig::{SigAlg, Signer, Verifier};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(test)]
mod xwing_kat;

// Multi-backend differential: libcrux ML-KEM-768 vs the independent RustCrypto
// `ml-kem` implementation (byte-identical keygen/encaps/decaps under FIPS 203).
#[cfg(test)]
mod differential;

// NIST ACVP (FIPS 203) ground-truth conformance vectors for ML-KEM-768.
#[cfg(test)]
mod acvp;

// Generative property-based tests of combiner / hybrid-KEM invariants.
#[cfg(test)]
mod proptests;

// ContextBound combiner reference vectors (positive KAT, independently cross-checked).
#[cfg(test)]
mod contextbound_kat;

// Enhanced-mode suite (ML-KEM-1024 + X25519) end-to-end pinned KAT.
#[cfg(test)]
mod enhanced_kat;

// Optional, off-by-default backends (see Cargo.toml [features]).
#[cfg(feature = "slh-dsa")]
mod slhdsa;
#[cfg(feature = "slh-dsa")]
pub use slhdsa::{SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s};

// NIST ACVP (FIPS 205) ground-truth conformance vectors for SLH-DSA-SHA2-{128,192,256}s.
#[cfg(all(test, feature = "slh-dsa"))]
mod acvp_slhdsa;

#[cfg(feature = "hqc")]
mod hqc;
#[cfg(feature = "hqc")]
pub use hqc::{Hqc128, Hqc192, Hqc256};

/// X25519 public-key / secret-key / ciphertext length, bytes.
pub const X25519_LEN: usize = 32;

#[inline]
fn to_arr<const N: usize>(s: &[u8]) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(s).map_err(|_| Error::InvalidLength)
}

#[inline]
fn write_exact(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
    if dst.len() != src.len() {
        return Err(Error::InvalidLength);
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// Declares an ML-KEM (FIPS 203) backend over a libcrux `mlkem{512,768,1024}`
/// module: the public length constants, the unit struct, its seed-deterministic
/// `generate` associated fn, and the [`Kem`] impl. All parameter sets share this
/// boilerplate (constant-time HACL*-derived primitive, C2PRI ⇒ ciphertext-binding),
/// differing only in module, key/ciphertext types, and byte lengths — so they are
/// generated from one definition rather than hand-copied.
macro_rules! mlkem_backend {
    (
        $name:ident, $m:ident, $alg:literal,
        $pk_len:ident = $pk:literal,
        $sk_len:ident = $sk:literal,
        $ct_len:ident = $ct:literal,
        $seed_len:ident = $seed:literal,
        $rand_len:ident = $rand:literal,
        $PkT:ident, $SkT:ident, $CtT:ident,
        $struct_doc:literal
    ) => {
        #[doc = concat!($alg, " encapsulation-key (public key) length, bytes.")]
        pub const $pk_len: usize = $pk;
        #[doc = concat!($alg, " decapsulation-key (secret key) length, bytes.")]
        pub const $sk_len: usize = $sk;
        #[doc = concat!($alg, " ciphertext length, bytes.")]
        pub const $ct_len: usize = $ct;
        #[doc = concat!($alg, " key-generation seed length, bytes (FIPS 203 d‖z).")]
        pub const $seed_len: usize = $seed;
        #[doc = concat!($alg, " encapsulation randomness length, bytes.")]
        pub const $rand_len: usize = $rand;

        #[doc = $struct_doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Deterministically generate a key pair from a 64-byte seed.
            /// Returns `(decapsulation_key, encapsulation_key)`.
            #[must_use]
            pub fn generate(seed: [u8; $seed_len]) -> ([u8; $sk_len], [u8; $pk_len]) {
                let kp = $m::generate_key_pair(seed);
                let mut sk = [0u8; $sk_len];
                let mut pk = [0u8; $pk_len];
                sk.copy_from_slice(kp.private_key().as_slice());
                pk.copy_from_slice(kp.public_key().as_slice());
                (sk, pk)
            }
        }

        impl Kem for $name {
            const C2PRI: bool = true; // ML-KEM binds its ciphertext (FO transform).

            fn algorithm(&self) -> &'static str {
                $alg
            }

            fn encapsulate(
                &self,
                pk: &[u8],
                randomness: &[u8],
                ct: &mut [u8],
                ss: &mut [u8],
            ) -> Result<(), Error> {
                let pk_arr = to_arr::<$pk_len>(pk)?;
                let rand = to_arr::<$rand_len>(randomness)?;
                let public = $m::$PkT::from(pk_arr);
                let (ciphertext, shared) = $m::encapsulate(&public, rand);
                write_exact(ct, ciphertext.as_slice())?;
                write_exact(ss, shared.as_slice())
            }

            fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
                let sk_arr = to_arr::<$sk_len>(sk)?;
                let ct_arr = to_arr::<$ct_len>(ct)?;
                let private = $m::$SkT::from(sk_arr);
                let ciphertext = $m::$CtT::from(ct_arr);
                let shared = $m::decapsulate(&private, &ciphertext);
                write_exact(ss, shared.as_slice())
            }
        }
    };
}

mlkem_backend!(
    MlKem768,
    mlkem768,
    "ML-KEM-768",
    ML_KEM_768_PK_LEN = 1184,
    ML_KEM_768_SK_LEN = 2400,
    ML_KEM_768_CT_LEN = 1088,
    ML_KEM_768_KEYGEN_SEED_LEN = 64,
    ML_KEM_768_ENCAPS_RAND_LEN = 32,
    MlKem768PublicKey,
    MlKem768PrivateKey,
    MlKem768Ciphertext,
    "ML-KEM-768 backend (FIPS 203) via libcrux."
);

mlkem_backend!(
    MlKem1024,
    mlkem1024,
    "ML-KEM-1024",
    ML_KEM_1024_PK_LEN = 1568,
    ML_KEM_1024_SK_LEN = 3168,
    ML_KEM_1024_CT_LEN = 1568,
    ML_KEM_1024_KEYGEN_SEED_LEN = 64,
    ML_KEM_1024_ENCAPS_RAND_LEN = 32,
    MlKem1024PublicKey,
    MlKem1024PrivateKey,
    MlKem1024Ciphertext,
    "ML-KEM-1024 backend (FIPS 203, NIST level 5) via libcrux — the enhanced-mode KEM."
);

mlkem_backend!(
    MlKem512,
    mlkem512,
    "ML-KEM-512",
    ML_KEM_512_PK_LEN = 800,
    ML_KEM_512_SK_LEN = 1632,
    ML_KEM_512_CT_LEN = 768,
    ML_KEM_512_KEYGEN_SEED_LEN = 64,
    ML_KEM_512_ENCAPS_RAND_LEN = 32,
    MlKem512PublicKey,
    MlKem512PrivateKey,
    MlKem512Ciphertext,
    "ML-KEM-512 backend (FIPS 203, NIST level 1) via libcrux — the smallest parameter set."
);

/// X25519 ECDH-as-KEM backend (deterministic from a 32-byte scalar).
#[derive(Clone, Copy, Debug, Default)]
pub struct X25519;

impl X25519 {
    /// Deterministically derive a key pair from a 32-byte secret scalar.
    /// Returns `(secret_key, public_key)`.
    #[must_use]
    pub fn generate(secret: [u8; X25519_LEN]) -> ([u8; X25519_LEN], [u8; X25519_LEN]) {
        let s = StaticSecret::from(secret);
        let p = PublicKey::from(&s);
        (s.to_bytes(), p.to_bytes())
    }
}

impl Kem for X25519 {
    // C2PRI defaults to false: X25519-as-KEM does not bind its ciphertext, so
    // q-periapt-kem forbids it under the fast CompatXWing profile.

    fn algorithm(&self) -> &'static str {
        "X25519"
    }

    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        // The ephemeral scalar is the caller-supplied randomness; the ciphertext
        // is the ephemeral public key.
        let eph = StaticSecret::from(to_arr::<X25519_LEN>(randomness)?);
        let peer = PublicKey::from(to_arr::<X25519_LEN>(pk)?);
        let eph_pub = PublicKey::from(&eph);
        let shared = eph.diffie_hellman(&peer);
        write_exact(ct, eph_pub.as_bytes())?;
        write_exact(ss, shared.as_bytes())
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        let secret = StaticSecret::from(to_arr::<X25519_LEN>(sk)?);
        let eph_pub = PublicKey::from(to_arr::<X25519_LEN>(ct)?);
        let shared = secret.diffie_hellman(&eph_pub);
        write_exact(ss, shared.as_bytes())
    }
}

/// Inline staging capacity for [`Sha3_256Xof`]. The CompatXWing / X-Wing combiner
/// input is a single 134-byte SHA3-256 block, so this keeps that path — the only
/// performance-sensitive one — entirely on the stack (no heap allocation).
const SHA3_XOF_INLINE_CAP: usize = 200;

/// SHA3-256-based [`Xof256`] for the combiner (fixed 32-byte output), via libcrux.
///
/// libcrux exposes a one-shot SHA3-256 (`sha256`), so absorbed chunks are staged
/// contiguously and hashed at finalize; SHA3-256 over the concatenation equals the
/// incremental hash, so the digest is byte-identical to X-Wing. The hot path — the
/// 134-byte single-block CompatXWing combiner — stages into a fixed inline buffer
/// and **never allocates**; only the larger multi-KB ContextBound transcript spills
/// to the heap. This makes the X-Wing-compatible combiner allocation-free: it does
/// the minimal single-block Keccak work with no per-`update` sponge bookkeeping and
/// no heap traffic, while producing identical bytes.
pub struct Sha3_256Xof {
    inline: [u8; SHA3_XOF_INLINE_CAP],
    len: usize,
    spill: Vec<u8>,
}

impl Drop for Sha3_256Xof {
    fn drop(&mut self) {
        // The inline buffer and heap spill stage raw component shared secrets absorbed
        // into the combiner; wipe both (the spill's live allocation included) before the
        // storage is released, mirroring `core::Secret`'s volatile wipe — otherwise the
        // same key material `Secret::drop` protects would persist here. (Intermediate
        // reallocations while the spill grows are a residual the Vec API can't reach.)
        q_periapt_core::secure_wipe(&mut self.inline);
        q_periapt_core::secure_wipe(self.spill.as_mut_slice());
        self.len = 0;
    }
}

impl Default for Sha3_256Xof {
    fn default() -> Self {
        <Self as Xof256>::new()
    }
}

impl Xof256 for Sha3_256Xof {
    fn new() -> Self {
        Self {
            inline: [0u8; SHA3_XOF_INLINE_CAP],
            len: 0,
            spill: Vec::new(),
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        // Once the input has outgrown the inline buffer, everything goes to heap.
        if !self.spill.is_empty() {
            self.spill.extend_from_slice(data);
            return;
        }
        let end = self.len + data.len();
        match self.inline.get_mut(self.len..end) {
            Some(dst) => {
                dst.copy_from_slice(data);
                self.len = end;
            }
            None => {
                // Inline capacity exceeded (ContextBound): migrate staged bytes.
                self.spill.reserve(end);
                if let Some(staged) = self.inline.get(..self.len) {
                    self.spill.extend_from_slice(staged);
                }
                self.spill.extend_from_slice(data);
                self.len = 0;
            }
        }
    }

    fn squeeze32(self) -> [u8; SHARED_SECRET_LEN] {
        if self.spill.is_empty() {
            libcrux_sha3::sha256(self.inline.get(..self.len).unwrap_or(&[]))
        } else {
            libcrux_sha3::sha256(&self.spill)
        }
    }
}

/// Declares an ML-DSA (FIPS 204) backend over a libcrux `ml_dsa_{44,65,87}`
/// module: the public length constants, the unit struct, its seed-deterministic
/// `generate` associated fn, and the suite-default [`Signer`]/[`Verifier`] impls
/// (external interface, pure, empty context). All parameter sets share this
/// boilerplate, differing only in module, key/signature types, byte lengths, and
/// [`SigAlg`] tag — so they are generated from one definition rather than
/// hand-copied. The extended multi-mode conformance surface (context/hedged +
/// SHAKE-128 pre-hash + internal interface) is layered on separately via
/// [`impl_mldsa_modes!`].
macro_rules! mldsa_backend {
    (
        $name:ident, $m:ident, $alg:expr,
        $sk_len:ident = $sk:literal,
        $vk_len:ident = $vk:literal,
        $sig_len:ident = $sig:literal,
        $seed_len:ident = $seed:literal,
        $rand_len:ident = $rand:literal,
        $alg_str:literal,
        $SkT:ident, $VkT:ident, $SigT:ident,
        $struct_doc:literal
    ) => {
        #[doc = concat!($alg_str, " signing-key length, bytes (FIPS 204).")]
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
            /// Returns `(signing_key, verification_key)`.
            #[must_use]
            pub fn generate(seed: [u8; $seed_len]) -> ([u8; $sk_len], [u8; $vk_len]) {
                let kp = $m::generate_key_pair(seed);
                let mut sk = [0u8; $sk_len];
                let mut vk = [0u8; $vk_len];
                sk.copy_from_slice(kp.signing_key.as_slice());
                vk.copy_from_slice(kp.verification_key.as_slice());
                (sk, vk)
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
                let sk_arr = to_arr::<$sk_len>(sk)?;
                let rnd = to_arr::<$rand_len>(randomness)?;
                let signing_key = $m::$SkT::new(sk_arr);
                let sig = $m::sign(&signing_key, msg, b"", rnd).map_err(|_| Error::Backend)?;
                write_exact(out_sig, sig.as_slice())?;
                Ok(out_sig.len())
            }
        }

        impl Verifier for $name {
            fn algorithm(&self) -> SigAlg {
                $alg
            }

            fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
                let vk_arr = to_arr::<$vk_len>(pk)?;
                let sig_arr = to_arr::<$sig_len>(sig)?;
                let vk = $m::$VkT::new(vk_arr);
                let signature = $m::$SigT::new(sig_arr);
                $m::verify(&vk, msg, b"", &signature).map_err(|_| Error::Backend)
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
    "ML-DSA-65",
    MLDSA65SigningKey,
    MLDSA65VerificationKey,
    MLDSA65Signature,
    "ML-DSA-65 backend (FIPS 204) via libcrux."
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
    "ML-DSA-87",
    MLDSA87SigningKey,
    MLDSA87VerificationKey,
    MLDSA87Signature,
    "ML-DSA-87 backend (FIPS 204, NIST level 5) via libcrux — the enhanced-mode signature."
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
    "ML-DSA-44",
    MLDSA44SigningKey,
    MLDSA44VerificationKey,
    MLDSA44Signature,
    "ML-DSA-44 backend (FIPS 204, NIST level 2) via libcrux — the smallest ML-DSA."
);

/// Extended FIPS 204 conformance surface for an ML-DSA backend, beyond the suite's
/// default mode (the [`Signer`]/[`Verifier`] impls fix external interface, pure,
/// empty context). These wrap libcrux's fuller public API — external `ML-DSA.Sign`
/// with explicit `context` and caller `randomness` (deterministic when zero, hedged
/// otherwise), and `HashML-DSA` with a SHAKE128 pre-hash — so the multi-mode ACVP
/// conformance vectors can be exercised. The hybrid suite itself does not use these
/// methods. (libcrux does not publicly expose the internal interface or `externalMu`,
/// nor `HashML-DSA` with hashes other than SHAKE128, so those ACVP modes are not
/// covered here — see `acvp.rs`.)
macro_rules! impl_mldsa_modes {
    ($ty:ty, $m:ident, $sk_len:ident, $vk_len:ident, $sig_len:ident, $rnd_len:ident,
     $SkT:ident, $VkT:ident, $SigT:ident) => {
        impl $ty {
            /// External `ML-DSA.Sign` with explicit `context` and caller `randomness`
            /// (all-zero ⇒ deterministic, random ⇒ hedged).
            pub fn sign_ctx(
                &self,
                sk: &[u8],
                msg: &[u8],
                context: &[u8],
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                let sk_arr = to_arr::<$sk_len>(sk)?;
                let rnd = to_arr::<$rnd_len>(randomness)?;
                let signing_key = $m::$SkT::new(sk_arr);
                let sig = $m::sign(&signing_key, msg, context, rnd).map_err(|_| Error::Backend)?;
                write_exact(out_sig, sig.as_slice())?;
                Ok(out_sig.len())
            }

            /// External `ML-DSA.Verify` with explicit `context`.
            pub fn verify_ctx(
                &self,
                pk: &[u8],
                msg: &[u8],
                context: &[u8],
                sig: &[u8],
            ) -> Result<(), Error> {
                let vk_arr = to_arr::<$vk_len>(pk)?;
                let sig_arr = to_arr::<$sig_len>(sig)?;
                let vk = $m::$VkT::new(vk_arr);
                let signature = $m::$SigT::new(sig_arr);
                $m::verify(&vk, msg, context, &signature).map_err(|_| Error::Backend)
            }

            /// `HashML-DSA` sign with a SHAKE128 pre-hash and explicit `context`.
            pub fn sign_pre_hashed_shake128(
                &self,
                sk: &[u8],
                msg: &[u8],
                context: &[u8],
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                let sk_arr = to_arr::<$sk_len>(sk)?;
                let rnd = to_arr::<$rnd_len>(randomness)?;
                let signing_key = $m::$SkT::new(sk_arr);
                let sig = $m::sign_pre_hashed_shake128(&signing_key, msg, context, rnd)
                    .map_err(|_| Error::Backend)?;
                write_exact(out_sig, sig.as_slice())?;
                Ok(out_sig.len())
            }

            /// `HashML-DSA` verify with a SHAKE128 pre-hash and explicit `context`.
            pub fn verify_pre_hashed_shake128(
                &self,
                pk: &[u8],
                msg: &[u8],
                context: &[u8],
                sig: &[u8],
            ) -> Result<(), Error> {
                let vk_arr = to_arr::<$vk_len>(pk)?;
                let sig_arr = to_arr::<$sig_len>(sig)?;
                let vk = $m::$VkT::new(vk_arr);
                let signature = $m::$SigT::new(sig_arr);
                $m::verify_pre_hashed_shake128(&vk, msg, context, &signature)
                    .map_err(|_| Error::Backend)
            }

            /// Internal-interface `ML-DSA.Sign_internal` (FIPS 204 Alg. 7): signs the
            /// already-domain-separated `msg` directly (no context prefix), with caller
            /// `randomness` (zero ⇒ deterministic). Exposed by the libcrux `acvp` feature.
            pub fn sign_internal(
                &self,
                sk: &[u8],
                msg: &[u8],
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                let sk_arr = to_arr::<$sk_len>(sk)?;
                let rnd = to_arr::<$rnd_len>(randomness)?;
                let signing_key = $m::$SkT::new(sk_arr);
                let sig = $m::sign_internal(&signing_key, msg, rnd).map_err(|_| Error::Backend)?;
                write_exact(out_sig, sig.as_slice())?;
                Ok(out_sig.len())
            }

            /// Internal-interface `ML-DSA.Verify_internal` (FIPS 204 Alg. 8).
            pub fn verify_internal(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
                let vk_arr = to_arr::<$vk_len>(pk)?;
                let sig_arr = to_arr::<$sig_len>(sig)?;
                let vk = $m::$VkT::new(vk_arr);
                let signature = $m::$SigT::new(sig_arr);
                $m::verify_internal(&vk, msg, &signature).map_err(|_| Error::Backend)
            }
        }
    };
}

impl_mldsa_modes!(
    MlDsa44,
    ml_dsa_44,
    ML_DSA_44_SK_LEN,
    ML_DSA_44_VK_LEN,
    ML_DSA_44_SIG_LEN,
    ML_DSA_44_SIGN_RAND_LEN,
    MLDSA44SigningKey,
    MLDSA44VerificationKey,
    MLDSA44Signature
);
impl_mldsa_modes!(
    MlDsa65,
    ml_dsa_65,
    ML_DSA_65_SK_LEN,
    ML_DSA_65_VK_LEN,
    ML_DSA_65_SIG_LEN,
    ML_DSA_65_SIGN_RAND_LEN,
    MLDSA65SigningKey,
    MLDSA65VerificationKey,
    MLDSA65Signature
);
impl_mldsa_modes!(
    MlDsa87,
    ml_dsa_87,
    ML_DSA_87_SK_LEN,
    ML_DSA_87_VK_LEN,
    ML_DSA_87_SIG_LEN,
    ML_DSA_87_SIGN_RAND_LEN,
    MLDSA87SigningKey,
    MLDSA87VerificationKey,
    MLDSA87Signature
);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn sha3_256_known_answer() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let mut x = Sha3_256Xof::new();
        x.absorb(b"");
        let d = x.squeeze32();
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        let got: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn mlkem768_roundtrip() {
        let (sk, pk) = MlKem768::generate([7u8; 64]);
        let kem = MlKem768;
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        let mut ss_e = [0u8; 32];
        kem.encapsulate(&pk, &[3u8; 32], &mut ct, &mut ss_e)
            .unwrap();
        let mut ss_d = [0u8; 32];
        kem.decapsulate(&sk, &ct, &mut ss_d).unwrap();
        assert_eq!(ss_e, ss_d, "ML-KEM-768 encaps/decaps must agree");
        assert_ne!(ss_e, [0u8; 32], "shared secret must be non-trivial");
    }

    #[test]
    fn mlkem_algorithm_strings() {
        // `algorithm()` is generated from the `mlkem_backend!` `$alg` literal — pin the
        // three strings so a future macro edit can't silently relabel a backend.
        assert_eq!(MlKem512.algorithm(), "ML-KEM-512");
        assert_eq!(MlKem768.algorithm(), "ML-KEM-768");
        assert_eq!(MlKem1024.algorithm(), "ML-KEM-1024");
    }

    #[test]
    fn x25519_roundtrip() {
        let (sk, pk) = X25519::generate([9u8; 32]);
        let kem = X25519;
        let mut ct = [0u8; 32];
        let mut ss_e = [0u8; 32];
        kem.encapsulate(&pk, &[5u8; 32], &mut ct, &mut ss_e)
            .unwrap();
        let mut ss_d = [0u8; 32];
        kem.decapsulate(&sk, &ct, &mut ss_d).unwrap();
        assert_eq!(ss_e, ss_d, "X25519 encaps/decaps must agree");
    }

    #[test]
    fn hybrid_real_roundtrip_both_profiles() {
        use q_periapt_core::Profile;
        use q_periapt_kem::HybridKem;

        let (sk_pq, pk_pq) = MlKem768::generate([7u8; 64]);
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let ctx = b"q-periapt/v1/test-transcript";

        for profile in [Profile::CompatXWing, Profile::ContextBound] {
            let (pq, trad) = (MlKem768, X25519);
            let kem =
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, b"ML-KEM-768+X25519", 1)
                    .unwrap();

            let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    ctx,
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .unwrap();

            let dec = kem
                .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, ctx)
                .unwrap();

            assert_eq!(
                enc.as_bytes(),
                dec.as_bytes(),
                "{profile:?}: real hybrid encap/decap must agree"
            );
        }
    }

    #[test]
    fn enhanced_hybrid_real_roundtrip_both_profiles() {
        // The enhanced suite: ML-KEM-1024 + X25519. ML-KEM-1024 is C2PRI, so both
        // profiles are legal; the buffers are sized to the 1024 ciphertext (1568, NOT
        // the 768 length). Proves the enhanced HybridKem actually round-trips.
        use q_periapt_core::Profile;
        use q_periapt_kem::HybridKem;

        let (sk_pq, pk_pq) = MlKem1024::generate([7u8; 64]);
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let ctx = b"q-periapt/v1/enhanced-transcript";

        for profile in [Profile::CompatXWing, Profile::ContextBound] {
            let (pq, trad) = (MlKem1024, X25519);
            let kem =
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, b"ML-KEM-1024+X25519", 1)
                    .unwrap();

            let mut ct_pq = [0u8; ML_KEM_1024_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    ctx,
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .unwrap();

            let dec = kem
                .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, ctx)
                .unwrap();

            assert_eq!(
                enc.as_bytes(),
                dec.as_bytes(),
                "{profile:?}: enhanced hybrid encap/decap must agree"
            );
        }
    }

    #[test]
    fn deterministic_encaps() {
        // Same randomness ⇒ identical ciphertext+secret (KAT precondition).
        let (_sk, pk) = MlKem768::generate([1u8; 64]);
        let kem = MlKem768;
        let (mut ct1, mut ss1) = ([0u8; ML_KEM_768_CT_LEN], [0u8; 32]);
        let (mut ct2, mut ss2) = ([0u8; ML_KEM_768_CT_LEN], [0u8; 32]);
        kem.encapsulate(&pk, &[42u8; 32], &mut ct1, &mut ss1)
            .unwrap();
        kem.encapsulate(&pk, &[42u8; 32], &mut ct2, &mut ss2)
            .unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn mldsa65_sign_verify_and_reject() {
        let (sk, vk) = MlDsa65::generate([4u8; 32]);
        let signer = MlDsa65;
        let msg = b"authenticated handshake transcript";
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let n = signer.sign(&sk, msg, &[9u8; 32], &mut sig).unwrap();
        assert_eq!(n, ML_DSA_65_SIG_LEN);

        let verifier = MlDsa65;
        verifier.verify(&vk, msg, &sig).unwrap();
        assert!(verifier.verify(&vk, b"tampered message", &sig).is_err());
        let mut bad = sig;
        bad[0] ^= 0xFF;
        assert!(verifier.verify(&vk, msg, &bad).is_err());
    }
}
