#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-backends
//!
//! Vetted primitive backends wired into the `q-periapt-core` traits:
//! - [`MlKem768`] — ML-KEM-768 (FIPS 203) via `libcrux-ml-kem` (HACL*-derived,
//!   constant-time). C2PRI ⇒ usable with the fast `CompatXWing` profile.
//! - [`X25519`] — X25519 ECDH-as-KEM via `x25519-dalek`, deterministic from a
//!   32-byte scalar (non-C2PRI ⇒ `ContextBound` only, enforced by `q-periapt-kem`).
//! - [`Sha3_256Xof`] — the combiner XOF (SHA3-256).
//!
//! These are the only crates that touch real cryptographic primitives; the
//! security-critical composition stays in the dependency-free `q-periapt-core`.

use libcrux_ml_dsa::{ml_dsa_65, ml_dsa_87};
use libcrux_ml_kem::{mlkem1024, mlkem768};
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
pub use slhdsa::{SlhDsaSha2_128s, SlhDsaSha2_256s};

#[cfg(feature = "hqc")]
mod hqc;
#[cfg(feature = "hqc")]
pub use hqc::{Hqc128, Hqc256};

/// ML-KEM-768 encapsulation-key (public key) length, bytes.
pub const ML_KEM_768_PK_LEN: usize = 1184;
/// ML-KEM-768 decapsulation-key (secret key) length, bytes.
pub const ML_KEM_768_SK_LEN: usize = 2400;
/// ML-KEM-768 ciphertext length, bytes.
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// ML-KEM-768 key-generation seed length, bytes (FIPS 203 d‖z).
pub const ML_KEM_768_KEYGEN_SEED_LEN: usize = 64;
/// ML-KEM-768 encapsulation randomness length, bytes.
pub const ML_KEM_768_ENCAPS_RAND_LEN: usize = 32;
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

/// ML-KEM-768 backend (FIPS 203) via libcrux.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem768;

impl MlKem768 {
    /// Deterministically generate a key pair from a 64-byte seed.
    /// Returns `(decapsulation_key, encapsulation_key)` as fixed-size arrays.
    #[must_use]
    pub fn generate(
        seed: [u8; ML_KEM_768_KEYGEN_SEED_LEN],
    ) -> ([u8; ML_KEM_768_SK_LEN], [u8; ML_KEM_768_PK_LEN]) {
        let kp = mlkem768::generate_key_pair(seed);
        let mut sk = [0u8; ML_KEM_768_SK_LEN];
        let mut pk = [0u8; ML_KEM_768_PK_LEN];
        sk.copy_from_slice(kp.private_key().as_slice());
        pk.copy_from_slice(kp.public_key().as_slice());
        (sk, pk)
    }
}

impl Kem for MlKem768 {
    const C2PRI: bool = true; // ML-KEM-768 binds its ciphertext (FO transform).

    fn algorithm(&self) -> &'static str {
        "ML-KEM-768"
    }

    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        let pk_arr = to_arr::<ML_KEM_768_PK_LEN>(pk)?;
        let rand = to_arr::<ML_KEM_768_ENCAPS_RAND_LEN>(randomness)?;
        let public = mlkem768::MlKem768PublicKey::from(pk_arr);
        let (ciphertext, shared) = mlkem768::encapsulate(&public, rand);
        write_exact(ct, ciphertext.as_slice())?;
        write_exact(ss, shared.as_slice())
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        let sk_arr = to_arr::<ML_KEM_768_SK_LEN>(sk)?;
        let ct_arr = to_arr::<ML_KEM_768_CT_LEN>(ct)?;
        let private = mlkem768::MlKem768PrivateKey::from(sk_arr);
        let ciphertext = mlkem768::MlKem768Ciphertext::from(ct_arr);
        let shared = mlkem768::decapsulate(&private, &ciphertext);
        write_exact(ss, shared.as_slice())
    }
}

/// ML-KEM-1024 encapsulation-key (public key) length, bytes.
pub const ML_KEM_1024_PK_LEN: usize = 1568;
/// ML-KEM-1024 decapsulation-key (secret key) length, bytes.
pub const ML_KEM_1024_SK_LEN: usize = 3168;
/// ML-KEM-1024 ciphertext length, bytes.
pub const ML_KEM_1024_CT_LEN: usize = 1568;
/// ML-KEM-1024 key-generation seed length, bytes (FIPS 203 d‖z).
pub const ML_KEM_1024_KEYGEN_SEED_LEN: usize = 64;
/// ML-KEM-1024 encapsulation randomness length, bytes.
pub const ML_KEM_1024_ENCAPS_RAND_LEN: usize = 32;

/// ML-KEM-1024 backend (FIPS 203, NIST level 5) via libcrux — the enhanced-mode KEM.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem1024;

impl MlKem1024 {
    /// Deterministically generate a key pair from a 64-byte seed.
    /// Returns `(decapsulation_key, encapsulation_key)`.
    #[must_use]
    pub fn generate(
        seed: [u8; ML_KEM_1024_KEYGEN_SEED_LEN],
    ) -> ([u8; ML_KEM_1024_SK_LEN], [u8; ML_KEM_1024_PK_LEN]) {
        let kp = mlkem1024::generate_key_pair(seed);
        let mut sk = [0u8; ML_KEM_1024_SK_LEN];
        let mut pk = [0u8; ML_KEM_1024_PK_LEN];
        sk.copy_from_slice(kp.private_key().as_slice());
        pk.copy_from_slice(kp.public_key().as_slice());
        (sk, pk)
    }
}

impl Kem for MlKem1024 {
    const C2PRI: bool = true; // ML-KEM-1024 binds its ciphertext (FO transform).

    fn algorithm(&self) -> &'static str {
        "ML-KEM-1024"
    }

    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        let pk_arr = to_arr::<ML_KEM_1024_PK_LEN>(pk)?;
        let rand = to_arr::<ML_KEM_1024_ENCAPS_RAND_LEN>(randomness)?;
        let public = mlkem1024::MlKem1024PublicKey::from(pk_arr);
        let (ciphertext, shared) = mlkem1024::encapsulate(&public, rand);
        write_exact(ct, ciphertext.as_slice())?;
        write_exact(ss, shared.as_slice())
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        let sk_arr = to_arr::<ML_KEM_1024_SK_LEN>(sk)?;
        let ct_arr = to_arr::<ML_KEM_1024_CT_LEN>(ct)?;
        let private = mlkem1024::MlKem1024PrivateKey::from(sk_arr);
        let ciphertext = mlkem1024::MlKem1024Ciphertext::from(ct_arr);
        let shared = mlkem1024::decapsulate(&private, &ciphertext);
        write_exact(ss, shared.as_slice())
    }
}

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
#[derive(Clone)]
pub struct Sha3_256Xof {
    inline: [u8; SHA3_XOF_INLINE_CAP],
    len: usize,
    spill: Vec<u8>,
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

/// ML-DSA-65 signing-key length, bytes (FIPS 204).
pub const ML_DSA_65_SK_LEN: usize = 4032;
/// ML-DSA-65 verification-key length, bytes.
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// ML-DSA-65 signature length, bytes.
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// ML-DSA-65 key-generation seed length, bytes.
pub const ML_DSA_65_KEYGEN_SEED_LEN: usize = 32;
/// ML-DSA-65 signing-randomness length, bytes.
pub const ML_DSA_65_SIGN_RAND_LEN: usize = 32;

/// ML-DSA-65 backend (FIPS 204) via libcrux.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa65;

impl MlDsa65 {
    /// Deterministically generate a key pair from a 32-byte seed.
    /// Returns `(signing_key, verification_key)`.
    #[must_use]
    pub fn generate(
        seed: [u8; ML_DSA_65_KEYGEN_SEED_LEN],
    ) -> ([u8; ML_DSA_65_SK_LEN], [u8; ML_DSA_65_VK_LEN]) {
        let kp = ml_dsa_65::generate_key_pair(seed);
        let mut sk = [0u8; ML_DSA_65_SK_LEN];
        let mut vk = [0u8; ML_DSA_65_VK_LEN];
        sk.copy_from_slice(kp.signing_key.as_slice());
        vk.copy_from_slice(kp.verification_key.as_slice());
        (sk, vk)
    }
}

impl Signer for MlDsa65 {
    fn algorithm(&self) -> SigAlg {
        SigAlg::MlDsa65
    }

    fn sign(
        &self,
        sk: &[u8],
        msg: &[u8],
        randomness: &[u8],
        out_sig: &mut [u8],
    ) -> Result<usize, Error> {
        let sk_arr = to_arr::<ML_DSA_65_SK_LEN>(sk)?;
        let rnd = to_arr::<ML_DSA_65_SIGN_RAND_LEN>(randomness)?;
        let signing_key = ml_dsa_65::MLDSA65SigningKey::new(sk_arr);
        let sig = ml_dsa_65::sign(&signing_key, msg, b"", rnd).map_err(|_| Error::Backend)?;
        write_exact(out_sig, sig.as_slice())?;
        Ok(out_sig.len())
    }
}

impl Verifier for MlDsa65 {
    fn algorithm(&self) -> SigAlg {
        SigAlg::MlDsa65
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let vk_arr = to_arr::<ML_DSA_65_VK_LEN>(pk)?;
        let sig_arr = to_arr::<ML_DSA_65_SIG_LEN>(sig)?;
        let vk = ml_dsa_65::MLDSA65VerificationKey::new(vk_arr);
        let signature = ml_dsa_65::MLDSA65Signature::new(sig_arr);
        ml_dsa_65::verify(&vk, msg, b"", &signature).map_err(|_| Error::Backend)
    }
}

/// ML-DSA-87 signing-key length, bytes (FIPS 204).
pub const ML_DSA_87_SK_LEN: usize = 4896;
/// ML-DSA-87 verification-key length, bytes.
pub const ML_DSA_87_VK_LEN: usize = 2592;
/// ML-DSA-87 signature length, bytes.
pub const ML_DSA_87_SIG_LEN: usize = 4627;
/// ML-DSA-87 key-generation seed length, bytes.
pub const ML_DSA_87_KEYGEN_SEED_LEN: usize = 32;
/// ML-DSA-87 signing-randomness length, bytes.
pub const ML_DSA_87_SIGN_RAND_LEN: usize = 32;

/// ML-DSA-87 backend (FIPS 204, NIST level 5) via libcrux — the enhanced-mode signature.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa87;

impl MlDsa87 {
    /// Deterministically generate a key pair from a 32-byte seed.
    /// Returns `(signing_key, verification_key)`.
    #[must_use]
    pub fn generate(
        seed: [u8; ML_DSA_87_KEYGEN_SEED_LEN],
    ) -> ([u8; ML_DSA_87_SK_LEN], [u8; ML_DSA_87_VK_LEN]) {
        let kp = ml_dsa_87::generate_key_pair(seed);
        let mut sk = [0u8; ML_DSA_87_SK_LEN];
        let mut vk = [0u8; ML_DSA_87_VK_LEN];
        sk.copy_from_slice(kp.signing_key.as_slice());
        vk.copy_from_slice(kp.verification_key.as_slice());
        (sk, vk)
    }
}

impl Signer for MlDsa87 {
    fn algorithm(&self) -> SigAlg {
        SigAlg::MlDsa87
    }

    fn sign(
        &self,
        sk: &[u8],
        msg: &[u8],
        randomness: &[u8],
        out_sig: &mut [u8],
    ) -> Result<usize, Error> {
        let sk_arr = to_arr::<ML_DSA_87_SK_LEN>(sk)?;
        let rnd = to_arr::<ML_DSA_87_SIGN_RAND_LEN>(randomness)?;
        let signing_key = ml_dsa_87::MLDSA87SigningKey::new(sk_arr);
        let sig = ml_dsa_87::sign(&signing_key, msg, b"", rnd).map_err(|_| Error::Backend)?;
        write_exact(out_sig, sig.as_slice())?;
        Ok(out_sig.len())
    }
}

impl Verifier for MlDsa87 {
    fn algorithm(&self) -> SigAlg {
        SigAlg::MlDsa87
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let vk_arr = to_arr::<ML_DSA_87_VK_LEN>(pk)?;
        let sig_arr = to_arr::<ML_DSA_87_SIG_LEN>(sig)?;
        let vk = ml_dsa_87::MLDSA87VerificationKey::new(vk_arr);
        let signature = ml_dsa_87::MLDSA87Signature::new(sig_arr);
        ml_dsa_87::verify(&vk, msg, b"", &signature).map_err(|_| Error::Backend)
    }
}

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
            let mut ss_pq = [0u8; 32];
            let mut ct_trad = [0u8; X25519_LEN];
            let mut ss_trad = [0u8; 32];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    ctx,
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ss_pq,
                    &mut ct_trad,
                    &mut ss_trad,
                )
                .unwrap();

            let mut d_ss_pq = [0u8; 32];
            let mut d_ss_trad = [0u8; 32];
            let dec = kem
                .decapsulate(
                    &sk_pq,
                    &ct_pq,
                    &pk_pq,
                    &sk_trad,
                    &ct_trad,
                    &pk_trad,
                    ctx,
                    &mut d_ss_pq,
                    &mut d_ss_trad,
                )
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
            let mut ss_pq = [0u8; 32];
            let mut ct_trad = [0u8; X25519_LEN];
            let mut ss_trad = [0u8; 32];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    ctx,
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ss_pq,
                    &mut ct_trad,
                    &mut ss_trad,
                )
                .unwrap();

            let mut d_ss_pq = [0u8; 32];
            let mut d_ss_trad = [0u8; 32];
            let dec = kem
                .decapsulate(
                    &sk_pq,
                    &ct_pq,
                    &pk_pq,
                    &sk_trad,
                    &ct_trad,
                    &pk_trad,
                    ctx,
                    &mut d_ss_pq,
                    &mut d_ss_trad,
                )
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
