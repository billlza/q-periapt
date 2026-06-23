#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # pqt-backends
//!
//! Vetted primitive backends wired into the `pqt-core` traits:
//! - [`MlKem768`] — ML-KEM-768 (FIPS 203) via `libcrux-ml-kem` (HACL*-derived,
//!   constant-time). C2PRI ⇒ usable with the fast `CompatXWing` profile.
//! - [`X25519`] — X25519 ECDH-as-KEM via `x25519-dalek`, deterministic from a
//!   32-byte scalar (non-C2PRI ⇒ `ContextBound` only, enforced by `pqt-kem`).
//! - [`Sha3_256Xof`] — the combiner XOF (SHA3-256).
//!
//! These are the only crates that touch real cryptographic primitives; the
//! security-critical composition stays in the dependency-free `pqt-core`.

use libcrux_ml_kem::mlkem768;
use pqt_core::{Error, Kem, Xof256, SHARED_SECRET_LEN};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(test)]
mod xwing_kat;

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
    // pqt-kem forbids it under the fast CompatXWing profile.

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

/// SHA3-256-based [`Xof256`] for the combiner (fixed 32-byte output), via libcrux.
///
/// libcrux exposes a one-shot `sha256`, so absorbed chunks are buffered and
/// hashed at finalize. SHA3-256 over the concatenation equals the incremental
/// hash, so this is faithful. (A no_std backend would use the incremental
/// `libcrux_sha3::portable` API instead of a heap buffer.)
#[derive(Clone, Default)]
pub struct Sha3_256Xof(Vec<u8>);

impl Xof256 for Sha3_256Xof {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn absorb(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
    fn squeeze32(self) -> [u8; SHARED_SECRET_LEN] {
        libcrux_sha3::sha256(&self.0)
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
        use pqt_core::Profile;
        use pqt_kem::HybridKem;

        let (sk_pq, pk_pq) = MlKem768::generate([7u8; 64]);
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let ctx = b"pqt/v1/test-transcript";

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
}
