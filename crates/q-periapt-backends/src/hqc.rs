//! HQC code-based KEM backend (assumption diversity: lattice + code), enabled by
//! the `hqc` cargo feature.
//!
//! # ⚠ NON-DETERMINISTIC, UNAUDITED, STD/NATIVE-ONLY, PRE-STANDARD
//! - **Non-deterministic:** unlike every other KEM/signer here, HQC encapsulation
//!   does NOT consume the caller-supplied randomness. PQClean `crypto_kem_enc`
//!   takes no coins and self-seeds from its internal `randombytes()`; pqcrypto-hqc
//!   0.2.2 exposes no seeded variant. So HQC encaps is NOT reproducible from
//!   injected bytes and is EXCLUDED from the suite's deterministic-KAT guarantees.
//!   `C2PRI = false` confines HQC to [`q_periapt_core::Profile::ContextBound`].
//! - **Unaudited C:** the `hqc` feature compiles vendored PQClean C via `cc`. It is
//!   not formally audited, not guaranteed constant-time (HQC reference code has
//!   documented cache-timing channels), and its transitive `pqcrypto-internals` is
//!   flagged unmaintained (RUSTSEC-2026-0163, PQClean archiving). Off by default.
//! - **Pre-standard:** NIST selected HQC (2025-03) as the 5th PQC KEM (FIPS 207),
//!   not final as of 2026; the bundled impl is the round-4/pre-FIPS HQC. KATs/sizes
//!   may change. Experimental; not FIPS-validated.
//!
//! Also note: HQC's shared secret is **64 bytes** (all parameter sets), not the
//! suite's 32. This is a standalone [`Kem`]; to use HQC inside the hybrid combiner,
//! the caller must first hash the 64-byte secret to 32 (e.g. SHA3-256). This
//! backend never truncates silently.

// Fence: this feature must never reach wasm32 or no_std (it needs a C toolchain).
#[cfg(any(target_arch = "wasm32", target_os = "none"))]
compile_error!(
    "the `hqc` feature requires a std/native target with a C toolchain; \
     it is unsupported on wasm32 and no_std"
);

use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use q_periapt_core::{Error, Kem};

macro_rules! hqc_backend {
    ($name:ident, $m:ident, $alg:literal, $pk:literal, $sk:literal, $ct:literal, $ss:literal) => {
        #[doc = concat!($alg, " code-based KEM backend (PQClean C via pqcrypto-hqc). See module docs.")]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Public-key length, bytes.
            pub const PK_LEN: usize = $pk;
            /// Secret-key length, bytes.
            pub const SK_LEN: usize = $sk;
            /// Ciphertext length, bytes.
            pub const CT_LEN: usize = $ct;
            /// Shared-secret length, bytes (HQC produces 64).
            pub const SS_LEN: usize = $ss;

            /// Generate a key pair from the OS CSPRNG (NON-deterministic). Returns
            /// `(secret_key, public_key)`.
            #[must_use]
            pub fn generate() -> ([u8; $sk], [u8; $pk]) {
                let (pk, sk) = pqcrypto_hqc::$m::keypair();
                let mut skb = [0u8; $sk];
                let mut pkb = [0u8; $pk];
                skb.copy_from_slice(sk.as_bytes());
                pkb.copy_from_slice(pk.as_bytes());
                (skb, pkb)
            }
        }

        impl Kem for $name {
            // NOT ciphertext-second-preimage-resistant here -> forces ContextBound.
            const C2PRI: bool = false;

            fn algorithm(&self) -> &'static str {
                $alg
            }

            fn encapsulate(
                &self,
                pk: &[u8],
                _randomness: &[u8], // IGNORED: PQClean HQC self-seeds (non-deterministic)
                ct: &mut [u8],
                ss: &mut [u8],
            ) -> Result<(), Error> {
                let public = pqcrypto_hqc::$m::PublicKey::from_bytes(pk)
                    .map_err(|_| Error::InvalidLength)?;
                let (shared, ciphertext) = pqcrypto_hqc::$m::encapsulate(&public);
                crate::write_exact(ct, ciphertext.as_bytes())?;
                crate::write_exact(ss, shared.as_bytes())
            }

            fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
                let secret = pqcrypto_hqc::$m::SecretKey::from_bytes(sk)
                    .map_err(|_| Error::InvalidLength)?;
                let ciphertext = pqcrypto_hqc::$m::Ciphertext::from_bytes(ct)
                    .map_err(|_| Error::InvalidLength)?;
                // Implicit rejection is handled inside PQClean; never signals failure.
                let shared = pqcrypto_hqc::$m::decapsulate(&ciphertext, &secret);
                crate::write_exact(ss, shared.as_bytes())
            }
        }
    };
}

hqc_backend!(Hqc128, hqc128, "HQC-128", 2249, 2305, 4433, 64);
hqc_backend!(Hqc192, hqc192, "HQC-192", 4522, 4586, 8978, 64);
hqc_backend!(Hqc256, hqc256, "HQC-256", 7245, 7317, 14421, 64);

/// Domain tag separating the HQC 64→32 secret compression from every other suite hash.
const HQC_SS_KDF_DOMAIN: &[u8] = b"Q-PERIAPT-HQC-SS-KDF/v1";

/// Adapter that makes an HQC backend usable inside the **hybrid** combiner. HQC's shared
/// secret is 64 bytes; the suite's combiner consumes 32. `HqcAsKem` performs exactly the
/// hashing step the module docs require — `ss32 = SHA3-XOF(DOMAIN ‖ ss64)` — so an HQC leg
/// drops into [`q_periapt_kem::HybridKem`] like any 32-byte KEM. HQC is not ciphertext-
/// second-preimage-resistant, so this keeps `C2PRI = false`; [`HybridKem::new`] therefore
/// rejects pairing it with [`q_periapt_core::Profile::CompatXWing`] and confines it to
/// [`q_periapt_core::Profile::ContextBound`] (which binds every ciphertext).
#[derive(Clone, Copy, Debug, Default)]
pub struct HqcAsKem<H>(pub H);

impl<H: Kem> Kem for HqcAsKem<H> {
    const C2PRI: bool = false;

    fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }

    fn encapsulate(&self, pk: &[u8], rand: &[u8], ct: &mut [u8], ss: &mut [u8]) -> Result<(), Error> {
        let mut ss64 = [0u8; 64];
        let out = self
            .0
            .encapsulate(pk, rand, ct, &mut ss64)
            .and_then(|()| hqc_ss_kdf(&ss64, ss));
        q_periapt_core::secure_wipe(&mut ss64);
        out
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        let mut ss64 = [0u8; 64];
        let out = self
            .0
            .decapsulate(sk, ct, &mut ss64)
            .and_then(|()| hqc_ss_kdf(&ss64, ss));
        q_periapt_core::secure_wipe(&mut ss64);
        out
    }
}

/// `ss_out = SHA3-XOF(HQC_SS_KDF_DOMAIN ‖ ss64)`; `ss_out` must be exactly 32 bytes. Both the
/// 64-byte HQC secret (by the caller) and the intermediate digest are wiped.
fn hqc_ss_kdf(ss64: &[u8], ss_out: &mut [u8]) -> Result<(), Error> {
    use q_periapt_core::Xof256;
    let mut x = crate::Sha3_256Xof::new();
    x.absorb(HQC_SS_KDF_DOMAIN);
    x.absorb(ss64);
    let mut digest = x.squeeze32();
    let r = crate::write_exact(ss_out, &digest);
    q_periapt_core::secure_wipe(&mut digest);
    r
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn hqc128_roundtrip() {
        let (sk, pk) = Hqc128::generate();
        let kem = Hqc128;
        let mut ct = [0u8; Hqc128::CT_LEN];
        let mut ss_e = [0u8; Hqc128::SS_LEN];
        kem.encapsulate(&pk, &[0u8; 32], &mut ct, &mut ss_e)
            .unwrap();
        let mut ss_d = [0u8; Hqc128::SS_LEN];
        kem.decapsulate(&sk, &ct, &mut ss_d).unwrap();
        assert_eq!(ss_e, ss_d, "HQC encaps/decaps must agree");
        assert_ne!(ss_e, [0u8; Hqc128::SS_LEN]);
    }

    #[test]
    fn hqc_as_kem_roundtrips_in_contextbound_hybrid() {
        // HQC wired into the live hybrid via the 64->32 KDF adapter, under ContextBound.
        use crate::{Sha3_256Xof, X25519, X25519_LEN};
        use q_periapt_core::Profile;
        use q_periapt_kem::HybridKem;
        let pq = HqcAsKem(Hqc128);
        let (sk_pq, pk_pq) = Hqc128::generate();
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let kem = HybridKem::<_, _, Sha3_256Xof>::new(
            &pq,
            &X25519,
            Profile::ContextBound,
            b"HQC-128+X25519",
            1,
        )
        .unwrap();
        let mut ct_pq = [0u8; Hqc128::CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let ss_e = kem
            .encapsulate(
                &pk_pq,
                &pk_trad,
                b"q-periapt/hqc-test",
                &[0u8; 32],
                &[2u8; 32],
                &mut ct_pq,
                &mut ct_trad,
            )
            .unwrap();
        let ss_d = kem
            .decapsulate(
                &sk_pq,
                &ct_pq,
                &pk_pq,
                &sk_trad,
                &ct_trad,
                &pk_trad,
                b"q-periapt/hqc-test",
            )
            .unwrap();
        assert_eq!(
            ss_e.as_bytes(),
            ss_d.as_bytes(),
            "HQC ContextBound hybrid must roundtrip"
        );
    }

    #[test]
    fn hqc_as_kem_is_rejected_with_compatxwing() {
        // HQC is not C2PRI: the hybrid must refuse the ciphertext-omitting X-Wing profile.
        use q_periapt_core::Profile;
        use q_periapt_kem::HybridKem;
        let pq = HqcAsKem(Hqc128);
        assert!(HybridKem::<_, _, crate::Sha3_256Xof>::new(
            &pq,
            &crate::X25519,
            Profile::CompatXWing,
            b"x",
            1
        )
        .is_err());
    }

    #[test]
    fn hqc192_roundtrip() {
        let (sk, pk) = Hqc192::generate();
        let mut ct = [0u8; Hqc192::CT_LEN];
        let mut ss_e = [0u8; Hqc192::SS_LEN];
        Hqc192
            .encapsulate(&pk, &[0u8; 32], &mut ct, &mut ss_e)
            .unwrap();
        let mut ss_d = [0u8; Hqc192::SS_LEN];
        Hqc192.decapsulate(&sk, &ct, &mut ss_d).unwrap();
        assert_eq!(ss_e, ss_d, "HQC-192 encaps/decaps must agree");
        assert_ne!(ss_e, [0u8; Hqc192::SS_LEN]);
    }

    #[test]
    fn hqc128_ignores_injected_randomness() {
        // Documents the contract: HQC self-seeds, so the SAME injected randomness
        // yields DIFFERENT ciphertexts (the inverse of the ML-KEM determinism test).
        let (_sk, pk) = Hqc128::generate();
        let kem = Hqc128;
        let (mut c1, mut s1) = ([0u8; Hqc128::CT_LEN], [0u8; Hqc128::SS_LEN]);
        let (mut c2, mut s2) = ([0u8; Hqc128::CT_LEN], [0u8; Hqc128::SS_LEN]);
        kem.encapsulate(&pk, &[7u8; 32], &mut c1, &mut s1).unwrap();
        kem.encapsulate(&pk, &[7u8; 32], &mut c2, &mut s2).unwrap();
        assert_ne!(
            c1, c2,
            "HQC encaps must be non-deterministic (ignores injected randomness)"
        );
    }

    #[test]
    fn hqc_sizes_match_runtime() {
        use pqcrypto_hqc::{hqc128, hqc192, hqc256};
        assert_eq!(hqc128::public_key_bytes(), Hqc128::PK_LEN);
        assert_eq!(hqc128::secret_key_bytes(), Hqc128::SK_LEN);
        assert_eq!(hqc128::ciphertext_bytes(), Hqc128::CT_LEN);
        assert_eq!(hqc128::shared_secret_bytes(), Hqc128::SS_LEN);
        assert_eq!(hqc192::public_key_bytes(), Hqc192::PK_LEN);
        assert_eq!(hqc192::secret_key_bytes(), Hqc192::SK_LEN);
        assert_eq!(hqc192::ciphertext_bytes(), Hqc192::CT_LEN);
        assert_eq!(hqc192::shared_secret_bytes(), Hqc192::SS_LEN);
        assert_eq!(hqc256::public_key_bytes(), Hqc256::PK_LEN);
        assert_eq!(hqc256::secret_key_bytes(), Hqc256::SK_LEN);
        assert_eq!(hqc256::ciphertext_bytes(), Hqc256::CT_LEN);
        assert_eq!(hqc256::shared_secret_bytes(), Hqc256::SS_LEN);
    }

    #[test]
    fn hqc_rejects_bad_length() {
        let kem = Hqc128;
        let mut ss = [0u8; Hqc128::SS_LEN];
        assert!(kem
            .decapsulate(&[0u8; 10], &[0u8; Hqc128::CT_LEN], &mut ss)
            .is_err());
    }
}
