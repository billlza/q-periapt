//! SLH-DSA (FIPS 205) signature backend, enabled by the `slh-dsa` cargo feature.
//!
//! SLH-DSA is the conservative, hash-based signature scheme for roots / firmware /
//! long-term keys (large, slow signatures, minimal assumptions). Signing here is
//! FIPS 205 **deterministic (non-hedged)** — a pure function of (secret key,
//! message) — so it is KAT-reproducible and uses no entropy at sign time; the
//! `Signer` randomness argument is therefore intentionally unused.
//!
//! Backend choice: this wires the pure-Rust, stable **`fips205`** crate rather
//! than RustCrypto `slh-dsa` (a release candidate whose bleeding-edge rand_core
//! 0.10 keygen RNG is impractical to drive here). Both implement FIPS 205;
//! non-hedged signing satisfies the deterministic / no-internal-RNG contract.

use fips205::traits::{SerDes as _, Signer as _, Verifier as _};
use q_periapt_core::Error;
use q_periapt_sig::{SigAlg, Signer, Verifier};

macro_rules! slhdsa_backend {
    ($name:ident, $m:ident, $alg:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Signing-key length, bytes.
            pub const SK_LEN: usize = fips205::$m::SK_LEN;
            /// Verifying-key length, bytes.
            pub const VK_LEN: usize = fips205::$m::PK_LEN;
            /// Signature length, bytes.
            pub const SIG_LEN: usize = fips205::$m::SIG_LEN;

            /// Generate a key pair from the OS CSPRNG (NON-deterministic; unlike
            /// the seed-based ML-KEM/ML-DSA generators). Returns `(signing_key,
            /// verifying_key)`.
            pub fn generate(
            ) -> Result<([u8; fips205::$m::SK_LEN], [u8; fips205::$m::PK_LEN]), Error> {
                let (vk, sk) = fips205::$m::try_keygen().map_err(|_| Error::Backend)?;
                Ok((sk.into_bytes(), vk.into_bytes()))
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
                _randomness: &[u8], // unused: non-hedged SLH-DSA is already deterministic
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                let sk_arr = crate::to_arr::<{ fips205::$m::SK_LEN }>(sk)?;
                let key =
                    fips205::$m::PrivateKey::try_from_bytes(&sk_arr).map_err(|_| Error::Backend)?;
                // ctx = empty, hedged = false (deterministic, KAT-reproducible).
                let sig = key.try_sign(msg, b"", false).map_err(|_| Error::Backend)?;
                crate::write_exact(out_sig, &sig)?;
                Ok(out_sig.len())
            }
        }

        impl Verifier for $name {
            fn algorithm(&self) -> SigAlg {
                $alg
            }

            fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
                let pk_arr = crate::to_arr::<{ fips205::$m::PK_LEN }>(pk)?;
                let sig_arr = crate::to_arr::<{ fips205::$m::SIG_LEN }>(sig)?;
                let key =
                    fips205::$m::PublicKey::try_from_bytes(&pk_arr).map_err(|_| Error::Backend)?;
                if key.verify(msg, &sig_arr, b"") {
                    Ok(())
                } else {
                    Err(Error::Backend)
                }
            }
        }
    };
}

slhdsa_backend!(
    SlhDsaSha2_128s,
    slh_dsa_sha2_128s,
    SigAlg::SlhDsaSha2_128s,
    "SLH-DSA-SHA2-128s backend (FIPS 205), via `fips205`."
);
slhdsa_backend!(
    SlhDsaSha2_256s,
    slh_dsa_sha2_256s,
    SigAlg::SlhDsaSha2_256s,
    "SLH-DSA-SHA2-256s backend (FIPS 205), via `fips205`."
);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn slhdsa_128s_sign_verify_and_reject() {
        let (sk, vk) = SlhDsaSha2_128s::generate().unwrap();
        let s = SlhDsaSha2_128s;
        let msg = b"root-of-trust statement";
        let mut sig = [0u8; SlhDsaSha2_128s::SIG_LEN];
        let n = s.sign(&sk, msg, &[0u8; 32], &mut sig).unwrap();
        assert_eq!(n, SlhDsaSha2_128s::SIG_LEN);
        s.verify(&vk, msg, &sig).unwrap();
        assert!(s.verify(&vk, b"tampered", &sig).is_err());
        let mut bad = sig;
        bad[0] ^= 0xFF;
        assert!(s.verify(&vk, msg, &bad).is_err());
    }

    #[test]
    fn slhdsa_128s_deterministic() {
        let (sk, _vk) = SlhDsaSha2_128s::generate().unwrap();
        let s = SlhDsaSha2_128s;
        let mut a = [0u8; SlhDsaSha2_128s::SIG_LEN];
        let mut b = [0u8; SlhDsaSha2_128s::SIG_LEN];
        s.sign(&sk, b"m", &[0u8; 32], &mut a).unwrap();
        s.sign(&sk, b"m", &[0u8; 32], &mut b).unwrap();
        assert_eq!(a, b, "non-hedged SLH-DSA signing must be deterministic");
    }

    #[test]
    fn slhdsa_256s_sizes_and_keygen() {
        assert_eq!(SlhDsaSha2_256s::VK_LEN, 64);
        assert_eq!(SlhDsaSha2_256s::SK_LEN, 128);
        assert_eq!(SlhDsaSha2_256s::SIG_LEN, 29792);
        // keygen is cheap; full 256s signing is slow, so it is exercised only by 128s.
        let _ = SlhDsaSha2_256s::generate().unwrap();
    }
}
