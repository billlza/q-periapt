//! SLH-DSA (FIPS 205) signature backend, enabled by the `slh-dsa` cargo feature.
//!
//! SLH-DSA is the conservative, hash-based signature scheme for roots / firmware /
//! long-term keys (large, slow signatures, minimal assumptions). The `Signer`
//! randomness argument selects the FIPS 205 signing variant: an all-zero value
//! (any length, including empty) selects **deterministic (non-hedged)** signing —
//! a pure function of (secret key, message), KAT-reproducible, no entropy at sign
//! time — while any non-zero value requests the **hedged** variant, must be
//! exactly `SIGN_RAND_LEN` bytes, and is used verbatim as the FIPS 205 additional
//! randomness (`addrnd`). A non-zero value of any other length fails with
//! [`Error::InvalidLength`]: a hedged request is never silently downgraded to
//! deterministic signing.
//!
//! Backend choice: this wires the pure-Rust, stable **`fips205`** crate rather
//! than RustCrypto `slh-dsa` (a release candidate whose bleeding-edge rand_core
//! 0.10 keygen RNG is impractical to drive here). Both implement FIPS 205; the
//! caller supplies all signing randomness explicitly, so no internal RNG is drawn.

use fips205::traits::{SerDes as _, Signer as _, Verifier as _};
use q_periapt_core::Error;
use q_periapt_sig::{SigAlg, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};

/// Single-use `CryptoRngCore` that hands the caller's hedging randomness to
/// `fips205::*::try_sign_with_rng`. Hedged SLH-DSA signing draws exactly one
/// n-byte `addrnd` via `try_fill_bytes`; any other draw pattern fails the sign
/// call (fail-closed) rather than substituting different randomness. Marked
/// `CryptoRng` only to satisfy the bound — it is a caller-randomness feeder,
/// NOT a generator.
struct CallerAddrnd<'a> {
    addrnd: &'a [u8],
    spent: bool,
}

impl RngCore for CallerAddrnd<'_> {
    fn next_u32(&mut self) -> u32 {
        unreachable!("hedged SLH-DSA signing draws addrnd only via try_fill_bytes")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("hedged SLH-DSA signing draws addrnd only via try_fill_bytes")
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unreachable!("hedged SLH-DSA signing draws addrnd only via try_fill_bytes")
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        if self.spent || dest.len() != self.addrnd.len() {
            return Err(rand_core::Error::from(core::num::NonZeroU32::MIN));
        }
        dest.copy_from_slice(self.addrnd);
        self.spent = true;
        Ok(())
    }
}

impl CryptoRng for CallerAddrnd<'_> {}

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
            /// Hedged-signing additional-randomness (`addrnd`) length, bytes
            /// (FIPS 205 `n`).
            pub const SIGN_RAND_LEN: usize = fips205::$m::N;

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
                randomness: &[u8],
                out_sig: &mut [u8],
            ) -> Result<usize, Error> {
                let sk = crate::to_zeroizing::<{ fips205::$m::SK_LEN }>(sk)?;
                let key = fips205::$m::PrivateKey::try_from_bytes(sk.as_bytes())
                    .map_err(|_| Error::Backend)?;
                // ctx = empty. All-zero randomness selects deterministic
                // (non-hedged, KAT-reproducible) signing; anything else must be
                // an exact n-byte addrnd and selects hedged signing with that
                // value — a hedged request is never silently dropped.
                let sig = if randomness.iter().any(|&byte| byte != 0) {
                    if randomness.len() != Self::SIGN_RAND_LEN {
                        return Err(Error::InvalidLength);
                    }
                    let mut addrnd = CallerAddrnd {
                        addrnd: randomness,
                        spent: false,
                    };
                    key.try_sign_with_rng(&mut addrnd, msg, b"", true)
                } else {
                    key.try_sign(msg, b"", false)
                }
                .map_err(|_| Error::Backend)?;
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
    SlhDsaSha2_192s,
    slh_dsa_sha2_192s,
    SigAlg::SlhDsaSha2_192s,
    "SLH-DSA-SHA2-192s backend (FIPS 205, NIST level 3), via `fips205`."
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
    fn slhdsa_192s_sign_verify_and_reject() {
        let (sk, vk) = SlhDsaSha2_192s::generate().unwrap();
        let s = SlhDsaSha2_192s;
        let msg = b"L3 hash-based statement";
        let mut sig = [0u8; SlhDsaSha2_192s::SIG_LEN];
        let n = s.sign(&sk, msg, &[0u8; 32], &mut sig).unwrap();
        assert_eq!(n, SlhDsaSha2_192s::SIG_LEN);
        s.verify(&vk, msg, &sig).unwrap();
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
    fn slhdsa_128s_hedged_uses_caller_addrnd() {
        let (sk, vk) = SlhDsaSha2_128s::generate().unwrap();
        let s = SlhDsaSha2_128s;
        let msg = b"hedged statement";
        let addrnd = [0x5Au8; SlhDsaSha2_128s::SIGN_RAND_LEN];
        let mut hedged_a = [0u8; SlhDsaSha2_128s::SIG_LEN];
        let mut hedged_b = [0u8; SlhDsaSha2_128s::SIG_LEN];
        let mut deterministic = [0u8; SlhDsaSha2_128s::SIG_LEN];
        s.sign(&sk, msg, &addrnd, &mut hedged_a).unwrap();
        s.sign(&sk, msg, &addrnd, &mut hedged_b).unwrap();
        s.sign(&sk, msg, &[], &mut deterministic).unwrap();
        s.verify(&vk, msg, &hedged_a).unwrap();
        assert_eq!(
            hedged_a, hedged_b,
            "hedged signing must be a pure function of (sk, msg, addrnd)"
        );
        assert_ne!(
            hedged_a, deterministic,
            "caller addrnd must reach the hedged PRF, not be discarded"
        );
    }

    #[test]
    fn slhdsa_128s_hedged_rejects_wrong_addrnd_length() {
        let (sk, _vk) = SlhDsaSha2_128s::generate().unwrap();
        let s = SlhDsaSha2_128s;
        let mut sig = [0u8; SlhDsaSha2_128s::SIG_LEN];
        // 32 non-zero bytes request hedging but are not the 16-byte 128s addrnd:
        // the request must fail closed, not silently degrade to deterministic.
        assert!(matches!(
            s.sign(&sk, b"m", &[0x5Au8; 32], &mut sig),
            Err(Error::InvalidLength)
        ));
        assert!(matches!(
            s.sign(
                &sk,
                b"m",
                &[0x5Au8; SlhDsaSha2_128s::SIGN_RAND_LEN - 1],
                &mut sig
            ),
            Err(Error::InvalidLength)
        ));
    }

    #[test]
    fn slhdsa_256s_sizes_and_keygen() {
        assert_eq!(SlhDsaSha2_256s::VK_LEN, 64);
        assert_eq!(SlhDsaSha2_256s::SK_LEN, 128);
        assert_eq!(SlhDsaSha2_256s::SIG_LEN, 29792);
        assert_eq!(SlhDsaSha2_128s::SIGN_RAND_LEN, 16);
        assert_eq!(SlhDsaSha2_192s::SIGN_RAND_LEN, 24);
        assert_eq!(SlhDsaSha2_256s::SIGN_RAND_LEN, 32);
        // keygen is cheap; full 256s signing is slow, so it is exercised only by 128s.
        let _ = SlhDsaSha2_256s::generate().unwrap();
    }
}
