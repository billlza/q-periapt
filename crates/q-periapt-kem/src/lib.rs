#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-kem
//!
//! The PQ/T hybrid KEM: a post-quantum component (ML-KEM-768, HQC backup) and a
//! traditional component (X25519) combined into one IND-CCA2-aware shared secret
//! via [`q_periapt_core::combine`].
//!
//! This crate is generic over the two [`Kem`] backends and the [`Xof256`] used
//! by the combiner, so the same logic runs against any vetted primitive
//! implementation. Concrete backends (libcrux ML-KEM, x25519-dalek, sha3,
//! pqcrypto HQC) are wired in behind cargo features — tracked in `docs/ROADMAP.md`.
//!
//! ## Safety invariant (C2PRI guard)
//! [`Profile::CompatXWing`] omits the PQ ciphertext from the KDF; that is sound
//! **only** when the PQ KEM is [`Kem::C2PRI`]. [`HybridKem::new`] enforces this:
//! pairing a non-C2PRI PQ KEM (e.g. HQC) with `CompatXWing` is rejected with
//! [`Error::PolicyDenied`]. Non-C2PRI components must use
//! [`Profile::ContextBound`], which binds every ciphertext.

use core::marker::PhantomData;
use q_periapt_core::{combine, CombineInput, Error, Kem, Profile, Secret, Xof256};

/// A PQ/T hybrid KEM binding a post-quantum and a traditional component.
///
/// The combined shared secret binds the agility block (`suite_id`,
/// `policy_version`) first-class under [`Profile::ContextBound`], plus a
/// caller-supplied `context` (e.g. a handshake transcript) per encap/decap call.
pub struct HybridKem<'a, P: Kem, T: Kem, X: Xof256> {
    pq: &'a P,
    trad: &'a T,
    profile: Profile,
    suite_id: &'a [u8],
    policy_version: u32,
    _xof: PhantomData<X>,
}

impl<'a, P: Kem, T: Kem, X: Xof256> HybridKem<'a, P, T, X> {
    /// Build a hybrid KEM. Returns [`Error::PolicyDenied`] if `profile` is
    /// [`Profile::CompatXWing`] but the PQ backend is not [`Kem::C2PRI`].
    pub fn new(
        pq: &'a P,
        trad: &'a T,
        profile: Profile,
        suite_id: &'a [u8],
        policy_version: u32,
    ) -> Result<Self, Error> {
        if matches!(profile, Profile::CompatXWing) && !P::C2PRI {
            // The fast profile omits the PQ ciphertext; only safe for a C2PRI KEM.
            return Err(Error::PolicyDenied);
        }
        Ok(Self {
            pq,
            trad,
            profile,
            suite_id,
            policy_version,
            _xof: PhantomData,
        })
    }

    /// The post-quantum component's algorithm id (e.g. `"ML-KEM-768"`).
    pub fn pq_algorithm(&self) -> &'static str {
        self.pq.algorithm()
    }

    /// The traditional component's algorithm id (e.g. `"X25519"`).
    pub fn trad_algorithm(&self) -> &'static str {
        self.trad.algorithm()
    }

    /// Encapsulate to both recipient public keys, producing both ciphertexts and
    /// the combined hybrid shared secret. `context` is bound only under
    /// [`Profile::ContextBound`].
    #[allow(clippy::too_many_arguments)]
    pub fn encapsulate(
        &self,
        pk_pq: &[u8],
        pk_trad: &[u8],
        context: &[u8],
        rand_pq: &[u8],
        rand_trad: &[u8],
        ct_pq: &mut [u8],
        ss_pq: &mut [u8],
        ct_trad: &mut [u8],
        ss_trad: &mut [u8],
    ) -> Result<Secret, Error> {
        self.pq.encapsulate(pk_pq, rand_pq, ct_pq, ss_pq)?;
        self.trad
            .encapsulate(pk_trad, rand_trad, ct_trad, ss_trad)?;
        let input = CombineInput {
            suite_id: self.suite_id,
            policy_version: self.policy_version,
            ss_pq,
            ss_trad,
            ct_pq,
            pk_pq,
            ct_trad,
            pk_trad,
            context,
        };
        combine::<X>(self.profile, &input)
    }

    /// Decapsulate both ciphertexts and recompute the combined hybrid secret.
    ///
    /// Both component backends use implicit rejection (see [`Kem`]), so an
    /// invalid ciphertext yields a pseudorandom secret rather than an error —
    /// the failure path is indistinguishable from success. The `?` operators
    /// here propagate only *public* conditions (e.g. buffer-length mismatches).
    #[allow(clippy::too_many_arguments)]
    pub fn decapsulate(
        &self,
        sk_pq: &[u8],
        ct_pq: &[u8],
        pk_pq: &[u8],
        sk_trad: &[u8],
        ct_trad: &[u8],
        pk_trad: &[u8],
        context: &[u8],
        ss_pq: &mut [u8],
        ss_trad: &mut [u8],
    ) -> Result<Secret, Error> {
        self.pq.decapsulate(sk_pq, ct_pq, ss_pq)?;
        self.trad.decapsulate(sk_trad, ct_trad, ss_trad)?;
        let input = CombineInput {
            suite_id: self.suite_id,
            policy_version: self.policy_version,
            ss_pq,
            ss_trad,
            ct_pq,
            pk_pq,
            ct_trad,
            pk_trad,
            context,
        };
        combine::<X>(self.profile, &input)
    }
}

#[cfg(test)]
mod tests {
    // `unwrap`/indexing are idiomatic in tests; the workspace lints target library code.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    struct ToyXof(u64);
    impl Xof256 for ToyXof {
        fn new() -> Self {
            ToyXof(0xcbf2_9ce4_8422_2325)
        }
        fn absorb(&mut self, data: &[u8]) {
            for &b in data {
                self.0 ^= u64::from(b);
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        fn squeeze32(mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for chunk in out.chunks_mut(8) {
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3) ^ 0x9e37_79b9_7f4a_7c15;
                let bytes = self.0.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            out
        }
    }

    /// Toy KEM. Deterministic, NON-cryptographic; with all fields sized 32 so it
    /// works under either profile. `C2PRI` is parameterized via two newtypes.
    struct ToyKem(&'static str);
    impl Kem for ToyKem {
        const C2PRI: bool = true; // pretend "ML-KEM-like": binds its ciphertext
        fn algorithm(&self) -> &'static str {
            self.0
        }
        fn encapsulate(
            &self,
            pk: &[u8],
            _randomness: &[u8],
            ct: &mut [u8],
            ss: &mut [u8],
        ) -> Result<(), Error> {
            for (i, b) in ct.iter_mut().enumerate() {
                *b = pk.get(i).copied().unwrap_or(0) ^ 0xAA;
            }
            for (i, b) in ss.iter_mut().enumerate() {
                *b = pk.get(i).copied().unwrap_or(0);
            }
            Ok(())
        }
        fn decapsulate(&self, _sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
            for (i, b) in ss.iter_mut().enumerate() {
                *b = ct.get(i).copied().unwrap_or(0) ^ 0xAA;
            }
            Ok(())
        }
    }

    /// Non-C2PRI toy KEM (default `C2PRI = false`), like an HQC stand-in.
    struct ToyKemWeak;
    impl Kem for ToyKemWeak {
        fn algorithm(&self) -> &'static str {
            "TOY-WEAK"
        }
        fn encapsulate(
            &self,
            _pk: &[u8],
            _randomness: &[u8],
            _ct: &mut [u8],
            _ss: &mut [u8],
        ) -> Result<(), Error> {
            Ok(())
        }
        fn decapsulate(&self, _sk: &[u8], _ct: &[u8], _ss: &mut [u8]) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn hybrid_roundtrip_agrees() {
        let pq = ToyKem("TOY-PQ");
        let trad = ToyKem("TOY-TRAD");
        let kem =
            HybridKem::<_, _, ToyXof>::new(&pq, &trad, Profile::ContextBound, b"TOY-SUITE", 1)
                .unwrap();

        let pk_pq = [9u8; 32];
        let pk_trad = [7u8; 32];
        let (sk_pq, sk_trad) = ([0u8; 32], [0u8; 32]);
        let ctx = b"handshake-transcript";

        let (mut ct_pq, mut ss_pq) = ([0u8; 32], [0u8; 32]);
        let (mut ct_trad, mut ss_trad) = ([0u8; 32], [0u8; 32]);
        let enc = kem
            .encapsulate(
                &pk_pq,
                &pk_trad,
                ctx,
                &[0xEEu8; 32],
                &[0xDDu8; 32],
                &mut ct_pq,
                &mut ss_pq,
                &mut ct_trad,
                &mut ss_trad,
            )
            .unwrap();

        let (mut d_ss_pq, mut d_ss_trad) = ([0u8; 32], [0u8; 32]);
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

        assert_eq!(enc.as_bytes(), dec.as_bytes(), "encap/decap must agree");
    }

    #[test]
    fn c2pri_guard_rejects_weak_kem_in_fast_profile() {
        let weak = ToyKemWeak;
        let trad = ToyKem("TOY-TRAD");
        // Non-C2PRI PQ KEM + fast profile MUST be rejected.
        let res = HybridKem::<_, _, ToyXof>::new(&weak, &trad, Profile::CompatXWing, b"S", 1);
        assert!(matches!(res.err(), Some(Error::PolicyDenied)));
        // ...but the same weak KEM is fine under the context-bound profile.
        let ok = HybridKem::<_, _, ToyXof>::new(&weak, &trad, Profile::ContextBound, b"S", 1);
        assert!(ok.is_ok());
    }
}
