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
//! ## Safety invariant (`CompatXWing` backend guard)
//! [`Profile::CompatXWing`] omits the PQ ciphertext from the KDF; that is sound
//! **only** when the PQ backend is explicitly [`Kem::COMPAT_XWING_SAFE`]. [`HybridKem::new`]
//! enforces this: raw/imported-key or non-C2PRI PQ KEMs (e.g. expanded ML-KEM, HQC)
//! are rejected with [`Error::PolicyDenied`]. Those components must use
//! [`Profile::ContextBound`], which binds every ciphertext and public key.

use core::marker::PhantomData;
use q_periapt_core::{
    combine, secure_wipe, CombineInput, Error, Kem, Profile, Secret, Xof256, SHARED_SECRET_LEN,
};

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
    /// [`Profile::CompatXWing`] but the PQ backend is not [`Kem::COMPAT_XWING_SAFE`].
    pub fn new(
        pq: &'a P,
        trad: &'a T,
        profile: Profile,
        suite_id: &'a [u8],
        policy_version: u32,
    ) -> Result<Self, Error> {
        if matches!(profile, Profile::CompatXWing) && !P::COMPAT_XWING_SAFE {
            // The fast profile omits the PQ ciphertext/public key; only a backend whose
            // exposed key format preserves X-Wing's self-binding precondition may use it.
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
    ///
    /// The component (ML-KEM and X25519) shared secrets never cross the API boundary:
    /// they are held in internal scratch and securely wiped before return, since each
    /// is attack-sufficient (the combined key is a deterministic hash of them) and only
    /// the returned [`Secret`] — which carries its own zeroizing `Drop` — is wanted.
    #[allow(clippy::too_many_arguments)]
    pub fn encapsulate(
        &self,
        pk_pq: &[u8],
        pk_trad: &[u8],
        context: &[u8],
        rand_pq: &[u8],
        rand_trad: &[u8],
        ct_pq: &mut [u8],
        ct_trad: &mut [u8],
    ) -> Result<Secret, Error> {
        let mut ss_pq = [0u8; SHARED_SECRET_LEN];
        let mut ss_trad = [0u8; SHARED_SECRET_LEN];
        // Run the fallible body, then wipe BOTH component secrets on every exit path. The
        // second backend's `?` (or a combiner error) early-returns *after* `ss_pq` already
        // holds a live ML-KEM secret; that error is a public length condition reachable from
        // the FFI/WASM faces with caller-controlled buffer lengths, so the wipe must not be
        // skipped. (Wiping the unconditional way also covers the first-backend error path.)
        let out = (|| -> Result<Secret, Error> {
            self.pq.encapsulate(pk_pq, rand_pq, ct_pq, &mut ss_pq)?;
            self.trad
                .encapsulate(pk_trad, rand_trad, ct_trad, &mut ss_trad)?;
            combine::<X>(
                self.profile,
                &CombineInput {
                    suite_id: self.suite_id,
                    policy_version: self.policy_version,
                    ss_pq: &ss_pq,
                    ss_trad: &ss_trad,
                    ct_pq,
                    pk_pq,
                    ct_trad,
                    pk_trad,
                    context,
                },
            )
        })();
        secure_wipe(&mut ss_pq);
        secure_wipe(&mut ss_trad);
        out
    }

    /// Decapsulate both ciphertexts and recompute the combined hybrid secret.
    ///
    /// The FO-KEM (PQ) leg uses implicit rejection (see [`Kem`]): a cryptographically
    /// invalid ciphertext yields a pseudorandom secret rather than an error, so its failure path is
    /// indistinguishable from success — there is no secret-dependent decapsulation oracle. The `?`
    /// operators here propagate only *public* conditions: a buffer-length mismatch
    /// ([`Error::InvalidLength`]), or — for the DH-style traditional leg — a low-order /
    /// non-contributory key share ([`Error::InvalidKeyShare`]). Those depend solely on public
    /// inputs the attacker already controls, so they are validity rejections, not an oracle.
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
    ) -> Result<Secret, Error> {
        let mut ss_pq = [0u8; SHARED_SECRET_LEN];
        let mut ss_trad = [0u8; SHARED_SECRET_LEN];
        // Wipe both component secrets on every exit path (see `encapsulate`): a public
        // length error from the second backend must not leave a live ML-KEM secret behind.
        let out = (|| -> Result<Secret, Error> {
            self.pq.decapsulate(sk_pq, ct_pq, &mut ss_pq)?;
            self.trad.decapsulate(sk_trad, ct_trad, &mut ss_trad)?;
            combine::<X>(
                self.profile,
                &CombineInput {
                    suite_id: self.suite_id,
                    policy_version: self.policy_version,
                    ss_pq: &ss_pq,
                    ss_trad: &ss_trad,
                    ct_pq,
                    pk_pq,
                    ct_trad,
                    pk_trad,
                    context,
                },
            )
        })();
        secure_wipe(&mut ss_pq);
        secure_wipe(&mut ss_trad);
        out
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
    /// works under either profile.
    struct ToyKem(&'static str);
    impl Kem for ToyKem {
        const C2PRI: bool = true; // pretend "ML-KEM-like": binds its ciphertext
        const COMPAT_XWING_SAFE: bool = true;
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

        let (mut ct_pq, mut ct_trad) = ([0u8; 32], [0u8; 32]);
        let enc = kem
            .encapsulate(
                &pk_pq,
                &pk_trad,
                ctx,
                &[0xEEu8; 32],
                &[0xDDu8; 32],
                &mut ct_pq,
                &mut ct_trad,
            )
            .unwrap();

        let dec = kem
            .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, ctx)
            .unwrap();

        assert_eq!(enc.as_bytes(), dec.as_bytes(), "encap/decap must agree");
    }

    /// A backend that always fails — used to drive the path where the FIRST component
    /// already produced a live shared secret and the SECOND component errors.
    struct ToyKemErr;
    impl Kem for ToyKemErr {
        const C2PRI: bool = true;
        const COMPAT_XWING_SAFE: bool = true;
        fn algorithm(&self) -> &'static str {
            "TOY-ERR"
        }
        fn encapsulate(
            &self,
            _pk: &[u8],
            _r: &[u8],
            _ct: &mut [u8],
            _ss: &mut [u8],
        ) -> Result<(), Error> {
            Err(Error::Backend)
        }
        fn decapsulate(&self, _sk: &[u8], _ct: &[u8], _ss: &mut [u8]) -> Result<(), Error> {
            Err(Error::Backend)
        }
    }

    /// Regression for the wipe-on-error contract: when the PQ backend succeeds (leaving a
    /// live `ss_pq`) and the trad backend then errors, the error must propagate — and the
    /// fix makes the `secure_wipe` of both component secrets unconditional, so no live
    /// secret survives this path (which is reachable from the FFI/WASM faces via a valid
    /// PQ input plus a wrong-length trad input).
    #[test]
    fn second_backend_error_propagates_on_both_directions() {
        let pq = ToyKem("TOY-PQ");
        let trad = ToyKemErr;
        let kem =
            HybridKem::<_, _, ToyXof>::new(&pq, &trad, Profile::ContextBound, b"S", 1).unwrap();
        let (mut ct_pq, mut ct_trad) = ([0u8; 32], [0u8; 32]);
        let enc = kem.encapsulate(
            &[9u8; 32],
            &[7u8; 32],
            b"ctx",
            &[0xEEu8; 32],
            &[0xDDu8; 32],
            &mut ct_pq,
            &mut ct_trad,
        );
        assert!(enc.is_err(), "second-backend error must propagate (encap)");
        let dec = kem.decapsulate(
            &[0u8; 32], &ct_pq, &[9u8; 32], &[0u8; 32], &ct_trad, &[7u8; 32], b"ctx",
        );
        assert!(dec.is_err(), "second-backend error must propagate (decap)");
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
