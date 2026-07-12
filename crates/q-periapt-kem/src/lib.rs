#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-kem
//!
//! A generic PQ/T hybrid KEM: one post-quantum component and one traditional
//! component combined into one IND-CCA2-aware shared secret via
//! [`q_periapt_core::combine`].
//!
//! This crate is generic over the two [`Kem`] backends and the [`Xof256`] used
//! by the combiner, so the same logic runs against any compatible primitive
//! implementation. Concrete release-graph backends are wired in
//! `q-periapt-backends` and tracked in `docs/ROADMAP.md`; isolated research
//! candidates do not acquire a suite code or ABI merely by implementing [`Kem`].
//!
//! ## Safety invariant (`CompatXWing` backend guard)
//! [`Profile::CompatXWing`] omits the first (`P`, conventionally PQ) component's
//! ciphertext and public key from the KDF; that is sound **only** when that backend
//! is both [`Kem::C2PRI`] and [`Kem::COMPAT_XWING_SAFE`]. [`HybridKem::new`] enforces
//! both independent capabilities: raw/imported-key or non-C2PRI first-slot KEMs
//! are rejected with [`Error::PolicyDenied`]. Those components must use
//! [`Profile::ContextBound`], which binds every ciphertext and public key.

use core::marker::PhantomData;
use q_periapt_core::{
    combine, CombineInput, Error, Kem, Profile, Secret, Xof256, ZeroizingBytes, SHARED_SECRET_LEN,
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
    /// [`Profile::CompatXWing`] but the first-slot backend is not both
    /// [`Kem::C2PRI`] and [`Kem::COMPAT_XWING_SAFE`].
    pub fn new(
        pq: &'a P,
        trad: &'a T,
        profile: Profile,
        suite_id: &'a [u8],
        policy_version: u32,
    ) -> Result<Self, Error> {
        if matches!(profile, Profile::CompatXWing) && (!P::C2PRI || !P::COMPAT_XWING_SAFE) {
            // The fast profile omits the first-slot ciphertext/public key. Primitive
            // C2PRI and an X-Wing-safe exposed key format are separate load-bearing
            // requirements, so contradictory third-party capability declarations fail closed.
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
    /// Component secrets never cross this composition API boundary. The
    /// composition-owned output scratch buffers have zeroizing `Drop`; backend-internal
    /// copies remain backend-managed (see `docs/THREAT_MODEL.md`). Only the returned
    /// [`Secret`] is intentionally exposed by this layer.
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
        let mut ss_pq = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        let mut ss_trad = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        // Drop-based ownership wipes both component secrets on success, Result
        // errors, and panic unwinding. In particular, a second-backend failure
        // cannot bypass cleanup after the first backend filled `ss_pq`.
        self.pq
            .encapsulate(pk_pq, rand_pq, ct_pq, ss_pq.as_mut_bytes())?;
        self.trad
            .encapsulate(pk_trad, rand_trad, ct_trad, ss_trad.as_mut_bytes())?;
        combine::<X>(
            self.profile,
            &CombineInput {
                suite_id: self.suite_id,
                policy_version: self.policy_version,
                ss_pq: ss_pq.as_bytes(),
                ss_trad: ss_trad.as_bytes(),
                ct_pq,
                pk_pq,
                ct_trad,
                pk_trad,
                context,
            },
        )
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
        let mut ss_pq = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        let mut ss_trad = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        self.pq.decapsulate(sk_pq, ct_pq, ss_pq.as_mut_bytes())?;
        self.trad
            .decapsulate(sk_trad, ct_trad, ss_trad.as_mut_bytes())?;
        combine::<X>(
            self.profile,
            &CombineInput {
                suite_id: self.suite_id,
                policy_version: self.policy_version,
                ss_pq: ss_pq.as_bytes(),
                ss_trad: ss_trad.as_bytes(),
                ct_pq,
                pk_pq,
                ct_trad,
                pk_trad,
                context,
            },
        )
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

    /// Capability-matrix backend for construction-time guard regression tests.
    struct CapabilityKem<const C2PRI: bool, const SAFE: bool>;
    impl<const C2PRI: bool, const SAFE: bool> Kem for CapabilityKem<C2PRI, SAFE> {
        const C2PRI: bool = C2PRI;
        const COMPAT_XWING_SAFE: bool = SAFE;

        fn algorithm(&self) -> &'static str {
            "TOY-CAPABILITY"
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
    /// Drop-owned component buffers still clean both secrets, so no live owned scratch
    /// survives this path (which is reachable from the FFI/WASM faces via a valid PQ input
    /// plus a wrong-length trad input).
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
    fn compat_guard_requires_both_c2pri_and_safe_capabilities() {
        let trad = ToyKem("TOY-TRAD");
        let neither = CapabilityKem::<false, false>;
        let c2pri_only = CapabilityKem::<true, false>;
        let safe_without_c2pri = CapabilityKem::<false, true>;
        let both = CapabilityKem::<true, true>;

        assert!(matches!(
            HybridKem::<_, _, ToyXof>::new(&neither, &trad, Profile::CompatXWing, b"S", 1,).err(),
            Some(Error::PolicyDenied)
        ));
        assert!(matches!(
            HybridKem::<_, _, ToyXof>::new(&c2pri_only, &trad, Profile::CompatXWing, b"S", 1,)
                .err(),
            Some(Error::PolicyDenied)
        ));
        assert!(matches!(
            HybridKem::<_, _, ToyXof>::new(
                &safe_without_c2pri,
                &trad,
                Profile::CompatXWing,
                b"S",
                1,
            )
            .err(),
            Some(Error::PolicyDenied)
        ));
        assert!(
            HybridKem::<_, _, ToyXof>::new(&both, &trad, Profile::CompatXWing, b"S", 1,).is_ok()
        );

        // ContextBound binds the omitted fields directly and therefore does not
        // require either fast-profile capability.
        assert!(HybridKem::<_, _, ToyXof>::new(
            &safe_without_c2pri,
            &trad,
            Profile::ContextBound,
            b"S",
            1,
        )
        .is_ok());
    }
}
