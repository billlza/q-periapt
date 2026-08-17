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
    combine, CombineInput, Error, Kem, PreparedKem, Profile, Secret, Xof256, ZeroizingBytes,
    SHARED_SECRET_LEN,
};

/// A PQ/T hybrid KEM binding a post-quantum and a traditional component.
///
/// The combined shared secret binds the agility block (`suite_id`,
/// `policy_version`) first-class under [`Profile::ContextBound`], plus a
/// caller-supplied `context` (e.g. a handshake transcript) per encap/decap call.
/// [`Profile::CompatXWing`] instead requires the canonical X-Wing metadata
/// representation: an empty suite identifier, policy version zero, and empty context.
pub struct HybridKem<'a, P: Kem, T: Kem, X: Xof256> {
    pq: &'a P,
    trad: &'a T,
    profile: Profile,
    suite_id: &'a [u8],
    policy_version: u32,
    _xof: PhantomData<X>,
}

/// Borrowed inputs shared by serialized-key and prepared-key decapsulation.
struct DecapsulationInput<'a> {
    ct_pq: &'a [u8],
    pk_pq: &'a [u8],
    sk_trad: &'a [u8],
    ct_trad: &'a [u8],
    pk_trad: &'a [u8],
    context: &'a [u8],
}

impl<'a, P: Kem, T: Kem, X: Xof256> HybridKem<'a, P, T, X> {
    /// Build a hybrid KEM. Returns [`Error::PolicyDenied`] if `profile` is
    /// [`Profile::CompatXWing`] but the first-slot backend is not both
    /// [`Kem::C2PRI`] and [`Kem::COMPAT_XWING_SAFE`], or if its suite identifier
    /// is non-empty or policy version is nonzero.
    pub fn new(
        pq: &'a P,
        trad: &'a T,
        profile: Profile,
        suite_id: &'a [u8],
        policy_version: u32,
    ) -> Result<Self, Error> {
        profile.validate_static_inputs(suite_id, policy_version)?;
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
    /// the combined hybrid shared secret. `context` is bound under
    /// [`Profile::ContextBound`] and must be empty under [`Profile::CompatXWing`].
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
        self.profile
            .validate_operation_inputs(self.suite_id, self.policy_version, context)?;
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
    /// indistinguishable from success — there is no secret-dependent decapsulation oracle. Public
    /// input failures remain classifiable: a buffer-length mismatch ([`Error::InvalidLength`]), or
    /// — for the DH-style traditional leg — a low-order/non-contributory key share
    /// ([`Error::InvalidKeyShare`]). A fixed-length but malformed caller-supplied local expanded
    /// ML-KEM key may instead produce opaque [`Error::Backend`]; that represents a local
    /// key-storage/provider failure, not peer behavior or ciphertext validity.
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
        self.profile
            .validate_operation_inputs(self.suite_id, self.policy_version, context)?;
        self.decapsulate_validated(
            DecapsulationInput {
                ct_pq,
                pk_pq,
                sk_trad,
                ct_trad,
                pk_trad,
                context,
            },
            |ss_pq| self.pq.decapsulate(sk_pq, ct_pq, ss_pq),
        )
    }

    /// Finish a decapsulation after the public profile inputs have been
    /// validated, sharing the traditional-component and combiner path between
    /// serialized and prepared PQ keys.
    fn decapsulate_validated<F>(
        &self,
        input: DecapsulationInput<'_>,
        decapsulate_pq: F,
    ) -> Result<Secret, Error>
    where
        F: FnOnce(&mut [u8]) -> Result<(), Error>,
    {
        let mut ss_pq = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        let mut ss_trad = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        decapsulate_pq(ss_pq.as_mut_bytes())?;
        self.trad
            .decapsulate(input.sk_trad, input.ct_trad, ss_trad.as_mut_bytes())?;
        combine::<X>(
            self.profile,
            &CombineInput {
                suite_id: self.suite_id,
                policy_version: self.policy_version,
                ss_pq: ss_pq.as_bytes(),
                ss_trad: ss_trad.as_bytes(),
                ct_pq: input.ct_pq,
                pk_pq: input.pk_pq,
                ct_trad: input.ct_trad,
                pk_trad: input.pk_trad,
                context: input.context,
            },
        )
    }
}

impl<'a, P: PreparedKem, T: Kem, X: Xof256> HybridKem<'a, P, T, X> {
    /// Decapsulate with a process-local prepared PQ key and the serialized
    /// traditional key.
    ///
    /// The prepared owner supplies its paired public key, so callers cannot
    /// accidentally combine an unrelated PQ public key. Profile validation runs
    /// before either component backend. After that guard, this method reuses the
    /// exact traditional decapsulation and combiner path used by
    /// [`HybridKem::decapsulate`].
    pub fn decapsulate_prepared(
        &self,
        prepared_pq: &P::PreparedKey,
        ct_pq: &[u8],
        sk_trad: &[u8],
        ct_trad: &[u8],
        pk_trad: &[u8],
        context: &[u8],
    ) -> Result<Secret, Error> {
        self.profile
            .validate_operation_inputs(self.suite_id, self.policy_version, context)?;
        let pk_pq = self.pq.prepared_encapsulation_key(prepared_pq);
        self.decapsulate_validated(
            DecapsulationInput {
                ct_pq,
                pk_pq,
                sk_trad,
                ct_trad,
                pk_trad,
                context,
            },
            |ss_pq| self.pq.decapsulate_prepared(prepared_pq, ct_pq, ss_pq),
        )
    }
}

#[cfg(test)]
mod tests {
    // `unwrap`/indexing are idiomatic in tests; the workspace lints target library code.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use core::cell::Cell;

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

    /// Operation spy whose writes make an accidental backend call observable.
    struct CountingKem<'a> {
        calls: &'a Cell<usize>,
    }

    impl Kem for CountingKem<'_> {
        const C2PRI: bool = true;
        const COMPAT_XWING_SAFE: bool = true;

        fn algorithm(&self) -> &'static str {
            "COUNTING-KEM"
        }

        fn encapsulate(
            &self,
            _pk: &[u8],
            _randomness: &[u8],
            ct: &mut [u8],
            ss: &mut [u8],
        ) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            ct.fill(0x11);
            ss.fill(0x22);
            Ok(())
        }

        fn decapsulate(&self, _sk: &[u8], _ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            ss.fill(0x33);
            Ok(())
        }
    }

    impl PreparedKem for CountingKem<'_> {
        type PreparedKey = [u8; 32];

        fn prepared_encapsulation_key<'a>(&self, key: &'a Self::PreparedKey) -> &'a [u8] {
            key
        }

        fn decapsulate_prepared(
            &self,
            _key: &Self::PreparedKey,
            _ct: &[u8],
            ss: &mut [u8],
        ) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            ss.fill(0x33);
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
            HybridKem::<_, _, ToyXof>::new(&neither, &trad, Profile::CompatXWing, b"", 0,).err(),
            Some(Error::PolicyDenied)
        ));
        assert!(matches!(
            HybridKem::<_, _, ToyXof>::new(&c2pri_only, &trad, Profile::CompatXWing, b"", 0,).err(),
            Some(Error::PolicyDenied)
        ));
        assert!(matches!(
            HybridKem::<_, _, ToyXof>::new(
                &safe_without_c2pri,
                &trad,
                Profile::CompatXWing,
                b"",
                0,
            )
            .err(),
            Some(Error::PolicyDenied)
        ));
        assert!(
            HybridKem::<_, _, ToyXof>::new(&both, &trad, Profile::CompatXWing, b"", 0,).is_ok()
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

    #[test]
    fn compat_constructor_rejects_noncanonical_static_metadata() {
        let pq = CapabilityKem::<true, true>;
        let trad = ToyKem("TOY-TRAD");

        assert_eq!(
            HybridKem::<_, _, ToyXof>::new(&pq, &trad, Profile::CompatXWing, b"suite", 0).err(),
            Some(Error::PolicyDenied)
        );
        assert_eq!(
            HybridKem::<_, _, ToyXof>::new(&pq, &trad, Profile::CompatXWing, b"", 1).err(),
            Some(Error::PolicyDenied)
        );
    }

    #[test]
    fn compat_bad_context_calls_no_backend_and_preserves_ciphertext_outputs() {
        let pq_calls = Cell::new(0);
        let trad_calls = Cell::new(0);
        let pq = CountingKem { calls: &pq_calls };
        let trad = CountingKem { calls: &trad_calls };
        let kem = HybridKem::<_, _, ToyXof>::new(&pq, &trad, Profile::CompatXWing, b"", 0).unwrap();

        let mut ct_pq = [0xA5u8; 32];
        let mut ct_trad = [0x5Au8; 32];
        let expected_ct_pq = ct_pq;
        let expected_ct_trad = ct_trad;
        let encapsulation = kem.encapsulate(
            &[0x10u8; 32],
            &[0x20u8; 32],
            b"forbidden-context",
            &[0x30u8; 32],
            &[0x40u8; 32],
            &mut ct_pq,
            &mut ct_trad,
        );

        assert_eq!(encapsulation.err(), Some(Error::PolicyDenied));
        assert_eq!(pq_calls.get(), 0, "PQ encapsulation backend must not run");
        assert_eq!(trad_calls.get(), 0, "traditional backend must not run");
        assert_eq!(ct_pq, expected_ct_pq, "PQ ciphertext must remain untouched");
        assert_eq!(
            ct_trad, expected_ct_trad,
            "traditional ciphertext must remain untouched"
        );

        let decapsulation = kem.decapsulate(
            &[0x50u8; 32],
            &ct_pq,
            &[0x10u8; 32],
            &[0x60u8; 32],
            &ct_trad,
            &[0x20u8; 32],
            b"forbidden-context",
        );
        assert_eq!(decapsulation.err(), Some(Error::PolicyDenied));
        assert_eq!(pq_calls.get(), 0, "PQ decapsulation backend must not run");
        assert_eq!(trad_calls.get(), 0, "traditional backend must not run");

        let prepared_decapsulation = kem.decapsulate_prepared(
            &[0x50u8; 32],
            &ct_pq,
            &[0x60u8; 32],
            &ct_trad,
            &[0x20u8; 32],
            b"forbidden-context",
        );
        assert_eq!(prepared_decapsulation.err(), Some(Error::PolicyDenied));
        assert_eq!(
            pq_calls.get(),
            0,
            "prepared PQ decapsulation must not run before profile validation"
        );
        assert_eq!(
            trad_calls.get(),
            0,
            "traditional backend must not run before profile validation"
        );
    }

    #[test]
    fn prepared_context_bound_empty_context_fails_before_backends() {
        let pq_calls = Cell::new(0);
        let trad_calls = Cell::new(0);
        let pq = CountingKem { calls: &pq_calls };
        let trad = CountingKem { calls: &trad_calls };
        let kem =
            HybridKem::<_, _, ToyXof>::new(&pq, &trad, Profile::ContextBound, b"suite", 1).unwrap();

        let result = kem.decapsulate_prepared(
            &[0x11; 32],
            &[0x22; 1],
            &[0x33; 1],
            &[0x44; 1],
            &[0x55; 1],
            b"",
        );
        assert_eq!(result.err(), Some(Error::InvalidLength));
        assert_eq!(pq_calls.get(), 0);
        assert_eq!(trad_calls.get(), 0);
    }
}
