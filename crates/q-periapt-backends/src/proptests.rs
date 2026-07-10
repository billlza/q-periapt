//! Generative property-based tests (proptest).
//!
//! A sixth, orthogonal assurance method alongside fixed KATs, NIST ACVP, the
//! multi-backend differential, the EasyCrypt proof, and cross-platform consistency.
//! proptest generates random inputs (and shrinks any failure to a minimal case),
//! exercising the load-bearing combiner / hybrid-KEM invariants — binding
//! injectivity, determinism, domain separation, the length / context guards, and
//! KEM round-trip — over the **real** SHA3 + ML-KEM-768 + X25519 backends.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{
    MlKem1024, MlKem768, MlKem768XWingSeed, Sha3_256Xof, ML_KEM_1024_CT_LEN, ML_KEM_768_CT_LEN,
    X25519, X25519_LEN,
};
use proptest::prelude::*;
use q_periapt_core::{combine, CombineInput, Error, Profile, SHARED_SECRET_LEN};
use q_periapt_kem::HybridKem;

/// A `ContextBound` input with every field supplied; tests vary what they probe.
#[allow(clippy::too_many_arguments)]
fn ctx_input<'a>(
    suite_id: &'a [u8],
    ss_pq: &'a [u8],
    ss_trad: &'a [u8],
    ct_pq: &'a [u8],
    pk_pq: &'a [u8],
    ct_trad: &'a [u8],
    pk_trad: &'a [u8],
    context: &'a [u8],
) -> CombineInput<'a> {
    CombineInput {
        suite_id,
        policy_version: 1,
        ss_pq,
        ss_trad,
        ct_pq,
        pk_pq,
        ct_trad,
        pk_trad,
        context,
    }
}

fn secret(profile: Profile, inp: &CombineInput) -> Result<[u8; SHARED_SECRET_LEN], Error> {
    combine::<Sha3_256Xof>(profile, inp).map(|s| *s.as_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The combiner is a deterministic function of its inputs.
    #[test]
    fn compat_xwing_deterministic(
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(),
        c in any::<[u8; 32]>(), d in any::<[u8; 32]>(),
    ) {
        let inp = CombineInput {
            suite_id: b"", policy_version: 0, ss_pq: &a, ss_trad: &b,
            ct_pq: &[], pk_pq: &[], ct_trad: &c, pk_trad: &d, context: &[],
        };
        prop_assert_eq!(
            secret(Profile::CompatXWing, &inp).unwrap(),
            secret(Profile::CompatXWing, &inp).unwrap()
        );
    }

    /// CompatXWing rejects any of its four fields that is not exactly 32 bytes
    /// (the hard length check that prevents cross-boundary concatenation collisions).
    #[test]
    fn compat_xwing_rejects_non_32(
        bad in prop::collection::vec(any::<u8>(), 0..48), ok in any::<[u8; 32]>(),
    ) {
        prop_assume!(bad.len() != 32);
        let inp = CombineInput {
            suite_id: b"", policy_version: 0, ss_pq: &bad, ss_trad: &ok,
            ct_pq: &[], pk_pq: &[], ct_trad: &ok, pk_trad: &ok, context: &[],
        };
        prop_assert_eq!(secret(Profile::CompatXWing, &inp), Err(Error::InvalidLength));
    }

    /// ContextBound requires a non-empty context (the MAL-BIND-K-CTX precondition).
    #[test]
    fn contextbound_rejects_empty_context(
        s in any::<[u8; 32]>(), v in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        let inp = ctx_input(b"suite", &s, &s, &v, &v, &s, &s, &[]);
        prop_assert_eq!(secret(Profile::ContextBound, &inp), Err(Error::InvalidLength));
    }

    /// The canonical encoding is INJECTIVE across a variable-length field boundary:
    /// two different splits of the same concatenation `ss_pq‖ss_trad` yield different
    /// secrets. Naive concatenation would collide here; the fixed-width length prefix
    /// is what prevents it (the binding property machine-checked in EasyCrypt).
    #[test]
    fn contextbound_injective_under_boundary_shift(
        buf in prop::collection::vec(any::<u8>(), 4..40),
        r1 in 0usize..4096, r2 in 0usize..4096,
    ) {
        let n = buf.len();
        let (k1, k2) = (1 + r1 % (n - 1), 1 + r2 % (n - 1));
        prop_assume!(k1 != k2);
        let mk = |k: usize| secret(
            Profile::ContextBound,
            &ctx_input(b"S", &buf[..k], &buf[k..], &[1], &[2], &[3], &[4], b"ctx"),
        ).unwrap();
        prop_assert_ne!(mk(k1), mk(k2));
    }

    /// The two profiles are domain-separated: identical component material, but
    /// CompatXWing and ContextBound derive different keys (DOMAIN vs XWING_LABEL).
    #[test]
    fn profiles_domain_separated(
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(),
        c in any::<[u8; 32]>(), d in any::<[u8; 32]>(),
    ) {
        let compat = CombineInput {
            suite_id: b"", policy_version: 0, ss_pq: &a, ss_trad: &b,
            ct_pq: &[], pk_pq: &[], ct_trad: &c, pk_trad: &d, context: &[],
        };
        let bound = ctx_input(b"", &a, &b, &[], &[], &c, &d, b"x");
        prop_assert_ne!(
            secret(Profile::CompatXWing, &compat).unwrap(),
            secret(Profile::ContextBound, &bound).unwrap()
        );
    }

    /// ContextBound binds the caller context: flipping a single bit of `context`
    /// changes the derived key (the K-CTX guarantee).
    #[test]
    fn contextbound_binds_context(
        s in any::<[u8; 32]>(), ctx in prop::collection::vec(any::<u8>(), 1..40),
        idx in 0usize..40, bit in 0u8..8,
    ) {
        prop_assume!(idx < ctx.len());
        let mut ctx2 = ctx.clone();
        ctx2[idx] ^= 1u8 << bit;
        let base = ctx_input(b"S", &s, &s, &s, &s, &s, &s, &ctx);
        let flipped = ctx_input(b"S", &s, &s, &s, &s, &s, &s, &ctx2);
        prop_assert_ne!(
            secret(Profile::ContextBound, &base).unwrap(),
            secret(Profile::ContextBound, &flipped).unwrap()
        );
    }

    /// Hybrid CompatXWing KEM correctness over random seed-dk keys: decapsulation recovers
    /// exactly the encapsulated secret (real ML-KEM-768 seed format + X25519 + SHA3).
    #[test]
    fn hybrid_compat_round_trip(
        seed_pq in any::<[u8; 32]>(), seed_x in any::<[u8; 32]>(),
        m in any::<[u8; 32]>(), eph in any::<[u8; 32]>(),
    ) {
        let (sk_pq, pk_pq) = MlKem768XWingSeed::generate(seed_pq);
        let (sk_x, pk_x) = X25519::generate(seed_x);
        let (pq, trad) = (MlKem768XWingSeed, X25519);
        let hk = HybridKem::<MlKem768XWingSeed, X25519, Sha3_256Xof>::new(
            &pq, &trad, Profile::CompatXWing, b"", 0,
        ).unwrap();

        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_x = [0u8; X25519_LEN];
        let enc = hk
            .encapsulate(&pk_pq, &pk_x, b"", &m, &eph, &mut ct_pq, &mut ct_x)
            .unwrap();

        let dec = hk
            .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_x, &ct_x, &pk_x, b"")
            .unwrap();

        prop_assert_eq!(enc.as_bytes(), dec.as_bytes());
    }

    /// Raw FIPS-expanded ML-KEM keys must not be admitted to the ciphertext-omitting
    /// CompatXWing profile. ContextBound is the supported profile for imported/expanded keys.
    #[test]
    fn expanded_mlkem_rejected_with_compat_xwing(_seed in any::<[u8; 64]>()) {
        let (pq, trad) = (MlKem768, X25519);
        prop_assert!(matches!(
            HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(
                &pq, &trad, Profile::CompatXWing, b"", 0,
            ),
            Err(Error::PolicyDenied)
        ));
    }

    /// Enhanced suite (ML-KEM-1024 + X25519) round-trip over random keys under the
    /// policy-correct `ContextBound` profile: decapsulation recovers the encapsulated
    /// secret. Gives the enhanced suite the same generative assurance as the default.
    #[test]
    fn hybrid_enhanced_round_trip(
        seed_pq in any::<[u8; 64]>(), seed_x in any::<[u8; 32]>(),
        m in any::<[u8; 32]>(), eph in any::<[u8; 32]>(),
        ctx in proptest::collection::vec(any::<u8>(), 1..40),
    ) {
        let (sk_pq, pk_pq) = MlKem1024::generate(seed_pq);
        let (sk_x, pk_x) = X25519::generate(seed_x);
        let (pq, trad) = (MlKem1024, X25519);
        let hk = HybridKem::<MlKem1024, X25519, Sha3_256Xof>::new(
            &pq, &trad, Profile::ContextBound, b"ML-KEM-1024+X25519", 1,
        ).unwrap();

        let mut ct_pq = [0u8; ML_KEM_1024_CT_LEN];
        let mut ct_x = [0u8; X25519_LEN];
        let enc = hk
            .encapsulate(&pk_pq, &pk_x, &ctx, &m, &eph, &mut ct_pq, &mut ct_x)
            .unwrap();

        let dec = hk
            .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_x, &ct_x, &pk_x, &ctx)
            .unwrap();

        prop_assert_eq!(enc.as_bytes(), dec.as_bytes());
    }
}
