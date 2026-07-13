//! Enhanced-mode suite (ML-KEM-1024 + X25519) end-to-end pinned KAT.
//!
//! The policy's `enhanced()` posture (NIST level 5) names **ML-KEM-1024 + X25519**
//! under `ContextBound`. This drives a *real* [`HybridKem`] over the ML-KEM-1024 and
//! X25519 backends through a full encapsulate/decapsulate round-trip with fixed
//! inputs, then pins the resulting 32-byte secret **three** independent ways:
//!
//! 1. **Round-trip** — decapsulation recovers exactly the encapsulated secret.
//! 2. **Spec-anchored** — the secret equals an INDEPENDENT RustCrypto SHA3-256
//!    recompute over the hand-built 8-byte big-endian length-prefixed `ContextBound`
//!    encoding (`docs/COMBINER_SPEC.md` §3.2), fed the actual ML-KEM-1024 / X25519
//!    shared secrets and ciphertexts — so the pin guards the spec/field-order, not
//!    merely itself.
//! 3. **Regression** — the secret equals a hardcoded golden hex.
//!
//! ML-KEM-1024 + X25519 is not an external standard (X-Wing is ML-KEM-768-only), so
//! a self-pinned, independently-cross-checked vector is the strongest available KAT.
//! The exposed ML-KEM-1024 backend uses an expanded/imported decapsulation key format,
//! so it is deliberately `ContextBound`-only even though the primitive is C2PRI.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{MlKem1024, Sha3_256Xof, ML_KEM_1024_CT_LEN, X25519, X25519_LEN};
use q_periapt_core::{Kem, Profile, DOMAIN};
use q_periapt_kem::HybridKem;
use sha3::{Digest, Sha3_256};

const SUITE_ID: &[u8] = b"ML-KEM-1024+X25519";
const POLICY_VERSION: u32 = 1;
const CONTEXT: &[u8] = b"q-periapt/v1/enhanced-transcript";

/// The pinned enhanced-suite secret (minted once from the deterministic round-trip
/// below; also independently recomputed by `independent_k`).
const GOLDEN_K: &str = "3663279468c4510b2c6f57c11340f1c51f4b76c982f631d27feb670e7c3ddcc8";

/// Length-prefix one field exactly as `q_periapt_core::absorb_lp` does.
fn lp(h: &mut Sha3_256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// INDEPENDENT canonical recompute of the `ContextBound` key (spec §3.2) — a separate
/// SHA3 implementation and hand-written encoder, sharing only `DOMAIN` and field order.
#[allow(clippy::too_many_arguments)]
fn independent_k(
    suite: &[u8],
    ver: u32,
    ss_pq: &[u8],
    ss_trad: &[u8],
    ct_pq: &[u8],
    pk_pq: &[u8],
    ct_trad: &[u8],
    pk_trad: &[u8],
    ctx: &[u8],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    lp(&mut h, DOMAIN);
    lp(&mut h, suite);
    lp(&mut h, &ver.to_be_bytes());
    lp(&mut h, ss_pq);
    lp(&mut h, ss_trad);
    lp(&mut h, ct_pq);
    lp(&mut h, pk_pq);
    lp(&mut h, ct_trad);
    lp(&mut h, pk_trad);
    lp(&mut h, ctx);
    h.finalize().into()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn enhanced_suite_pinned_reference_vector() {
    let (sk_pq, pk_pq) = MlKem1024::generate([7u8; 64]).unwrap();
    let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);

    let (pq, trad) = (MlKem1024, X25519);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(
        &pq,
        &trad,
        Profile::ContextBound,
        SUITE_ID,
        POLICY_VERSION,
    )
    .unwrap();

    // --- encapsulate (deterministic from fixed randomness) ---
    let mut ct_pq = [0u8; ML_KEM_1024_CT_LEN];
    let mut ct_trad = [0u8; X25519_LEN];
    let secret = kem
        .encapsulate(
            &pk_pq,
            &pk_trad,
            CONTEXT,
            &[11u8; 32],
            &[22u8; 32],
            &mut ct_pq,
            &mut ct_trad,
        )
        .unwrap();

    // --- (1) round-trip: decapsulation recovers the same secret ---
    let dec = kem
        .decapsulate(
            &sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, CONTEXT,
        )
        .unwrap();
    assert_eq!(
        secret.as_bytes(),
        dec.as_bytes(),
        "enhanced suite: decaps must recover the encapsulated secret"
    );

    // --- (2) spec-anchored: the hybrid KEM keeps the component secrets internal (and
    // wipes them), so derive them INDEPENDENTLY from the backends with the same fixed
    // randomness, then recompute K via the from-scratch canonical encoder. The
    // independently-derived ciphertexts must equal the hybrid's. ---
    let mut ss_pq = [0u8; 32];
    let mut ind_ct_pq = [0u8; ML_KEM_1024_CT_LEN];
    MlKem1024
        .encapsulate(&pk_pq, &[11u8; 32], &mut ind_ct_pq, &mut ss_pq)
        .unwrap();
    let mut ss_trad = [0u8; 32];
    let mut ind_ct_trad = [0u8; X25519_LEN];
    X25519
        .encapsulate(&pk_trad, &[22u8; 32], &mut ind_ct_trad, &mut ss_trad)
        .unwrap();
    assert_eq!(
        ind_ct_pq, ct_pq,
        "independent ct_pq must match the hybrid's"
    );
    assert_eq!(
        ind_ct_trad, ct_trad,
        "independent ct_trad must match the hybrid's"
    );
    let recomputed = independent_k(
        SUITE_ID,
        POLICY_VERSION,
        &ss_pq,
        &ss_trad,
        &ct_pq,
        &pk_pq,
        &ct_trad,
        &pk_trad,
        CONTEXT,
    );
    assert_eq!(
        secret.as_bytes(),
        &recomputed,
        "enhanced suite: combine() must equal the independent canonical encoding"
    );

    // --- (3) regression: the pinned golden value ---
    assert_eq!(
        secret.as_bytes(),
        hex(GOLDEN_K).as_slice(),
        "enhanced suite: secret drifted from the pinned golden vector"
    );
}
