//! Paper artifact (matériel B): a *real, executable* reproduction of Schmieg's
//! expanded-dk MAL-BIND-K-PK counterexample against **real libcrux ML-KEM-768**, used to
//! demonstrate one combiner-design invariant — and nothing more.
//!
//! WHAT THIS IS NOT. We do **not** claim to discover any cryptographic fact here, and we do
//! **not** claim X-Wing fails MAL-BIND-K-PK. Correctly-implemented seed-dk X-Wing
//! (draft-connolly-cfrg-xwing-kem: KeyGen re-derives `H(ek)` and `z` from a 32-byte seed)
//! **attains** MAL-BIND-K-PK. The underlying facts are published prior art:
//!   * Schmieg, eprint 2024/523 — ML-KEM in the FIPS-203 *expanded* dk format is neither
//!     MAL-BIND-K-CT nor MAL-BIND-K-PK (the seed-dk format fixes both).
//!   * Güneysu–Hövelmanns–Pietrzak / Chempat, eprint 2025/1416 — a hash-everything combiner
//!     is binding from collision-resistance alone, while a lean combiner inherits the binding
//!     of whatever component field it omits. (ContextBound *is* this hash-everything
//!     construction; it is not a new primitive.)
//!   * Cremers et al., CCS'24 — the MAL-BIND-K-{CT,PK} notions.
//!
//! WHAT THIS IS. An executable, CI-gated witness that operationalises one design invariant:
//! *binding `pk_pq`/`ct_pq` in the KDF makes hybrid MAL-BIND independent of the component
//! KEM's key-serialization format.* The lean combiner shape (X-Wing's byte-exact
//! `CompatXWing`, which omits `ct_pq`/`pk_pq`) attains K-PK only **conditionally** — it relies
//! on the component ML-KEM being self-binding, which holds only for the seed-dk format. When
//! the same shape is instantiated over the FIPS-203 **expanded** dk (which X-Wing-the-scheme
//! forbids, but which production libraries — libcrux here — consume and may cache/transport),
//! Schmieg's break propagates straight through the omitted field. `ContextBound` absorbs
//! `pk_pq` directly, so its K-PK reduces to SHA3 collision-resistance **regardless** of the
//! component dk format.
//!
//! This is a *robustness / assumption-minimality* separation in the combiner's dependence on
//! the component dk format — NOT a binding-strength gap against seed-dk X-Wing, on which both
//! shapes attain the same MAL ceiling (see docs/BINDING_SECURITY.md §6.6).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use q_periapt_backends::{
    MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN,
};
use q_periapt_core::{combine, CombineInput, Kem, Profile};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

// FIPS-203 ML-KEM-768 expanded dk layout: dk_pke(1152) ‖ ek(1184) ‖ H(ek)(32) ‖ z(32).
const Z_OFFSET: usize = ML_KEM_768_SK_LEN - 32; // 2368: the implicit-rejection seed.

fn input<'a>(
    ss_pq: &'a [u8],
    pk_pq: &'a [u8],
    ct_pq: &'a [u8],
    common: (&'a [u8], &'a [u8], &'a [u8]),
) -> CombineInput<'a> {
    let (ss_trad, ct_trad, pk_trad) = common;
    CombineInput {
        suite_id: b"S",
        policy_version: 1,
        ss_pq,
        ss_trad,
        ct_pq,
        pk_pq,
        ct_trad,
        pk_trad,
        context: b"ctx",
    }
}

/// The lean (X-Wing-shaped) combiner's K-PK is *contingent* on the component dk format: over
/// the FIPS-203 expanded dk it collides; ContextBound (binds `pk_pq`) does not. This is a
/// robustness separation of the combiner shape — NOT a defeat of seed-dk X-Wing.
#[test]
fn lean_xwing_shape_over_expanded_dk_loses_k_pk_contextbound_keeps_it() {
    // (1) Two honest ML-KEM-768 key pairs.
    let (mut dk1, ek1) = MlKem768::generate([0x11; 64]);
    let (mut dk2, ek2) = MlKem768::generate([0x22; 64]);
    assert_ne!(ek1, ek2, "distinct public keys");

    // (2) The attack (Schmieg 2024/523): equalize ONLY the implicit-rejection seed `z` across
    //     two adversary-supplied EXPANDED dks. The (ek, H(ek)) fields stay distinct — the MAL
    //     model quantifies over adversary-chosen keys, and the expanded dk stores `z` as a free,
    //     substitutable field. (A seed-dk format would re-derive `z` and defeat this.)
    let z_shared = [0x5a_u8; 32];
    dk1[Z_OFFSET..].copy_from_slice(&z_shared);
    dk2[Z_OFFSET..].copy_from_slice(&z_shared);
    assert_ne!(
        dk1[..Z_OFFSET],
        dk2[..Z_OFFSET],
        "only z was equalized; ek and H(ek) remain distinct"
    );

    // (3) A garbage ciphertext fails re-encryption ⇒ both keys take the implicit-rejection
    //     branch K = J(z ‖ c). Same z, same c ⇒ **same ML-KEM shared secret under two distinct
    //     public keys** — Schmieg's MAL-BIND-K-PK precondition, on real libcrux.
    let ct_garbage = [0xab_u8; ML_KEM_768_CT_LEN];
    let mut ss1 = [0u8; 32];
    let mut ss2 = [0u8; 32];
    MlKem768.decapsulate(&dk1, &ct_garbage, &mut ss1).unwrap();
    MlKem768.decapsulate(&dk2, &ct_garbage, &mut ss2).unwrap();
    assert_ne!(
        ss1, [0u8; 32],
        "implicit-rejection secret is non-zero (real reject branch)"
    );
    assert_eq!(
        ss1, ss2,
        "Schmieg MAL-BIND-K-PK precondition: same ML-KEM K under ek1 != ek2"
    );

    // (4) Two hybrid transcripts agreeing on everything except the ML-KEM public key.
    let ss_trad = [0x33_u8; 32];
    let ct_trad = [0x44_u8; 32];
    let pk_trad = [0x55_u8; 32];
    let common = (&ss_trad[..], &ct_trad[..], &pk_trad[..]);

    // (5a) LEAN shape over EXPANDED dk (CompatXWing / X-Wing byte-exact combiner): omits pk_pq
    //      ⇒ SAME hybrid key for the two distinct public keys ⇒ K-PK collides for THIS shape
    //      over THIS dk format. (Seed-dk X-Wing is unaffected.)
    let lean1 = combine::<Sha3_256Xof>(
        Profile::CompatXWing,
        &input(&ss1, &ek1, &ct_garbage, common),
    )
    .unwrap();
    let lean2 = combine::<Sha3_256Xof>(
        Profile::CompatXWing,
        &input(&ss1, &ek2, &ct_garbage, common),
    )
    .unwrap();
    assert_eq!(
        lean1.as_bytes(),
        lean2.as_bytes(),
        "lean shape over expanded-dk collides (same K, different hybrid PK)"
    );

    // (5b) FULL-BINDING (ContextBound): absorbs pk_pq ⇒ the two public keys give DIFFERENT
    //      hybrid keys ⇒ K-PK holds under CR(SHA3) alone, independent of the component dk format.
    let cb1 = combine::<Sha3_256Xof>(
        Profile::ContextBound,
        &input(&ss1, &ek1, &ct_garbage, common),
    )
    .unwrap();
    let cb2 = combine::<Sha3_256Xof>(
        Profile::ContextBound,
        &input(&ss1, &ek2, &ct_garbage, common),
    )
    .unwrap();
    assert_ne!(
        cb1.as_bytes(),
        cb2.as_bytes(),
        "ContextBound binds pk_pq, so K-PK survives the expanded-dk witness"
    );

    eprintln!(
        "combiner dk-format-coupling witness (real libcrux ML-KEM-768):\n  \
         attack (Schmieg 2024/523): equal z, garbage ct -> same ML-KEM K under ek1 != ek2\n  \
         lean shape over expanded-dk (CompatXWing, omits pk_pq): K1 == K2  => K-PK collides\n  \
         full binding (ContextBound, binds pk_pq):               K1 != K2  => K-PK holds\n  \
         NB: correctly-implemented seed-dk X-Wing is NOT affected; this is a robustness\n  \
         separation of the combiner shape, not a break of X-Wing."
    );
}

/// X-Wing-style seed-dk keygen: a single 32-byte secret seed is expanded to the 64-byte ML-KEM
/// keygen seed `(d ‖ z)`. Because `d` (which fixes the public key) and the implicit-rejection seed
/// `z` BOTH come from the one seed, `z` is bound to the public key. (We model the expansion `zof`
/// with SHAKE-256; draft-connolly-cfrg-xwing-kem uses a different but equally collision-resistant
/// KDF — the injectivity argument is identical.)
fn seed_dk_keypair(seed32: [u8; 32]) -> ([u8; ML_KEM_768_SK_LEN], [u8; ML_KEM_768_PK_LEN]) {
    let mut dz = [0u8; 64];
    let mut xof = Shake256::default();
    xof.update(&seed32);
    xof.finalize_xof().read(&mut dz);
    MlKem768::generate(dz)
}

/// SEED-DK NEGATIVE CONTROL — the executable counterpart to the EasyCrypt lemma
/// `lean_kpk_seed_le_cr` and to the "the seed-dk format fixes both" half of Schmieg 2024/523.
///
/// The expanded-dk witness above wins only because it overwrites `z` as a free, stored field. Under
/// the seed-dk format that deployed X-Wing mandates, `z` is re-derived from the same 32-byte seed as
/// the public key, so two distinct public keys carry distinct `z` (equalizing them would require a
/// collision in the expansion). The garbage ciphertext therefore implicit-rejects to *different*
/// shared secrets: Schmieg's MAL-BIND-K-PK precondition `ss1 == ss2` is unreachable, the attack
/// vector is closed, and even the lean (X-Wing-shaped) combiner is not collided by it. This is the
/// concrete reason correctly-deployed X-Wing is unaffected; the *general* seed-dk K-PK safety is the
/// reduction `lean_kpk_seed_le_cr`, which this test does not replace, only witnesses one vector of.
#[test]
fn seed_dk_control_z_bound_to_key_closes_schmieg_vector() {
    // (1) Two honest key pairs from two DISTINCT 32-byte X-Wing seeds.
    let (dk1, ek1) = seed_dk_keypair([0x11; 32]);
    let (dk2, ek2) = seed_dk_keypair([0x22; 32]);
    assert_ne!(ek1, ek2, "distinct public keys");

    // (2) The field the expanded-dk attack overwrote by hand is now BOUND to the key: distinct
    //     seeds give distinct `z`. The adversary cannot set z1 == z2 without a SHAKE collision.
    assert_ne!(
        dk1[Z_OFFSET..],
        dk2[Z_OFFSET..],
        "seed-dk: z is re-derived from the keygen seed, so it differs across distinct public keys"
    );

    // (3) Same garbage ciphertext -> implicit rejection. Distinct z -> DISTINCT ML-KEM shared
    //     secrets: the Schmieg precondition (ss1 == ss2) is NOT met.
    let ct_garbage = [0xab_u8; ML_KEM_768_CT_LEN];
    let mut ss1 = [0u8; 32];
    let mut ss2 = [0u8; 32];
    MlKem768.decapsulate(&dk1, &ct_garbage, &mut ss1).unwrap();
    MlKem768.decapsulate(&dk2, &ct_garbage, &mut ss2).unwrap();
    assert_ne!(
        ss1, ss2,
        "seed-dk defeats Schmieg: distinct z -> distinct implicit-rejection secret under ek1 != ek2"
    );

    // (4) With the attack vector closed, even the LEAN shape is not collided by it: the ML-KEM leg
    //     already separates the two transcripts, so the hybrid keys differ without binding pk_pq.
    let ss_trad = [0x33_u8; 32];
    let ct_trad = [0x44_u8; 32];
    let pk_trad = [0x55_u8; 32];
    let common = (&ss_trad[..], &ct_trad[..], &pk_trad[..]);
    let lean1 = combine::<Sha3_256Xof>(
        Profile::CompatXWing,
        &input(&ss1, &ek1, &ct_garbage, common),
    )
    .unwrap();
    let lean2 = combine::<Sha3_256Xof>(
        Profile::CompatXWing,
        &input(&ss2, &ek2, &ct_garbage, common),
    )
    .unwrap();
    assert_ne!(
        lean1.as_bytes(),
        lean2.as_bytes(),
        "seed-dk closes Schmieg's vector: ss already differs, so the lean keys differ too"
    );

    eprintln!(
        "seed-dk negative control (real libcrux ML-KEM-768, z derived from a 32-byte seed):\n  \
         distinct seeds -> distinct z -> distinct implicit-rejection ss under ek1 != ek2\n  \
         Schmieg precondition ss1 == ss2 is UNREACHABLE -> the expanded-dk attack vector is closed\n  \
         even the lean shape (CompatXWing) is not collided by it; deployed seed-dk X-Wing is safe."
    );
}
