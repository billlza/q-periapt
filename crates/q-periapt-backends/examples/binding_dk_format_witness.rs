//! Standalone, reviewer-runnable witness for the paper's combiner dk-format-coupling separation
//! (Theorem 1, item 5; EasyCrypt `xwing_kpk_broken` / `lean_kpk_seed_le_cr`). Run with:
//!
//! ```sh
//! cargo run -p q-periapt-backends --example binding_dk_format_witness
//! ```
//!
//! It prints both halves against **real libcrux ML-KEM-768**:
//!   * EXPANDED-dk witness — Schmieg's free-`z` substitution makes two distinct public keys share
//!     one ML-KEM shared secret, so the lean (X-Wing-shaped) `CompatXWing` combiner collides (loses
//!     MAL-BIND-K-PK) while `ContextBound` — which binds `pk_pq` — does not.
//!   * SEED-dk negative control — when `z` is re-derived from a 32-byte seed (as deployed X-Wing
//!     mandates), distinct keys carry distinct `z`, the shared secrets differ, and the attack vector
//!     is closed. This is why correctly-deployed X-Wing is NOT affected.
//!
//! This reproduces published prior art (Schmieg eprint 2024/523; Chempat eprint 2025/1416; CDM
//! CCS'24). It is a robustness / assumption-minimality separation of the *combiner shape* over the
//! component dk format — it is NOT a break of X-Wing as standardized.
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
const Z_OFFSET: usize = ML_KEM_768_SK_LEN - 32;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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

/// X-Wing-style seed-dk: 32-byte seed -> SHAKE-256 -> 64-byte (d ‖ z) -> ML-KEM keygen, so `z` is
/// bound to the same seed as the public key.
fn seed_dk_keypair(seed32: [u8; 32]) -> ([u8; ML_KEM_768_SK_LEN], [u8; ML_KEM_768_PK_LEN]) {
    let mut dz = [0u8; 64];
    let mut xof = Shake256::default();
    xof.update(&seed32);
    xof.finalize_xof().read(&mut dz);
    MlKem768::generate(dz)
}

fn main() {
    let common = (&[0x33u8; 32][..], &[0x44u8; 32][..], &[0x55u8; 32][..]);
    let ct_garbage = [0xab_u8; ML_KEM_768_CT_LEN];

    // ---- EXPANDED-dk witness: the free-z substitution (Schmieg 2024/523) ---------------------
    println!("== EXPANDED-dk witness (Schmieg free-z substitution) ==");
    let (mut dk1, ek1) = MlKem768::generate([0x11; 64]);
    let (mut dk2, ek2) = MlKem768::generate([0x22; 64]);
    println!(
        "  ek1[..8]   = {}…  ek2[..8] = {}…  (distinct: {})",
        hex(&ek1[..8]),
        hex(&ek2[..8]),
        ek1 != ek2
    );

    let z_shared = [0x5a_u8; 32];
    dk1[Z_OFFSET..].copy_from_slice(&z_shared);
    dk2[Z_OFFSET..].copy_from_slice(&z_shared);
    println!(
        "  overwrote z := {}…  on both dks (ek/H(ek) left distinct)",
        hex(&z_shared[..8])
    );

    let (mut e1, mut e2) = ([0u8; 32], [0u8; 32]);
    MlKem768.decapsulate(&dk1, &ct_garbage, &mut e1).unwrap();
    MlKem768.decapsulate(&dk2, &ct_garbage, &mut e2).unwrap();
    println!("  ss1 = {}\n  ss2 = {}", hex(&e1), hex(&e2));
    println!(
        "  -> ss1 == ss2 : {}  (Schmieg precondition met under ek1 != ek2)",
        e1 == e2
    );

    let lean1 =
        combine::<Sha3_256Xof>(Profile::CompatXWing, &input(&e1, &ek1, &ct_garbage, common))
            .unwrap();
    let lean2 =
        combine::<Sha3_256Xof>(Profile::CompatXWing, &input(&e1, &ek2, &ct_garbage, common))
            .unwrap();
    let cb1 = combine::<Sha3_256Xof>(
        Profile::ContextBound,
        &input(&e1, &ek1, &ct_garbage, common),
    )
    .unwrap();
    let cb2 = combine::<Sha3_256Xof>(
        Profile::ContextBound,
        &input(&e1, &ek2, &ct_garbage, common),
    )
    .unwrap();
    println!(
        "  lean/CompatXWing (omits pk_pq): K1 == K2 : {}  <- K-PK COLLIDES over expanded-dk",
        lean1.as_bytes() == lean2.as_bytes()
    );
    println!(
        "  ContextBound     (binds pk_pq): K1 == K2 : {}  <- K-PK HOLDS (CR(SHA3))\n",
        cb1.as_bytes() == cb2.as_bytes()
    );

    // ---- SEED-dk negative control: z bound to the key closes the vector ----------------------
    println!("== SEED-dk negative control (z derived from a 32-byte seed, as deployed X-Wing) ==");
    let (sdk1, sek1) = seed_dk_keypair([0x11; 32]);
    let (sdk2, sek2) = seed_dk_keypair([0x22; 32]);
    println!(
        "  ek1[..8]   = {}…  ek2[..8] = {}…  (distinct: {})",
        hex(&sek1[..8]),
        hex(&sek2[..8]),
        sek1 != sek2
    );
    println!(
        "  z1 = {}…  z2 = {}…  (distinct: {})  <- cannot be equalized without a SHAKE collision",
        hex(&sdk1[Z_OFFSET..Z_OFFSET + 8]),
        hex(&sdk2[Z_OFFSET..Z_OFFSET + 8]),
        sdk1[Z_OFFSET..] != sdk2[Z_OFFSET..]
    );

    let (mut s1, mut s2) = ([0u8; 32], [0u8; 32]);
    MlKem768.decapsulate(&sdk1, &ct_garbage, &mut s1).unwrap();
    MlKem768.decapsulate(&sdk2, &ct_garbage, &mut s2).unwrap();
    println!("  ss1 = {}\n  ss2 = {}", hex(&s1), hex(&s2));
    println!(
        "  -> ss1 == ss2 : {}  (Schmieg precondition UNREACHABLE)",
        s1 == s2
    );

    let sl1 = combine::<Sha3_256Xof>(
        Profile::CompatXWing,
        &input(&s1, &sek1, &ct_garbage, common),
    )
    .unwrap();
    let sl2 = combine::<Sha3_256Xof>(
        Profile::CompatXWing,
        &input(&s2, &sek2, &ct_garbage, common),
    )
    .unwrap();
    println!(
        "  lean/CompatXWing: K1 == K2 : {}  <- vector closed, lean NOT collided\n",
        sl1.as_bytes() == sl2.as_bytes()
    );

    println!("Summary: the lean shape's MAL-BIND-K-PK is contingent on the component dk format");
    println!("(broken over expanded-dk, safe over seed-dk); ContextBound binds pk_pq and is K-PK-");
    println!("binding regardless. Deployed seed-dk X-Wing is unaffected — this is a robustness");
    println!("separation of the combiner shape, not a break of X-Wing.");
}
