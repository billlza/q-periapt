//! Best-effort dudect-style timing-leakage report for ML-KEM-768 decapsulation.
//!
//! REPORT MODE: prints the Welch t-statistic and exits 0. It does **not** gate
//! CI — shared cloud runners are too noisy for a hard threshold (see
//! `ctstats/README.md`). On *dedicated, quiesced hardware*, `|t| > 4.5` between
//! the fixed-valid and random-invalid ciphertext classes indicates a leak.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use pqt_backends::{MlKem768, ML_KEM_768_CT_LEN};
use pqt_core::Kem;
use pqt_ctstats::welch_t;
use std::time::Instant;

fn main() {
    let (sk, pk) = MlKem768::generate([1u8; 64]);
    let kem = MlKem768;
    let mut ct = [0u8; ML_KEM_768_CT_LEN];
    let mut ss = [0u8; 32];
    kem.encapsulate(&pk, &[2u8; 32], &mut ct, &mut ss).unwrap();

    let n: usize = 50_000;
    let mut ta = Vec::with_capacity(n); // class A: fixed valid ciphertext
    let mut tb = Vec::with_capacity(n); // class B: random (invalid) ciphertext
    let mut out = [0u8; 32];
    let mut seed = 0x0123_4567_89ab_cdefu64;

    for _ in 0..2_000 {
        let _ = kem.decapsulate(&sk, &ct, &mut out); // warm up
    }

    for _ in 0..n {
        let t0 = Instant::now();
        let _ = kem.decapsulate(&sk, &ct, &mut out);
        ta.push(t0.elapsed().as_nanos() as f64);

        let mut bad = ct;
        for byte in bad.iter_mut() {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (seed >> 33) as u8;
        }
        let t1 = Instant::now();
        let _ = kem.decapsulate(&sk, &bad, &mut out);
        tb.push(t1.elapsed().as_nanos() as f64);
    }

    let t = welch_t(&ta, &tb);
    let verdict = if t.abs() > 4.5 {
        "LEAK SUSPECTED (re-run on dedicated hardware before believing it)"
    } else {
        "no leak detected at this sample size"
    };
    println!("dudect ML-KEM-768 decaps: n={n} welch_t={t:.3} -> {verdict}");
    println!("(report mode: informational, not a CI gate; see ctstats/README.md)");
}
