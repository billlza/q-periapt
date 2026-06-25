//! Source→binary CT gap probe for the **HQC** backend (PQClean C via `pqcrypto-hqc`) — the
//! suite's UNAUDITED, documented-cache-timing code-based KEM.
//!
//! Contrast with `ct_decaps_gap` (ML-KEM, HACL*-verified, probe = 0 gap): HQC is **expected to
//! flag**, which (a) demonstrates the gap probe is a real *discriminator* — clean vs leaky in
//! one framework, so ML-KEM's 0 is not a vacuous "the tool always says 0" — and (b) shows the
//! suite's per-backend CT gating (HQC is feature-gated and `C2PRI = false`, forcing ContextBound)
//! is *necessary*, not theatre.
//!
//! Modes (argv[1]):
//!   whole   mark the full sk (incl. the embedded public key)   → baseline
//!   prefix  mark only sk[0..56] (SK_LEN−PK_LEN, the genuinely-secret prefix, no embedded pk)
//!           → flags here are REAL secret-dependent leakage (the decoder), not embedded-pk noise
//!
//! Run under `valgrind --track-origins=yes` and inspect the flagged *function names* (HQC decoder
//! functions = a genuine source→binary leak in this primitive).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use core::ffi::c_void;
use core::hint::black_box;

use q_periapt_backends::Hqc128;
use q_periapt_core::Kem;

#[link(name = "qperiapt_ct_shim", kind = "static")]
extern "C" {
    fn qperiapt_ct_mark_undefined(p: *mut c_void, n: usize);
}
fn mark_secret(b: &[u8]) {
    // SAFETY: valid pointer+len owned by `b`, handed only to the Valgrind client request.
    unsafe { qperiapt_ct_mark_undefined(b.as_ptr() as *mut c_void, b.len()) };
}

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "whole".to_string());

    let (sk, pk) = Hqc128::generate();
    let mut ct = [0u8; Hqc128::CT_LEN];
    let mut ss = [0u8; Hqc128::SS_LEN];
    Hqc128.encapsulate(&pk, &[], &mut ct, &mut ss).unwrap();

    let sk_m = sk;
    // PQClean HQC sk = <secret prefix> ‖ <embedded pk>; the prefix is the genuinely-secret part.
    let prefix = Hqc128::SK_LEN - Hqc128::PK_LEN;
    match mode.as_str() {
        "prefix" => mark_secret(&sk_m[0..prefix]),
        _ => mark_secret(&sk_m[..]),
    }

    let mut out = [0u8; Hqc128::SS_LEN];
    Hqc128.decapsulate(&sk_m, &ct, &mut out).unwrap();
    black_box(out);
    eprintln!("hqc {mode}: decapsulated over marked sk — run under Memcheck to localize leaks");
}
