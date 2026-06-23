#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    missing_docs
)]
//! Combiner micro-benchmark.
//!
//! The CompatXWing profile is X-Wing byte-for-byte, so this isolates the ONLY
//! thing an X-Wing-compatible suite controls: the combiner *implementation*. All
//! three paths below hash the identical 134-byte single-block input and produce
//! byte-identical output (asserted at startup), so the only variable is cost:
//!
//!   * `ours_libcrux_inline_zero_alloc` — our combiner: libcrux one-shot SHA3-256
//!     over a stack-staged single block, **no heap allocation**.
//!   * `xwing_streaming_rustcrypto`     — the de-facto reference X-Wing combiner
//!     shape: a streaming SHA3-256 sponge (RustCrypto `sha3`), 5 incremental
//!     `update`s + finalize.
//!   * `xwing_oneshot_heap_vec`         — one-shot over a heap `Vec` (the path we
//!     replaced), to show the allocation cost that was removed.
//!
//! ContextBound (deliberately heavier) is benched separately for reference.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use q_periapt_backends::Sha3_256Xof;
use q_periapt_core::{combine, CombineInput, Profile};
use sha3::{Digest, Sha3_256};

/// X-Wing combiner label `\.//^\` (draft-connolly-cfrg-xwing-kem).
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

fn fixed32(add: u8, xor: u8) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(add) ^ xor;
    }
    o
}

/// Reference X-Wing combiner: streaming SHA3-256, 5 incremental updates.
fn xwing_streaming(ss_pq: &[u8], ss_trad: &[u8], ct_trad: &[u8], pk_trad: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ss_pq);
    h.update(ss_trad);
    h.update(ct_trad);
    h.update(pk_trad);
    h.update(XWING_LABEL);
    h.finalize().into()
}

/// Allocating one-shot path (the heap `Vec` staging we removed), RustCrypto SHA3.
fn xwing_oneshot_heap(ss_pq: &[u8], ss_trad: &[u8], ct_trad: &[u8], pk_trad: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(ss_pq);
    buf.extend_from_slice(ss_trad);
    buf.extend_from_slice(ct_trad);
    buf.extend_from_slice(pk_trad);
    buf.extend_from_slice(&XWING_LABEL);
    Sha3_256::digest(&buf).into()
}

/// Single-block stack one-shot: stage the 134-byte block on the stack (no alloc)
/// and hash it in ONE RustCrypto SHA3-256 call (no 5-update sponge bookkeeping).
fn xwing_stack_oneshot_rc(
    ss_pq: &[u8],
    ss_trad: &[u8],
    ct_trad: &[u8],
    pk_trad: &[u8],
) -> [u8; 32] {
    let mut buf = [0u8; 134];
    buf[..32].copy_from_slice(ss_pq);
    buf[32..64].copy_from_slice(ss_trad);
    buf[64..96].copy_from_slice(ct_trad);
    buf[96..128].copy_from_slice(pk_trad);
    buf[128..].copy_from_slice(&XWING_LABEL);
    Sha3_256::digest(buf).into()
}

fn bench_compat(c: &mut Criterion) {
    let ss_pq = fixed32(0x00, 0x00);
    let ss_trad = fixed32(0x00, 0x55);
    let ct_trad = fixed32(0x80, 0x00);
    let pk_trad = fixed32(0x00, 0xAA);

    let input = CombineInput {
        suite_id: b"",
        policy_version: 0,
        ss_pq: &ss_pq,
        ss_trad: &ss_trad,
        ct_pq: &[],
        pk_pq: &[],
        ct_trad: &ct_trad,
        pk_trad: &pk_trad,
        context: &[],
    };

    // Prove all three paths are byte-identical (a fair comparison, same output).
    let ours = *combine::<Sha3_256Xof>(Profile::CompatXWing, &input)
        .unwrap()
        .as_bytes();
    let stream = xwing_streaming(&ss_pq, &ss_trad, &ct_trad, &pk_trad);
    let heap = xwing_oneshot_heap(&ss_pq, &ss_trad, &ct_trad, &pk_trad);
    let stack_rc = xwing_stack_oneshot_rc(&ss_pq, &ss_trad, &ct_trad, &pk_trad);
    assert_eq!(ours, stream, "ours != streaming X-Wing combiner");
    assert_eq!(ours, heap, "ours != one-shot heap combiner");
    assert_eq!(ours, stack_rc, "ours != stack one-shot combiner");

    let mut g = c.benchmark_group("compat_xwing_combiner_134B");
    g.bench_function("ours_libcrux_inline_zero_alloc", |b| {
        b.iter(|| {
            black_box(combine::<Sha3_256Xof>(Profile::CompatXWing, black_box(&input)).unwrap())
        });
    });
    g.bench_function("xwing_streaming_rustcrypto", |b| {
        b.iter(|| {
            black_box(xwing_streaming(
                black_box(&ss_pq),
                &ss_trad,
                &ct_trad,
                &pk_trad,
            ))
        });
    });
    g.bench_function("xwing_oneshot_heap_vec", |b| {
        b.iter(|| {
            black_box(xwing_oneshot_heap(
                black_box(&ss_pq),
                &ss_trad,
                &ct_trad,
                &pk_trad,
            ))
        });
    });
    g.bench_function("stack_oneshot_rustcrypto", |b| {
        b.iter(|| {
            black_box(xwing_stack_oneshot_rc(
                black_box(&ss_pq),
                &ss_trad,
                &ct_trad,
                &pk_trad,
            ))
        });
    });
    g.finish();
}

fn bench_contextbound(c: &mut Criterion) {
    // Realistic ML-KEM-768 sizes so the cost reflects the real transcript.
    let ss = fixed32(0x01, 0x00);
    let ct_pq = vec![0x42u8; 1088];
    let pk_pq = vec![0x37u8; 1184];
    let ctx = *b"q-periapt/v1/bench-context";
    let input = CombineInput {
        suite_id: b"ML-KEM-768+X25519",
        policy_version: 1,
        ss_pq: &ss,
        ss_trad: &ss,
        ct_pq: &ct_pq,
        pk_pq: &pk_pq,
        ct_trad: &ss,
        pk_trad: &ss,
        context: &ctx,
    };
    c.benchmark_group("contextbound_combiner_2.5KB")
        .bench_function("ours_libcrux", |b| {
            b.iter(|| {
                black_box(combine::<Sha3_256Xof>(Profile::ContextBound, black_box(&input)).unwrap())
            });
        });
}

criterion_group!(benches, bench_compat, bench_contextbound);
criterion_main!(benches);
