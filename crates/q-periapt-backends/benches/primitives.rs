#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]
//! Primitive + hybrid KEM micro-benchmarks: keygen / encapsulate / decapsulate across the
//! ML-KEM family and X25519, plus the full ContextBound / CompatXWing hybrid. Real numbers for
//! the paper's performance table. `cargo bench -p q-periapt-backends --bench primitives`.
use std::time::Duration;

use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
};
use q_periapt_backends::{
    MlKem1024, MlKem512, MlKem768, MlKem768XWingSeed, Sha3_256Xof, ML_KEM_1024_CT_LEN,
    ML_KEM_512_CT_LEN, ML_KEM_768_CT_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{Kem, Profile};
use q_periapt_kem::HybridKem;

macro_rules! bench_mlkem {
    ($g:expr, $tag:literal, $T:ty, $ct:expr) => {{
        let (dk, ek) = <$T>::generate([7u8; 64]);
        let mut ct = [0u8; $ct];
        let mut ss = [0u8; 32];
        $g.bench_function(concat!($tag, "/keygen"), |b| {
            b.iter(|| black_box(<$T>::generate(black_box([7u8; 64]))))
        });
        $g.bench_function(concat!($tag, "/encaps"), |b| {
            b.iter(|| {
                <$T>::default()
                    .encapsulate(black_box(&ek), &[3u8; 32], &mut ct, &mut ss)
                    .unwrap();
                black_box(ss)
            })
        });
        <$T>::default()
            .encapsulate(&ek, &[3u8; 32], &mut ct, &mut ss)
            .unwrap();
        $g.bench_function(concat!($tag, "/decaps"), |b| {
            b.iter(|| {
                <$T>::default()
                    .decapsulate(black_box(&dk), black_box(&ct), &mut ss)
                    .unwrap();
                black_box(ss)
            })
        });
    }};
}

fn primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("kem");
    g.measurement_time(Duration::from_secs(2)).sample_size(60);
    bench_mlkem!(g, "ML-KEM-512", MlKem512, ML_KEM_512_CT_LEN);
    bench_mlkem!(g, "ML-KEM-768", MlKem768, ML_KEM_768_CT_LEN);
    bench_mlkem!(g, "ML-KEM-1024", MlKem1024, ML_KEM_1024_CT_LEN);
    // X25519 (32-byte keygen seed; exercised in the full hybrid below).
    let (xsk, xpk) = X25519::generate([9u8; 32]);
    let mut xct = [0u8; X25519_LEN];
    let mut xss = [0u8; 32];
    g.bench_function("X25519/keygen", |b| {
        b.iter(|| black_box(X25519::generate(black_box([9u8; 32]))))
    });
    g.bench_function("X25519/encaps", |b| {
        b.iter(|| {
            X25519
                .encapsulate(black_box(&xpk), &[5u8; 32], &mut xct, &mut xss)
                .unwrap();
            black_box(xss)
        })
    });
    X25519
        .encapsulate(&xpk, &[5u8; 32], &mut xct, &mut xss)
        .unwrap();
    g.bench_function("X25519/decaps", |b| {
        b.iter(|| {
            X25519
                .decapsulate(black_box(&xsk), black_box(&xct), &mut xss)
                .unwrap();
            black_box(xss)
        })
    });
    g.finish();
}

struct HybridBenchCase<'a, P: Kem> {
    tag: &'a str,
    pq: &'a P,
    sk_pq: &'a [u8],
    pk_pq: &'a [u8],
    profile: Profile,
    suite_id: &'a [u8],
    policy_version: u32,
    context: &'a [u8],
}

fn bench_hybrid_case<P: Kem>(g: &mut BenchmarkGroup<'_, WallTime>, case: HybridBenchCase<'_, P>) {
    let HybridBenchCase {
        tag,
        pq,
        sk_pq,
        pk_pq,
        profile,
        suite_id,
        policy_version,
        context,
    } = case;
    let (sk_tr, pk_tr) = X25519::generate([9u8; 32]);
    let trad = X25519;
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(pq, &trad, profile, suite_id, policy_version)
        .expect("benchmark case must use a backend admitted by its profile");
    let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
    let mut ct_tr = [0u8; X25519_LEN];
    g.bench_function(format!("{tag}/encaps"), |b| {
        b.iter(|| {
            black_box(
                kem.encapsulate(
                    pk_pq, &pk_tr, context, &[1u8; 32], &[2u8; 32], &mut ct_pq, &mut ct_tr,
                )
                .unwrap(),
            )
        })
    });
    let _ = kem
        .encapsulate(
            pk_pq, &pk_tr, context, &[1u8; 32], &[2u8; 32], &mut ct_pq, &mut ct_tr,
        )
        .unwrap();
    g.bench_function(format!("{tag}/decaps"), |b| {
        b.iter(|| {
            black_box(
                kem.decapsulate(sk_pq, &ct_pq, pk_pq, &sk_tr, &ct_tr, &pk_tr, context)
                    .unwrap(),
            )
        })
    });
}

fn hybrid(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid");
    g.measurement_time(Duration::from_secs(2)).sample_size(60);

    let expanded_pq = MlKem768;
    let (expanded_sk, expanded_pk) = MlKem768::generate([7u8; 64]);
    bench_hybrid_case(
        &mut g,
        HybridBenchCase {
            tag: "ContextBound",
            pq: &expanded_pq,
            sk_pq: &expanded_sk,
            pk_pq: &expanded_pk,
            profile: Profile::ContextBound,
            suite_id: b"suite",
            policy_version: 1,
            context: b"ctx",
        },
    );

    // CompatXWing deliberately rejects imported/expanded ML-KEM keys. Benchmark the
    // policy-admitted X-Wing seed-dk backend instead of weakening that invariant.
    let seed_pq = MlKem768XWingSeed;
    let (seed_sk, seed_pk) = MlKem768XWingSeed::generate([7u8; 32]);
    bench_hybrid_case(
        &mut g,
        HybridBenchCase {
            tag: "CompatXWing",
            pq: &seed_pq,
            sk_pq: &seed_sk,
            pk_pq: &seed_pk,
            profile: Profile::CompatXWing,
            suite_id: b"",
            policy_version: 0,
            context: b"",
        },
    );

    g.finish();
}

criterion_group!(benches, primitives, hybrid);
criterion_main!(benches);
