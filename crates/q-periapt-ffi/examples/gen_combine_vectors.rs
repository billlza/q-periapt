//! Generates `bindings/contextbound-vectors.txt` — one vector per line:
//! `<profile> <input_hex> <k_hex>`, where `input` is the nine-field 8-byte-BE
//! length-prefixed transport consumed by the internal Rust combiner. The vector is
//! conformance evidence only: ABI2 product bindings deliberately do not export
//! `q_periapt_combine` or expose a deterministic product bypass.
//!
//! Run: `cargo run -p q-periapt-ffi --example gen_combine_vectors > bindings/contextbound-vectors.txt`

use q_periapt_backends::Sha3_256Xof;
use q_periapt_core::{combine, CombineInput, Profile};

fn lp(b: &mut Vec<u8>, f: &[u8]) {
    b.extend_from_slice(&(f.len() as u64).to_be_bytes());
    b.extend_from_slice(f);
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
fn emit(
    profile: Profile,
    pcode: u8,
    suite: &[u8],
    ver: u32,
    ss_pq: &[u8],
    ss_trad: &[u8],
    ct_pq: &[u8],
    pk_pq: &[u8],
    ct_trad: &[u8],
    pk_trad: &[u8],
    ctx: &[u8],
) {
    let mut input = Vec::new();
    lp(&mut input, suite);
    lp(&mut input, &ver.to_be_bytes());
    lp(&mut input, ss_pq);
    lp(&mut input, ss_trad);
    lp(&mut input, ct_pq);
    lp(&mut input, pk_pq);
    lp(&mut input, ct_trad);
    lp(&mut input, pk_trad);
    lp(&mut input, ctx);
    let ci = CombineInput {
        suite_id: suite,
        policy_version: ver,
        ss_pq,
        ss_trad,
        ct_pq,
        pk_pq,
        ct_trad,
        pk_trad,
        context: ctx,
    };
    let k = combine::<Sha3_256Xof>(profile, &ci).expect("combine should succeed for these inputs");
    println!("{pcode} {} {}", hexs(&input), hexs(k.as_bytes()));
}

fn main() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let c = [0x33u8; 32];
    let d = [0x44u8; 32];
    let ct_pq = [0x42u8; 1088];
    let pk_pq = [0x37u8; 1184];

    // ContextBound (mirrors crates/q-periapt-backends/src/contextbound_kat.rs cases).
    let cb = Profile::ContextBound;
    emit(
        cb,
        2,
        b"ML-KEM-768+X25519",
        1,
        &a,
        &b,
        &c,
        &d,
        &a,
        &b,
        b"q-periapt/v1/ctx",
    );
    emit(cb, 2, b"S", 0, &a, &b, &[], &[], &[], &[], b"x");
    emit(
        cb,
        2,
        b"ML-KEM-768+X25519",
        2,
        &a,
        &b,
        &ct_pq,
        &pk_pq,
        &c,
        &d,
        b"handshake-transcript",
    );
    // The injectivity collision pair (identical naive concat, distinct keys).
    emit(cb, 2, b"S", 9, b"AB", b"X", b"C", b"D", b"E", b"F", b"ctx");
    emit(cb, 2, b"S", 9, b"A", b"BX", b"C", b"D", b"E", b"F", b"ctx");
    // CompatXWing (its four absorbed fields are the 32-byte ss/ct/pk; others ignored).
    emit(
        Profile::CompatXWing,
        1,
        b"",
        0,
        &a,
        &b,
        &[],
        &[],
        &c,
        &d,
        b"",
    );
}
