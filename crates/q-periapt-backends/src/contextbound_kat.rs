//! ContextBound combiner reference vectors (positive KAT, doubly verified).
//!
//! CompatXWing is pinned byte-for-byte by the X-Wing draft KAT; this is the
//! corresponding positive KAT for **ContextBound**. Each `(fields) -> K` vector is
//! verified two structurally separate ways: (1) against our `combine()` (`sha3` over the
//! `absorb_lp` loop), and (2) against a hand-written recomputation using the same
//! SHA3-256 primitive crate over a canonical 8-byte big-endian length-prefixed encoding
//! per `docs/COMBINER_SPEC.md` §3 / `docs/BINDING_SECURITY.md` §3.2. So the vectors
//! validate the construction against the spec, not merely against itself, and pin it
//! against silent encoding/field-order/domain changes.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::Sha3_256Xof;
use q_periapt_core::{combine, CombineInput, Profile, DOMAIN};
use sha3::{Digest, Sha3_256};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Length-prefix one field exactly as `q_periapt_core::absorb_lp` does.
fn lp(h: &mut Sha3_256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// Structurally separate canonical recompute of the ContextBound key (spec §3.2),
/// using a hand-written encoder — no shared composition code with the combiner beyond
/// the `DOMAIN` constant and the field order it pins. Primitive independence is supplied
/// by the externally generated pinned vectors, not by this helper's shared `sha3` crate.
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

struct Case<'a> {
    suite: &'a [u8],
    ver: u32,
    ss_pq: &'a [u8],
    ss_trad: &'a [u8],
    ct_pq: &'a [u8],
    pk_pq: &'a [u8],
    ct_trad: &'a [u8],
    pk_trad: &'a [u8],
    ctx: &'a [u8],
    k: &'a str,
}

#[test]
fn contextbound_reference_vectors() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let c = [0x33u8; 32];
    let d = [0x44u8; 32];
    let ct_pq_real = [0x42u8; 1088];
    let pk_pq_real = [0x37u8; 1184];

    let cases = [
        // 1. Typical: all 32-byte components, real suite id, short context.
        Case {
            suite: b"ML-KEM-768+X25519",
            ver: 1,
            ss_pq: &a,
            ss_trad: &b,
            ct_pq: &c,
            pk_pq: &d,
            ct_trad: &a,
            pk_trad: &b,
            ctx: b"q-periapt/v1/ctx",
            k: "f0a32d28860bd9d8aaab4faf4c859205924b27651a68e70042abe908fef5da85",
        },
        // 2. Empty optional component fields (length-0, prefix only).
        Case {
            suite: b"S",
            ver: 0,
            ss_pq: &a,
            ss_trad: &b,
            ct_pq: &[],
            pk_pq: &[],
            ct_trad: &[],
            pk_trad: &[],
            ctx: b"x",
            k: "98476bc6033b9f04d50e48b2298011c25a38d3f5efe0914b18670623e576c4bc",
        },
        // 3. Realistic ML-KEM-768 ciphertext/pubkey sizes.
        Case {
            suite: b"ML-KEM-768+X25519",
            ver: 2,
            ss_pq: &a,
            ss_trad: &b,
            ct_pq: &ct_pq_real,
            pk_pq: &pk_pq_real,
            ct_trad: &c,
            pk_trad: &d,
            ctx: b"handshake-transcript",
            k: "6c28e6a465773c6c7969349a2ca827792799591b94c8fa23927d18b0cb1cf9f3",
        },
        // 4a / 4b. Collision PAIR: identical EXCEPT the ss_pq|ss_trad boundary, so the
        // naive (no-prefix) transcript concatenation is byte-identical ("...ABX...")
        // — only the fixed-width length prefix keeps the derived keys distinct. The
        // post-loop assertions below make this disambiguation load-bearing here.
        Case {
            suite: b"S",
            ver: 9,
            ss_pq: b"AB",
            ss_trad: b"X",
            ct_pq: b"C",
            pk_pq: b"D",
            ct_trad: b"E",
            pk_trad: b"F",
            ctx: b"ctx",
            k: "572cbe29ec15781bb54103465c551839dffbfa17346f3a679e8f483a2b1d49d6",
        },
        Case {
            suite: b"S",
            ver: 9,
            ss_pq: b"A",
            ss_trad: b"BX",
            ct_pq: b"C",
            pk_pq: b"D",
            ct_trad: b"E",
            pk_trad: b"F",
            ctx: b"ctx",
            k: "8fa3ad2f914b5838586f2b7f881377f26c56dd2de75b50de352dffec4ce2fcad",
        },
        // 6. Empty suite_id, max policy version, long context.
        Case {
            suite: b"",
            ver: 0xFFFF_FFFF,
            ss_pq: &a,
            ss_trad: &b,
            ct_pq: &c,
            pk_pq: &d,
            ct_trad: &a,
            pk_trad: &b,
            ctx: &[0x5au8; 200],
            k: "043a5998baccd1462ad2e55cf14a64c58d6fca254b880f193d3fc0b18833f069",
        },
    ];

    let mut ks = Vec::new();
    for (i, t) in cases.iter().enumerate() {
        let input = CombineInput {
            suite_id: t.suite,
            policy_version: t.ver,
            ss_pq: t.ss_pq,
            ss_trad: t.ss_trad,
            ct_pq: t.ct_pq,
            pk_pq: t.pk_pq,
            ct_trad: t.ct_trad,
            pk_trad: t.pk_trad,
            context: t.ctx,
        };
        let k_ours = *combine::<Sha3_256Xof>(Profile::ContextBound, &input)
            .unwrap()
            .as_bytes();
        let k_indep = independent_k(
            t.suite, t.ver, t.ss_pq, t.ss_trad, t.ct_pq, t.pk_pq, t.ct_trad, t.pk_trad, t.ctx,
        );
        // (1) combiner agrees with the independent canonical recompute (spec-correct).
        assert_eq!(
            k_ours, k_indep,
            "case {i}: combiner != independent canonical recompute"
        );
        // (2) pinned reference vector (golden master).
        assert_eq!(
            &k_ours[..],
            hex(t.k).as_slice(),
            "case {i}: != pinned reference vector"
        );
        ks.push(k_ours);
    }

    // (3) Injectivity, made load-bearing here. The pair (cases 3 and 4) has a
    // byte-identical NAIVE (no-length-prefix) transcript concatenation, so without
    // the fixed-width length prefix the combiner would derive the SAME key — the
    // prefix is exactly what keeps them distinct (cf. the `encode_inj` EasyCrypt
    // lemma and the proptest boundary-shift property).
    let naive = |t: &Case| {
        let mut v = Vec::new();
        v.extend_from_slice(t.suite);
        v.extend_from_slice(&t.ver.to_be_bytes());
        v.extend_from_slice(t.ss_pq);
        v.extend_from_slice(t.ss_trad);
        v.extend_from_slice(t.ct_pq);
        v.extend_from_slice(t.pk_pq);
        v.extend_from_slice(t.ct_trad);
        v.extend_from_slice(t.pk_trad);
        v.extend_from_slice(t.ctx);
        v
    };
    assert_eq!(
        naive(&cases[3]),
        naive(&cases[4]),
        "collision-pair precondition: naive concatenations must be identical"
    );
    assert_ne!(
        ks[3], ks[4],
        "length prefix must disambiguate the naive-concat collision pair"
    );
}
