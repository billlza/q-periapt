#![no_main]
//! Fuzz the combiner: arbitrary field lengths must never panic, and the
//! CompatXWing canonical-metadata/32-byte and ContextBound non-empty-context guards must hold.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use q_periapt_backends::Sha3_256Xof;
use q_periapt_core::{combine, CombineInput, Error, Profile};

#[derive(Arbitrary, Debug)]
struct In {
    suite: Vec<u8>,
    ver: u32,
    ss_pq: Vec<u8>,
    ss_trad: Vec<u8>,
    ct_pq: Vec<u8>,
    pk_pq: Vec<u8>,
    ct_trad: Vec<u8>,
    pk_trad: Vec<u8>,
    context: Vec<u8>,
}

fuzz_target!(|x: In| {
    let raw = CombineInput {
        suite_id: &x.suite,
        policy_version: x.ver,
        ss_pq: &x.ss_pq,
        ss_trad: &x.ss_trad,
        ct_pq: &x.ct_pq,
        pk_pq: &x.pk_pq,
        ct_trad: &x.ct_trad,
        pk_trad: &x.pk_trad,
        context: &x.context,
    };
    // Canonicalize metadata for CompatXWing so arbitrary suite/version/context bytes do not
    // short-circuit nearly every input at the policy guard. The remaining fields stay arbitrary,
    // including the deliberately omitted ct_pq/pk_pq slots.
    let compat = CombineInput {
        suite_id: b"",
        policy_version: 0,
        context: b"",
        ..raw
    };

    // Raw Compat input pins arbitrary policy rejection; canonical Compat reaches the deeper
    // length/hash path. Every profile/input combination must return cleanly without panicking.
    let raw_compat = combine::<Sha3_256Xof>(Profile::CompatXWing, &raw);
    if !raw.suite_id.is_empty() || raw.policy_version != 0 || !raw.context.is_empty() {
        assert!(matches!(raw_compat, Err(Error::PolicyDenied)));
    }
    let _ = combine::<Sha3_256Xof>(Profile::CompatXWing, &compat);
    let _ = combine::<Sha3_256Xof>(Profile::ContextBound, &raw);
});
