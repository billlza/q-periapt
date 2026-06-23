#![no_main]
//! Fuzz the combiner: arbitrary field lengths must never panic, and the
//! CompatXWing 32-byte / ContextBound non-empty-context guards must hold.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use q_periapt_backends::Sha3_256Xof;
use q_periapt_core::{combine, CombineInput, Profile};

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
    let inp = CombineInput {
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
    // Both profiles must return cleanly (Ok/Err) without panicking.
    let _ = combine::<Sha3_256Xof>(Profile::CompatXWing, &inp);
    let _ = combine::<Sha3_256Xof>(Profile::ContextBound, &inp);
});
