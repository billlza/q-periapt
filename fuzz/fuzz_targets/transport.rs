#![no_main]
//! Exercise the actual nine-field decoder with unstructured, attacker-controlled
//! bytes. Successful decoding must consume exactly one canonical representation.

use libfuzzer_sys::fuzz_target;
use q_periapt_core::CombineInput;

fuzz_target!(|data: &[u8]| {
    let Some(decoded) = CombineInput::from_transport(data) else {
        return;
    };
    let version = decoded.policy_version.to_be_bytes();
    let fields = [
        decoded.suite_id,
        version.as_slice(),
        decoded.ss_pq,
        decoded.ss_trad,
        decoded.ct_pq,
        decoded.pk_pq,
        decoded.ct_trad,
        decoded.pk_trad,
        decoded.context,
    ];
    let mut canonical = Vec::with_capacity(data.len());
    for field in fields {
        canonical.extend_from_slice(
            &u64::try_from(field.len())
                .expect("field length fits the transport prefix")
                .to_be_bytes(),
        );
        canonical.extend_from_slice(field);
    }
    assert_eq!(
        canonical, data,
        "decoder changed framing or accepted trailing bytes"
    );

    // Every valid encoding is at least nine prefixes plus the version field.
    assert!(data.len() >= 76);
    assert!(CombineInput::from_transport(&data[..data.len() - 1]).is_none());
    canonical.push(0);
    assert!(CombineInput::from_transport(&canonical).is_none());
});
