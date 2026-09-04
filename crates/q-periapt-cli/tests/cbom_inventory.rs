//! The CBOM against the backends that actually define the algorithms.
//!
//! `src/lib.rs` derives every row's identifier and level from the four suite
//! crates it depends on, so a removed or renamed backend is a build failure
//! there rather than a stale claim in a released CBOM. What derivation cannot
//! police is the row *set*: nothing in the workspace enumerates the backends,
//! so the inventory names them and so does this file, and these guards are the
//! independent re-enumeration that fails when the two drift apart.
//!
//! They ship with the published crate. The four crates they import are ordinary
//! dependencies that the published manifest names, so `cargo test` on the
//! crates.io crate builds and runs them against the same backends the release
//! described.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use q_periapt_cli::cbom;

/// Every asset name the CBOM this build emits claims.
fn cbom_names() -> BTreeSet<String> {
    cbom()["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component["name"].as_str().unwrap().to_string())
        .collect()
}

/// Every algorithm identifier the backends this build compiles report for
/// themselves.
///
/// Read from `q-periapt-backends` rather than retyped, so a renamed or
/// removed backend fails here (or fails to compile) instead of leaving a
/// released CBOM claiming an algorithm the suite does not ship, or omitting
/// one it does. The `slh-dsa` feature is the backends' own, so this set moves
/// with the gate exactly as the CBOM must.
fn shipped_algorithm_ids() -> BTreeSet<String> {
    use q_periapt_backends::{
        MlDsa44, MlDsa65, MlDsa87, MlKem1024, MlKem512, MlKem768, MlKem768XWingSeed, Sha3_256Xof,
        X25519,
    };
    use q_periapt_core::{Kem, Xof256};
    use q_periapt_sig::Signer;

    let mut ids = BTreeSet::new();
    for kem in [
        MlKem512.algorithm(),
        MlKem768.algorithm(),
        MlKem1024.algorithm(),
        X25519.algorithm(),
    ] {
        ids.insert(kem.to_string());
    }
    // The X-Wing seed backend is the same FIPS 203 parameter set behind a
    // different key format ("ML-KEM-768(seed-dk)"), so it is the ML-KEM-768
    // row rather than a further asset. Naming it keeps its removal visible.
    assert!(MlKem768XWingSeed
        .algorithm()
        .starts_with(MlKem768.algorithm()));
    for signer in [
        MlDsa44.algorithm(),
        MlDsa65.algorithm(),
        MlDsa87.algorithm(),
    ] {
        ids.insert(signer.id().to_string());
    }
    #[cfg(feature = "slh-dsa")]
    {
        use q_periapt_backends::{SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s};
        for signer in [
            SlhDsaSha2_128s.algorithm(),
            SlhDsaSha2_192s.algorithm(),
            SlhDsaSha2_256s.algorithm(),
        ] {
            ids.insert(signer.id().to_string());
        }
    }
    // `Xof256` carries no algorithm identifier, so the combiner hash and the
    // XOF are named here; linking the backend that provides both still makes
    // its removal a compile failure.
    let _ = Sha3_256Xof::new();
    ids.insert("SHA3-256".to_string());
    ids.insert("SHAKE-256".to_string());
    ids
}

#[test]
fn the_cbom_lists_exactly_the_algorithms_the_shipped_backends_report() {
    assert_eq!(cbom_names(), shipped_algorithm_ids());
}

#[test]
fn the_slh_dsa_rows_follow_the_backends_off_by_default_gate() {
    let slh: Vec<String> = cbom_names()
        .into_iter()
        .filter(|name| name.starts_with("SLH-DSA"))
        .collect();
    if cfg!(feature = "slh-dsa") {
        assert_eq!(
            slh,
            [
                "SLH-DSA-SHA2-128s",
                "SLH-DSA-SHA2-192s",
                "SLH-DSA-SHA2-256s"
            ]
        );
    } else {
        // The default build compiles no SLH-DSA backend, so a CBOM that
        // claimed one would tell an auditor the released package contains an
        // algorithm it does not.
        assert!(
            slh.is_empty(),
            "default build must claim no SLH-DSA: {slh:?}"
        );
    }
}

/// The signature rows take their level from `SigAlg::nist_level` and the rest
/// from `q_periapt_policy::nist_level`, so this is the cross-check that the
/// signature layer's own strength claim and the table the downgrade floor is
/// enforced against still agree — and that no row reaches the CBOM with a level
/// the policy layer would not recognise.
#[test]
fn every_cbom_row_reports_the_level_the_policy_layer_enforces() {
    for component in cbom()["components"].as_array().unwrap() {
        let name = component["name"].as_str().unwrap();
        let level = component["cryptoProperties"]["algorithmProperties"]
            ["nistQuantumSecurityLevel"]
            .as_u64()
            .unwrap();
        // Level 0 is this CBOM's spelling of "not a leveled post-quantum
        // algorithm", which is exactly what the policy layer answers `None`
        // for -- the traditional hybrid partner and the hashes.
        let expected = u64::from(q_periapt_policy::nist_level(name).unwrap_or(0));
        assert_eq!(level, expected, "{name} claims the wrong NIST level");
    }
}
