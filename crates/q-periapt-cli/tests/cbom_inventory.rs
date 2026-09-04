//! The CBOM against the backends that actually define the algorithms.
//!
//! `src/lib.rs` derives every row's identifier and level from the four suite
//! crates it depends on, so a removed or renamed backend is a build failure
//! there rather than a stale claim in a released CBOM. The row *set* is checked
//! here, against the registries `q-periapt-backends` generates from its own
//! declaration macros: `ML_KEM_BACKEND_ALGORITHMS`, `ML_DSA_BACKEND_ALGORITHMS`
//! and `SLH_DSA_BACKEND_ALGORITHMS` are expanded by the same
//! `mlkem_backends!` / `mldsa_backends!` / `slhdsa_backends!` invocations that
//! define the backends, from the same literals those backends report, so a
//! parameter set added to one of them reaches this file without anyone
//! remembering to list it.
//!
//! Caught, and named in the failure:
//!
//! * a parameter set **added** through one of those three declaration macros
//!   that no CBOM row accounts for, and a CBOM row no backend reports: the
//!   comparison runs in both directions;
//! * a backend removed or renamed — `src/lib.rs` names the types, so it stops
//!   compiling, and if it still compiles these guards fail;
//! * a CBOM row emitted twice — `cbom_names` and `cbom_levels` reject the
//!   duplicate rather than collapsing it into a set or a map;
//! * a level the two layers disagree about, and a row whose level the policy
//!   layer cannot supply — see the level guards below for which comparisons are
//!   real and which are not;
//! * a hybrid suite added to the policy layer — `HybridSuite` is not
//!   `#[non_exhaustive]`, so the match in `suite_pq_component` stops compiling;
//! * an SLH-DSA row that does not follow the off-by-default feature gate, in
//!   both directions.
//!
//! **Not caught, by anything in this workspace:**
//!
//! * a backend added as a hand-written `impl Kem` / `Signer` / `Verifier` /
//!   `Xof256` that does not go through a declaration macro. It is in no
//!   registry, and no guard here or elsewhere sees it — `MlKem768XWingSeed`,
//!   `X25519` and `Sha3_256Xof` are exactly such impls, which is why the
//!   registries are per-macro-family and are not the crate's backend inventory.
//!   A `pub struct` and a `pub use` in the crate root are its only trace, and
//!   that is a review artifact, not a guard;
//! * a backend implemented in another crate this one links, or produced by a
//!   procedural macro;
//! * a second *hand-written* backend type reporting an identifier an existing
//!   row already covers — deliberately, since that is the same CBOM asset, as
//!   `MlKem768XWingSeed` is today. The registries are of identifiers, not of
//!   types, so this is not a type census. A second *macro-declared* backend
//!   reporting an existing identifier is a different matter: it repeats that
//!   identifier inside its family's registry, and
//!   `every_row_is_claimed_by_exactly_one_level_source` fails on it;
//! * component *order* and the rest of the emitted JSON shape, which
//!   `artifact/c-package.sh` and `artifact/package_bom.py` verify byte-for-byte
//!   at package-verification time instead.
//!
//! These guards do ship. The four crates they import are ordinary dependencies
//! that the published manifest names, so `cargo test` on the crates.io crate
//! builds and runs them against the same backends the release described.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};

use q_periapt_cli::cbom;
use q_periapt_policy::HybridSuite;
use q_periapt_sig::SigAlg;

/// Every asset name the CBOM this build emits, in emission order, one entry per
/// component — duplicates included.
fn cbom_row_names() -> Vec<String> {
    cbom()["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component["name"].as_str().unwrap().to_string())
        .collect()
}

/// Every asset name the CBOM this build emits, each emitted exactly once.
///
/// The set comparisons below cannot see a row emitted twice — the second copy
/// collapses into the first and every one of them still passes — so the
/// duplicate is rejected here instead. `artifact/package_bom.py` rejects it too,
/// but only once a release package exists; this is the half a crates.io
/// consumer can run.
fn cbom_names() -> BTreeSet<String> {
    let rows = cbom_row_names();
    let names: BTreeSet<String> = rows.iter().cloned().collect();
    assert_eq!(
        rows.len(),
        names.len(),
        "the CBOM emits an asset more than once: {rows:?}"
    );
    names
}

/// Every asset name the CBOM this build emits, with the level it publishes.
///
/// A `BTreeMap` would silently keep the last of two rows sharing a name, so a
/// duplicate — whose two copies may carry different levels — is rejected here
/// as well, rather than leaving one row's level unread by every level guard.
fn cbom_levels() -> BTreeMap<String, u64> {
    let mut levels = BTreeMap::new();
    for component in cbom()["components"].as_array().unwrap() {
        let level = component["cryptoProperties"]["algorithmProperties"]
            ["nistQuantumSecurityLevel"]
            .as_u64()
            .unwrap();
        let name = component["name"].as_str().unwrap().to_string();
        assert_eq!(
            levels.insert(name.clone(), level),
            None,
            "{name} is emitted more than once, so one row's level is unread"
        );
    }
    levels
}

/// The ML-KEM identifiers the compiled backends report for themselves. These
/// are the rows whose level `q_periapt_policy::nist_level` supplies.
///
/// Read from the registry `q-periapt-backends`' `mlkem_backends!` invocation
/// generates, not retyped, so a parameter set added to that invocation is here
/// by construction. A hand-written `impl Kem` is not in that registry and so is
/// not here — see the module doc.
fn shipped_ml_kem_ids() -> Vec<&'static str> {
    q_periapt_backends::ML_KEM_BACKEND_ALGORITHMS.to_vec()
}

/// The signature algorithms the compiled backends report for themselves. These
/// are the rows whose level `SigAlg::nist_level` supplies.
///
/// Both registries are generated by their family's own declaration-macro
/// invocation, so a parameter set added to either is here by construction. The
/// `slh-dsa` half moves with the backends' own feature gate, exactly as the
/// CBOM must.
fn shipped_signature_algorithms() -> Vec<SigAlg> {
    #[allow(unused_mut)]
    let mut algorithms = q_periapt_backends::ML_DSA_BACKEND_ALGORITHMS.to_vec();
    #[cfg(feature = "slh-dsa")]
    algorithms.extend_from_slice(q_periapt_backends::SLH_DSA_BACKEND_ALGORITHMS);
    algorithms
}

/// The rows that publish level 0: the traditional hybrid partner the backends
/// report, and the two FIPS 202 identifiers no backend reports at all.
fn unleveled_ids() -> Vec<&'static str> {
    use q_periapt_backends::X25519;
    use q_periapt_core::Kem;

    vec![X25519.algorithm(), "SHA3-256", "SHAKE-256"]
}

/// The post-quantum component of a suite the policy layer defines, and the
/// level that layer states for it through the suite.
///
/// The match is exhaustive: `HybridSuite` is not `#[non_exhaustive]`, so a
/// suite added to the policy layer stops this file compiling until the CBOM's
/// inventory has been reconsidered.
fn suite_pq_component(suite: HybridSuite) -> (&'static str, u8) {
    match suite {
        HybridSuite::MlKem768X25519 | HybridSuite::MlKem1024X25519 => {
            (suite.pq_kem(), suite.nist_level())
        }
    }
}

/// Every algorithm identifier the CBOM owes a row: the three macro-declared
/// families, plus the identifiers named below because no backend reports them.
///
/// Read from `q-periapt-backends` rather than retyped, so a renamed or removed
/// backend fails here (or fails to compile), and a parameter set added to a
/// declaration macro fails here, instead of leaving a released CBOM claiming an
/// algorithm the suite does not ship or omitting one it does. The `slh-dsa`
/// feature is the backends' own, so this set moves with the gate exactly as the
/// CBOM must.
///
/// The two `unleveled_ids` FIPS 202 names and the X-Wing key-format wrapper are
/// the crate's hand-written impls, so they are named rather than enumerated; a
/// *further* hand-written impl would be in neither the registries nor this
/// function, and nothing would fail.
fn shipped_algorithm_ids() -> BTreeSet<String> {
    use q_periapt_backends::{MlKem768, MlKem768XWingSeed, Sha3_256Xof};
    use q_periapt_core::{Kem, Xof256};

    let mut ids = BTreeSet::new();
    for kem in shipped_ml_kem_ids() {
        ids.insert(kem.to_string());
    }
    for unleveled in unleveled_ids() {
        ids.insert(unleveled.to_string());
    }
    // The X-Wing seed backend is the same FIPS 203 parameter set behind a
    // different key format ("ML-KEM-768(seed-dk)"), so it is the ML-KEM-768
    // row rather than a further asset. Naming it keeps its removal visible.
    assert!(MlKem768XWingSeed
        .algorithm()
        .starts_with(MlKem768.algorithm()));
    for signer in shipped_signature_algorithms() {
        ids.insert(signer.id().to_string());
    }
    // `Xof256` carries no algorithm identifier, so the two FIPS 202 rows are
    // named above rather than derived. Linking `Sha3_256Xof` still makes the
    // removal of the combiner sponge a compile failure -- it is the SHA3-256
    // row's implementation. SHAKE-256 has no such backend: it is the XOF the
    // X-Wing seed format expands with, inside `MlKem768XWingSeed`.
    let _ = Sha3_256Xof::new();
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

/// Every row belongs to exactly one of the three level sources.
///
/// This is what makes the guards below total. A row that reached the CBOM
/// through some fourth path — a new backend named in `src/lib.rs`, an
/// identifier no layer levels — would be in none of these sets and fail here
/// rather than pass three guards that never looked at it.
#[test]
fn every_row_is_claimed_by_exactly_one_level_source() {
    let policy: Vec<String> = shipped_ml_kem_ids()
        .iter()
        .map(|id| id.to_string())
        .collect();
    let signature: Vec<String> = shipped_signature_algorithms()
        .iter()
        .map(|alg| alg.id().to_string())
        .collect();
    let unleveled: Vec<String> = unleveled_ids().iter().map(|id| id.to_string()).collect();

    let mut claimed: BTreeMap<String, &'static str> = BTreeMap::new();
    for (source, ids) in [
        ("policy", policy),
        ("signature", signature),
        ("unleveled", unleveled),
    ] {
        for id in ids {
            assert_eq!(
                claimed.insert(id.clone(), source),
                None,
                "{id} is claimed by more than one level source"
            );
        }
    }
    assert_eq!(
        claimed.keys().cloned().collect::<BTreeSet<_>>(),
        cbom_names(),
        "a CBOM row belongs to no level source"
    );
}

/// The signature rows: a real cross-check.
///
/// `src/lib.rs` takes these levels from `SigAlg::nist_level`, and
/// `q_periapt_policy::nist_level` states the same claim independently — the
/// signature layer's own strength claim against the table the downgrade floor
/// is enforced against. A disagreement between the two fails here.
#[test]
fn the_signature_rows_agree_with_the_policy_layers_strength_table() {
    let levels = cbom_levels();
    for alg in shipped_signature_algorithms() {
        assert!(
            levels.contains_key(alg.id()),
            "a shipped signature backend reports {}, which the CBOM has no row for",
            alg.id()
        );
        let emitted = levels[alg.id()];
        assert_eq!(
            emitted,
            u64::from(alg.nist_level()),
            "{} claims a level its signature backend does not",
            alg.id()
        );
        assert_eq!(
            Some(emitted),
            q_periapt_policy::nist_level(alg.id()).map(u64::from),
            "{} is leveled differently by the signature layer and the policy layer",
            alg.id()
        );
    }
}

/// The ML-KEM rows: a totality check, and one genuine cross-check of two.
///
/// These levels come from `q_periapt_policy::nist_level`, so re-reading that
/// table and comparing is a tautology and proves nothing about the number.
/// What it does establish is the property the emission depends on: the table
/// levels every key-establishment row the CBOM publishes, so the lookup in
/// `NistLevel::from_policy` can never come back empty and no row can reach an
/// auditor carrying a substituted 0.
///
/// The two parameter sets that a `HybridSuite` names are cross-checked for
/// real, against the level that enum states through `HybridSuite::nist_level`.
/// ML-KEM-512 belongs to no suite, so its number has exactly one source in the
/// workspace and no cross-check for it exists.
#[test]
fn the_kem_rows_are_leveled_by_the_table_the_downgrade_floor_uses() {
    let levels = cbom_levels();
    for id in shipped_ml_kem_ids() {
        let level = q_periapt_policy::nist_level(id);
        assert!(
            level.is_some(),
            "the policy layer levels no {id}, so the CBOM has no number to publish for it"
        );
        assert!(
            levels.contains_key(id),
            "a shipped ML-KEM backend reports {id}, which the CBOM has no row for"
        );
        assert_eq!(levels[id], u64::from(level.unwrap()));
    }
    for suite in [HybridSuite::MlKem768X25519, HybridSuite::MlKem1024X25519] {
        let (pq_kem, level) = suite_pq_component(suite);
        assert_eq!(
            levels[pq_kem],
            u64::from(level),
            "{pq_kem} claims a level the suite that uses it does not"
        );
    }
}

/// The level-0 rows: declared, not defaulted.
///
/// Level 0 is this CBOM's spelling of "not a leveled post-quantum algorithm",
/// and `src/lib.rs` writes it from two separate declarations rather than from a
/// failed lookup. This checks the claim each declaration makes: that the policy
/// layer levels none of these three identifiers, and still classifies X25519 as
/// the traditional hybrid partner. If the policy layer ever does level one of
/// them, the declaration has become a stale claim and this fails.
#[test]
fn the_level_zero_rows_are_the_ones_no_layer_levels() {
    use q_periapt_backends::X25519;
    use q_periapt_core::Kem;

    let levels = cbom_levels();
    for id in unleveled_ids() {
        assert_eq!(
            q_periapt_policy::nist_level(id),
            None,
            "{id} is leveled by the policy layer, so the CBOM must not publish 0 for it"
        );
        assert_eq!(levels[id], 0, "{id} must publish the unleveled 0");
    }
    assert!(
        q_periapt_policy::is_traditional(X25519.algorithm()),
        "the policy layer no longer classifies the hybrid partner as traditional"
    );
}
