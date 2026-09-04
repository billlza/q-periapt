#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-cli (library)
//!
//! Auditability & migration tooling for the PQ/T hybrid suite:
//! - [`cbom`] — a CycloneDX 1.6 **Crypto** Bill of Materials of the suite's
//!   cryptographic assets (algorithms, parameter sets, quantum-security levels),
//!   derived from the crates that define them rather than retyped from them.
//! - [`sbom`] — a CycloneDX 1.6 SBOM derived from a `Cargo.lock`.
//! - [`scan`] — a migration scanner that flags legacy / quantum-vulnerable
//!   primitives (RSA, ECDSA, ECDH, DSA, NIST curves, MD5/SHA-1, 3DES, RC4) and
//!   recommends a PQ/T replacement + policy.
//!
//! Output is plain `serde_json` so it diffs cleanly and needs no derive.

use q_periapt_backends::{
    MlDsa44, MlDsa65, MlDsa87, MlKem1024, MlKem512, MlKem768, Sha3_256Xof, X25519,
};
use q_periapt_core::{Kem, Xof256};
use q_periapt_sig::{SigAlg, Signer};
use serde_json::{json, Value};
use std::path::Path;

/// The CycloneDX facts about an algorithm that no suite crate represents.
///
/// `primitive`, `functions`, `family`, `oid` and `note` are editorial: they
/// describe an algorithm to an auditor and exist nowhere in the implementation,
/// so they are written here. Everything the implementation *does* carry — the
/// identifier and the security level — is read from it rather than retyped, and
/// each of these blocks travels attached to the derivation it annotates, so a
/// row can neither lose its metadata nor outlive the backend it describes.
struct AssetMetadata {
    primitive: &'static str, // CycloneDX algorithmProperties.primitive
    functions: &'static [&'static str],
    family: &'static str, // lattice / elliptic-curve / hash / code
    oid: Option<&'static str>,
    note: &'static str,
}

/// The NIST quantum-security level a row publishes, with the statement that
/// establishes it.
///
/// The four constructors below are the only ways to obtain one, and none of
/// them can answer "unknown": three read a number a crate asserts, and the
/// fourth records the single editorial fact this CBOM declares. There is no
/// `Default`, no conversion from a bare `u8`, and no path that turns a failed
/// lookup into a value — so a level no layer can supply stops the emission
/// instead of reaching an auditor as `0`.
#[derive(Clone, Copy)]
struct NistLevel(u8);

impl NistLevel {
    /// The level `q_periapt_policy::nist_level` states for a leveled
    /// post-quantum identifier — in this inventory, the three ML-KEM rows.
    ///
    /// That table is the one the downgrade floor is enforced against, so the
    /// number an auditor reads here is the number the runtime refuses to go
    /// below. It answers `None` only for identifiers that are not leveled
    /// post-quantum algorithms, and no such row reaches this constructor: they
    /// are built by [`NistLevel::traditional_partner`] and
    /// [`NistLevel::declared_sponge`] instead. A `None` here therefore means a
    /// backend reports a key-establishment identifier the policy layer does not
    /// level, for which there is no number to publish — so the emission stops.
    /// `tests/cbom_inventory.rs` fails before a build can get this far.
    fn from_policy(id: &str) -> Self {
        Self(
            q_periapt_policy::nist_level(id)
                .expect("the policy layer levels every ML-KEM row this CBOM publishes"),
        )
    }

    /// The level the signature layer states for `alg`.
    ///
    /// `SigAlg::nist_level` is total — every variant has one — so nothing can
    /// be missing here. It is an independent second statement of the same
    /// claim the policy layer's table makes, and `tests/cbom_inventory.rs`
    /// cross-checks the two.
    fn from_signature(alg: SigAlg) -> Self {
        Self(alg.nist_level())
    }

    /// Level 0 for the traditional hybrid partner.
    ///
    /// Two policy-layer statements produce this number: `is_traditional`
    /// recognises the identifier, and the strength table levels it not at all,
    /// because a NIST PQ level would claim quantum resistance it does not have.
    /// The 0 is therefore derived rather than assumed, and a partner the policy
    /// layer stopped recognising — or started leveling — stops the emission
    /// here instead of publishing a stale claim.
    fn traditional_partner(id: &str) -> Self {
        assert!(
            q_periapt_policy::is_traditional(id) && q_periapt_policy::nist_level(id).is_none(),
            "{id} is no longer the policy layer's unleveled traditional partner"
        );
        Self(0)
    }

    /// Level 0 declared for a FIPS 202 sponge function.
    ///
    /// This is the one level in the CBOM that no crate states, because none
    /// has one to state: NIST's levels rank KEMs and signature schemes, not the
    /// digest or XOF a combiner absorbs into. The policy layer's silence about
    /// SHA3-256 and SHAKE-256 is thus the expected answer rather than a missing
    /// one, and this constructor records that as a fact of the standard.
    /// `tests/cbom_inventory.rs` pins it by failing if the policy layer ever
    /// does level either identifier.
    const fn declared_sponge() -> Self {
        Self(0)
    }

    /// The number to emit.
    const fn get(self) -> u8 {
        self.0
    }
}

/// One CBOM row: a derived identity joined to its metadata.
struct CryptoAsset {
    name: &'static str,
    /// NIST PQ security level 1/2/3/5, or 0 for a row no layer levels — see
    /// [`NistLevel`] for the statement behind each one.
    nist_quantum_level: NistLevel,
    meta: AssetMetadata,
}

const KEM_FUNCTIONS: &[&str] = &["keygen", "encapsulate", "decapsulate"];
const KEY_AGREEMENT_FUNCTIONS: &[&str] = &["keygen", "key-agree"];
const SIGNATURE_FUNCTIONS: &[&str] = &["keygen", "sign", "verify"];
const DIGEST_FUNCTIONS: &[&str] = &["digest"];

/// A row named by its backend and leveled by the policy layer's strength table.
fn policy_leveled_row(name: &'static str, meta: AssetMetadata) -> CryptoAsset {
    CryptoAsset {
        name,
        nist_quantum_level: NistLevel::from_policy(name),
        meta,
    }
}

/// The traditional hybrid partner's row: named by its backend, and level 0
/// because the policy layer classifies it as traditional and levels it not.
fn traditional_row(name: &'static str, meta: AssetMetadata) -> CryptoAsset {
    CryptoAsset {
        name,
        nist_quantum_level: NistLevel::traditional_partner(name),
        meta,
    }
}

/// A signature row named and leveled by the algorithm the backend reports.
fn signature_row(alg: SigAlg, meta: AssetMetadata) -> CryptoAsset {
    CryptoAsset {
        name: alg.id(),
        nist_quantum_level: NistLevel::from_signature(alg),
        meta,
    }
}

/// A FIPS 202 sponge row, at the declared level 0.
fn sponge_row(name: &'static str, meta: AssetMetadata) -> CryptoAsset {
    CryptoAsset {
        name,
        nist_quantum_level: NistLevel::declared_sponge(),
        meta,
    }
}

/// Key-establishment and ML-DSA assets, present in every build.
///
/// Every identifier is the one the linked backend reports for itself, so a
/// backend that is removed or renamed is a build failure here rather than a
/// released CBOM claiming an algorithm the suite does not ship. The opposite
/// drift is not caught here and cannot be: a backend *added* to
/// `q-periapt-backends` still compiles, and is simply missing from this list.
/// Nothing in this crate enumerates that crate's declarations, so the guard for
/// an addition is `artifact/test_cbom_backend_inventory.py`, which re-reads them
/// from the backends crate's source and fails on one no row accounts for.
fn key_and_signature_assets() -> Vec<CryptoAsset> {
    vec![
        policy_leveled_row(
            MlKem512.algorithm(),
            AssetMetadata {
                primitive: "kem",
                functions: KEM_FUNCTIONS,
                family: "lattice",
                oid: Some("2.16.840.1.101.3.4.4.1"),
                note: "FIPS 203; smallest parameter set, for agility at a level-1 floor.",
            },
        ),
        policy_leveled_row(
            MlKem768.algorithm(),
            AssetMetadata {
                primitive: "kem",
                functions: KEM_FUNCTIONS,
                family: "lattice",
                oid: Some("2.16.840.1.101.3.4.4.2"),
                note: "FIPS 203; default PQ KEM component (C2PRI).",
            },
        ),
        policy_leveled_row(
            MlKem1024.algorithm(),
            AssetMetadata {
                primitive: "kem",
                functions: KEM_FUNCTIONS,
                family: "lattice",
                oid: Some("2.16.840.1.101.3.4.4.3"),
                note: "FIPS 203; enhanced (L5) PQ KEM component.",
            },
        ),
        traditional_row(
            X25519.algorithm(),
            AssetMetadata {
                primitive: "key-agree",
                functions: KEY_AGREEMENT_FUNCTIONS,
                family: "elliptic-curve",
                oid: Some("1.3.101.110"),
                note: "RFC 7748; classical (quantum-vulnerable) — used ONLY as a hybrid partner.",
            },
        ),
        signature_row(
            MlDsa44.algorithm(),
            AssetMetadata {
                primitive: "signature",
                functions: SIGNATURE_FUNCTIONS,
                family: "lattice",
                oid: Some("2.16.840.1.101.3.4.3.17"),
                note: "FIPS 204; smallest parameter set, for agility at a level-2 floor.",
            },
        ),
        signature_row(
            MlDsa65.algorithm(),
            AssetMetadata {
                primitive: "signature",
                functions: SIGNATURE_FUNCTIONS,
                family: "lattice",
                oid: Some("2.16.840.1.101.3.4.3.18"),
                note: "FIPS 204; general-purpose signatures.",
            },
        ),
        signature_row(
            MlDsa87.algorithm(),
            AssetMetadata {
                primitive: "signature",
                functions: SIGNATURE_FUNCTIONS,
                family: "lattice",
                oid: Some("2.16.840.1.101.3.4.3.19"),
                note: "FIPS 204; enhanced (L5) signatures.",
            },
        ),
    ]
}

/// SLH-DSA assets, present only when the `slh-dsa` backends are compiled.
///
/// `q-periapt-backends` gates all three parameter sets behind its
/// off-by-default `slh-dsa` feature, which this crate's feature of the same name
/// forwards to. Naming the three backend types is what makes the gate binding:
/// the rows exist exactly when the parameter sets are compiled, so a default
/// build cannot claim them and a `--features slh-dsa` build cannot omit them.
#[cfg(feature = "slh-dsa")]
fn slh_dsa_assets() -> Vec<CryptoAsset> {
    use q_periapt_backends::{SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s};

    const CONSERVATIVE: &str =
        "FIPS 205; conservative hash-based signatures for roots / firmware / long-term.";
    [
        SlhDsaSha2_128s.algorithm(),
        SlhDsaSha2_192s.algorithm(),
        SlhDsaSha2_256s.algorithm(),
    ]
    .into_iter()
    .map(|alg| {
        signature_row(
            alg,
            AssetMetadata {
                primitive: "signature",
                functions: SIGNATURE_FUNCTIONS,
                family: "hash",
                oid: None,
                note: CONSERVATIVE,
            },
        )
    })
    .collect()
}

#[cfg(not(feature = "slh-dsa"))]
fn slh_dsa_assets() -> Vec<CryptoAsset> {
    Vec::new()
}

/// The combiner sponge carries no algorithm identifier — `Xof256` reports none
/// — so the two rows below are the only names this file still writes out.
///
/// `Sha3_256Xof` anchors the SHA3-256 row alone: its `squeeze32` returns the
/// SHA3-256 digest of the combiner transcript, which is exactly what that row
/// describes, and naming the type keeps its removal a build failure rather than
/// a stale claim. The SHAKE-256 row has no anchor here. No backend reports it
/// as its algorithm: it is the XOF `MlKem768XWingSeed` expands its 32-byte
/// X-Wing seed with, through a private helper this crate cannot name. That row
/// is therefore written from the standard rather than derived, and the
/// inventory guard is what holds it to the backend set.
const _: fn() -> Sha3_256Xof = <Sha3_256Xof as Xof256>::new;

/// Hash and XOF assets, present in every build.
fn hash_assets() -> Vec<CryptoAsset> {
    vec![
        sponge_row(
            "SHA3-256",
            AssetMetadata {
                primitive: "hash",
                functions: DIGEST_FUNCTIONS,
                family: "hash",
                oid: Some("2.16.840.1.101.3.4.2.8"),
                note: "FIPS 202; combiner hash.",
            },
        ),
        sponge_row(
            "SHAKE-256",
            AssetMetadata {
                primitive: "xof",
                functions: DIGEST_FUNCTIONS,
                family: "hash",
                oid: Some("2.16.840.1.101.3.4.2.12"),
                note: "FIPS 202; XOF for key derivation / expansion.",
            },
        ),
    ]
}

/// Every cryptographic asset this build ships, in inventory order.
fn assets() -> Vec<CryptoAsset> {
    let mut inventory = key_and_signature_assets();
    inventory.extend(slh_dsa_assets());
    inventory.extend(hash_assets());
    inventory
}

/// Build a CycloneDX 1.6 CBOM of the suite's cryptographic assets.
#[must_use]
pub fn cbom() -> Value {
    let components: Vec<Value> = assets()
        .into_iter()
        .map(|a| {
            let algo = json!({
                "primitive": a.meta.primitive,
                "parameterSetIdentifier": a.name,
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
                "cryptoFunctions": a.meta.functions,
                "nistQuantumSecurityLevel": a.nist_quantum_level.get(),
            });
            let mut crypto = serde_json::Map::new();
            crypto.insert("assetType".to_string(), json!("algorithm"));
            crypto.insert("algorithmProperties".to_string(), algo);
            if let Some(oid) = a.meta.oid {
                crypto.insert("oid".to_string(), json!(oid));
            }
            json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto/{}", a.name.to_lowercase()),
                "name": a.name,
                "description": format!(
                    "{} ({} family). {}",
                    a.name, a.meta.family, a.meta.note
                ),
                "cryptoProperties": Value::Object(crypto),
            })
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": { "type": "application", "name": "q-periapt-hybrid-suite" },
            "tools": [{ "name": "q-periapt-cli", "vendor": "q-periapt-hybrid-suite" }],
        },
        "components": components,
    })
}

/// Build a CycloneDX 1.6 SBOM from the text of a `Cargo.lock`.
#[must_use]
pub fn sbom(cargo_lock: &str) -> Value {
    let mut components = Vec::new();
    let (mut name, mut version): (Option<String>, Option<String>) = (None, None);
    let mut in_pkg = false;

    let flush = |components: &mut Vec<Value>, name: &Option<String>, version: &Option<String>| {
        if let (Some(n), Some(v)) = (name, version) {
            components.push(json!({
                "type": "library",
                "bom-ref": format!("pkg:cargo/{n}@{v}"),
                "name": n,
                "version": v,
                "purl": format!("pkg:cargo/{n}@{v}"),
            }));
        }
    };

    for line in cargo_lock.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(&mut components, &name, &version);
            name = None;
            version = None;
            in_pkg = true;
        } else if in_pkg {
            if let Some(v) = t.strip_prefix("name = ") {
                name = Some(v.trim_matches('"').to_string());
            } else if let Some(v) = t.strip_prefix("version = ") {
                version = Some(v.trim_matches('"').to_string());
            }
        }
    }
    flush(&mut components, &name, &version);

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": { "component": { "type": "application", "name": "q-periapt-hybrid-suite" } },
        "components": components,
    })
}

/// A migration finding: a legacy / quantum-vulnerable primitive use site.
#[derive(Clone, Debug)]
pub struct Finding {
    /// File path (as given to [`scan`]).
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// Severity: `critical` (broken), `high` (quantum-vulnerable), `advisory`.
    pub severity: &'static str,
    /// The matched token.
    pub token: &'static str,
    /// What it is.
    pub category: &'static str,
    /// Recommended PQ/T migration.
    pub recommendation: &'static str,
}

/// A path the scanner could not inspect. These are fail-closed audit conditions:
/// callers must not treat a scan with access errors as a clean result.
#[derive(Clone, Debug)]
pub struct ScanError {
    /// File or directory path the scanner tried to inspect.
    pub path: String,
    /// Operation that failed (`metadata`, `read_dir`, `dir_entry`, `read_file`,
    /// `too_large`, `symlink_skipped`).
    pub operation: &'static str,
    /// OS error rendered with context.
    pub message: String,
}

/// Full scanner output: findings plus any paths that could not be inspected.
#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    /// Legacy / quantum-vulnerable crypto findings.
    pub findings: Vec<Finding>,
    /// Access/read errors that make the scan incomplete.
    pub errors: Vec<ScanError>,
}

struct Pattern {
    token: &'static str,
    severity: &'static str,
    category: &'static str,
    recommendation: &'static str,
}

const PATTERNS: &[Pattern] = &[
    Pattern { token: "rsa", severity: "high", category: "RSA (broken by Shor)", recommendation: "Sign with ML-DSA-65; key-establish with ML-KEM-768+X25519 (ContextBound). Set policy min_nist_level>=3." },
    Pattern { token: "pkcs1", severity: "high", category: "RSA PKCS#1", recommendation: "Replace RSA with ML-KEM (KEM) / ML-DSA (signatures)." },
    Pattern { token: "ecdsa", severity: "high", category: "ECDSA (broken by Shor)", recommendation: "Replace with ML-DSA-65 (or SLH-DSA for roots/firmware)." },
    Pattern { token: "ecdh", severity: "high", category: "ECDH alone (broken by Shor)", recommendation: "Use the ML-KEM-768+X25519 hybrid KEM, not bare ECDH." },
    Pattern { token: "dsa", severity: "high", category: "DSA (broken by Shor)", recommendation: "Replace with ML-DSA-65." },
    Pattern { token: "secp256r1", severity: "high", category: "NIST P-256 curve", recommendation: "Hybridize: ML-KEM-768+X25519 for KEX; ML-DSA for signatures." },
    Pattern { token: "secp384r1", severity: "high", category: "NIST P-384 curve", recommendation: "Hybridize to L5: ML-KEM-1024 + a traditional partner; ML-DSA-87." },
    Pattern { token: "secp256k1", severity: "high", category: "secp256k1 curve", recommendation: "Quantum-vulnerable; pair with / migrate to a PQ scheme per policy." },
    Pattern { token: "prime256v1", severity: "high", category: "NIST P-256 (prime256v1)", recommendation: "Hybridize: ML-KEM-768+X25519." },
    Pattern { token: "ed25519", severity: "advisory", category: "Ed25519 signature (quantum-vulnerable)", recommendation: "OK only alongside a PQ signature; pair with ML-DSA-65 / SLH-DSA." },
    Pattern { token: "x25519", severity: "advisory", category: "X25519 key-agreement (quantum-vulnerable)", recommendation: "OK only as a HYBRID partner; ensure it is combined with ML-KEM-768 (not standalone)." },
    Pattern { token: "md5", severity: "critical", category: "MD5 (collision-broken)", recommendation: "Replace with SHA3-256." },
    Pattern { token: "sha1", severity: "critical", category: "SHA-1 (collision-broken)", recommendation: "Replace with SHA3-256." },
    Pattern { token: "sha-1", severity: "critical", category: "SHA-1 (collision-broken)", recommendation: "Replace with SHA3-256." },
    Pattern { token: "3des", severity: "critical", category: "3DES (weak/deprecated)", recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305." },
    Pattern { token: "rc4", severity: "critical", category: "RC4 (broken)", recommendation: "Replace with an AEAD (AES-256-GCM / ChaCha20-Poly1305)." },
];

const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    ".build",
    ".gradle",
    "build",
    "vendor",
];
const CODE_EXTS: &[&str] = &[
    "rs", "c", "h", "cc", "cpp", "hpp", "cxx", "go", "py", "java", "kt", "kts", "swift", "ts",
    "tsx", "js", "jsx", "mjs", "cs", "rb", "php", "scala", "m", "mm", "toml", "yaml", "yml",
    "gradle",
];

fn is_boundary(c: Option<char>) -> bool {
    // `_` counts as a boundary so identifiers like `rsa_sign` / `x25519_dalek`
    // still match, while substrings inside a word (e.g. `coarse`) do not.
    match c {
        None => true,
        Some(ch) => !ch.is_ascii_alphanumeric(),
    }
}

/// Case-insensitive token search with non-alphanumeric word boundaries, so `rsa`
/// matches `rsa::sign` / `rsa_sign` but not `coarse`.
fn contains_token(haystack_lower: &str, token: &str) -> bool {
    let bytes = haystack_lower.as_bytes();
    let mut from = 0;
    while let Some(rel) = haystack_lower[from..].find(token) {
        let start = from + rel;
        let end = start + token.len();
        let before = haystack_lower[..start].chars().next_back();
        let after = bytes.get(end).map(|&b| b as char);
        if is_boundary(before) && is_boundary(after) {
            return true;
        }
        from = start + 1;
    }
    false
}

/// True if the line uses **legacy DSA** — a `dsa` token that is NOT the trailing
/// component of a post-quantum `ml-dsa` / `slh-dsa` identifier. Because `is_boundary`
/// treats `-`/`_` as word boundaries, a plain `contains_token(.., "dsa")` matches
/// inside `ml-dsa` / `slh-dsa` / `ml_dsa`, which would make the migration scanner flag
/// the very PQ signatures it recommends (and trip the exit-2 CI gate on this repo's own
/// Cargo.toml). `ecdsa` is matched by its own pattern, not this one.
fn contains_legacy_dsa(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("dsa") {
        let start = from + rel;
        let end = start + 3;
        let before = lower[..start].chars().next_back();
        let after = bytes.get(end).map(|&b| b as char);
        if is_boundary(before) && is_boundary(after) {
            // `lower[..start]` ends with the boundary char; reject ml-/ml_/slh-/slh_.
            let prefix = &lower[..start];
            let is_pq = prefix.ends_with("ml-")
                || prefix.ends_with("ml_")
                || prefix.ends_with("slh-")
                || prefix.ends_with("slh_");
            if !is_pq {
                return true;
            }
        }
        from = start + 1;
    }
    false
}

/// Recursively scan `root` for legacy / quantum-vulnerable crypto.
#[must_use]
pub fn scan(root: &Path) -> ScanReport {
    let mut report = ScanReport::default();
    scan_path(root, &mut report, true);
    report
}

fn push_scan_error(
    report: &mut ScanReport,
    path: &Path,
    operation: &'static str,
    error: std::io::Error,
) {
    report.errors.push(ScanError {
        path: path.display().to_string(),
        operation,
        message: error.to_string(),
    });
}

fn scan_path(path: &Path, report: &mut ScanReport, is_root: bool) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            push_scan_error(report, path, "metadata", e);
            return;
        }
    };
    if meta.is_dir() {
        // Skip rules apply only to descendants: an explicitly named root
        // (`qperiapt scan vendor`, `qperiapt scan .config`) must always be scanned.
        if !is_root {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if SKIP_DIRS.contains(&name) || name.starts_with('.') && name != "." {
                    return;
                }
            }
        }
        match std::fs::read_dir(path) {
            Ok(entries) => {
                let mut paths = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => paths.push(entry.path()),
                        Err(e) => push_scan_error(report, path, "dir_entry", e),
                    }
                }
                paths.sort();
                for p in paths {
                    scan_path(&p, report, false);
                }
            }
            Err(e) => push_scan_error(report, path, "read_dir", e),
        }
    } else if meta.is_file() {
        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| CODE_EXTS.contains(&e))
            .unwrap_or(false);
        if !ext_ok {
            return;
        }
        if meta.len() > 2 * 1024 * 1024 {
            report.errors.push(ScanError {
                path: path.display().to_string(),
                operation: "too_large",
                message: "code file exceeds 2 MiB scanner limit".to_string(),
            });
            return;
        }
        match std::fs::read_to_string(path) {
            Ok(text) => scan_text(&path.display().to_string(), &text, &mut report.findings),
            Err(e) => push_scan_error(report, path, "read_file", e),
        }
    } else if meta.is_symlink() {
        // Fail closed: symlinks are never auto-followed (cycles, tree escapes), but
        // silently skipping one would let the report claim a clean, complete scan.
        report.errors.push(ScanError {
            path: path.display().to_string(),
            operation: "symlink_skipped",
            message: "symlink not followed; scan its target explicitly".to_string(),
        });
    }
}

fn scan_text(file: &str, text: &str, out: &mut Vec<Finding>) {
    for (idx, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        for p in PATTERNS {
            // The bare `dsa` token needs PQ-aware matching so `ml-dsa` / `slh-dsa`
            // (recommended, not legacy) are not flagged; every other token is plain.
            let hit = if p.token == "dsa" {
                contains_legacy_dsa(&lower)
            } else {
                contains_token(&lower, p.token)
            };
            if hit {
                out.push(Finding {
                    file: file.to_string(),
                    line: idx + 1,
                    severity: p.severity,
                    token: p.token,
                    category: p.category,
                    recommendation: p.recommendation,
                });
            }
        }
    }
}

/// Render scan findings as CycloneDX-adjacent JSON (an array of objects).
#[must_use]
pub fn findings_to_json(findings: &[Finding]) -> Value {
    let items: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "token": f.token,
                "category": f.category,
                "recommendation": f.recommendation,
            })
        })
        .collect();
    json!({ "findings": items, "count": findings.len() })
}

/// Render a full scanner report as JSON, including fail-closed access errors.
#[must_use]
pub fn scan_report_to_json(report: &ScanReport) -> Value {
    let findings: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "token": f.token,
                "category": f.category,
                "recommendation": f.recommendation,
            })
        })
        .collect();
    let errors: Vec<Value> = report
        .errors
        .iter()
        .map(|e| {
            json!({
                "path": e.path,
                "operation": e.operation,
                "message": e.message,
            })
        })
        .collect();
    json!({
        "findings": findings,
        "count": report.findings.len(),
        "errors": errors,
        "error_count": report.errors.len(),
        "complete": report.errors.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn cbom_is_valid_cyclonedx_and_excludes_research_hqc() {
        let b = cbom();
        assert_eq!(b["bomFormat"], "CycloneDX");
        assert_eq!(b["specVersion"], "1.6");
        let comps = b["components"].as_array().unwrap();
        assert!(comps.iter().any(|c| c["name"] == "ML-KEM-768"));
        assert!(
            !comps
                .iter()
                .any(|c| c["name"].as_str().is_some_and(|name| name.contains("HQC"))),
            "the shipping CBOM must not include the isolated HQC draft-candidate research lane"
        );
        let mlkem = comps.iter().find(|c| c["name"] == "ML-KEM-768").unwrap();
        assert_eq!(
            mlkem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
            3
        );
    }

    #[test]
    fn sbom_parses_cargo_lock() {
        let lock = "version = 3\n\n[[package]]\nname = \"libcrux-ml-kem\"\nversion = \"0.0.9\"\n\n[[package]]\nname = \"x25519-dalek\"\nversion = \"2.0.1\"\n";
        let b = sbom(lock);
        let comps = b["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0]["purl"], "pkg:cargo/libcrux-ml-kem@0.0.9");
    }

    #[test]
    fn scan_flags_legacy_and_respects_boundaries() {
        let mut out = Vec::new();
        scan_text(
            "x.rs",
            "use rsa::Pkcs1v15;\nlet h = Md5::new();\nlet myrsacontext = 1; // coarse parser\nlet k = ecdsa_sign();\nx25519_only();",
            &mut out,
        );
        // RSA (line1), MD5 (line2), ECDSA (line4), X25519 advisory (line5).
        assert!(out.iter().any(|f| f.token == "rsa" && f.line == 1));
        assert!(out
            .iter()
            .any(|f| f.token == "md5" && f.severity == "critical"));
        assert!(out.iter().any(|f| f.token == "ecdsa" && f.line == 4));
        assert!(out
            .iter()
            .any(|f| f.token == "x25519" && f.severity == "advisory"));
        // "coarse" must NOT match "rsa".
        assert!(!out.iter().any(|f| f.line == 3 && f.token == "rsa"));
    }

    #[test]
    fn scan_does_not_flag_pq_ml_dsa_slh_dsa_as_legacy_dsa() {
        let mut out = Vec::new();
        scan_text(
            "x.toml",
            "ml-dsa-65 signing\nslh-dsa-sha2-256s\nlet k = ml_dsa::sign();\nlibcrux-ml-dsa = \"0.0.9\"",
            &mut out,
        );
        assert!(
            !out.iter().any(|f| f.token == "dsa"),
            "ml-dsa / slh-dsa are recommended PQ algorithms, not legacy DSA: {out:?}"
        );

        // But real legacy DSA usage IS still flagged.
        let mut legacy = Vec::new();
        scan_text(
            "y.rs",
            "use dsa::Signature;\nlet s = dsa_sign(k);",
            &mut legacy,
        );
        assert!(legacy.iter().any(|f| f.token == "dsa" && f.line == 1));
        assert!(legacy.iter().any(|f| f.token == "dsa" && f.line == 2));
    }

    #[test]
    fn scan_reports_missing_root_as_incomplete() {
        let report = scan(Path::new("/definitely/not/q-periapt/missing"));
        assert!(report.findings.is_empty());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].operation, "metadata");
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("q-periapt-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn scan_records_symlink_as_error_so_report_is_incomplete() {
        let dir = scratch_dir("symlink");
        std::fs::write(dir.join("real.rs"), "use rsa::Pkcs1v15;\n").unwrap();
        let link = dir.join("link.rs");
        std::os::unix::fs::symlink(dir.join("real.rs"), &link).unwrap();

        let report = scan(&dir);
        assert!(report.findings.iter().any(|f| f.token == "rsa"));
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].operation, "symlink_skipped");
        assert_eq!(report.errors[0].path, link.display().to_string());
        assert_eq!(scan_report_to_json(&report)["complete"], false);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn scan_never_skips_the_explicitly_named_root() {
        let parent = scratch_dir("root-skip");
        for name in ["target", ".config"] {
            let root = parent.join(name);
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("legacy.rs"), "let s = ecdsa_sign();\n").unwrap();
            // A skip-listed descendant is still pruned.
            let nested = root.join("target");
            std::fs::create_dir(&nested).unwrap();
            std::fs::write(nested.join("gen.rs"), "let h = Md5::new();\n").unwrap();

            let report = scan(&root);
            assert!(
                report.errors.is_empty(),
                "scan of root {name:?} hit errors: {:?}",
                report.errors
            );
            assert!(
                report.findings.iter().any(|f| f.token == "ecdsa"),
                "root {name:?} must be scanned even though it matches the skip rules"
            );
            assert!(
                !report.findings.iter().any(|f| f.token == "md5"),
                "descendant skip dirs under root {name:?} must still be pruned"
            );
        }
        std::fs::remove_dir_all(&parent).unwrap();
    }
}
