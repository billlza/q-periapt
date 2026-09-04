#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-cli (library)
//!
//! Auditability & migration tooling for the PQ/T hybrid suite:
//! - [`cbom`] — a CycloneDX 1.6 **Crypto** Bill of Materials of the suite's
//!   cryptographic assets (algorithms, parameter sets, quantum-security levels).
//! - [`sbom`] — a CycloneDX 1.6 SBOM derived from a `Cargo.lock`.
//! - [`scan`] — a migration scanner that flags legacy / quantum-vulnerable
//!   primitives (RSA, ECDSA, ECDH, DSA, NIST curves, MD5/SHA-1, 3DES, RC4) and
//!   recommends a PQ/T replacement + policy.
//!
//! Output is plain `serde_json` so it diffs cleanly and needs no derive.

use serde_json::{json, Value};
use std::path::Path;

/// A cryptographic asset of the suite, used to build the CBOM.
struct CryptoAsset {
    name: &'static str,
    primitive: &'static str, // CycloneDX algorithmProperties.primitive
    functions: &'static [&'static str],
    /// NIST PQ security level 1/3/5, or 0 for a (quantum-vulnerable) classical alg.
    nist_quantum_level: u8,
    family: &'static str, // lattice / elliptic-curve / hash / code
    oid: Option<&'static str>,
    note: &'static str,
}

/// Key-establishment and ML-DSA assets, present in every build.
///
/// This list is a statement about the algorithms `q-periapt-backends` ships,
/// and the CLI deliberately has no dependency edge to it
/// (`docs/ARCHITECTURE.md` §12). What keeps the two in step is
/// `the_cbom_lists_exactly_the_algorithms_the_shipped_backends_report`, which
/// links the real backends as a dev-dependency and reads their own reported
/// identifiers, so adding or removing one fails here rather than silently
/// desynchronising a released CBOM.
const KEY_AND_SIGNATURE_ASSETS: &[CryptoAsset] = &[
    CryptoAsset {
        name: "ML-KEM-512",
        primitive: "kem",
        functions: &["keygen", "encapsulate", "decapsulate"],
        nist_quantum_level: 1,
        family: "lattice",
        oid: Some("2.16.840.1.101.3.4.4.1"),
        note: "FIPS 203; smallest parameter set, for agility at a level-1 floor.",
    },
    CryptoAsset {
        name: "ML-KEM-768",
        primitive: "kem",
        functions: &["keygen", "encapsulate", "decapsulate"],
        nist_quantum_level: 3,
        family: "lattice",
        oid: Some("2.16.840.1.101.3.4.4.2"),
        note: "FIPS 203; default PQ KEM component (C2PRI).",
    },
    CryptoAsset {
        name: "ML-KEM-1024",
        primitive: "kem",
        functions: &["keygen", "encapsulate", "decapsulate"],
        nist_quantum_level: 5,
        family: "lattice",
        oid: Some("2.16.840.1.101.3.4.4.3"),
        note: "FIPS 203; enhanced (L5) PQ KEM component.",
    },
    CryptoAsset {
        name: "X25519",
        primitive: "key-agree",
        functions: &["keygen", "key-agree"],
        nist_quantum_level: 0,
        family: "elliptic-curve",
        oid: Some("1.3.101.110"),
        note: "RFC 7748; classical (quantum-vulnerable) — used ONLY as a hybrid partner.",
    },
    CryptoAsset {
        name: "ML-DSA-44",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 2,
        family: "lattice",
        oid: Some("2.16.840.1.101.3.4.3.17"),
        note: "FIPS 204; smallest parameter set, for agility at a level-2 floor.",
    },
    CryptoAsset {
        name: "ML-DSA-65",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 3,
        family: "lattice",
        oid: Some("2.16.840.1.101.3.4.3.18"),
        note: "FIPS 204; general-purpose signatures.",
    },
    CryptoAsset {
        name: "ML-DSA-87",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 5,
        family: "lattice",
        oid: Some("2.16.840.1.101.3.4.3.19"),
        note: "FIPS 204; enhanced (L5) signatures.",
    },
];

/// SLH-DSA assets, present only when the `slh-dsa` backends are compiled.
///
/// `q-periapt-backends` gates all three parameter sets behind its
/// off-by-default `slh-dsa` feature, which this crate's feature of the same
/// name forwards to. A CBOM emitted by the default build must therefore not
/// claim them, and one emitted with the feature on must claim all three.
#[cfg(feature = "slh-dsa")]
const SLH_DSA_ASSETS: &[CryptoAsset] = &[
    CryptoAsset {
        name: "SLH-DSA-SHA2-128s",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 1,
        family: "hash",
        oid: None,
        note: "FIPS 205; conservative hash-based signatures for roots / firmware / long-term.",
    },
    CryptoAsset {
        name: "SLH-DSA-SHA2-192s",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 3,
        family: "hash",
        oid: None,
        note: "FIPS 205; conservative hash-based signatures for roots / firmware / long-term.",
    },
    CryptoAsset {
        name: "SLH-DSA-SHA2-256s",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 5,
        family: "hash",
        oid: None,
        note: "FIPS 205; conservative hash-based signatures for roots / firmware / long-term.",
    },
];

#[cfg(not(feature = "slh-dsa"))]
const SLH_DSA_ASSETS: &[CryptoAsset] = &[];

/// Hash and XOF assets, present in every build.
const HASH_ASSETS: &[CryptoAsset] = &[
    CryptoAsset {
        name: "SHA3-256",
        primitive: "hash",
        functions: &["digest"],
        nist_quantum_level: 0,
        family: "hash",
        oid: Some("2.16.840.1.101.3.4.2.8"),
        note: "FIPS 202; combiner hash.",
    },
    CryptoAsset {
        name: "SHAKE-256",
        primitive: "xof",
        functions: &["digest"],
        nist_quantum_level: 0,
        family: "hash",
        oid: Some("2.16.840.1.101.3.4.2.12"),
        note: "FIPS 202; XOF for key derivation / expansion.",
    },
];

/// Every cryptographic asset this build ships, in inventory order.
fn assets() -> impl Iterator<Item = &'static CryptoAsset> {
    KEY_AND_SIGNATURE_ASSETS
        .iter()
        .chain(SLH_DSA_ASSETS)
        .chain(HASH_ASSETS)
}

/// Build a CycloneDX 1.6 CBOM of the suite's cryptographic assets.
#[must_use]
pub fn cbom() -> Value {
    let components: Vec<Value> = assets()
        .map(|a| {
            let algo = json!({
                "primitive": a.primitive,
                "parameterSetIdentifier": a.name,
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
                "cryptoFunctions": a.functions,
                "nistQuantumSecurityLevel": a.nist_quantum_level,
            });
            let mut crypto = serde_json::Map::new();
            crypto.insert("assetType".to_string(), json!("algorithm"));
            crypto.insert("algorithmProperties".to_string(), algo);
            if let Some(oid) = a.oid {
                crypto.insert("oid".to_string(), json!(oid));
            }
            json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto/{}", a.name.to_lowercase()),
                "name": a.name,
                "description": format!("{} ({} family). {}", a.name, a.family, a.note),
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

    /// Every asset name the CBOM this build emits claims.
    fn cbom_names() -> std::collections::BTreeSet<String> {
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
    /// released CBOM claiming an algorithm the suite does not ship, or
    /// omitting one it does. The `slh-dsa` feature is the backends' own, so
    /// this set moves with the gate exactly as the CBOM must.
    fn shipped_algorithm_ids() -> std::collections::BTreeSet<String> {
        use q_periapt_backends::{
            MlDsa44, MlDsa65, MlDsa87, MlKem1024, MlKem512, MlKem768, MlKem768XWingSeed,
            Sha3_256Xof, X25519,
        };
        use q_periapt_core::{Kem, Xof256};
        use q_periapt_sig::Signer;

        let mut ids = std::collections::BTreeSet::new();
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
        // `Xof256` carries no algorithm identifier, so the combiner hash and
        // the XOF are named here; linking the backend that provides both still
        // makes its removal a compile failure.
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
            // claimed one would tell an auditor the released package contains
            // an algorithm it does not.
            assert!(
                slh.is_empty(),
                "default build must claim no SLH-DSA: {slh:?}"
            );
        }
    }

    #[test]
    fn every_cbom_row_reports_the_level_the_policy_layer_enforces() {
        for component in cbom()["components"].as_array().unwrap() {
            let name = component["name"].as_str().unwrap();
            let level = component["cryptoProperties"]["algorithmProperties"]
                ["nistQuantumSecurityLevel"]
                .as_u64()
                .unwrap();
            // Level 0 is this CBOM's spelling of "not a leveled post-quantum
            // algorithm", which is exactly what the policy layer answers
            // `None` for -- the traditional hybrid partner and the hashes.
            let expected = u64::from(q_periapt_policy::nist_level(name).unwrap_or(0));
            assert_eq!(level, expected, "{name} claims the wrong NIST level");
        }
    }

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
