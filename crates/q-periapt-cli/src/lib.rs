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

const ASSETS: &[CryptoAsset] = &[
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
        name: "HQC-256",
        primitive: "kem",
        functions: &["keygen", "encapsulate", "decapsulate"],
        nist_quantum_level: 5,
        family: "code",
        oid: None,
        note: "Code-based backup KEM for assumption diversity (enhanced; non-C2PRI -> ContextBound only).",
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
    CryptoAsset {
        name: "SLH-DSA-SHA2-256s",
        primitive: "signature",
        functions: &["keygen", "sign", "verify"],
        nist_quantum_level: 5,
        family: "hash",
        oid: None,
        note: "FIPS 205; conservative hash-based signatures for roots / firmware / long-term.",
    },
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

/// Build a CycloneDX 1.6 CBOM of the suite's cryptographic assets.
#[must_use]
pub fn cbom() -> Value {
    let components: Vec<Value> = ASSETS
        .iter()
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
pub fn scan(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    scan_path(root, &mut out);
    out
}

fn scan_path(path: &Path, out: &mut Vec<Finding>) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if SKIP_DIRS.contains(&name) || name.starts_with('.') && name != "." {
                return;
            }
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            paths.sort();
            for p in paths {
                scan_path(&p, out);
            }
        }
    } else if meta.is_file() {
        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| CODE_EXTS.contains(&e))
            .unwrap_or(false);
        if !ext_ok || meta.len() > 2 * 1024 * 1024 {
            return;
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            scan_text(&path.display().to_string(), &text, out);
        }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn cbom_is_valid_cyclonedx_with_mlkem() {
        let b = cbom();
        assert_eq!(b["bomFormat"], "CycloneDX");
        assert_eq!(b["specVersion"], "1.6");
        let comps = b["components"].as_array().unwrap();
        assert!(comps.iter().any(|c| c["name"] == "ML-KEM-768"));
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
}
