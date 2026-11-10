// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native SDK catalogue. TLS choices come from the product factory; SDK KDF
//! labels are reviewed declarations for purpose.rs's `Hkdf<Sha256>`, not a claim
//! to discover every primitive inside upstream C or the operating-system RNG.
use super::{cbom, MlDsa44, MlDsa65, MlDsa87, Signer};
use q_periapt_rustls::standard::{algorithm_inventory, CertificateAlgorithm};
use rustls::pki_types::alg_id as alg;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fmt};

/// An unsupported build/provider must not emit a partial SDK inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbomError(String);
impl fmt::Display for CbomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CbomError {}
fn failure(message: impl Into<String>) -> CbomError {
    CbomError(message.into())
}

type Assets = BTreeMap<String, Value>;
fn algorithm_mut(asset: &mut Value) -> Result<&mut Map<String, Value>, CbomError> {
    asset
        .pointer_mut("/cryptoProperties/algorithmProperties")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| failure("malformed algorithm row"))
}
fn add(
    assets: &mut Assets,
    name: &str,
    primitive: &str,
    functions: &[&str],
    level: Option<u8>,
    usage: &str,
) -> Result<(), CbomError> {
    let entry = assets.entry(name.to_owned()).or_insert_with(|| {
        let mut algorithm = Map::from_iter([
            ("primitive".to_owned(), json!(primitive)),
            ("parameterSetIdentifier".to_owned(), json!(name)),
            (
                "executionEnvironment".to_owned(),
                json!("software-plain-ram"),
            ),
            ("implementationPlatform".to_owned(), json!("generic")),
            ("cryptoFunctions".to_owned(), json!([])),
        ]);
        if let Some(level) = level {
            algorithm.insert("nistQuantumSecurityLevel".to_owned(), json!(level));
        }
        json!({"type": "cryptographic-asset", "bom-ref": format!("crypto/{}", name.to_lowercase()),
            "name": name, "description": format!("{name}; native SDK configured algorithm."),
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algorithm}})
    });
    let algorithm = algorithm_mut(entry)?;
    if algorithm.get("primitive").and_then(Value::as_str) != Some(primitive)
        || level.is_some_and(|n| {
            algorithm
                .get("nistQuantumSecurityLevel")
                .and_then(Value::as_u64)
                != Some(u64::from(n))
        })
    {
        return Err(failure(format!("conflicting CBOM metadata for {name}")));
    }
    let declared = algorithm
        .get_mut("cryptoFunctions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| failure("missing functions"))?;
    for function in functions {
        if !declared.iter().any(|v| v == function) {
            declared.push(json!(function));
        }
    }
    let properties = entry
        .as_object_mut()
        .ok_or_else(|| failure("malformed component"))?
        .entry("properties")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| failure("malformed properties"))?;
    let property = json!({"name": "qperiapt:algorithm-usage", "value": usage});
    if !properties.contains(&property) {
        properties.push(property);
    }
    Ok(())
}

fn certificate_asset(
    a: &CertificateAlgorithm,
) -> Result<(String, u8, Option<&'static str>), CbomError> {
    let key = a.public_key_algorithm.as_slice();
    let signature = a.signature_algorithm.as_slice();
    for (id, curve) in [
        (alg::ECDSA_P256, "P256"),
        (alg::ECDSA_P384, "P384"),
        (alg::ECDSA_P521, "P521"),
    ] {
        if key == id.as_ref() {
            for (id, hash) in [
                (alg::ECDSA_SHA256, "SHA-256"),
                (alg::ECDSA_SHA384, "SHA-384"),
                (alg::ECDSA_SHA512, "SHA-512"),
            ] {
                if signature == id.as_ref() {
                    return Ok((format!("ECDSA-{curve}-{hash}"), 0, Some(hash)));
                }
            }
        }
    }
    if key == alg::RSA_ENCRYPTION.as_ref() {
        for (id, hash) in [
            (alg::RSA_PSS_SHA256, "SHA-256"),
            (alg::RSA_PSS_SHA384, "SHA-384"),
            (alg::RSA_PSS_SHA512, "SHA-512"),
        ] {
            if signature == id.as_ref() {
                return Ok((format!("RSA-PSS-{hash}"), 0, Some(hash)));
            }
        }
        for (id, hash) in [
            (alg::RSA_PKCS1_SHA256, "SHA-256"),
            (alg::RSA_PKCS1_SHA384, "SHA-384"),
            (alg::RSA_PKCS1_SHA512, "SHA-512"),
        ] {
            // webpki separately supports the standard NULL and absent-parameter
            // encodings. Both are recorded below in the exact provider snapshot.
            if signature == id.as_ref() || id.as_ref().strip_suffix(&[5, 0]) == Some(signature) {
                return Ok((format!("RSA-PKCS1v1.5-{hash}"), 0, Some(hash)));
            }
        }
    }
    if key == alg::ED25519.as_ref() && signature == alg::ED25519.as_ref() {
        return Ok(("Ed25519".to_owned(), 0, Some("SHA-512")));
    }
    for (id, algorithm) in [
        (alg::ML_DSA_44, MlDsa44.algorithm()),
        (alg::ML_DSA_65, MlDsa65.algorithm()),
        (alg::ML_DSA_87, MlDsa87.algorithm()),
    ] {
        if key == id.as_ref() && signature == id.as_ref() {
            return Ok((algorithm.id().to_owned(), algorithm.nist_level(), None));
        }
    }
    Err(failure(
        "unmapped configured certificate algorithm; review the upstream provider before emitting",
    ))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Emit the native SDK algorithm catalogue, including configured TLS choices.
///
/// This describes product-level algorithms and the retained backend catalogue,
/// not every transitive internal primitive, OS entropy source or negotiated peer.
/// No NIST category is invented for hash/MAC/KDF/AEAD/combiner rows. The default
/// backends-only `cbom()` remains separately available for historical tooling.
/// Unknown configured algorithms or an incompatible SLH-DSA build fail explicitly.
pub fn native_sdk_cbom() -> Result<Value, CbomError> {
    if cfg!(feature = "slh-dsa") {
        return Err(failure(
            "native SDK CBOM profile excludes optional SLH-DSA builds",
        ));
    }
    let Value::Object(mut document) = cbom() else {
        return Err(failure("malformed backend document"));
    };
    let Some(Value::Array(components)) = document.remove("components") else {
        return Err(failure("missing backend catalogue"));
    };
    let mut assets = Assets::new();
    for mut component in components {
        let name = component
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("missing backend name"))?
            .to_owned();
        if matches!(name.as_str(), "SHA3-256" | "SHAKE-256") {
            algorithm_mut(&mut component)?.remove("nistQuantumSecurityLevel");
        }
        if assets.insert(name, component).is_some() {
            return Err(failure("duplicate backend asset"));
        }
    }
    for (name, primitive, functions) in [
        ("SHA-256", "hash", &["digest"][..]),
        ("HMAC-SHA-256", "mac", &["tag"][..]),
        ("HKDF-SHA-256", "kdf", &["keyderive"][..]),
    ] {
        add(
            &mut assets,
            name,
            primitive,
            functions,
            None,
            "q-periapt-sdk purpose-key schedule and root binding",
        )?;
    }
    add(
        &mut assets,
        &format!("Q-Periapt-{:?}", q_periapt_core::Profile::ContextBound),
        "combiner",
        &["keyderive"],
        None,
        "owned SDK ContextBound combiner; exact SHA3-256 transcript contract",
    )?;
    let inventory = algorithm_inventory();
    if inventory.key_exchange_groups != [u16::from(rustls::NamedGroup::X25519MLKEM768)] {
        return Err(failure(
            "native SDK CBOM requires exactly standard X25519MLKEM768",
        ));
    }
    add(
        &mut assets,
        "X25519MLKEM768",
        "combiner",
        &["keygen", "encapsulate", "decapsulate"],
        None,
        "RFC 10024 standard TLS; separate from ContextBound",
    )?;
    add(
        &mut assets,
        "ML-KEM-768",
        "kem",
        &["keygen", "encapsulate", "decapsulate"],
        Some(3),
        "rustls/AWS-LC standard group",
    )?;
    add(
        &mut assets,
        "X25519",
        "key-agree",
        &["keygen", "keyderive"],
        Some(0),
        "rustls/AWS-LC standard group",
    )?;
    for (suite, hash_name) in &inventory.cipher_suites {
        let (aead, expected_hash, hash) = match *suite {
            0x1301 => ("AES-128-GCM", "SHA256", "SHA-256"),
            0x1302 => ("AES-256-GCM", "SHA384", "SHA-384"),
            0x1303 => ("ChaCha20-Poly1305", "SHA256", "SHA-256"),
            _ => return Err(failure(format!("unmapped TLS cipher suite {suite:#06x}"))),
        };
        if hash_name != expected_hash {
            return Err(failure("TLS cipher-suite hash differs"));
        }
        add(
            &mut assets,
            aead,
            "ae",
            &["encrypt", "decrypt", "tag"],
            None,
            "TLS 1.3 record protection",
        )?;
        add(
            &mut assets,
            hash,
            "hash",
            &["digest"],
            None,
            "TLS 1.3 transcript and key schedule",
        )?;
        add(
            &mut assets,
            &format!("HMAC-{hash}"),
            "mac",
            &["tag"],
            None,
            "TLS 1.3 key schedule",
        )?;
        add(
            &mut assets,
            &format!("HKDF-{hash}"),
            "kdf",
            &["keyderive"],
            None,
            "TLS 1.3 key schedule",
        )?;
    }
    let mut certificates = Vec::new();
    for algorithm in &inventory.certificate_algorithms {
        let (name, level, hash) = certificate_asset(algorithm)?;
        add(
            &mut assets,
            &name,
            "signature",
            &["verify"],
            Some(level),
            "configured TLS certificate-chain verifier",
        )?;
        if let Some(hash) = hash {
            add(
                &mut assets,
                hash,
                "hash",
                &["digest"],
                None,
                "configured certificate signature verification",
            )?;
        }
        certificates.push(
            json!({"asset": name, "public_key_algorithm_der": hex(&algorithm.public_key_algorithm),
            "signature_algorithm_der": hex(&algorithm.signature_algorithm)}),
        );
    }
    // Certificate-chain support is broader than TLS 1.3 CertificateVerify.
    for code in &inventory.signature_schemes {
        use rustls::SignatureScheme as S;
        let (name, level) = match S::from(*code) {
            S::ECDSA_NISTP256_SHA256 => ("ECDSA-P256-SHA-256", 0),
            S::ECDSA_NISTP384_SHA384 => ("ECDSA-P384-SHA-384", 0),
            S::ECDSA_NISTP521_SHA512 => ("ECDSA-P521-SHA-512", 0),
            S::ED25519 => ("Ed25519", 0),
            S::RSA_PSS_SHA256 => ("RSA-PSS-SHA-256", 0),
            S::RSA_PSS_SHA384 => ("RSA-PSS-SHA-384", 0),
            S::RSA_PSS_SHA512 => ("RSA-PSS-SHA-512", 0),
            S::ML_DSA_44 => (MlDsa44.algorithm().id(), MlDsa44.algorithm().nist_level()),
            S::ML_DSA_65 => (MlDsa65.algorithm().id(), MlDsa65.algorithm().nist_level()),
            S::ML_DSA_87 => (MlDsa87.algorithm().id(), MlDsa87.algorithm().nist_level()),
            S::RSA_PKCS1_SHA256 | S::RSA_PKCS1_SHA384 | S::RSA_PKCS1_SHA512 => continue,
            _ => {
                return Err(failure(format!(
                    "unmapped configured SignatureScheme {code:#06x}"
                )))
            }
        };
        if !assets.contains_key(name) {
            return Err(failure("handshake signature lacks a certificate asset"));
        }
        add(
            &mut assets,
            name,
            "signature",
            &["sign", "verify"],
            Some(level),
            "TLS 1.3 CertificateVerify; key loaded by AWS-LC",
        )?;
    }
    let snapshot = json!({"groups": inventory.key_exchange_groups, "cipher_suites": inventory.cipher_suites,
        "signature_schemes": inventory.signature_schemes, "certificate_algorithms": certificates});
    document.insert(
        "components".to_owned(),
        json!(assets.into_values().collect::<Vec<_>>()),
    );
    let metadata = document
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| failure("missing CBOM metadata"))?;
    metadata
        .get_mut("component")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| failure("missing CBOM component"))?
        .insert("version".to_owned(), json!(env!("CARGO_PKG_VERSION")));
    metadata.insert("properties".to_owned(), json!([
        {"name": "qperiapt:cbom-profile", "value": "native-sdk-020"},
        {"name": "qperiapt:configured-tls-provider", "value": snapshot.to_string()},
        {"name": "qperiapt:inventory-scope", "value": "product algorithms and backend catalogue; not a census of transitive provider internals or OS RNG; not a negotiated-session or security-validation claim"}
    ]));
    Ok(Value::Object(document))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_certificate_algorithm_fails_instead_of_omitting_a_row() {
        assert!(certificate_asset(&CertificateAlgorithm {
            public_key_algorithm: vec![1],
            signature_algorithm: vec![2],
        })
        .is_err());
    }

    #[test]
    fn native_catalogue_covers_actual_provider_and_distinguishes_categories() {
        if cfg!(feature = "slh-dsa") {
            assert!(native_sdk_cbom().is_err());
            return;
        }
        let document = native_sdk_cbom().expect("supported native profile");
        let components = document
            .get("components")
            .and_then(Value::as_array)
            .expect("components");
        for algorithm in algorithm_inventory().certificate_algorithms {
            let (name, _, _) = certificate_asset(&algorithm).expect("known verifier");
            assert_eq!(
                components
                    .iter()
                    .filter(|c| c.get("name").and_then(Value::as_str) == Some(name.as_str()))
                    .count(),
                1
            );
        }
        for name in [
            "HKDF-SHA-256",
            "HMAC-SHA-256",
            "SHA-256",
            "AES-128-GCM",
            "AES-256-GCM",
            "ChaCha20-Poly1305",
            "SHA3-256",
            "SHAKE-256",
            "Q-Periapt-ContextBound",
        ] {
            let row = components
                .iter()
                .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
                .expect("required asset");
            let algorithm = row
                .pointer("/cryptoProperties/algorithmProperties")
                .and_then(Value::as_object)
                .expect("algorithm");
            assert!(!algorithm.contains_key("nistQuantumSecurityLevel"));
        }
        let x = components
            .iter()
            .find(|c| c.get("name").and_then(Value::as_str) == Some("X25519"))
            .expect("X25519");
        assert_eq!(
            x.pointer("/cryptoProperties/algorithmProperties/cryptoFunctions"),
            Some(&json!(["keygen", "keyderive"]))
        );
    }
}
