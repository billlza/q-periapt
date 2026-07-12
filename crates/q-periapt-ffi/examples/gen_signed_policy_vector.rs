//! Generates `bindings/signed-policy-vectors.json`, consumed by Swift host tests and
//! the physical Apple-device runner. The vector proves the C/Swift binding for
//! ML-DSA-65 signed policy loading selects the expected profile and fails closed
//! on rollback or signature tampering.
//!
//! Run:
//! `cargo run -p q-periapt-ffi --example gen_signed_policy_vector > bindings/signed-policy-vectors.json`

use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_policy::{policy_signature_message, HybridSuite, Policy};
use q_periapt_sig::Signer;

const POLICY_TOML: &str = "schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\n\
default_profile = \"ContextBound\"\n\
allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
allowed_sigs = [\"ML-DSA-65\"]\n\
deprecated = []\n";

fn hexs(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn json_string(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn main() -> Result<(), String> {
    let (sk, vk) = MlDsa65::generate([8u8; 32]);
    let mut sig = [0u8; ML_DSA_65_SIG_LEN];
    let message = policy_signature_message(POLICY_TOML.as_bytes());
    let n = MlDsa65
        .sign(&sk, &message, &[0u8; 32], &mut sig)
        .map_err(|err| format!("ML-DSA-65 vector signing failed: {err:?}"))?;
    let signature = sig
        .get(..n)
        .ok_or_else(|| format!("ML-DSA-65 signer returned out-of-range length: {n}"))?;
    let authenticated = Policy::load_signed(&MlDsa65, &vk, POLICY_TOML.as_bytes(), signature)
        .map_err(|err| format!("generated policy did not verify: {err}"))?;
    let decision = authenticated
        .resolve_suite(&[HybridSuite::MlKem768X25519])
        .map_err(|err| format!("generated policy did not resolve: {err}"))?;
    let resolved = decision.resolved();

    println!("{{");
    println!("  \"schema_version\": 1,");
    println!("  \"algorithm\": \"ML-DSA-65\",");
    println!("  \"policy_toml\": \"{}\",", json_string(POLICY_TOML));
    println!("  \"verification_key\": \"{}\",", hexs(&vk));
    println!("  \"signature\": \"{}\",", hexs(signature));
    println!("  \"policy_version\": {},", resolved.policy_version());
    println!("  \"decision_version\": 1,");
    println!("  \"selected_suite_code\": {},", resolved.suite().to_u8());
    println!("  \"selected_profile\": \"ContextBound\",");
    println!("  \"selected_profile_code\": 2,");
    println!(
        "  \"selected_key_format_code\": {},",
        resolved.key_format().to_u8()
    );
    println!(
        "  \"policy_digest\": \"{}\",",
        hexs(&decision.trusted_state().digest())
    );
    println!("  \"last_trusted_version_accept\": 2,");
    println!("  \"last_trusted_version_reject\": 3,");
    println!("  \"tamper_signature_byte\": 0");
    println!("}}");
    Ok(())
}
