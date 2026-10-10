//! Generates `bindings/signed-policy-vectors.json`, consumed by Swift host tests and
//! the physical Apple-device runner. The vector proves the C/Swift binding for
//! ML-DSA-65 signed policy loading selects the expected profile and fails closed
//! on rollback or signature tampering.
//!
//! Run:
//! `cargo run -p q-periapt-ffi --example gen_signed_policy_vector > bindings/signed-policy-vectors.json`

use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_policy::{policy_signature_message, HybridSuite, Policy, PolicyResolutionError};
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
    // Default output remains byte-identical to the frozen version-2 fixture.
    // Optional VERSION [--disable-suite] produces signed SDK transition fixtures.
    let mut args = std::env::args().skip(1);
    let version = args
        .next()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "invalid policy version".to_owned())
        })
        .transpose()?
        .unwrap_or(2);
    let rejected_version = version
        .checked_add(1)
        .filter(|_| version > 0)
        .ok_or("version must be in 1..u32::MAX")?;
    let disabled = match args.next().as_deref() {
        None => false,
        Some("--disable-suite") => true,
        Some(_) => return Err("expected --disable-suite".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let policy = POLICY_TOML.replace("policy_version = 2", &format!("policy_version = {version}"));
    let policy = if disabled {
        policy.replace("ML-KEM-768", "ML-KEM-1024")
    } else {
        policy
    };
    let (sk, vk) = MlDsa65::generate([8u8; 32]);
    let mut sig = [0u8; ML_DSA_65_SIG_LEN];
    let message = policy_signature_message(policy.as_bytes());
    let n = MlDsa65
        .sign(&sk, &message, &[0u8; 32], &mut sig)
        .map_err(|err| format!("ML-DSA-65 vector signing failed: {err:?}"))?;
    let signature = sig
        .get(..n)
        .ok_or_else(|| format!("ML-DSA-65 signer returned out-of-range length: {n}"))?;
    let authenticated = Policy::load_signed(&MlDsa65, &vk, policy.as_bytes(), signature)
        .map_err(|err| format!("generated policy did not verify: {err}"))?;
    let resolved = match authenticated.resolve_suite(&[HybridSuite::MlKem768X25519]) {
        Ok(decision) if !disabled => Some(decision.resolved()),
        Err(PolicyResolutionError::NoSupportedSuite) if disabled => None,
        result => {
            return Err(format!(
                "generated policy resolved unexpectedly: {result:?}"
            ))
        }
    };

    println!("{{");
    println!("  \"schema_version\": 1,");
    println!("  \"algorithm\": \"ML-DSA-65\",");
    println!("  \"policy_toml\": \"{}\",", json_string(&policy));
    println!("  \"verification_key\": \"{}\",", hexs(&vk));
    println!("  \"signature\": \"{}\",", hexs(signature));
    println!("  \"policy_version\": {version},");
    println!("  \"decision_version\": 1,");
    println!(
        "  \"selected_suite_code\": {},",
        resolved.map_or("null".to_owned(), |value| value.suite().to_u8().to_string())
    );
    println!(
        "  \"selected_profile\": {},",
        if disabled { "null" } else { "\"ContextBound\"" }
    );
    println!(
        "  \"selected_profile_code\": {},",
        if disabled { "null" } else { "2" }
    );
    println!(
        "  \"selected_key_format_code\": {},",
        resolved.map_or("null".to_owned(), |value| value
            .key_format()
            .to_u8()
            .to_string())
    );
    println!(
        "  \"policy_digest\": \"{}\",",
        hexs(&authenticated.trusted_state().digest())
    );
    println!("  \"last_trusted_version_accept\": {version},");
    println!("  \"last_trusted_version_reject\": {rejected_version},");
    println!("  \"tamper_signature_byte\": 0");
    println!("}}");
    Ok(())
}
