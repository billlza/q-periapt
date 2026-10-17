//! Reproduce PUBLIC recovery test vectors. The fixed seeds below are not issuer keys.
//! Run with an existing private temporary directory; output contains public hex only.
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_host_store::{PolicyRecoveryAuthorization, PolicyRecoveryTrust, PolicyStore};
use q_periapt_policy::policy_signature_message;
use q_periapt_sdk::Limits;
use q_periapt_sig::Signer;
use std::{
    io::{self, Write},
    path::PathBuf,
};

fn sign(key: &[u8], message: &[u8]) -> io::Result<Vec<u8>> {
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(key, message, &[0; 32], &mut signature)
        .map_err(|_| io::Error::other("test-vector signature failed"))?;
    Ok(signature)
}
fn policy(version: u32, enabled: bool) -> Vec<u8> {
    format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"{}\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n", if enabled { "ML-KEM-768" } else { "ML-KEM-1024" }).into_bytes()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::args_os()
        .nth(1)
        .ok_or_else(|| io::Error::other("private temporary directory required"))?;
    let path = PathBuf::from(directory).join("fixture-policy.redb");
    let (initial_key, initial) = MlDsa65::generate([81; 32]);
    let (recovery_key, recovery) = MlDsa65::generate([82; 32]);
    let (incoming_key, incoming) = MlDsa65::generate([83; 32]);
    let scope = [84; 32];
    let operation = [85; 32];
    let initial_policy = policy(u32::MAX, true);
    let initial_signature = sign(&initial_key, &policy_signature_message(&initial_policy))?;
    let next_policy = policy(1, false);
    let next_signature = sign(&incoming_key, &policy_signature_message(&next_policy))?;
    let current_policy = policy(2, true);
    let current_signature = sign(&incoming_key, &policy_signature_message(&current_policy))?;
    let trust = PolicyRecoveryTrust::new(scope, &initial, &recovery)?;
    let enrollment_message = trust.enrollment_message();
    let enrollment_signature = sign(&recovery_key, &enrollment_message)?;
    let mut store = PolicyStore::provision_recoverable(
        &path,
        &initial_policy,
        &initial_signature,
        &trust,
        &enrollment_signature,
        Limits::default(),
    )?;
    let request =
        store.prepare_authority_recovery(operation, &next_policy, &next_signature, &incoming)?;
    let approval_message = request.authorization_message();
    let possession_message = request.possession_message();
    let approval_signature = sign(&recovery_key, &approval_message)?;
    let possession_signature = sign(&incoming_key, &possession_message)?;
    let authorization = PolicyRecoveryAuthorization::new(
        request.clone(),
        &approval_signature,
        &possession_signature,
    )?;
    store.close();
    let values: [(&str, &[u8]); 18] = [
        ("scope", &scope),
        ("operation", &operation),
        ("initial_root", &initial),
        ("recovery_root", &recovery),
        ("incoming_root", &incoming),
        ("initial_policy", &initial_policy),
        ("initial_signature", &initial_signature),
        ("next_policy", &next_policy),
        ("next_signature", &next_signature),
        ("current_policy", &current_policy),
        ("current_signature", &current_signature),
        ("enrollment_message", &enrollment_message),
        ("enrollment_signature", &enrollment_signature),
        ("request", &request.to_bytes()),
        ("approval_message", &approval_message),
        ("possession_message", &possession_message),
        ("approval_signature", &approval_signature),
        ("possession_signature", &possession_signature),
    ];
    let mut output = io::stdout().lock();
    writeln!(output, "{{")?;
    for (name, bytes) in values {
        writeln!(output, "  \"{name}\": \"{}\",", hex(bytes))?;
    }
    writeln!(
        output,
        "  \"authorization\": \"{}\"\n}}",
        hex(&authorization.to_bytes())
    )?;
    Ok(())
}
