#![warn(missing_docs)]

//! # q-periapt-wasm
//!
//! WASM bindings for the PQ/T hybrid suite, exposing the same one Rust core to
//! JavaScript/TypeScript. Randomness (encapsulation coins, seeds) is supplied by
//! the JS caller as `Uint8Array`, so no in-WASM entropy source is required and the
//! operations stay deterministic / KAT-able.
//!
//! Build: `wasm-pack build crates/q-periapt-wasm --target web` (see `README.md`).

#[cfg(feature = "signed-policy")]
use q_periapt_backends::MlDsa65;
use q_periapt_backends::{
    MlKem768, MlKem768XWingSeed, Sha3_256Xof, DEFAULT_SUITE_ID, ML_KEM_768_CT_LEN,
    ML_KEM_768_KEYGEN_SEED_LEN, ML_KEM_768_XWING_SEED_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{
    combine as core_combine, encode_policy_bound_context, policy_bound_context_len, secure_wipe,
    CombineInput, Profile,
};
use q_periapt_kem::HybridKem;
#[cfg(feature = "signed-policy")]
use q_periapt_policy::{HybridSuite, Policy, TrustedPolicyState};
use wasm_bindgen::prelude::*;

fn profile(code: u8) -> Result<Profile, JsError> {
    Profile::from_u8(code).ok_or_else(|| JsError::new("invalid profile code"))
}

struct ParsedPolicyDecision {
    profile: Profile,
    policy_version: u32,
    policy_digest: [u8; 32],
}

fn parse_policy_decision(encoded: &[u8]) -> Result<ParsedPolicyDecision, JsError> {
    if encoded.len() != 40 || encoded.first() != Some(&1) || encoded.get(1) != Some(&1) {
        return Err(JsError::new("invalid or unsupported policy decision"));
    }
    let profile = profile(
        *encoded
            .get(2)
            .ok_or_else(|| JsError::new("missing policy profile"))?,
    )?;
    let expected_key_format = match profile {
        Profile::ContextBound => 1,
        Profile::CompatXWing => 2,
    };
    if encoded.get(3) != Some(&expected_key_format) {
        return Err(JsError::new("policy profile/key-format mismatch"));
    }
    let policy_version = u32::from_be_bytes(
        encoded
            .get(4..8)
            .ok_or_else(|| JsError::new("missing policy version"))?
            .try_into()
            .map_err(|_| JsError::new("invalid policy version"))?,
    );
    if policy_version == 0 {
        return Err(JsError::new("zero policy version"));
    }
    let policy_digest = encoded
        .get(8..)
        .ok_or_else(|| JsError::new("missing policy digest"))?
        .try_into()
        .map_err(|_| JsError::new("invalid policy digest"))?;
    Ok(ParsedPolicyDecision {
        profile,
        policy_version,
        policy_digest,
    })
}

fn bound_policy_context(
    decision: &ParsedPolicyDecision,
    application_context: &[u8],
) -> Result<Vec<u8>, JsError> {
    if decision.profile != Profile::ContextBound {
        return Err(JsError::new(
            "CompatXWing cannot bind an authenticated policy digest",
        ));
    }
    let len = policy_bound_context_len(application_context.len())
        .ok_or_else(|| JsError::new("application context too large"))?;
    let mut context = vec![0u8; len];
    encode_policy_bound_context(&decision.policy_digest, application_context, &mut context)
        .map_err(|_| JsError::new("policy context encoding failed"))?;
    Ok(context)
}

/// The only suite the fixed WASM hybrid API implements. The combiner binds `suite_id`, so
/// `encapsulate`/`decapsulate` reject any other value: a caller must not bind false agility
/// metadata (e.g. claim `ML-KEM-1024`) into a key actually derived from ML-KEM-768 + X25519.
fn wasm_suite_id() -> &'static [u8] {
    DEFAULT_SUITE_ID
}

/// Return the Rust crate version used to build this WASM module.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Return the fixed suite id implemented by this WASM module.
#[wasm_bindgen]
pub fn fixed_suite_id() -> Vec<u8> {
    wasm_suite_id().to_vec()
}

/// Maximum exact signed-policy document size accepted by this module.
#[cfg(feature = "signed-policy")]
#[wasm_bindgen]
pub fn max_signed_policy_bytes() -> usize {
    q_periapt_policy::MAX_SIGNED_POLICY_BYTES
}

/// Maximum application-context size accepted by policy-bound operations.
#[wasm_bindgen]
pub fn max_application_context_bytes() -> usize {
    q_periapt_core::MAX_APPLICATION_CONTEXT_BYTES
}

/// Derive a combined secret directly from the serialized combiner inputs — the
/// cross-platform reference-vector entry point. `input` is the nine fields, each
/// 8-byte big-endian length-prefixed (suite_id, policy_version as 4-byte BE, ss_pq,
/// ss_trad, ct_pq, pk_pq, ct_trad, pk_trad, context); `profile_code` is 1 or 2. Uses
/// the single `CombineInput::from_transport` decoder shared with the C ABI face.
#[wasm_bindgen]
pub fn combine(profile_code: u8, input: &[u8]) -> Result<Vec<u8>, JsError> {
    let profile = profile(profile_code)?;
    let ci = CombineInput::from_transport(input)
        .ok_or_else(|| JsError::new("malformed combine input"))?;
    let secret =
        core_combine::<Sha3_256Xof>(profile, &ci).map_err(|_| JsError::new("combine failed"))?;
    Ok(secret.as_bytes().to_vec())
}

/// Verify a detached, domain-separated signed policy and atomically resolve it against this
/// module's fixed ML-KEM-768 + X25519 suite.
///
/// Returns 40 canonical bytes: `decision_version || suite_code || profile_code ||
/// key_format_code || policy_version_be || SHA3-256(exact_policy_bytes)`. Pass an empty
/// `last_trusted_state` on first load; thereafter persist and pass the returned bytes 4..40.
/// A policy requiring another suite, a rollback, or different bytes reusing the same version is
/// rejected instead of silently executing the fixed suite.
///
/// Behind the off-by-default `signed-policy` cargo feature: it links an ML-DSA verifier, which
/// roughly quadruples the module, so the lean default build ships without it.
#[cfg(feature = "signed-policy")]
#[wasm_bindgen]
pub fn decision_from_signed_policy(
    toml: &[u8],
    signature: &[u8],
    verification_key: &[u8],
    last_trusted_state: &[u8],
) -> Result<Vec<u8>, JsError> {
    let last_state = if last_trusted_state.is_empty() {
        None
    } else {
        Some(
            TrustedPolicyState::decode(last_trusted_state)
                .map_err(|e| JsError::new(&format!("trusted policy state rejected: {e}")))?,
        )
    };
    let policy = Policy::load_signed_monotonic(
        &MlDsa65,
        verification_key,
        toml,
        signature,
        last_state.as_ref(),
    )
    .map_err(|e| JsError::new(&format!("policy rejected: {e}")))?;
    let decision = policy
        .resolve_suite(&[HybridSuite::MlKem768X25519])
        .map_err(|e| JsError::new(&format!("policy suite rejected: {e}")))?;
    let resolved = decision.resolved();
    if resolved.profile() != Profile::ContextBound {
        return Err(JsError::new(
            "signed-policy execution requires ContextBound policy-digest binding",
        ));
    }
    let mut encoded = Vec::with_capacity(40);
    encoded.extend_from_slice(&[
        1,
        resolved.suite().to_u8(),
        resolved.profile().to_u8(),
        resolved.key_format().to_u8(),
    ]);
    encoded.extend_from_slice(&resolved.policy_version().to_be_bytes());
    encoded.extend_from_slice(&decision.trusted_state().digest());
    debug_assert_eq!(encoded.len(), 40);
    Ok(encoded)
}

/// A generated key pair (`sk`, `pk`) exposed to JS.
#[wasm_bindgen]
pub struct KeyPair {
    sk: Vec<u8>,
    pk: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // `sk` is secret key material; wipe the WASM-side copy on drop (`pk` is public). The
        // copy handed to JS via the getter is outside our control, but the linear-memory
        // original must not linger.
        secure_wipe(&mut self.sk);
    }
}

#[wasm_bindgen]
impl KeyPair {
    /// The secret/signing/decapsulation key bytes.
    #[wasm_bindgen(getter)]
    pub fn sk(&self) -> Vec<u8> {
        self.sk.clone()
    }
    /// The public/verification/encapsulation key bytes.
    #[wasm_bindgen(getter)]
    pub fn pk(&self) -> Vec<u8> {
        self.pk.clone()
    }
}

/// The result of an encapsulation: both ciphertexts and the combined secret.
#[wasm_bindgen]
pub struct EncapResult {
    ct_pq: Vec<u8>,
    ct_trad: Vec<u8>,
    secret: Vec<u8>,
}

impl Drop for EncapResult {
    fn drop(&mut self) {
        // `secret` is the session key; wipe the WASM-side copy on drop (ciphertexts are public).
        secure_wipe(&mut self.secret);
    }
}

#[wasm_bindgen]
impl EncapResult {
    /// ML-KEM-768 ciphertext.
    #[wasm_bindgen(getter)]
    pub fn ct_pq(&self) -> Vec<u8> {
        self.ct_pq.clone()
    }
    /// X25519 ciphertext (ephemeral public key).
    #[wasm_bindgen(getter)]
    pub fn ct_trad(&self) -> Vec<u8> {
        self.ct_trad.clone()
    }
    /// The 32-byte combined hybrid secret.
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
}

/// Deterministically derive an ML-KEM-768 key pair from a 64-byte seed.
#[wasm_bindgen]
pub fn mlkem768_keypair(seed: &[u8]) -> Result<KeyPair, JsError> {
    let s = <[u8; ML_KEM_768_KEYGEN_SEED_LEN]>::try_from(seed)
        .map_err(|_| JsError::new("seed must be 64 bytes"))?;
    let (sk, pk) = MlKem768::generate(s);
    Ok(KeyPair {
        sk: sk.to_vec(),
        pk: pk.to_vec(),
    })
}

/// Deterministically derive an X-Wing-compatible ML-KEM-768 key pair from a 32-byte seed.
///
/// The returned secret key is the 32-byte seed accepted by `CompatXWing`
/// decapsulation. Use `mlkem768_keypair`'s expanded 2400-byte secret key with
/// `ContextBound`.
#[wasm_bindgen]
pub fn mlkem768_xwing_keypair(seed: &[u8]) -> Result<KeyPair, JsError> {
    let s = <[u8; ML_KEM_768_XWING_SEED_LEN]>::try_from(seed)
        .map_err(|_| JsError::new("seed must be 32 bytes"))?;
    let (sk, pk) = MlKem768XWingSeed::generate(s);
    Ok(KeyPair {
        sk: sk.to_vec(),
        pk: pk.to_vec(),
    })
}

/// Deterministically derive an X25519 key pair from a 32-byte scalar.
#[wasm_bindgen]
pub fn x25519_keypair(secret: &[u8]) -> Result<KeyPair, JsError> {
    let s = <[u8; X25519_LEN]>::try_from(secret)
        .map_err(|_| JsError::new("secret must be 32 bytes"))?;
    let (sk, pk) = X25519::generate(s);
    Ok(KeyPair {
        sk: sk.to_vec(),
        pk: pk.to_vec(),
    })
}

/// Hybrid encapsulation. `rand_pq`/`rand_trad` are 32-byte coins from the caller.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encapsulate(
    profile_code: u8,
    suite_id: &[u8],
    policy_version: u32,
    pk_pq: &[u8],
    pk_trad: &[u8],
    context: &[u8],
    rand_pq: &[u8],
    rand_trad: &[u8],
) -> Result<EncapResult, JsError> {
    let prof = profile(profile_code)?;
    if suite_id != wasm_suite_id() {
        return Err(JsError::new(
            "suite_id does not match this build (ML-KEM-768+X25519)",
        ));
    }
    let mut ct_pq = vec![0u8; ML_KEM_768_CT_LEN];
    let mut ct_trad = vec![0u8; X25519_LEN];
    let secret = match prof {
        Profile::ContextBound => {
            let (pq, trad) = (MlKem768, X25519);
            let kem =
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, prof, suite_id, policy_version)
                    .map_err(|_| JsError::new("policy denied"))?;
            kem.encapsulate(
                pk_pq,
                pk_trad,
                context,
                rand_pq,
                rand_trad,
                &mut ct_pq,
                &mut ct_trad,
            )
            .map_err(|_| JsError::new("encapsulate failed"))?
        }
        Profile::CompatXWing => {
            let (pq, trad) = (MlKem768XWingSeed, X25519);
            let kem =
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, prof, suite_id, policy_version)
                    .map_err(|_| JsError::new("policy denied"))?;
            kem.encapsulate(
                pk_pq,
                pk_trad,
                context,
                rand_pq,
                rand_trad,
                &mut ct_pq,
                &mut ct_trad,
            )
            .map_err(|_| JsError::new("encapsulate failed"))?
        }
    };
    Ok(EncapResult {
        ct_pq,
        ct_trad,
        secret: secret.as_bytes().to_vec(),
    })
}

/// Hybrid decapsulation. Returns the 32-byte session secret.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn decapsulate(
    profile_code: u8,
    suite_id: &[u8],
    policy_version: u32,
    sk_pq: &[u8],
    ct_pq: &[u8],
    pk_pq: &[u8],
    sk_trad: &[u8],
    ct_trad: &[u8],
    pk_trad: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsError> {
    let prof = profile(profile_code)?;
    if suite_id != wasm_suite_id() {
        return Err(JsError::new(
            "suite_id does not match this build (ML-KEM-768+X25519)",
        ));
    }
    let secret = match prof {
        Profile::ContextBound => {
            let (pq, trad) = (MlKem768, X25519);
            let kem =
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, prof, suite_id, policy_version)
                    .map_err(|_| JsError::new("policy denied"))?;
            kem.decapsulate(sk_pq, ct_pq, pk_pq, sk_trad, ct_trad, pk_trad, context)
                .map_err(|_| JsError::new("decapsulate failed"))?
        }
        Profile::CompatXWing => {
            let (pq, trad) = (MlKem768XWingSeed, X25519);
            let kem =
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, prof, suite_id, policy_version)
                    .map_err(|_| JsError::new("policy denied"))?;
            kem.decapsulate(sk_pq, ct_pq, pk_pq, sk_trad, ct_trad, pk_trad, context)
                .map_err(|_| JsError::new("decapsulate failed"))?
        }
    };
    Ok(secret.as_bytes().to_vec())
}

/// Hybrid encapsulation controlled by one authenticated policy decision.
///
/// The exact signed-policy digest and `application_context` are canonically
/// committed into the ContextBound KDF input. CompatXWing decisions are refused
/// because that profile intentionally ignores context.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encapsulate_with_decision(
    decision: &[u8],
    pk_pq: &[u8],
    pk_trad: &[u8],
    application_context: &[u8],
    rand_pq: &[u8],
    rand_trad: &[u8],
) -> Result<EncapResult, JsError> {
    let decision = parse_policy_decision(decision)?;
    let context = bound_policy_context(&decision, application_context)?;
    encapsulate(
        decision.profile.to_u8(),
        wasm_suite_id(),
        decision.policy_version,
        pk_pq,
        pk_trad,
        &context,
        rand_pq,
        rand_trad,
    )
}

/// Hybrid decapsulation controlled by the same authenticated decision and
/// policy-bound application context as [`encapsulate_with_decision`].
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn decapsulate_with_decision(
    decision: &[u8],
    sk_pq: &[u8],
    ct_pq: &[u8],
    pk_pq: &[u8],
    sk_trad: &[u8],
    ct_trad: &[u8],
    pk_trad: &[u8],
    application_context: &[u8],
) -> Result<Vec<u8>, JsError> {
    let decision = parse_policy_decision(decision)?;
    let context = bound_policy_context(&decision, application_context)?;
    decapsulate(
        decision.profile.to_u8(),
        wasm_suite_id(),
        decision.policy_version,
        sk_pq,
        ct_pq,
        pk_pq,
        sk_trad,
        ct_trad,
        pk_trad,
        &context,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    // Embedded at compile time so the SAME check runs on the host AND on real
    // wasm (no filesystem in wasm32).
    const SHARED_VECTOR: &str = include_str!("../../../bindings/shared-test-vectors.json");

    fn field(json: &str, k: &str) -> Vec<u8> {
        let pat = format!("\"{k}\"");
        let i = json.find(&pat).unwrap();
        let rest = &json[i + pat.len()..];
        let q1 = rest.find('"').unwrap();
        let q2 = rest[q1 + 1..].find('"').unwrap();
        let hex = &rest[q1 + 1..q1 + 1 + q2];
        (0..hex.len())
            .step_by(2)
            .map(|j| u8::from_str_radix(&hex[j..j + 2], 16).unwrap())
            .collect()
    }

    fn check_shared_vector() {
        let j = SHARED_VECTOR;
        let secret = decapsulate(
            2,
            &field(j, "suite_id"),
            1,
            &field(j, "sk_pq"),
            &field(j, "ct_pq"),
            &field(j, "pk_pq"),
            &field(j, "sk_trad"),
            &field(j, "ct_trad"),
            &field(j, "pk_trad"),
            &field(j, "context"),
        )
        .expect("WASM decapsulation should match the shared vector");
        assert_eq!(
            secret,
            field(j, "secret"),
            "WASM API must match the Rust core"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn metadata_matches_backend_suite() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(fixed_suite_id(), b"ML-KEM-768+X25519".to_vec());
        assert_eq!(max_application_context_bytes(), 65_536);
    }

    // Runs on actual wasm via `wasm-pack test --node crates/q-periapt-wasm`.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn metadata_matches_backend_suite_wasm() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(fixed_suite_id(), b"ML-KEM-768+X25519".to_vec());
        assert_eq!(max_application_context_bytes(), 65_536);
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn policy_context_cap_accepts_boundary_and_rejects_oversize_wasm() {
        let decision = ParsedPolicyDecision {
            profile: Profile::ContextBound,
            policy_version: 1,
            policy_digest: [0xA5; 32],
        };
        let boundary = vec![0x11; max_application_context_bytes()];
        assert!(bound_policy_context(&decision, &boundary).is_ok());
        let oversized = vec![0x22; max_application_context_bytes() + 1];
        assert!(bound_policy_context(&decision, &oversized).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decapsulate_matches_shared_vector() {
        check_shared_vector();
    }

    // Runs on actual wasm via `wasm-pack test --node crates/q-periapt-wasm`.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn decapsulate_matches_shared_vector_wasm() {
        check_shared_vector();
    }

    const COMBINE_VECTORS: &str = include_str!("../../../bindings/contextbound-vectors.txt");

    fn check_combine_vectors() {
        let hex = |s: &str| {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let mut n = 0;
        for line in COMBINE_VECTORS.lines().filter(|l| !l.trim().is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let got = combine(p[0].parse::<u8>().unwrap(), &hex(p[1])).unwrap();
            assert_eq!(got, hex(p[2]), "WASM combine K mismatch for: {line}");
            n += 1;
        }
        assert_eq!(n, 6);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn combine_matches_reference_vectors() {
        check_combine_vectors();
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn combine_matches_reference_vectors_wasm() {
        check_combine_vectors();
    }

    fn check_keypair_encap_decap_roundtrip() {
        // Cover the WASM surface the vector tests skip — mlkem768_keypair, x25519_keypair,
        // and encapsulate — via a self-consistency roundtrip (encap then decap must agree),
        // independent of the shared vector's keygen seeds. Catches a marshalling regression
        // in the KeyPair/EncapResult getters or the &[u8] -> [u8;N] try_from paths.
        let kp_pq = mlkem768_keypair(&[7u8; ML_KEM_768_KEYGEN_SEED_LEN]).unwrap();
        let kp_x = x25519_keypair(&[9u8; X25519_LEN]).unwrap();
        let suite = b"ML-KEM-768+X25519";
        let ctx = b"wasm-roundtrip-ctx";
        let enc = encapsulate(
            2,
            suite,
            1,
            &kp_pq.pk(),
            &kp_x.pk(),
            ctx,
            &[3u8; 32],
            &[5u8; 32],
        )
        .unwrap();
        let dec = decapsulate(
            2,
            suite,
            1,
            &kp_pq.sk(),
            &enc.ct_pq(),
            &kp_pq.pk(),
            &kp_x.sk(),
            &enc.ct_trad(),
            &kp_x.pk(),
            ctx,
        )
        .unwrap();
        assert_eq!(enc.secret(), dec, "WASM keypair/encap/decap must agree");
        assert_ne!(dec, vec![0u8; 32], "secret must be non-trivial");
    }

    fn check_xwing_seed_keypair_compat_roundtrip() {
        let kp_pq = mlkem768_xwing_keypair(&[7u8; ML_KEM_768_XWING_SEED_LEN]).unwrap();
        let kp_x = x25519_keypair(&[9u8; X25519_LEN]).unwrap();
        let suite = b"ML-KEM-768+X25519";
        let enc = encapsulate(
            1,
            suite,
            1,
            &kp_pq.pk(),
            &kp_x.pk(),
            b"",
            &[3u8; 32],
            &[5u8; 32],
        )
        .unwrap();
        let dec = decapsulate(
            1,
            suite,
            1,
            &kp_pq.sk(),
            &enc.ct_pq(),
            &kp_pq.pk(),
            &kp_x.sk(),
            &enc.ct_trad(),
            &kp_x.pk(),
            b"",
        )
        .unwrap();
        assert_eq!(
            enc.secret(),
            dec,
            "WASM CompatXWing seed-dk keypair/encap/decap must agree"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn keypair_encap_decap_roundtrip() {
        check_keypair_encap_decap_roundtrip();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn xwing_seed_keypair_compat_roundtrip() {
        check_xwing_seed_keypair_compat_roundtrip();
    }

    #[cfg(feature = "signed-policy")]
    fn check_decision_from_signed_policy() {
        // A signed floor-3 / ContextBound policy must resolve the complete fixed-suite decision.
        use q_periapt_backends::ML_DSA_65_SIG_LEN;
        use q_periapt_policy::policy_signature_message;
        use q_periapt_sig::Signer;
        let policy_toml = "schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\n\
            default_profile = \"ContextBound\"\n\
            allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
            allowed_sigs = [\"ML-DSA-65\"]\n\
            deprecated = []\n";
        let (sk, vk) = MlDsa65::generate([4u8; 32]);
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let message = policy_signature_message(policy_toml.as_bytes());
        let n = MlDsa65.sign(&sk, &message, &[0u8; 32], &mut sig).unwrap();
        let decision =
            decision_from_signed_policy(policy_toml.as_bytes(), &sig[..n], &vk, &[]).unwrap();
        assert_eq!(decision.len(), 40);
        assert_eq!(&decision[..4], &[1, 1, 2, 1]);
        assert_eq!(&decision[4..8], &2u32.to_be_bytes());
        let reapplied =
            decision_from_signed_policy(policy_toml.as_bytes(), &sig[..n], &vk, &decision[4..])
                .unwrap();
        assert_eq!(decision, reapplied);

        let kp_pq = mlkem768_keypair(&[9u8; ML_KEM_768_KEYGEN_SEED_LEN]).unwrap();
        let kp_x = x25519_keypair(&[10u8; X25519_LEN]).unwrap();
        let application_context = b"wasm-policy-context";
        let enc = encapsulate_with_decision(
            &decision,
            &kp_pq.pk(),
            &kp_x.pk(),
            application_context,
            &[11u8; 32],
            &[12u8; 32],
        )
        .unwrap();
        let dec = decapsulate_with_decision(
            &decision,
            &kp_pq.sk(),
            &enc.ct_pq(),
            &kp_pq.pk(),
            &kp_x.sk(),
            &enc.ct_trad(),
            &kp_x.pk(),
            application_context,
        )
        .unwrap();
        assert_eq!(enc.secret(), dec);
        let wrong_context = decapsulate_with_decision(
            &decision,
            &kp_pq.sk(),
            &enc.ct_pq(),
            &kp_pq.pk(),
            &kp_x.sk(),
            &enc.ct_trad(),
            &kp_x.pk(),
            b"wrong-context",
        )
        .unwrap();
        assert_ne!(dec, wrong_context);
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "signed-policy"))]
    #[test]
    fn decision_from_signed_policy_threads_the_policy() {
        check_decision_from_signed_policy();
    }

    #[cfg(all(target_arch = "wasm32", feature = "signed-policy"))]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn decision_from_signed_policy_threads_the_policy_wasm() {
        check_decision_from_signed_policy();
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn keypair_encap_decap_roundtrip_wasm() {
        check_keypair_encap_decap_roundtrip();
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn xwing_seed_keypair_compat_roundtrip_wasm() {
        check_xwing_seed_keypair_compat_roundtrip();
    }

    /// Regression for the 32-bit length-prefix truncation: corrupt a valid vector's
    /// first 8-byte length prefix by +2^32. A checked `usize::try_from` rejects it on
    /// every target; the old truncating `as usize` would silently mask it back to the
    /// original length on wasm32 (32-bit `usize`) and *accept* — a cross-platform
    /// accept/reject divergence. This must reject.
    #[cfg(target_arch = "wasm32")]
    fn check_overlong_prefix_rejected() {
        let hex = |s: &str| {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let first = COMBINE_VECTORS
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap();
        let p: Vec<&str> = first.split_whitespace().collect();
        let mut input = hex(p[1]);
        input[3] = input[3].wrapping_add(1); // +2^32 in the big-endian u64 prefix
        assert!(
            combine(p[0].parse::<u8>().unwrap(), &input).is_err(),
            "an over-long length prefix must be rejected, not truncated"
        );
    }

    // wasm32-only: this exercises `combine`'s *error* path, which constructs a `JsError`
    // (a wasm-bindgen import that panics on non-wasm hosts). The 64-bit rejection is
    // covered by `q_periapt_core`'s `from_transport_rejects_overlong_length_prefix`.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn overlong_prefix_rejected_wasm() {
        check_overlong_prefix_rejected();
    }
}
