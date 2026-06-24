#![warn(missing_docs)]

//! # q-periapt-wasm
//!
//! WASM bindings for the PQ/T hybrid suite, exposing the same one Rust core to
//! JavaScript/TypeScript. Randomness (encapsulation coins, seeds) is supplied by
//! the JS caller as `Uint8Array`, so no in-WASM entropy source is required and the
//! operations stay deterministic / KAT-able.
//!
//! Build: `wasm-pack build crates/q-periapt-wasm --target web` (see `README.md`).

use q_periapt_backends::{
    MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_KEYGEN_SEED_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{combine as core_combine, CombineInput, Profile};
use q_periapt_kem::HybridKem;
use wasm_bindgen::prelude::*;

fn profile(code: u8) -> Result<Profile, JsError> {
    Profile::from_u8(code).ok_or_else(|| JsError::new("invalid profile code"))
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

/// A generated key pair (`sk`, `pk`) exposed to JS.
#[wasm_bindgen]
pub struct KeyPair {
    sk: Vec<u8>,
    pk: Vec<u8>,
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
    let (pq, trad) = (MlKem768, X25519);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, prof, suite_id, policy_version)
        .map_err(|_| JsError::new("policy denied"))?;
    let mut ct_pq = vec![0u8; ML_KEM_768_CT_LEN];
    let mut ct_trad = vec![0u8; X25519_LEN];
    let secret = kem
        .encapsulate(
            pk_pq,
            pk_trad,
            context,
            rand_pq,
            rand_trad,
            &mut ct_pq,
            &mut ct_trad,
        )
        .map_err(|_| JsError::new("encapsulate failed"))?;
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
    let (pq, trad) = (MlKem768, X25519);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, prof, suite_id, policy_version)
        .map_err(|_| JsError::new("policy denied"))?;
    let secret = kem
        .decapsulate(sk_pq, ct_pq, pk_pq, sk_trad, ct_trad, pk_trad, context)
        .map_err(|_| JsError::new("decapsulate failed"))?;
    Ok(secret.as_bytes().to_vec())
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
        .unwrap_or_default();
        assert_eq!(
            secret,
            field(j, "secret"),
            "WASM API must match the Rust core"
        );
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
