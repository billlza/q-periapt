//! Emit a shared cross-platform reference vector (ContextBound profile) as JSON.
//!
//! Run: `cargo run -p pqt-backends --example refvec > bindings/shared-test-vectors.json`
//!
//! The C / Swift / Kotlin bindings load this and assert that decapsulation (and
//! re-encapsulation) reproduce `secret` byte-for-byte — operationalizing the
//! "one Rust core, byte-identical across platforms" claim.

use pqt_backends::{MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, X25519, X25519_LEN};
use pqt_core::Profile;
use pqt_kem::HybridKem;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let (sk_pq, pk_pq) = MlKem768::generate([0x11; 64]);
    let (sk_trad, pk_trad) = X25519::generate([0x22; 32]);
    let suite_id = b"ML-KEM-768+X25519";
    let policy_version: u32 = 1;
    let context = b"pqt/v1/refvec/initiator";
    let rand_pq = [0x33u8; 32];
    let rand_trad = [0x44u8; 32];

    let (pq, trad) = (MlKem768, X25519);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(
        &pq,
        &trad,
        Profile::ContextBound,
        suite_id,
        policy_version,
    )
    .expect("hybrid kem");

    let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
    let mut ss_pq = [0u8; 32];
    let mut ct_trad = [0u8; X25519_LEN];
    let mut ss_trad = [0u8; 32];
    let secret = kem
        .encapsulate(
            &pk_pq,
            &pk_trad,
            context,
            &rand_pq,
            &rand_trad,
            &mut ct_pq,
            &mut ss_pq,
            &mut ct_trad,
            &mut ss_trad,
        )
        .expect("encapsulate");

    // Single self-describing JSON object (hand-formatted; no serde dependency).
    println!("{{");
    println!("  \"profile\": \"ContextBound\",");
    println!("  \"profile_code\": 2,");
    println!("  \"suite_id\": \"{}\",", hex(suite_id));
    println!("  \"policy_version\": {policy_version},");
    println!("  \"context\": \"{}\",", hex(context));
    println!("  \"rand_pq\": \"{}\",", hex(&rand_pq));
    println!("  \"rand_trad\": \"{}\",", hex(&rand_trad));
    println!("  \"sk_pq\": \"{}\",", hex(&sk_pq));
    println!("  \"pk_pq\": \"{}\",", hex(&pk_pq));
    println!("  \"sk_trad\": \"{}\",", hex(&sk_trad));
    println!("  \"pk_trad\": \"{}\",", hex(&pk_trad));
    println!("  \"ct_pq\": \"{}\",", hex(&ct_pq));
    println!("  \"ct_trad\": \"{}\",", hex(&ct_trad));
    println!("  \"secret\": \"{}\"", hex(secret.as_bytes()));
    println!("}}");
}
