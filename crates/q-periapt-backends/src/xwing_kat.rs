//! Byte-exact X-Wing and concrete-hybrid-kems KATs.
//!
//! Preserves the three `draft-connolly-cfrg-xwing-kem-10` vectors and independently
//! pins the official `draft-irtf-cfrg-concrete-hybrid-kems-04` MLKEM768-X25519
//! vector. Both drive [`HybridKem`] with X-Wing's key-expansion
//! (`SHAKE-256(seed, 96)`) and encapsulation-coin split (`m = randomness[0..32]`,
//! `ekX = randomness[32..64]`). The assertions cover the ML-KEM-768 public key,
//! ciphertext, and shared secret byte-for-byte. This is not a full ACVP / FIPS 203
//! validation.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{
    MlKem768XWingSeed, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_XWING_SEED_LEN, X25519, X25519_LEN,
};
use q_periapt_core::Profile;
use q_periapt_kem::{
    HybridKem, PqCiphertext, PqPublicKey, PqSecretKey, TradCiphertext, TradPublicKey, TradSecretKey,
};

include!("concrete_hybrid_kems_04_vector.rs");
include!("xwing_vectors.rs");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn shake256_96(seed: &[u8]) -> [u8; 96] {
    crate::shake256::<96>(seed)
}

type XWingKatKeypair = (
    [u8; ML_KEM_768_XWING_SEED_LEN],
    [u8; ML_KEM_768_PK_LEN],
    [u8; X25519_LEN],
    [u8; X25519_LEN],
);

fn derive_xwing_keypair(seed: [u8; ML_KEM_768_XWING_SEED_LEN]) -> XWingKatKeypair {
    let expanded = shake256_96(&seed);
    let mut sk_x = [0u8; X25519_LEN];
    sk_x.copy_from_slice(&expanded[64..96]);
    let (sk_pq, pk_pq) = MlKem768XWingSeed::generate(seed).unwrap();
    let (_sk_x_bytes, pk_x) = X25519::generate(sk_x);
    (sk_pq, pk_pq, sk_x, pk_x)
}

struct ConcreteHybridKems04Vector {
    seed: [u8; ML_KEM_768_XWING_SEED_LEN],
    randomness: [u8; 2 * X25519_LEN],
    encapsulation_key: Vec<u8>,
    decapsulation_key: [u8; ML_KEM_768_XWING_SEED_LEN],
    decapsulation_key_pq: [u8; 64],
    decapsulation_key_t: [u8; X25519_LEN],
    ciphertext: Vec<u8>,
    shared_secret: [u8; 32],
}

fn concrete_hybrid_kems_04_vector() -> ConcreteHybridKems04Vector {
    let [seed, randomness, encapsulation_key, decapsulation_key, decapsulation_key_pq, decapsulation_key_t, ciphertext, shared_secret] =
        CONCRETE_HYBRID_KEMS_04_MLKEM768_X25519_VECTOR;
    ConcreteHybridKems04Vector {
        seed: unhex(seed).try_into().unwrap(),
        randomness: unhex(randomness).try_into().unwrap(),
        encapsulation_key: unhex(encapsulation_key),
        decapsulation_key: unhex(decapsulation_key).try_into().unwrap(),
        decapsulation_key_pq: unhex(decapsulation_key_pq).try_into().unwrap(),
        decapsulation_key_t: unhex(decapsulation_key_t).try_into().unwrap(),
        ciphertext: unhex(ciphertext),
        shared_secret: unhex(shared_secret).try_into().unwrap(),
    }
}

#[test]
fn xwing_draft_kat_byte_exact() {
    for v in XWING_VECTORS {
        let seed = unhex(v[0]);
        let eseed = unhex(v[1]);
        let ss_exp = unhex(v[2]);
        let pk_exp = unhex(v[4]);
        let ct_exp = unhex(v[5]);

        // --- X-Wing key expansion: SHAKE256(seed, 96) = ML-KEM(d‖z) ‖ skX ---
        let seed_m: [u8; 32] = seed.as_slice().try_into().unwrap();
        let (sk_m, pk_m, skx, pk_x) = derive_xwing_keypair(seed_m);

        // Public key = pkM ‖ pkX (validates ML-KEM-768 keygen byte-exactly).
        let mut pk = pk_m.to_vec();
        pk.extend_from_slice(&pk_x);
        assert_eq!(pk, pk_exp, "keygen pk must match X-Wing vector");

        // --- Encapsulate: CompatXWing combiner == X-Wing combiner ---
        let (pq, trad) = (MlKem768XWingSeed, X25519);
        let kem =
            HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, Profile::CompatXWing, b"", 0).unwrap();
        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let secret = kem
            .encapsulate(
                &pk_m,
                &pk_x,
                b"", // Canonical empty context: X-Wing has no context input.
                &eseed[0..32],
                &eseed[32..64],
                &mut ct_pq,
                &mut ct_trad,
            )
            .unwrap();

        let mut ct = ct_pq.to_vec();
        ct.extend_from_slice(&ct_trad);
        assert_eq!(ct, ct_exp, "ciphertext must match X-Wing vector");
        assert_eq!(
            secret.as_bytes(),
            ss_exp.as_slice(),
            "shared secret must match X-Wing vector"
        );

        // --- Decapsulate: must recover the same shared secret ---
        let dsec = kem
            .decapsulate(
                PqSecretKey::new(&sk_m),
                PqCiphertext::new(&ct_pq),
                PqPublicKey::new(&pk_m),
                TradSecretKey::new(&skx),
                TradCiphertext::new(&ct_trad),
                TradPublicKey::new(&pk_x),
                b"",
            )
            .unwrap();
        assert_eq!(
            dsec.as_bytes(),
            ss_exp.as_slice(),
            "decapsulated secret must match X-Wing vector"
        );
    }
}

#[test]
fn concrete_hybrid_kems_04_mlkem768_x25519_byte_exact() {
    let vector = concrete_hybrid_kems_04_vector();
    assert_eq!(
        vector.encapsulation_key.len(),
        ML_KEM_768_PK_LEN + X25519_LEN
    );
    assert_eq!(vector.ciphertext.len(), ML_KEM_768_CT_LEN + X25519_LEN);

    let (sk_pq, pk_pq, sk_x, pk_x) = derive_xwing_keypair(vector.seed);
    let expanded = shake256_96(&vector.seed);
    assert_eq!(sk_pq, vector.decapsulation_key);
    assert_eq!(&expanded[..64], &vector.decapsulation_key_pq);
    assert_eq!(sk_x, vector.decapsulation_key_t);
    let mut encapsulation_key = pk_pq.to_vec();
    encapsulation_key.extend_from_slice(&pk_x);
    assert_eq!(
        encapsulation_key, vector.encapsulation_key,
        "encapsulation key must match concrete-hybrid-kems-04 Appendix B.2"
    );

    let kem = HybridKem::<_, _, Sha3_256Xof>::new(
        &MlKem768XWingSeed,
        &X25519,
        Profile::CompatXWing,
        b"",
        0,
    )
    .unwrap();
    let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
    let mut ct_x = [0u8; X25519_LEN];
    let secret = kem
        .encapsulate(
            &pk_pq,
            &pk_x,
            b"",
            &vector.randomness[..32],
            &vector.randomness[32..],
            &mut ct_pq,
            &mut ct_x,
        )
        .unwrap();
    let mut ciphertext = ct_pq.to_vec();
    ciphertext.extend_from_slice(&ct_x);
    assert_eq!(
        ciphertext, vector.ciphertext,
        "ciphertext must match concrete-hybrid-kems-04 Appendix B.2"
    );
    assert_eq!(
        secret.as_bytes(),
        &vector.shared_secret,
        "shared secret must match concrete-hybrid-kems-04 Appendix B.2"
    );

    let decapsulated = kem
        .decapsulate(
            PqSecretKey::new(&sk_pq),
            PqCiphertext::new(&ct_pq),
            PqPublicKey::new(&pk_pq),
            TradSecretKey::new(&sk_x),
            TradCiphertext::new(&ct_x),
            TradPublicKey::new(&pk_x),
            b"",
        )
        .unwrap();
    assert_eq!(decapsulated.as_bytes(), &vector.shared_secret);
}

#[test]
fn correct_length_invalid_mlkem_ciphertext_uses_implicit_rejection() {
    let vector = concrete_hybrid_kems_04_vector();
    let (sk_pq, pk_pq, sk_x, pk_x) = derive_xwing_keypair(vector.seed);
    let mut malformed_ct_pq: [u8; ML_KEM_768_CT_LEN] =
        vector.ciphertext[..ML_KEM_768_CT_LEN].try_into().unwrap();
    let ct_x: [u8; X25519_LEN] = vector.ciphertext[ML_KEM_768_CT_LEN..].try_into().unwrap();
    malformed_ct_pq[0] ^= 1;

    let kem = HybridKem::<_, _, Sha3_256Xof>::new(
        &MlKem768XWingSeed,
        &X25519,
        Profile::CompatXWing,
        b"",
        0,
    )
    .unwrap();
    let rejected_a = kem
        .decapsulate(
            PqSecretKey::new(&sk_pq),
            PqCiphertext::new(&malformed_ct_pq),
            PqPublicKey::new(&pk_pq),
            TradSecretKey::new(&sk_x),
            TradCiphertext::new(&ct_x),
            TradPublicKey::new(&pk_x),
            b"",
        )
        .unwrap();
    let rejected_b = kem
        .decapsulate(
            PqSecretKey::new(&sk_pq),
            PqCiphertext::new(&malformed_ct_pq),
            PqPublicKey::new(&pk_pq),
            TradSecretKey::new(&sk_x),
            TradCiphertext::new(&ct_x),
            TradPublicKey::new(&pk_x),
            b"",
        )
        .unwrap();

    assert_eq!(
        rejected_a.as_bytes(),
        rejected_b.as_bytes(),
        "implicit rejection must be deterministic for one key and ciphertext"
    );
    assert_ne!(
        rejected_a.as_bytes(),
        &vector.shared_secret,
        "invalid correct-length ML-KEM ciphertext must not recover the valid secret"
    );
}
