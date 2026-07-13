//! Byte-exact X-Wing draft KAT.
//!
//! Proves the `CompatXWing` profile reproduces X-Wing (`draft-connolly-cfrg-xwing-kem`)
//! shared secrets and ciphertexts **byte-for-byte**, by driving [`HybridKem`] with
//! X-Wing's key-expansion (`SHAKE-256(seed, 96)`) and encapsulation-coin split
//! (`m = eseed[0..32]`, `ekX = eseed[32..64]`). Because the assertions cover the
//! ML-KEM-768 public key, ciphertext, and shared secret against the published
//! vectors, this reproduces the FIPS 203 reference output on these 3 X-Wing
//! happy-path vectors — it is NOT a full ACVP / FIPS 203 validation.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{MlKem768XWingSeed, Sha3_256Xof, ML_KEM_768_CT_LEN, X25519, X25519_LEN};
use q_periapt_core::Profile;
use q_periapt_kem::HybridKem;

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

#[test]
fn xwing_draft_kat_byte_exact() {
    for v in XWING_VECTORS {
        let seed = unhex(v[0]);
        let eseed = unhex(v[1]);
        let ss_exp = unhex(v[2]);
        let pk_exp = unhex(v[4]);
        let ct_exp = unhex(v[5]);

        // --- X-Wing key expansion: SHAKE256(seed, 96) = ML-KEM(d‖z) ‖ skX ---
        let expanded = shake256_96(&seed);
        let seed_m: [u8; 32] = seed.as_slice().try_into().unwrap();
        let mut skx = [0u8; 32];
        skx.copy_from_slice(&expanded[64..96]);
        let (sk_m, pk_m) = MlKem768XWingSeed::generate(seed_m);
        let (_skx_bytes, pk_x) = X25519::generate(skx);

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
                b"", // CompatXWing ignores context (X-Wing has none)
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
            .decapsulate(&sk_m, &ct_pq, &pk_m, &skx, &ct_trad, &pk_x, b"")
            .unwrap();
        assert_eq!(
            dsec.as_bytes(),
            ss_exp.as_slice(),
            "decapsulated secret must match X-Wing vector"
        );
    }
}
