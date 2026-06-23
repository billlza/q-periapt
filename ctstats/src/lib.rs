#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-ctstats
//!
//! Side-channel CI for the PQ/T hybrid suite. Two layers:
//!
//! 1. **Hard gates (deterministic tests).** Failure-path indistinguishability:
//!    a decapsulation of an *invalid* ciphertext must not error (no return-code
//!    oracle) and must yield a deterministic pseudorandom secret (implicit
//!    rejection). These run in normal CI and *fail the build* on regression.
//! 2. **Best-effort timing report** (`bin/dudect_decaps`). A dudect-style Welch
//!    t-test over decapsulation timing. **Report mode only** — cloud CI runners
//!    are too noisy for a hard threshold; `|t| > 4.5` on *dedicated hardware*
//!    indicates a leak. See `ctstats/README.md` for the honest coverage scope.

/// Welch's t-statistic between two timing samples (unequal variances).
/// `|t|` above ~4.5 is the conventional dudect leakage threshold.
#[must_use]
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let (na, nb) = (a.len() as f64, b.len() as f64);
    if na < 2.0 || nb < 2.0 {
        return 0.0;
    }
    let ma = a.iter().sum::<f64>() / na;
    let mb = b.iter().sum::<f64>() / nb;
    let va = a.iter().map(|x| (x - ma) * (x - ma)).sum::<f64>() / (na - 1.0);
    let vb = b.iter().map(|x| (x - mb) * (x - mb)).sum::<f64>() / (nb - 1.0);
    let denom = (va / na + vb / nb).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (ma - mb) / denom
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use q_periapt_backends::{MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, X25519, X25519_LEN};
    use q_periapt_core::{Kem, Profile};
    use q_periapt_kem::HybridKem;

    #[test]
    fn welch_t_zero_for_identical() {
        let a = [1.0, 2.0, 3.0, 4.0];
        assert!(super::welch_t(&a, &a).abs() < 1e-9);
    }

    /// HARD GATE: ML-KEM-768 must use implicit rejection — an invalid ciphertext
    /// must NOT return an error (no decapsulation oracle) and must produce a
    /// deterministic secret different from the valid one.
    #[test]
    fn mlkem_implicit_rejection_no_error_oracle() {
        let (sk, pk) = MlKem768::generate([5u8; 64]);
        let kem = MlKem768;
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        let mut ss = [0u8; 32];
        kem.encapsulate(&pk, &[7u8; 32], &mut ct, &mut ss).unwrap();

        let mut valid = [0u8; 32];
        kem.decapsulate(&sk, &ct, &mut valid).unwrap();

        let mut bad = ct;
        bad[0] ^= 0xFF; // corrupt the ciphertext

        let mut r1 = [0u8; 32];
        let r1_status = kem.decapsulate(&sk, &bad, &mut r1);
        let mut r2 = [0u8; 32];
        kem.decapsulate(&sk, &bad, &mut r2).unwrap();

        assert!(
            r1_status.is_ok(),
            "invalid ciphertext must NOT error (implicit rejection — no oracle)"
        );
        assert_ne!(r1, valid, "invalid ct must yield a different secret");
        assert_eq!(r1, r2, "implicit rejection must be deterministic");
    }

    /// HARD GATE: the hybrid decapsulation must also never surface a crypto-validity
    /// error — a corrupted PQ ciphertext still yields a (different) secret.
    #[test]
    fn hybrid_decaps_no_error_on_invalid_ct() {
        let (sk_pq, pk_pq) = MlKem768::generate([8u8; 64]);
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let (pq, trad) = (MlKem768, X25519);
        let kem =
            HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, Profile::ContextBound, b"suite", 1)
                .unwrap();
        let ctx = b"ctx";

        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ss_pq = [0u8; 32];
        let mut ct_trad = [0u8; X25519_LEN];
        let mut ss_trad = [0u8; 32];
        let good = kem
            .encapsulate(
                &pk_pq,
                &pk_trad,
                ctx,
                &[1u8; 32],
                &[2u8; 32],
                &mut ct_pq,
                &mut ss_pq,
                &mut ct_trad,
                &mut ss_trad,
            )
            .unwrap();

        let mut bad_ct_pq = ct_pq;
        bad_ct_pq[0] ^= 0xFF;
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        let dec = kem.decapsulate(
            &sk_pq, &bad_ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, ctx, &mut a, &mut b,
        );
        assert!(dec.is_ok(), "corrupt PQ ct must not surface an error");
        assert_ne!(
            dec.unwrap().as_bytes(),
            good.as_bytes(),
            "corrupt ct must change the derived secret"
        );
    }
}
