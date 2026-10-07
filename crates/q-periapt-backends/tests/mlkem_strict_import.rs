//! Parameterized regression tests for the public ML-KEM expanded-key adapters.
//!
//! These exercise only the stable `q_periapt_core::Kem` boundary. A primitive-provider change
//! must preserve strict FIPS 203 expanded-DK import, implicit rejection, and output atomicity for
//! every shipped parameter set without exposing provider-specific types as public API.

use std::panic::{catch_unwind, AssertUnwindSafe};

use q_periapt_backends::{
    MlKem1024, MlKem512, MlKem768, ML_KEM_1024_CT_LEN, ML_KEM_1024_PK_LEN, ML_KEM_1024_SK_LEN,
    ML_KEM_512_CT_LEN, ML_KEM_512_PK_LEN, ML_KEM_512_SK_LEN, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_SK_LEN,
};
use q_periapt_core::{Error, Kem};
use sha3::{Digest, Sha3_256};

const HASH_LEN: usize = 32;
const REJECTION_SEED_LEN: usize = 32;
const SHARED_SECRET_LEN: usize = 32;

type TestResult = Result<(), &'static str>;
type KeypairGenerator<const SK_LEN: usize, const PK_LEN: usize> =
    fn([u8; 64]) -> Result<([u8; SK_LEN], [u8; PK_LEN]), Error>;

fn exercise_strict_adapter<K, const SK_LEN: usize, const PK_LEN: usize, const CT_LEN: usize>(
    kem: &K,
    generate: KeypairGenerator<SK_LEN, PK_LEN>,
) -> TestResult
where
    K: Kem,
{
    let public_suffix_len = PK_LEN
        .checked_add(HASH_LEN + REJECTION_SEED_LEN)
        .ok_or("expanded-key suffix length overflow")?;
    let embedded_ek_offset = SK_LEN
        .checked_sub(public_suffix_len)
        .ok_or("expanded-key layout underflow")?;
    let embedded_ek_end = embedded_ek_offset
        .checked_add(PK_LEN)
        .ok_or("embedded-EK end overflow")?;
    let embedded_ek_hash_end = embedded_ek_end
        .checked_add(HASH_LEN)
        .ok_or("embedded-EK hash end overflow")?;
    if embedded_ek_hash_end + REJECTION_SEED_LEN != SK_LEN {
        return Err("expanded-key layout does not consume the complete key");
    }

    let (sk, pk) = generate([0x31; 64]).map_err(|_| "deterministic key generation failed")?;
    let mut valid_ct = [0u8; CT_LEN];
    let mut encapsulated_secret = [0u8; SHARED_SECRET_LEN];
    assert_eq!(
        kem.encapsulate(&pk, &[0x42; 32], &mut valid_ct, &mut encapsulated_secret,),
        Ok(())
    );

    let mut valid_decapsulated_secret = [0u8; SHARED_SECRET_LEN];
    assert_eq!(
        kem.decapsulate(&sk, &valid_ct, &mut valid_decapsulated_secret),
        Ok(())
    );
    assert_eq!(valid_decapsulated_secret, encapsulated_secret);

    // A fixed-length malformed ciphertext is not an import error. It must exercise deterministic
    // FIPS 203 implicit rejection without exposing a validity oracle.
    let mut invalid_ct = valid_ct;
    let invalid_byte = invalid_ct
        .get_mut(CT_LEN / 2)
        .ok_or("ciphertext mutation offset out of range")?;
    *invalid_byte ^= 0x80;
    let mut rejected_secret_a = [0u8; SHARED_SECRET_LEN];
    let mut rejected_secret_b = [0u8; SHARED_SECRET_LEN];
    assert_eq!(
        kem.decapsulate(&sk, &invalid_ct, &mut rejected_secret_a),
        Ok(())
    );
    assert_eq!(
        kem.decapsulate(&sk, &invalid_ct, &mut rejected_secret_b),
        Ok(())
    );
    assert_eq!(rejected_secret_a, rejected_secret_b);
    assert_ne!(rejected_secret_a, valid_decapsulated_secret);

    // Hash mismatch: strict expanded-DK import must reject and leave the caller's output intact.
    let mut bad_hash = sk;
    let bad_hash_byte = bad_hash
        .get_mut(embedded_ek_end)
        .ok_or("embedded-EK hash offset out of range")?;
    *bad_hash_byte ^= 1;
    let mut output = [0xa5; SHARED_SECRET_LEN];
    assert_eq!(
        kem.decapsulate(&bad_hash, &valid_ct, &mut output),
        Err(Error::Backend)
    );
    assert_eq!(output, [0xa5; SHARED_SECRET_LEN]);

    // A hash-only validator is insufficient: make the embedded EK non-canonical, then recompute
    // a matching H(EK). Strict import must still perform the public-key modulus/canonicality check.
    let mut noncanonical_embedded_ek = sk;
    *noncanonical_embedded_ek
        .get_mut(embedded_ek_offset)
        .ok_or("embedded-EK first coefficient byte missing")? = 0xff;
    *noncanonical_embedded_ek
        .get_mut(embedded_ek_offset + 1)
        .ok_or("embedded-EK second coefficient byte missing")? = 0x0f;
    let embedded_ek = noncanonical_embedded_ek
        .get(embedded_ek_offset..embedded_ek_end)
        .ok_or("embedded-EK range missing")?;
    let recomputed_hash = Sha3_256::digest(embedded_ek);
    noncanonical_embedded_ek
        .get_mut(embedded_ek_end..embedded_ek_hash_end)
        .ok_or("embedded-EK hash range missing")?
        .copy_from_slice(&recomputed_hash);
    output.fill(0x5a);
    assert_eq!(
        kem.decapsulate(&noncanonical_embedded_ek, &valid_ct, &mut output),
        Err(Error::Backend)
    );
    assert_eq!(output, [0x5a; SHARED_SECRET_LEN]);

    // Arbitrary fixed-length input must never panic or partially write output.
    let all_ff = [0xff; SK_LEN];
    let no_panic = catch_unwind(AssertUnwindSafe(|| {
        let mut scratch = [0x3c; SHARED_SECRET_LEN];
        let result = kem.decapsulate(&all_ff, &valid_ct, &mut scratch);
        (result, scratch)
    }));
    let (result, scratch) = match no_panic {
        Ok(value) => value,
        Err(_) => return Err("malformed fixed-length expanded DK panicked"),
    };
    assert_eq!(result, Err(Error::Backend));
    assert_eq!(scratch, [0x3c; SHARED_SECRET_LEN]);

    // Public-key canonicality failure is also atomic across both output buffers.
    let mut noncanonical_pk = pk;
    *noncanonical_pk
        .get_mut(0)
        .ok_or("public key first coefficient byte missing")? = 0xff;
    *noncanonical_pk
        .get_mut(1)
        .ok_or("public key second coefficient byte missing")? = 0x0f;
    let mut ct_output = [0x69; CT_LEN];
    let mut ss_output = [0x96; SHARED_SECRET_LEN];
    assert_eq!(
        kem.encapsulate(
            &noncanonical_pk,
            &[0x42; 32],
            &mut ct_output,
            &mut ss_output,
        ),
        Err(Error::InvalidKeyShare)
    );
    assert_eq!(ct_output, [0x69; CT_LEN]);
    assert_eq!(ss_output, [0x96; SHARED_SECRET_LEN]);

    // Length errors are public, exact, and atomic for short and long inputs/outputs.
    let short_sk = sk
        .get(..SK_LEN - 1)
        .ok_or("short expanded-DK slice missing")?;
    let mut long_sk = sk.to_vec();
    long_sk.push(0);
    for malformed_sk in [short_sk, long_sk.as_slice()] {
        output.fill(0x7b);
        assert_eq!(
            kem.decapsulate(malformed_sk, &valid_ct, &mut output),
            Err(Error::InvalidLength)
        );
        assert_eq!(output, [0x7b; SHARED_SECRET_LEN]);
    }

    let short_ct = valid_ct
        .get(..CT_LEN - 1)
        .ok_or("short ciphertext slice missing")?;
    let mut long_ct = valid_ct.to_vec();
    long_ct.push(0);
    for malformed_ct in [short_ct, long_ct.as_slice()] {
        output.fill(0x4d);
        assert_eq!(
            kem.decapsulate(&sk, malformed_ct, &mut output),
            Err(Error::InvalidLength)
        );
        assert_eq!(output, [0x4d; SHARED_SECRET_LEN]);
    }

    let mut short_ss = [0x2a; SHARED_SECRET_LEN - 1];
    assert_eq!(
        kem.decapsulate(&sk, &valid_ct, &mut short_ss),
        Err(Error::InvalidLength)
    );
    assert_eq!(short_ss, [0x2a; SHARED_SECRET_LEN - 1]);
    let mut long_ss = [0x2b; SHARED_SECRET_LEN + 1];
    assert_eq!(
        kem.decapsulate(&sk, &valid_ct, &mut long_ss),
        Err(Error::InvalidLength)
    );
    assert_eq!(long_ss, [0x2b; SHARED_SECRET_LEN + 1]);

    let short_pk = pk
        .get(..PK_LEN - 1)
        .ok_or("short public-key slice missing")?;
    let mut long_pk = pk.to_vec();
    long_pk.push(0);
    for malformed_pk in [short_pk, long_pk.as_slice()] {
        ct_output.fill(0x1a);
        ss_output.fill(0x1b);
        assert_eq!(
            kem.encapsulate(malformed_pk, &[0x42; 32], &mut ct_output, &mut ss_output,),
            Err(Error::InvalidLength)
        );
        assert_eq!(ct_output, [0x1a; CT_LEN]);
        assert_eq!(ss_output, [0x1b; SHARED_SECRET_LEN]);
    }

    let short_randomness = [0u8; 31];
    let long_randomness = [0u8; 33];
    for malformed_randomness in [short_randomness.as_slice(), long_randomness.as_slice()] {
        ct_output.fill(0x6a);
        ss_output.fill(0x6b);
        assert_eq!(
            kem.encapsulate(&pk, malformed_randomness, &mut ct_output, &mut ss_output,),
            Err(Error::InvalidLength)
        );
        assert_eq!(ct_output, [0x6a; CT_LEN]);
        assert_eq!(ss_output, [0x6b; SHARED_SECRET_LEN]);
    }

    let mut short_ct_output = vec![0x8a; CT_LEN - 1];
    ss_output.fill(0x8b);
    assert_eq!(
        kem.encapsulate(&pk, &[0x42; 32], &mut short_ct_output, &mut ss_output,),
        Err(Error::InvalidLength)
    );
    assert!(short_ct_output.iter().all(|byte| *byte == 0x8a));
    assert_eq!(ss_output, [0x8b; SHARED_SECRET_LEN]);

    let mut long_ct_output = vec![0x9a; CT_LEN + 1];
    ss_output.fill(0x9b);
    assert_eq!(
        kem.encapsulate(&pk, &[0x42; 32], &mut long_ct_output, &mut ss_output,),
        Err(Error::InvalidLength)
    );
    assert!(long_ct_output.iter().all(|byte| *byte == 0x9a));
    assert_eq!(ss_output, [0x9b; SHARED_SECRET_LEN]);

    let mut short_encaps_ss = [0xaa; SHARED_SECRET_LEN - 1];
    ct_output.fill(0xab);
    assert_eq!(
        kem.encapsulate(&pk, &[0x42; 32], &mut ct_output, &mut short_encaps_ss,),
        Err(Error::InvalidLength)
    );
    assert_eq!(ct_output, [0xab; CT_LEN]);
    assert_eq!(short_encaps_ss, [0xaa; SHARED_SECRET_LEN - 1]);

    let mut long_encaps_ss = [0xba; SHARED_SECRET_LEN + 1];
    ct_output.fill(0xbb);
    assert_eq!(
        kem.encapsulate(&pk, &[0x42; 32], &mut ct_output, &mut long_encaps_ss,),
        Err(Error::InvalidLength)
    );
    assert_eq!(ct_output, [0xbb; CT_LEN]);
    assert_eq!(long_encaps_ss, [0xba; SHARED_SECRET_LEN + 1]);

    Ok(())
}

#[test]
fn mlkem512_strict_import_and_output_atomicity() -> TestResult {
    exercise_strict_adapter::<_, ML_KEM_512_SK_LEN, ML_KEM_512_PK_LEN, ML_KEM_512_CT_LEN>(
        &MlKem512,
        MlKem512::generate,
    )
}

#[test]
fn mlkem768_strict_import_and_output_atomicity() -> TestResult {
    exercise_strict_adapter::<_, ML_KEM_768_SK_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_CT_LEN>(
        &MlKem768,
        MlKem768::generate,
    )
}

#[test]
fn mlkem1024_strict_import_and_output_atomicity() -> TestResult {
    exercise_strict_adapter::<_, ML_KEM_1024_SK_LEN, ML_KEM_1024_PK_LEN, ML_KEM_1024_CT_LEN>(
        &MlKem1024,
        MlKem1024::generate,
    )
}
