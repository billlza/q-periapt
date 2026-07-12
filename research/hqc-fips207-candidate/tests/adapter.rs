//! Contract tests for the isolated HQC v5 FIPS 207 draft-candidate adapters.

use q_periapt_core::{Error, Kem, Profile, Xof256};
use q_periapt_hqc_fips207_candidate::{
    Hqc128Fips207DraftCandidate, Hqc192Fips207DraftCandidate, Hqc256Fips207DraftCandidate,
    SHARED_SECRET_LEN,
};
use q_periapt_kem::HybridKem;

const TOY_LEN: usize = 32;

type DeterministicKeygen = fn([u8; 32]) -> (Vec<u8>, Vec<u8>);

#[derive(Clone, Copy, Debug, Default)]
struct ToyTraditional;

impl Kem for ToyTraditional {
    fn algorithm(&self) -> &'static str {
        "TEST-ONLY-TRADITIONAL"
    }

    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        if [pk.len(), randomness.len(), ct.len(), ss.len()]
            .iter()
            .any(|&len| len != TOY_LEN)
        {
            return Err(Error::InvalidLength);
        }
        ct.copy_from_slice(randomness);
        for ((out, public), coins) in ss.iter_mut().zip(pk).zip(randomness) {
            *out = *public ^ *coins;
        }
        Ok(())
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        if [sk.len(), ct.len(), ss.len()]
            .iter()
            .any(|&len| len != TOY_LEN)
        {
            return Err(Error::InvalidLength);
        }
        for ((out, secret), ciphertext) in ss.iter_mut().zip(sk).zip(ct) {
            *out = *secret ^ *ciphertext;
        }
        Ok(())
    }
}

struct TestXof(u64);

impl Xof256 for TestXof {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn squeeze32(mut self) -> [u8; SHARED_SECRET_LEN] {
        let mut output = [0u8; SHARED_SECRET_LEN];
        for chunk in output.chunks_mut(8) {
            self.0 = self.0.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
            chunk.copy_from_slice(&self.0.to_le_bytes());
        }
        output
    }
}

#[derive(Clone, Copy)]
struct Sizes {
    public_key: usize,
    secret_key: usize,
    ciphertext: usize,
    randomness: usize,
}

fn exercise_candidate<K: Kem + Copy>(
    kem: K,
    expected_algorithm: &'static str,
    sizes: Sizes,
    generate: DeterministicKeygen,
) {
    assert_eq!(kem.algorithm(), expected_algorithm);
    assert!(!K::C2PRI);
    assert!(!K::COMPAT_XWING_SAFE);

    let seed = [0x42u8; 32];
    let (sk, pk) = generate(seed);
    let (sk_again, pk_again) = generate(seed);
    assert_eq!(sk.len(), sizes.secret_key);
    assert_eq!(pk.len(), sizes.public_key);
    assert_eq!(sk, sk_again, "key generation must be deterministic");
    assert_eq!(pk, pk_again, "key generation must be deterministic");

    let randomness = vec![0x5au8; sizes.randomness];
    let mut ciphertext = vec![0u8; sizes.ciphertext];
    let mut shared_enc = [0u8; SHARED_SECRET_LEN];
    kem.encapsulate(&pk, &randomness, &mut ciphertext, &mut shared_enc)
        .expect("valid deterministic encapsulation");

    let mut ciphertext_again = vec![0u8; sizes.ciphertext];
    let mut shared_again = [0u8; SHARED_SECRET_LEN];
    kem.encapsulate(&pk, &randomness, &mut ciphertext_again, &mut shared_again)
        .expect("repeated deterministic encapsulation");
    assert_eq!(ciphertext, ciphertext_again);
    assert_eq!(shared_enc, shared_again);

    let mut shared_dec = [0u8; SHARED_SECRET_LEN];
    kem.decapsulate(&sk, &ciphertext, &mut shared_dec)
        .expect("honest decapsulation");
    assert_eq!(shared_enc, shared_dec);

    let mut corrupted = ciphertext.clone();
    let tamper_at = sizes.ciphertext / 2;
    let byte = corrupted
        .get_mut(tamper_at)
        .expect("ciphertext midpoint must exist");
    *byte ^= 0x01;
    let mut rejected_secret = [0u8; SHARED_SECRET_LEN];
    kem.decapsulate(&sk, &corrupted, &mut rejected_secret)
        .expect("same-length corrupt ciphertext uses implicit rejection");
    assert_ne!(rejected_secret, shared_enc);

    let short_pk = pk.split_last().expect("public key is non-empty").1;
    let short_randomness = randomness.split_last().expect("randomness is non-empty").1;
    let mut short_ct_output = vec![0u8; sizes.ciphertext - 1];
    let mut short_ss_output = [0u8; SHARED_SECRET_LEN - 1];
    assert_eq!(
        kem.encapsulate(
            short_pk,
            &randomness,
            &mut ciphertext_again,
            &mut shared_again
        ),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        kem.encapsulate(
            &pk,
            short_randomness,
            &mut ciphertext_again,
            &mut shared_again
        ),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        kem.encapsulate(&pk, &randomness, &mut short_ct_output, &mut shared_again),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        kem.encapsulate(
            &pk,
            &randomness,
            &mut ciphertext_again,
            &mut short_ss_output
        ),
        Err(Error::InvalidLength)
    );

    let short_sk = sk.split_last().expect("secret key is non-empty").1;
    let short_ct_input = ciphertext.split_last().expect("ciphertext is non-empty").1;
    assert_eq!(
        kem.decapsulate(short_sk, &ciphertext, &mut shared_dec),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        kem.decapsulate(&sk, short_ct_input, &mut shared_dec),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        kem.decapsulate(&sk, &ciphertext, &mut short_ss_output),
        Err(Error::InvalidLength)
    );

    let mut extended_pk = pk.clone();
    extended_pk.push(0);
    let mut extended_randomness = randomness.clone();
    extended_randomness.push(0);
    assert_eq!(
        kem.encapsulate(
            &extended_pk,
            &randomness,
            &mut ciphertext_again,
            &mut shared_again
        ),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        kem.encapsulate(
            &pk,
            &extended_randomness,
            &mut ciphertext_again,
            &mut shared_again
        ),
        Err(Error::InvalidLength)
    );

    let traditional = ToyTraditional;
    let context_bound = HybridKem::<_, _, TestXof>::new(
        &kem,
        &traditional,
        Profile::ContextBound,
        b"HQC-V5-FIPS207-DRAFT-CANDIDATE-RESEARCH-ONLY",
        0,
    )
    .expect("candidate is permitted only by the all-fields-bound profile");
    let traditional_key = [0x31u8; TOY_LEN];
    let traditional_randomness = [0x92u8; TOY_LEN];
    let mut hybrid_ct_pq = vec![0u8; sizes.ciphertext];
    let mut hybrid_ct_trad = [0u8; TOY_LEN];
    let combined_enc = context_bound
        .encapsulate(
            &pk,
            &traditional_key,
            b"candidate-profile-contract",
            &randomness,
            &traditional_randomness,
            &mut hybrid_ct_pq,
            &mut hybrid_ct_trad,
        )
        .expect("ContextBound hybrid encapsulation");
    let combined_dec = context_bound
        .decapsulate(
            &sk,
            &hybrid_ct_pq,
            &pk,
            &traditional_key,
            &hybrid_ct_trad,
            &traditional_key,
            b"candidate-profile-contract",
        )
        .expect("ContextBound hybrid decapsulation");
    assert_eq!(combined_enc.as_bytes(), combined_dec.as_bytes());

    let compat =
        HybridKem::<_, _, TestXof>::new(&kem, &traditional, Profile::CompatXWing, b"FORBIDDEN", 0);
    assert!(matches!(compat, Err(Error::PolicyDenied)));
}

fn run_with_crypto_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("hqc-draft-candidate-contract".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(test)
        .expect("spawn bounded HQC test thread")
        .join()
        .expect("HQC test thread completes without panic");
}

#[test]
fn hqc128_candidate_contract() {
    assert_eq!(
        Hqc128Fips207DraftCandidate::PK_LEN,
        hqc_kem::hqc128::PUBLIC_KEY_SIZE
    );
    assert_eq!(
        Hqc128Fips207DraftCandidate::SK_LEN,
        hqc_kem::hqc128::SECRET_KEY_SIZE
    );
    assert_eq!(
        Hqc128Fips207DraftCandidate::CT_LEN,
        hqc_kem::hqc128::CIPHERTEXT_SIZE
    );
    assert_eq!(
        Hqc128Fips207DraftCandidate::SS_LEN,
        hqc_kem::hqc128::SHARED_SECRET_SIZE
    );
    assert_eq!(
        Hqc128Fips207DraftCandidate::MESSAGE_LEN,
        hqc_kem::hqc128::MESSAGE_SIZE
    );
    assert_eq!(Hqc128Fips207DraftCandidate::ENCAPS_RANDOMNESS_LEN, 32);
    run_with_crypto_stack(|| {
        exercise_candidate(
            Hqc128Fips207DraftCandidate,
            "HQC-128-V5-FIPS207-DRAFT-CANDIDATE",
            Sizes {
                public_key: 2241,
                secret_key: 2321,
                ciphertext: 4433,
                randomness: 32,
            },
            |seed| {
                let (sk, pk) = Hqc128Fips207DraftCandidate::generate(seed);
                (sk.to_vec(), pk.to_vec())
            },
        );
    });
}

#[test]
fn hqc192_candidate_contract() {
    assert_eq!(
        Hqc192Fips207DraftCandidate::PK_LEN,
        hqc_kem::hqc192::PUBLIC_KEY_SIZE
    );
    assert_eq!(
        Hqc192Fips207DraftCandidate::SK_LEN,
        hqc_kem::hqc192::SECRET_KEY_SIZE
    );
    assert_eq!(
        Hqc192Fips207DraftCandidate::CT_LEN,
        hqc_kem::hqc192::CIPHERTEXT_SIZE
    );
    assert_eq!(
        Hqc192Fips207DraftCandidate::SS_LEN,
        hqc_kem::hqc192::SHARED_SECRET_SIZE
    );
    assert_eq!(
        Hqc192Fips207DraftCandidate::MESSAGE_LEN,
        hqc_kem::hqc192::MESSAGE_SIZE
    );
    assert_eq!(Hqc192Fips207DraftCandidate::ENCAPS_RANDOMNESS_LEN, 40);
    run_with_crypto_stack(|| {
        exercise_candidate(
            Hqc192Fips207DraftCandidate,
            "HQC-192-V5-FIPS207-DRAFT-CANDIDATE",
            Sizes {
                public_key: 4514,
                secret_key: 4602,
                ciphertext: 8978,
                randomness: 40,
            },
            |seed| {
                let (sk, pk) = Hqc192Fips207DraftCandidate::generate(seed);
                (sk.to_vec(), pk.to_vec())
            },
        );
    });
}

#[test]
fn hqc256_candidate_contract() {
    assert_eq!(
        Hqc256Fips207DraftCandidate::PK_LEN,
        hqc_kem::hqc256::PUBLIC_KEY_SIZE
    );
    assert_eq!(
        Hqc256Fips207DraftCandidate::SK_LEN,
        hqc_kem::hqc256::SECRET_KEY_SIZE
    );
    assert_eq!(
        Hqc256Fips207DraftCandidate::CT_LEN,
        hqc_kem::hqc256::CIPHERTEXT_SIZE
    );
    assert_eq!(
        Hqc256Fips207DraftCandidate::SS_LEN,
        hqc_kem::hqc256::SHARED_SECRET_SIZE
    );
    assert_eq!(
        Hqc256Fips207DraftCandidate::MESSAGE_LEN,
        hqc_kem::hqc256::MESSAGE_SIZE
    );
    assert_eq!(Hqc256Fips207DraftCandidate::ENCAPS_RANDOMNESS_LEN, 48);
    run_with_crypto_stack(|| {
        exercise_candidate(
            Hqc256Fips207DraftCandidate,
            "HQC-256-V5-FIPS207-DRAFT-CANDIDATE",
            Sizes {
                public_key: 7237,
                secret_key: 7333,
                ciphertext: 14421,
                randomness: 48,
            },
            |seed| {
                let (sk, pk) = Hqc256Fips207DraftCandidate::generate(seed);
                (sk.to_vec(), pk.to_vec())
            },
        );
    });
}
