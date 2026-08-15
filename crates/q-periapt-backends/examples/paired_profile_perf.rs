//! Paired performance evidence with two independently named estimands.
//!
//! `profile_non_regression` compares ContextBound with CompatXWing over the
//! target-selected product backend. A release-evidence build additionally links
//! one symbol-renamed portable C reference and measures
//! `implementation_improvement` as native/portable over the ContextBound product
//! encapsulation and decapsulation paths. The portable implementation is private
//! to this example build; it is not a product backend, Cargo feature, runtime
//! override, or shipping API.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use q_periapt_backends::{
    MlKem768XWingSeed, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_XWING_SEED_LEN, ML_KEM_IMPLEMENTATION_ID, X25519, X25519_LEN,
};
#[cfg(qperiapt_performance_evidence)]
use q_periapt_core::SHARED_SECRET_LEN;
use q_periapt_core::{combine, CombineInput, Kem, Profile, Xof256};
use q_periapt_kem::HybridKem;
use serde::Serialize;
#[cfg(qperiapt_performance_evidence)]
use sha3::{Digest, Sha3_256};

const SCHEMA_VERSION: u32 = 3;
const SCHEDULE: &str = "ABBA/BAAB";
const PROFILE_NON_REGRESSION: &str = "profile_non_regression";
#[cfg(qperiapt_performance_evidence)]
const IMPLEMENTATION_IMPROVEMENT: &str = "implementation_improvement";
const RELEASE_EVIDENCE_MODE: &str = "release_evidence";
const PROFILE_DIAGNOSTIC_MODE: &str = "profile_diagnostic";
#[cfg(qperiapt_performance_evidence)]
const NATIVE_IMPLEMENTATION_ID: &str = "mlkem-native-1.2.0/aarch64-native-arith+fips202-v8a-scalar";
#[cfg(qperiapt_performance_evidence)]
const PORTABLE_REFERENCE_IMPLEMENTATION_ID: &str =
    "mlkem-native-1.2.0/portable-c/evidence-only-reference";
#[cfg(qperiapt_performance_evidence)]
const PORTABLE_REFERENCE_SCOPE: &str = "evidence_only_non_product_reference";
const CORPUS_SIZE: usize = 64;
const SUITE_ID: &[u8] = b"ML-KEM-768+X25519";
const POLICY_VERSION: u32 = 1;
const APPLICATION_CONTEXT: &[u8] = b"q-periapt/performance-gate/v1";
const COMBINE_ITERATIONS_PER_SAMPLE: usize = 256;
const ENCAPSULATE_ITERATIONS_PER_SAMPLE: usize = 1;
const DECAPSULATE_ITERATIONS_PER_SAMPLE: usize = 2;

#[derive(Debug)]
struct BenchError(String);

impl fmt::Display for BenchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for BenchError {}

#[derive(Clone, Copy)]
enum MeasuredProfile {
    ContextBound,
    CompatXWing,
}

impl MeasuredProfile {
    const fn core(self) -> Profile {
        match self {
            Self::ContextBound => Profile::ContextBound,
            Self::CompatXWing => Profile::CompatXWing,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ContextBound => "ContextBound",
            Self::CompatXWing => "CompatXWing",
        }
    }
}

#[cfg(qperiapt_performance_evidence)]
#[derive(Clone, Copy)]
enum MeasuredImplementation {
    Native,
    Portable,
}

#[cfg(qperiapt_performance_evidence)]
impl MeasuredImplementation {
    const fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Portable => "portable",
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Combine,
    Encapsulate,
    Decapsulate,
}

impl Operation {
    const ALL: [Self; 3] = [Self::Combine, Self::Encapsulate, Self::Decapsulate];

    #[cfg(qperiapt_performance_evidence)]
    const IMPLEMENTATION: [Self; 2] = [Self::Encapsulate, Self::Decapsulate];

    const fn name(self) -> &'static str {
        match self {
            Self::Combine => "combine",
            Self::Encapsulate => "encapsulate",
            Self::Decapsulate => "decapsulate",
        }
    }

    const fn iterations_per_sample(self) -> usize {
        match self {
            Self::Combine => COMBINE_ITERATIONS_PER_SAMPLE,
            Self::Encapsulate => ENCAPSULATE_ITERATIONS_PER_SAMPLE,
            Self::Decapsulate => DECAPSULATE_ITERATIONS_PER_SAMPLE,
        }
    }
}

#[derive(Serialize)]
struct MetadataRecord {
    schema_version: u32,
    record_type: &'static str,
    mode: &'static str,
    target: String,
    schedule: &'static str,
    corpus_size: usize,
    samples_per_variant_operation: usize,
    iterations_per_sample: IterationsPerSample,
    warmup_ms: u64,
    suite_id_hex: String,
    policy_version: u32,
    application_context_hex: String,
    profile_non_regression: ProfileContract,
    implementation_improvement: Option<ImplementationContract>,
}

#[derive(Serialize)]
struct ProfileContract {
    backend: String,
    direction: &'static str,
    operations: [&'static str; 3],
    variants: [&'static str; 2],
}

#[derive(Serialize)]
struct ImplementationContract {
    digest_algorithm: &'static str,
    direction: &'static str,
    equivalence_cases_per_operation: EquivalenceCaseCounts,
    native_implementation_id: &'static str,
    operations: [&'static str; 2],
    portable_implementation_id: &'static str,
    product_profile: &'static str,
    reference_scope: &'static str,
    variants: [&'static str; 2],
}

#[derive(Serialize)]
struct EquivalenceCaseCounts {
    keypair: usize,
    encapsulate: usize,
    decapsulate: usize,
}

#[derive(Serialize)]
struct IterationsPerSample {
    combine: usize,
    encapsulate: usize,
    decapsulate: usize,
}

#[derive(Serialize)]
struct SampleRecord {
    schema_version: u32,
    record_type: &'static str,
    estimand: &'static str,
    operation: &'static str,
    variant: &'static str,
    pair_id: usize,
    schedule_index: usize,
    corpus_index: usize,
    elapsed_ns_total: u128,
}

#[cfg(qperiapt_performance_evidence)]
#[derive(Serialize)]
struct EquivalenceRecord {
    schema_version: u32,
    record_type: &'static str,
    operation: &'static str,
    case_id: usize,
    corpus_index: usize,
    input_digest_hex: String,
    native_output_digest_hex: String,
    portable_output_digest_hex: String,
}

struct Args {
    samples: usize,
    warmup_ms: u64,
    raw_out: PathBuf,
}

fn parse_positive<T>(name: &str, raw: &str) -> Result<T, BenchError>
where
    T: std::str::FromStr + PartialOrd + From<u8>,
{
    let value = raw
        .parse::<T>()
        .map_err(|_| BenchError(format!("{name} must be an integer: {raw}")))?;
    if value <= T::from(0) {
        return Err(BenchError(format!("{name} must be positive: {raw}")));
    }
    Ok(value)
}

fn parse_args() -> Result<Args, BenchError> {
    let mut args = std::env::args().skip(1);
    let mut samples = 20_480usize;
    let mut warmup_ms = 5_000u64;
    let mut raw_out = None;

    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| BenchError(format!("missing value for {flag}")))?;
        match flag.as_str() {
            "--samples" => samples = parse_positive("samples", &value)?,
            "--warmup-ms" => warmup_ms = parse_positive("warmup-ms", &value)?,
            "--raw-out" => raw_out = Some(PathBuf::from(value)),
            _ => return Err(BenchError(format!("unknown argument: {flag}"))),
        }
    }
    if samples % 2 != 0 {
        return Err(BenchError(
            "samples must be even so ABBA/BAAB yields equal paired counts".into(),
        ));
    }
    let raw_out = raw_out.ok_or_else(|| BenchError("--raw-out is required".into()))?;
    Ok(Args {
        samples,
        warmup_ms,
        raw_out,
    })
}

fn hex(bytes: &[u8]) -> Result<String, BenchError> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = DIGITS
            .get(usize::from(byte >> 4))
            .copied()
            .ok_or_else(|| BenchError("high hex nibble is out of range".into()))?;
        let low = DIGITS
            .get(usize::from(byte & 0x0f))
            .copied()
            .ok_or_else(|| BenchError("low hex nibble is out of range".into()))?;
        out.push(char::from(high));
        out.push(char::from(low));
    }
    Ok(out)
}

fn derive32(domain: u8, index: usize) -> [u8; 32] {
    let mut xof = Sha3_256Xof::new();
    xof.absorb_public(b"Q-PERIAPT-PAIRED-PERF-CORPUS/v1");
    xof.absorb_public(&[domain]);
    xof.absorb_public(&index.to_be_bytes());
    xof.squeeze32()
}

#[cfg(qperiapt_performance_evidence)]
fn digest_parts(parts: &[&[u8]]) -> Result<String, BenchError> {
    let mut digest = Sha3_256::new();
    for part in parts {
        Digest::update(&mut digest, (part.len() as u64).to_be_bytes());
        Digest::update(&mut digest, part);
    }
    hex(&digest.finalize())
}

fn backend_id() -> String {
    format!("ML-KEM-768(seed-dk)+X25519/{ML_KEM_IMPLEMENTATION_ID}+sha3+x25519-dalek")
}

struct CorpusEntry {
    rand_pq: [u8; 32],
    rand_trad: [u8; 32],
    ct_pq: [u8; ML_KEM_768_CT_LEN],
    ct_trad: [u8; X25519_LEN],
    #[cfg(qperiapt_performance_evidence)]
    bound_secret: [u8; SHARED_SECRET_LEN],
}

struct Fixture {
    sk_pq: [u8; ML_KEM_768_XWING_SEED_LEN],
    pk_pq: [u8; ML_KEM_768_PK_LEN],
    sk_trad: [u8; X25519_LEN],
    pk_trad: [u8; X25519_LEN],
    corpus: Vec<CorpusEntry>,
    combine_ss_pq: [u8; 32],
    combine_ss_trad: [u8; 32],
}

type MatchedKem<'a> = HybridKem<'a, MlKem768XWingSeed, X25519, Sha3_256Xof>;

fn kem_error(context: &str, error: q_periapt_core::Error) -> BenchError {
    BenchError(format!("{context}: {error:?}"))
}

fn build_fixture(bound: &MatchedKem<'_>, compat: &MatchedKem<'_>) -> Result<Fixture, BenchError> {
    let (sk_pq, pk_pq) = MlKem768XWingSeed::generate(derive32(1, 0))
        .map_err(|error| kem_error("prepare ML-KEM key pair", error))?;
    let (sk_trad, pk_trad) = X25519::generate(derive32(2, 0));
    let mut corpus = Vec::with_capacity(CORPUS_SIZE);
    let mut combine_ss_pq = [0u8; 32];
    let mut combine_ss_trad = [0u8; 32];

    for index in 0..CORPUS_SIZE {
        let rand_pq = derive32(3, index);
        let rand_trad = derive32(4, index);
        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let bound_secret = bound
            .encapsulate(
                &pk_pq,
                &pk_trad,
                APPLICATION_CONTEXT,
                &rand_pq,
                &rand_trad,
                &mut ct_pq,
                &mut ct_trad,
            )
            .map_err(|error| kem_error("prepare ContextBound corpus", error))?;
        let mut compat_ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut compat_ct_trad = [0u8; X25519_LEN];
        let compat_secret = compat
            .encapsulate(
                &pk_pq,
                &pk_trad,
                APPLICATION_CONTEXT,
                &rand_pq,
                &rand_trad,
                &mut compat_ct_pq,
                &mut compat_ct_trad,
            )
            .map_err(|error| kem_error("prepare CompatXWing corpus", error))?;
        if ct_pq != compat_ct_pq || ct_trad != compat_ct_trad {
            return Err(BenchError(
                "matched profiles produced different component ciphertexts".into(),
            ));
        }
        if bound_secret.as_bytes() == compat_secret.as_bytes() {
            return Err(BenchError(
                "profile negative control failed: combined secrets unexpectedly match".into(),
            ));
        }
        if index == 0 {
            MlKem768XWingSeed
                .decapsulate(&sk_pq, &ct_pq, &mut combine_ss_pq)
                .map_err(|error| kem_error("prepare PQ shared secret", error))?;
            X25519
                .decapsulate(&sk_trad, &ct_trad, &mut combine_ss_trad)
                .map_err(|error| kem_error("prepare traditional shared secret", error))?;
        }
        corpus.push(CorpusEntry {
            rand_pq,
            rand_trad,
            ct_pq,
            ct_trad,
            #[cfg(qperiapt_performance_evidence)]
            bound_secret: *bound_secret.as_bytes(),
        });
    }

    Ok(Fixture {
        sk_pq,
        pk_pq,
        sk_trad,
        pk_trad,
        corpus,
        combine_ss_pq,
        combine_ss_trad,
    })
}

fn run_profile_once(
    operation: Operation,
    profile: MeasuredProfile,
    bound: &MatchedKem<'_>,
    compat: &MatchedKem<'_>,
    fixture: &Fixture,
    corpus_index: usize,
) -> Result<(), BenchError> {
    let kem = match profile {
        MeasuredProfile::ContextBound => bound,
        MeasuredProfile::CompatXWing => compat,
    };
    let entry = fixture
        .corpus
        .get(corpus_index)
        .ok_or_else(|| BenchError(format!("corpus index is out of range: {corpus_index}")))?;
    match operation {
        Operation::Combine => {
            let input = CombineInput {
                suite_id: SUITE_ID,
                policy_version: POLICY_VERSION,
                ss_pq: &fixture.combine_ss_pq,
                ss_trad: &fixture.combine_ss_trad,
                ct_pq: &entry.ct_pq,
                pk_pq: &fixture.pk_pq,
                ct_trad: &entry.ct_trad,
                pk_trad: &fixture.pk_trad,
                context: APPLICATION_CONTEXT,
            };
            black_box(combine::<Sha3_256Xof>(profile.core(), black_box(&input)))
                .map_err(|error| kem_error("combine measurement", error))?;
        }
        Operation::Encapsulate => {
            let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            black_box(
                kem.encapsulate(
                    black_box(&fixture.pk_pq),
                    &fixture.pk_trad,
                    APPLICATION_CONTEXT,
                    &entry.rand_pq,
                    &entry.rand_trad,
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .map_err(|error| kem_error("encapsulation measurement", error))?,
            );
        }
        Operation::Decapsulate => {
            black_box(
                kem.decapsulate(
                    black_box(&fixture.sk_pq),
                    &entry.ct_pq,
                    &fixture.pk_pq,
                    &fixture.sk_trad,
                    &entry.ct_trad,
                    &fixture.pk_trad,
                    APPLICATION_CONTEXT,
                )
                .map_err(|error| kem_error("decapsulation measurement", error))?,
            );
        }
    }
    Ok(())
}

fn warm_up_profiles(
    duration: Duration,
    bound: &MatchedKem<'_>,
    compat: &MatchedKem<'_>,
    fixture: &Fixture,
) -> Result<(), BenchError> {
    let start = Instant::now();
    let mut iteration = 0usize;
    while start.elapsed() < duration {
        for operation in Operation::ALL {
            run_profile_once(
                operation,
                MeasuredProfile::ContextBound,
                bound,
                compat,
                fixture,
                iteration % CORPUS_SIZE,
            )?;
            run_profile_once(
                operation,
                MeasuredProfile::CompatXWing,
                bound,
                compat,
                fixture,
                iteration % CORPUS_SIZE,
            )?;
        }
        iteration = iteration.wrapping_add(1);
    }
    Ok(())
}

fn collect_profiles(
    operation: Operation,
    samples: usize,
    bound: &MatchedKem<'_>,
    compat: &MatchedKem<'_>,
    fixture: &Fixture,
    records: &mut Vec<SampleRecord>,
) -> Result<(), BenchError> {
    let cycles = samples / 2;
    for cycle in 0..cycles {
        let order = if cycle % 2 == 0 {
            [
                MeasuredProfile::ContextBound,
                MeasuredProfile::CompatXWing,
                MeasuredProfile::CompatXWing,
                MeasuredProfile::ContextBound,
            ]
        } else {
            [
                MeasuredProfile::CompatXWing,
                MeasuredProfile::ContextBound,
                MeasuredProfile::ContextBound,
                MeasuredProfile::CompatXWing,
            ]
        };
        for (slot, profile) in order.into_iter().enumerate() {
            let pair_id = cycle * 2 + usize::from(slot >= 2);
            let corpus_index = pair_id % CORPUS_SIZE;
            let iterations = operation.iterations_per_sample();
            let start = Instant::now();
            for repetition in 0..iterations {
                let repeated_corpus_index = black_box((corpus_index + repetition) % CORPUS_SIZE);
                black_box(run_profile_once(
                    operation,
                    profile,
                    bound,
                    compat,
                    fixture,
                    repeated_corpus_index,
                )?);
            }
            let elapsed_ns_total = start.elapsed().as_nanos();
            if elapsed_ns_total == 0 {
                return Err(BenchError(format!(
                    "{} {} timed batch returned zero elapsed time",
                    operation.name(),
                    profile.name()
                )));
            }
            records.push(SampleRecord {
                schema_version: SCHEMA_VERSION,
                record_type: "sample",
                estimand: PROFILE_NON_REGRESSION,
                operation: operation.name(),
                variant: profile.name(),
                pair_id,
                schedule_index: cycle * 4 + slot,
                corpus_index,
                elapsed_ns_total,
            });
        }
    }
    Ok(())
}

#[cfg(qperiapt_performance_evidence)]
mod portable_reference {
    use super::{BenchError, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_XWING_SEED_LEN};
    use q_periapt_core::{Error, Kem, SHARED_SECRET_LEN};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    const EXPANDED_SK_LEN: usize = 2400;
    const KEYGEN_SEED_LEN: usize = 64;

    unsafe extern "C" {
        fn qpn_mlkem_evidence_portable_v1_2_0_768_keypair_derand(
            public_key: *mut u8,
            decapsulation_key: *mut u8,
            seed: *const u8,
        ) -> i32;
        fn qpn_mlkem_evidence_portable_v1_2_0_768_encapsulate_derand(
            ciphertext: *mut u8,
            shared_secret: *mut u8,
            public_key: *const u8,
            seed: *const u8,
        ) -> i32;
        fn qpn_mlkem_evidence_portable_v1_2_0_768_decapsulate(
            shared_secret: *mut u8,
            ciphertext: *const u8,
            decapsulation_key: *const u8,
        ) -> i32;
    }

    #[derive(Clone, Copy)]
    pub(super) struct PortableMlKem768XWingSeed;

    fn expand_seed(seed: &[u8; ML_KEM_768_XWING_SEED_LEN]) -> [u8; KEYGEN_SEED_LEN] {
        let mut state = Shake256::default();
        state.update(seed);
        let mut reader = state.finalize_xof();
        let mut output = [0u8; KEYGEN_SEED_LEN];
        reader.read(&mut output);
        output
    }

    fn require_status(status: i32, operation: &str) -> Result<(), Error> {
        if status == 0 {
            Ok(())
        } else {
            let _ = operation;
            Err(Error::Backend)
        }
    }

    impl PortableMlKem768XWingSeed {
        pub(super) fn generate(
            seed: [u8; ML_KEM_768_XWING_SEED_LEN],
        ) -> Result<([u8; ML_KEM_768_XWING_SEED_LEN], [u8; ML_KEM_768_PK_LEN]), Error> {
            let expanded_seed = expand_seed(&seed);
            let mut public_key = [0u8; ML_KEM_768_PK_LEN];
            let mut expanded_key = [0u8; EXPANDED_SK_LEN];
            // SAFETY: all pointers name exact-size, non-overlapping live arrays
            // for the duration of the private C reference call.
            let status = unsafe {
                qpn_mlkem_evidence_portable_v1_2_0_768_keypair_derand(
                    public_key.as_mut_ptr(),
                    expanded_key.as_mut_ptr(),
                    expanded_seed.as_ptr(),
                )
            };
            require_status(status, "portable keypair")?;
            expanded_key.fill(0);
            Ok((seed, public_key))
        }
    }

    impl Kem for PortableMlKem768XWingSeed {
        const C2PRI: bool = true;
        const COMPAT_XWING_SAFE: bool = true;

        fn algorithm(&self) -> &'static str {
            "ML-KEM-768(seed-dk)/portable-evidence-reference"
        }

        fn encapsulate(
            &self,
            public_key: &[u8],
            randomness: &[u8],
            ciphertext: &mut [u8],
            shared_secret: &mut [u8],
        ) -> Result<(), Error> {
            let public_key: &[u8; ML_KEM_768_PK_LEN] =
                public_key.try_into().map_err(|_| Error::InvalidLength)?;
            let randomness: &[u8; 32] = randomness.try_into().map_err(|_| Error::InvalidLength)?;
            let ciphertext: &mut [u8; ML_KEM_768_CT_LEN] =
                ciphertext.try_into().map_err(|_| Error::InvalidLength)?;
            let shared_secret: &mut [u8; SHARED_SECRET_LEN] =
                shared_secret.try_into().map_err(|_| Error::InvalidLength)?;
            ciphertext.fill(0);
            shared_secret.fill(0);
            // SAFETY: the four exact-size arrays are live and non-overlapping.
            let status = unsafe {
                qpn_mlkem_evidence_portable_v1_2_0_768_encapsulate_derand(
                    ciphertext.as_mut_ptr(),
                    shared_secret.as_mut_ptr(),
                    public_key.as_ptr(),
                    randomness.as_ptr(),
                )
            };
            if let Err(error) = require_status(status, "portable encapsulate") {
                ciphertext.fill(0);
                shared_secret.fill(0);
                return Err(error);
            }
            Ok(())
        }

        fn decapsulate(
            &self,
            seed: &[u8],
            ciphertext: &[u8],
            shared_secret: &mut [u8],
        ) -> Result<(), Error> {
            let seed: &[u8; ML_KEM_768_XWING_SEED_LEN] =
                seed.try_into().map_err(|_| Error::InvalidLength)?;
            let ciphertext: &[u8; ML_KEM_768_CT_LEN] =
                ciphertext.try_into().map_err(|_| Error::InvalidLength)?;
            let shared_secret: &mut [u8; SHARED_SECRET_LEN] =
                shared_secret.try_into().map_err(|_| Error::InvalidLength)?;
            let expanded_seed = expand_seed(seed);
            let mut public_key = [0u8; ML_KEM_768_PK_LEN];
            let mut expanded_key = [0u8; EXPANDED_SK_LEN];
            // SAFETY: all pointers name exact-size, non-overlapping live arrays.
            let keypair_status = unsafe {
                qpn_mlkem_evidence_portable_v1_2_0_768_keypair_derand(
                    public_key.as_mut_ptr(),
                    expanded_key.as_mut_ptr(),
                    expanded_seed.as_ptr(),
                )
            };
            require_status(keypair_status, "portable decapsulation key expansion")?;
            shared_secret.fill(0);
            // SAFETY: all pointers name exact-size, non-overlapping live arrays.
            let status = unsafe {
                qpn_mlkem_evidence_portable_v1_2_0_768_decapsulate(
                    shared_secret.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    expanded_key.as_ptr(),
                )
            };
            expanded_key.fill(0);
            if let Err(error) = require_status(status, "portable decapsulate") {
                shared_secret.fill(0);
                return Err(error);
            }
            Ok(())
        }
    }

    pub(super) fn ensure_native_identity(actual: &str) -> Result<(), BenchError> {
        if actual != super::NATIVE_IMPLEMENTATION_ID {
            return Err(BenchError(format!(
                "release implementation evidence requires {}, got {actual}",
                super::NATIVE_IMPLEMENTATION_ID
            )));
        }
        Ok(())
    }
}

#[cfg(qperiapt_performance_evidence)]
type PortableMatchedKem<'a> =
    HybridKem<'a, portable_reference::PortableMlKem768XWingSeed, X25519, Sha3_256Xof>;

#[cfg(qperiapt_performance_evidence)]
fn build_portable_bound<'a>(
    pq: &'a portable_reference::PortableMlKem768XWingSeed,
    trad: &'a X25519,
) -> Result<PortableMatchedKem<'a>, BenchError> {
    HybridKem::<_, _, Sha3_256Xof>::new(pq, trad, Profile::ContextBound, SUITE_ID, POLICY_VERSION)
        .map_err(|error| kem_error("construct portable ContextBound harness", error))
}

#[cfg(qperiapt_performance_evidence)]
fn verify_implementation_equivalence(
    native: &MatchedKem<'_>,
    portable: &PortableMatchedKem<'_>,
    fixture: &Fixture,
) -> Result<Vec<EquivalenceRecord>, BenchError> {
    portable_reference::ensure_native_identity(ML_KEM_IMPLEMENTATION_ID)?;
    let seed = derive32(1, 0);
    let (portable_sk, portable_pk) = portable_reference::PortableMlKem768XWingSeed::generate(seed)
        .map_err(|error| kem_error("portable reference keypair", error))?;
    if portable_sk != fixture.sk_pq || portable_pk != fixture.pk_pq {
        return Err(BenchError(
            "native and portable keypair outputs differ".into(),
        ));
    }
    let keypair_input = digest_parts(&[&seed])?;
    let keypair_output = digest_parts(&[&fixture.sk_pq, &fixture.pk_pq])?;
    let mut records = vec![EquivalenceRecord {
        schema_version: SCHEMA_VERSION,
        record_type: "equivalence",
        operation: "keypair",
        case_id: 0,
        corpus_index: 0,
        input_digest_hex: keypair_input,
        native_output_digest_hex: keypair_output.clone(),
        portable_output_digest_hex: keypair_output,
    }];

    for (case_id, entry) in fixture.corpus.iter().enumerate() {
        let mut native_ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut native_ct_trad = [0u8; X25519_LEN];
        let native_secret = native
            .encapsulate(
                &fixture.pk_pq,
                &fixture.pk_trad,
                APPLICATION_CONTEXT,
                &entry.rand_pq,
                &entry.rand_trad,
                &mut native_ct_pq,
                &mut native_ct_trad,
            )
            .map_err(|error| kem_error("native equivalence encapsulation", error))?;
        let mut portable_ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut portable_ct_trad = [0u8; X25519_LEN];
        let portable_secret = portable
            .encapsulate(
                &fixture.pk_pq,
                &fixture.pk_trad,
                APPLICATION_CONTEXT,
                &entry.rand_pq,
                &entry.rand_trad,
                &mut portable_ct_pq,
                &mut portable_ct_trad,
            )
            .map_err(|error| kem_error("portable equivalence encapsulation", error))?;
        if native_ct_pq != entry.ct_pq
            || native_ct_trad != entry.ct_trad
            || native_secret.as_bytes() != &entry.bound_secret
            || native_ct_pq != portable_ct_pq
            || native_ct_trad != portable_ct_trad
            || native_secret.as_bytes() != portable_secret.as_bytes()
        {
            return Err(BenchError(format!(
                "native and portable encapsulation outputs differ for corpus case {case_id}"
            )));
        }
        let encapsulate_input = digest_parts(&[
            &fixture.pk_pq,
            &fixture.pk_trad,
            APPLICATION_CONTEXT,
            &entry.rand_pq,
            &entry.rand_trad,
        ])?;
        let encapsulate_output =
            digest_parts(&[&native_ct_pq, &native_ct_trad, native_secret.as_bytes()])?;
        records.push(EquivalenceRecord {
            schema_version: SCHEMA_VERSION,
            record_type: "equivalence",
            operation: "encapsulate",
            case_id,
            corpus_index: case_id,
            input_digest_hex: encapsulate_input,
            native_output_digest_hex: encapsulate_output.clone(),
            portable_output_digest_hex: encapsulate_output,
        });

        let native_decapsulated = native
            .decapsulate(
                &fixture.sk_pq,
                &entry.ct_pq,
                &fixture.pk_pq,
                &fixture.sk_trad,
                &entry.ct_trad,
                &fixture.pk_trad,
                APPLICATION_CONTEXT,
            )
            .map_err(|error| kem_error("native equivalence decapsulation", error))?;
        let portable_decapsulated = portable
            .decapsulate(
                &fixture.sk_pq,
                &entry.ct_pq,
                &fixture.pk_pq,
                &fixture.sk_trad,
                &entry.ct_trad,
                &fixture.pk_trad,
                APPLICATION_CONTEXT,
            )
            .map_err(|error| kem_error("portable equivalence decapsulation", error))?;
        if native_decapsulated.as_bytes() != &entry.bound_secret
            || native_decapsulated.as_bytes() != portable_decapsulated.as_bytes()
        {
            return Err(BenchError(format!(
                "native and portable decapsulation outputs differ for corpus case {case_id}"
            )));
        }
        let decapsulate_input = digest_parts(&[
            &fixture.sk_pq,
            &entry.ct_pq,
            &fixture.pk_pq,
            &fixture.sk_trad,
            &entry.ct_trad,
            &fixture.pk_trad,
            APPLICATION_CONTEXT,
        ])?;
        let decapsulate_output = digest_parts(&[native_decapsulated.as_bytes()])?;
        records.push(EquivalenceRecord {
            schema_version: SCHEMA_VERSION,
            record_type: "equivalence",
            operation: "decapsulate",
            case_id,
            corpus_index: case_id,
            input_digest_hex: decapsulate_input,
            native_output_digest_hex: decapsulate_output.clone(),
            portable_output_digest_hex: decapsulate_output,
        });
    }
    Ok(records)
}

#[cfg(qperiapt_performance_evidence)]
fn run_implementation_once(
    operation: Operation,
    implementation: MeasuredImplementation,
    native: &MatchedKem<'_>,
    portable: &PortableMatchedKem<'_>,
    fixture: &Fixture,
    corpus_index: usize,
) -> Result<(), BenchError> {
    let entry = fixture
        .corpus
        .get(corpus_index)
        .ok_or_else(|| BenchError(format!("corpus index is out of range: {corpus_index}")))?;
    match operation {
        Operation::Combine => {
            return Err(BenchError(
                "combine is not an implementation-improvement operation".into(),
            ))
        }
        Operation::Encapsulate => {
            let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            match implementation {
                MeasuredImplementation::Native => black_box(
                    native
                        .encapsulate(
                            black_box(&fixture.pk_pq),
                            &fixture.pk_trad,
                            APPLICATION_CONTEXT,
                            &entry.rand_pq,
                            &entry.rand_trad,
                            &mut ct_pq,
                            &mut ct_trad,
                        )
                        .map_err(|error| kem_error("native encapsulation measurement", error))?,
                ),
                MeasuredImplementation::Portable => black_box(
                    portable
                        .encapsulate(
                            black_box(&fixture.pk_pq),
                            &fixture.pk_trad,
                            APPLICATION_CONTEXT,
                            &entry.rand_pq,
                            &entry.rand_trad,
                            &mut ct_pq,
                            &mut ct_trad,
                        )
                        .map_err(|error| kem_error("portable encapsulation measurement", error))?,
                ),
            };
        }
        Operation::Decapsulate => {
            match implementation {
                MeasuredImplementation::Native => black_box(
                    native
                        .decapsulate(
                            black_box(&fixture.sk_pq),
                            &entry.ct_pq,
                            &fixture.pk_pq,
                            &fixture.sk_trad,
                            &entry.ct_trad,
                            &fixture.pk_trad,
                            APPLICATION_CONTEXT,
                        )
                        .map_err(|error| kem_error("native decapsulation measurement", error))?,
                ),
                MeasuredImplementation::Portable => black_box(
                    portable
                        .decapsulate(
                            black_box(&fixture.sk_pq),
                            &entry.ct_pq,
                            &fixture.pk_pq,
                            &fixture.sk_trad,
                            &entry.ct_trad,
                            &fixture.pk_trad,
                            APPLICATION_CONTEXT,
                        )
                        .map_err(|error| kem_error("portable decapsulation measurement", error))?,
                ),
            };
        }
    }
    Ok(())
}

#[cfg(qperiapt_performance_evidence)]
fn warm_up_implementations(
    duration: Duration,
    native: &MatchedKem<'_>,
    portable: &PortableMatchedKem<'_>,
    fixture: &Fixture,
) -> Result<(), BenchError> {
    let start = Instant::now();
    let mut iteration = 0usize;
    while start.elapsed() < duration {
        for operation in Operation::IMPLEMENTATION {
            run_implementation_once(
                operation,
                MeasuredImplementation::Native,
                native,
                portable,
                fixture,
                iteration % CORPUS_SIZE,
            )?;
            run_implementation_once(
                operation,
                MeasuredImplementation::Portable,
                native,
                portable,
                fixture,
                iteration % CORPUS_SIZE,
            )?;
        }
        iteration = iteration.wrapping_add(1);
    }
    Ok(())
}

#[cfg(qperiapt_performance_evidence)]
fn collect_implementations(
    operation: Operation,
    samples: usize,
    native: &MatchedKem<'_>,
    portable: &PortableMatchedKem<'_>,
    fixture: &Fixture,
    records: &mut Vec<SampleRecord>,
) -> Result<(), BenchError> {
    for cycle in 0..samples / 2 {
        let order = if cycle % 2 == 0 {
            [
                MeasuredImplementation::Native,
                MeasuredImplementation::Portable,
                MeasuredImplementation::Portable,
                MeasuredImplementation::Native,
            ]
        } else {
            [
                MeasuredImplementation::Portable,
                MeasuredImplementation::Native,
                MeasuredImplementation::Native,
                MeasuredImplementation::Portable,
            ]
        };
        for (slot, implementation) in order.into_iter().enumerate() {
            let pair_id = cycle * 2 + usize::from(slot >= 2);
            let corpus_index = pair_id % CORPUS_SIZE;
            let start = Instant::now();
            for repetition in 0..operation.iterations_per_sample() {
                let repeated_corpus_index = black_box((corpus_index + repetition) % CORPUS_SIZE);
                black_box(run_implementation_once(
                    operation,
                    implementation,
                    native,
                    portable,
                    fixture,
                    repeated_corpus_index,
                )?);
            }
            let elapsed_ns_total = start.elapsed().as_nanos();
            if elapsed_ns_total == 0 {
                return Err(BenchError(format!(
                    "{} {} timed batch returned zero elapsed time",
                    operation.name(),
                    implementation.name()
                )));
            }
            records.push(SampleRecord {
                schema_version: SCHEMA_VERSION,
                record_type: "sample",
                estimand: IMPLEMENTATION_IMPROVEMENT,
                operation: operation.name(),
                variant: implementation.name(),
                pair_id,
                schedule_index: cycle * 4 + slot,
                corpus_index,
                elapsed_ns_total,
            });
        }
    }
    Ok(())
}

fn write_json_line<T: Serialize>(
    writer: &mut BufWriter<File>,
    value: &T,
) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn harness_mode() -> &'static str {
    if cfg!(qperiapt_performance_evidence) {
        RELEASE_EVIDENCE_MODE
    } else {
        PROFILE_DIAGNOSTIC_MODE
    }
}

fn harness_target() -> String {
    #[cfg(qperiapt_performance_evidence)]
    {
        env!("QPERIAPT_PERFORMANCE_TARGET").to_owned()
    }
    #[cfg(not(qperiapt_performance_evidence))]
    {
        format!("diagnostic-{}", std::env::consts::ARCH)
    }
}

fn implementation_contract() -> Option<ImplementationContract> {
    #[cfg(qperiapt_performance_evidence)]
    {
        Some(ImplementationContract {
            digest_algorithm: "SHA3-256",
            direction: "native/portable",
            equivalence_cases_per_operation: EquivalenceCaseCounts {
                keypair: 1,
                encapsulate: CORPUS_SIZE,
                decapsulate: CORPUS_SIZE,
            },
            native_implementation_id: NATIVE_IMPLEMENTATION_ID,
            operations: ["encapsulate", "decapsulate"],
            portable_implementation_id: PORTABLE_REFERENCE_IMPLEMENTATION_ID,
            product_profile: "ContextBound",
            reference_scope: PORTABLE_REFERENCE_SCOPE,
            variants: ["native", "portable"],
        })
    }
    #[cfg(not(qperiapt_performance_evidence))]
    {
        None
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    if let Some(parent) = args.raw_out.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let pq = MlKem768XWingSeed;
    let trad = X25519;
    let bound = HybridKem::<_, _, Sha3_256Xof>::new(
        &pq,
        &trad,
        Profile::ContextBound,
        SUITE_ID,
        POLICY_VERSION,
    )
    .map_err(|error| kem_error("construct ContextBound harness", error))?;
    let compat = HybridKem::<_, _, Sha3_256Xof>::new(
        &pq,
        &trad,
        Profile::CompatXWing,
        SUITE_ID,
        POLICY_VERSION,
    )
    .map_err(|error| kem_error("construct CompatXWing harness", error))?;
    let fixture = build_fixture(&bound, &compat)?;

    #[cfg(qperiapt_performance_evidence)]
    let portable_pq = portable_reference::PortableMlKem768XWingSeed;
    #[cfg(qperiapt_performance_evidence)]
    let portable_bound = build_portable_bound(&portable_pq, &trad)?;
    #[cfg(qperiapt_performance_evidence)]
    let equivalence = verify_implementation_equivalence(&bound, &portable_bound, &fixture)?;

    warm_up_profiles(
        Duration::from_millis(args.warmup_ms),
        &bound,
        &compat,
        &fixture,
    )?;
    #[cfg(qperiapt_performance_evidence)]
    warm_up_implementations(
        Duration::from_millis(args.warmup_ms),
        &bound,
        &portable_bound,
        &fixture,
    )?;

    let multiplier = if cfg!(qperiapt_performance_evidence) {
        Operation::ALL.len() * 2 + 4
    } else {
        Operation::ALL.len() * 2
    };
    let capacity = args
        .samples
        .checked_mul(multiplier)
        .ok_or_else(|| BenchError("sample capacity overflow".into()))?;
    let mut records = Vec::with_capacity(capacity);
    for operation in Operation::ALL {
        collect_profiles(
            operation,
            args.samples,
            &bound,
            &compat,
            &fixture,
            &mut records,
        )?;
    }
    #[cfg(qperiapt_performance_evidence)]
    for operation in Operation::IMPLEMENTATION {
        collect_implementations(
            operation,
            args.samples,
            &bound,
            &portable_bound,
            &fixture,
            &mut records,
        )?;
    }

    let file = File::create(&args.raw_out)?;
    let mut writer = BufWriter::new(file);
    write_json_line(
        &mut writer,
        &MetadataRecord {
            schema_version: SCHEMA_VERSION,
            record_type: "metadata",
            mode: harness_mode(),
            target: harness_target(),
            schedule: SCHEDULE,
            corpus_size: CORPUS_SIZE,
            samples_per_variant_operation: args.samples,
            iterations_per_sample: IterationsPerSample {
                combine: Operation::Combine.iterations_per_sample(),
                encapsulate: Operation::Encapsulate.iterations_per_sample(),
                decapsulate: Operation::Decapsulate.iterations_per_sample(),
            },
            warmup_ms: args.warmup_ms,
            suite_id_hex: hex(SUITE_ID)?,
            policy_version: POLICY_VERSION,
            application_context_hex: hex(APPLICATION_CONTEXT)?,
            profile_non_regression: ProfileContract {
                backend: backend_id(),
                direction: "ContextBound/CompatXWing",
                operations: ["combine", "encapsulate", "decapsulate"],
                variants: ["ContextBound", "CompatXWing"],
            },
            implementation_improvement: implementation_contract(),
        },
    )?;
    #[cfg(qperiapt_performance_evidence)]
    for record in &equivalence {
        write_json_line(&mut writer, record)?;
    }
    for record in &records {
        write_json_line(&mut writer, record)?;
    }
    writer.flush()?;
    eprintln!(
        "PERFORMANCE_RAW_PASS mode={} samples={} records={} output={}",
        harness_mode(),
        args.samples,
        records.len(),
        args.raw_out.display()
    );
    Ok(())
}
