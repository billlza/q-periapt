//! Paired performance evidence with two independently named estimands.
//!
//! `profile_non_regression` compares ContextBound with CompatXWing over the
//! target-selected product backend. A release-evidence build additionally links
//! one symbol-renamed portable C reference and measures
//! `implementation_improvement` as native/portable over an independent
//! ContextBound expanded-key `HybridKem` surface. The portable implementation is
//! private to this example build; it is not a product backend, Cargo feature,
//! runtime override, or shipping API.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[cfg(qperiapt_performance_evidence)]
use q_periapt_backends::{MlKem768, ML_KEM_768_KEYGEN_SEED_LEN, ML_KEM_768_SK_LEN};
use q_periapt_backends::{
    MlKem768XWingSeed, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_XWING_SEED_LEN, ML_KEM_IMPLEMENTATION_ID, X25519, X25519_LEN,
};
#[cfg(qperiapt_performance_evidence)]
use q_periapt_core::SHARED_SECRET_LEN;
use q_periapt_core::{combine, CombineInput, Kem, Profile, Xof256, ZeroizingBytes};
use q_periapt_kem::HybridKem;
use serde::Serialize;
#[cfg(qperiapt_performance_evidence)]
use sha3::{Digest, Sha3_256};

const SCHEMA_VERSION: u32 = 5;
const SCHEDULE: &str = "ABBA/BAAB";
const WARMUP_SCOPE: &str = "per_estimand_operation_immediately_before_collection";
const PROFILE_NON_REGRESSION: &str = "profile_non_regression";
#[cfg(qperiapt_performance_evidence)]
const IMPLEMENTATION_IMPROVEMENT: &str = "implementation_improvement";
const RELEASE_EVIDENCE_MODE: &str = "release_evidence";
const PROFILE_DIAGNOSTIC_MODE: &str = "profile_diagnostic";
#[cfg(qperiapt_performance_evidence)]
const NATIVE_IMPLEMENTATION_ID: &str = "mlkem-native-1.2.0/aarch64-native-arith+fips202-v84a";
#[cfg(qperiapt_performance_evidence)]
const PORTABLE_REFERENCE_IMPLEMENTATION_ID: &str =
    "mlkem-native-1.2.0/portable-c/evidence-only-reference";
#[cfg(qperiapt_performance_evidence)]
const PORTABLE_REFERENCE_SCOPE: &str = "evidence_only_non_product_reference";
#[cfg(qperiapt_performance_evidence)]
const IMPLEMENTATION_SURFACE: &str = "hybrid_core";
#[cfg(qperiapt_performance_evidence)]
const IMPLEMENTATION_KEY_FORMAT: &str = "expanded_fips203_2400";
const CORPUS_SIZE: usize = 64;
const CONTEXT_BOUND_SUITE_ID: &[u8] = b"ML-KEM-768+X25519";
const CONTEXT_BOUND_POLICY_VERSION: u32 = 1;
const CONTEXT_BOUND_APPLICATION_CONTEXT: &[u8] = b"q-periapt/performance-gate/v1";
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

#[derive(Clone, Copy)]
struct CanonicalProfileInputs {
    suite_id: &'static [u8],
    policy_version: u32,
    application_context: &'static [u8],
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

    const fn inputs(self) -> CanonicalProfileInputs {
        match self {
            Self::ContextBound => CanonicalProfileInputs {
                suite_id: CONTEXT_BOUND_SUITE_ID,
                policy_version: CONTEXT_BOUND_POLICY_VERSION,
                application_context: CONTEXT_BOUND_APPLICATION_CONTEXT,
            },
            Self::CompatXWing => CanonicalProfileInputs {
                suite_id: b"",
                policy_version: 0,
                application_context: b"",
            },
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

    #[cfg(any(test, qperiapt_performance_evidence))]
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

fn for_each_warmed_operation<E>(
    operations: impl IntoIterator<Item = Operation>,
    mut warm_up: impl FnMut(Operation) -> Result<(), E>,
    mut collect: impl FnMut(Operation) -> Result<(), E>,
) -> Result<(), E> {
    for operation in operations {
        warm_up(operation)?;
        collect(operation)?;
    }
    Ok(())
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
    warmup_scope: &'static str,
    build_contract: Option<BuildContract>,
    profile_inputs: ProfileInputsRecord,
    profile_non_regression: ProfileContract,
    implementation_improvement: Option<ImplementationContract>,
}

#[derive(Serialize)]
struct ProfileInputsRecord {
    #[serde(rename = "ContextBound")]
    context_bound: ProfileInputRecord,
    #[serde(rename = "CompatXWing")]
    compat_xwing: ProfileInputRecord,
}

#[derive(Serialize)]
struct ProfileInputRecord {
    suite_id_hex: String,
    policy_version: u32,
    application_context_hex: String,
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
    includes_ffi: bool,
    includes_os_rng: bool,
    key_format: &'static str,
    keypair_generation_count: usize,
    native_implementation_id: &'static str,
    operations: [&'static str; 2],
    portable_implementation_id: &'static str,
    product_profile: &'static str,
    reference_scope: &'static str,
    surface: &'static str,
    variants: [&'static str; 2],
}

#[derive(Serialize)]
struct EquivalenceCaseCounts {
    encapsulate: usize,
    decapsulate: usize,
}

#[derive(Clone, Copy, Serialize)]
struct BuildContract {
    c_implementations: CImplementationBuilds,
    rust_harness: RustHarnessBuild,
}

#[derive(Clone, Copy, Serialize)]
struct CImplementationBuilds {
    product_native: CImplementationBuild,
    portable_reference: CImplementationBuild,
}

#[derive(Clone, Copy, Serialize)]
struct CImplementationBuild {
    architecture: &'static str,
    data_sections: bool,
    function_sections: bool,
    language_standard: &'static str,
    macos_deployment_target: &'static str,
    optimization: &'static str,
    position_independent_code: bool,
    visibility: &'static str,
}

#[derive(Clone, Copy, Serialize)]
struct RustHarnessBuild {
    codegen_units: usize,
    lto: &'static str,
    optimization: &'static str,
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
    rand_pq: ZeroizingBytes<32>,
    rand_trad: ZeroizingBytes<32>,
    ct_pq: [u8; ML_KEM_768_CT_LEN],
    ct_trad: [u8; X25519_LEN],
}

struct Fixture {
    sk_pq: ZeroizingBytes<ML_KEM_768_XWING_SEED_LEN>,
    pk_pq: [u8; ML_KEM_768_PK_LEN],
    sk_trad: ZeroizingBytes<X25519_LEN>,
    pk_trad: [u8; X25519_LEN],
    corpus: Vec<CorpusEntry>,
    combine_ss_pq: ZeroizingBytes<32>,
    combine_ss_trad: ZeroizingBytes<32>,
}

type MatchedKem<'a> = HybridKem<'a, MlKem768XWingSeed, X25519, Sha3_256Xof>;

fn kem_error(context: &str, error: q_periapt_core::Error) -> BenchError {
    BenchError(format!("{context}: {error:?}"))
}

fn build_fixture(bound: &MatchedKem<'_>, compat: &MatchedKem<'_>) -> Result<Fixture, BenchError> {
    let pq_seed = ZeroizingBytes::from_bytes(derive32(1, 0));
    let (sk_pq, pk_pq) = MlKem768XWingSeed::generate(*pq_seed.as_bytes())
        .map_err(|error| kem_error("prepare ML-KEM key pair", error))?;
    let sk_pq = ZeroizingBytes::from_bytes(sk_pq);
    let trad_seed = ZeroizingBytes::from_bytes(derive32(2, 0));
    let (sk_trad, pk_trad) = X25519::generate(*trad_seed.as_bytes());
    let sk_trad = ZeroizingBytes::from_bytes(sk_trad);
    let mut corpus = Vec::with_capacity(CORPUS_SIZE);
    let mut combine_ss_pq = ZeroizingBytes::<32>::zeroed();
    let mut combine_ss_trad = ZeroizingBytes::<32>::zeroed();
    let bound_inputs = MeasuredProfile::ContextBound.inputs();
    let compat_inputs = MeasuredProfile::CompatXWing.inputs();

    for index in 0..CORPUS_SIZE {
        let rand_pq = ZeroizingBytes::from_bytes(derive32(3, index));
        let rand_trad = ZeroizingBytes::from_bytes(derive32(4, index));
        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let bound_secret = bound
            .encapsulate(
                &pk_pq,
                &pk_trad,
                bound_inputs.application_context,
                rand_pq.as_bytes(),
                rand_trad.as_bytes(),
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
                compat_inputs.application_context,
                rand_pq.as_bytes(),
                rand_trad.as_bytes(),
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
                .decapsulate(sk_pq.as_bytes(), &ct_pq, combine_ss_pq.as_mut_bytes())
                .map_err(|error| kem_error("prepare PQ shared secret", error))?;
            X25519
                .decapsulate(sk_trad.as_bytes(), &ct_trad, combine_ss_trad.as_mut_bytes())
                .map_err(|error| kem_error("prepare traditional shared secret", error))?;
        }
        corpus.push(CorpusEntry {
            rand_pq,
            rand_trad,
            ct_pq,
            ct_trad,
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
    let inputs = profile.inputs();
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
                suite_id: inputs.suite_id,
                policy_version: inputs.policy_version,
                ss_pq: fixture.combine_ss_pq.as_bytes(),
                ss_trad: fixture.combine_ss_trad.as_bytes(),
                ct_pq: &entry.ct_pq,
                pk_pq: &fixture.pk_pq,
                ct_trad: &entry.ct_trad,
                pk_trad: &fixture.pk_trad,
                context: inputs.application_context,
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
                    inputs.application_context,
                    entry.rand_pq.as_bytes(),
                    entry.rand_trad.as_bytes(),
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .map_err(|error| kem_error("encapsulation measurement", error))?,
            );
        }
        Operation::Decapsulate => {
            black_box(
                kem.decapsulate(
                    black_box(fixture.sk_pq.as_bytes()),
                    &entry.ct_pq,
                    &fixture.pk_pq,
                    fixture.sk_trad.as_bytes(),
                    &entry.ct_trad,
                    &fixture.pk_trad,
                    inputs.application_context,
                )
                .map_err(|error| kem_error("decapsulation measurement", error))?,
            );
        }
    }
    Ok(())
}

fn warm_up_profile_operation(
    duration: Duration,
    operation: Operation,
    bound: &MatchedKem<'_>,
    compat: &MatchedKem<'_>,
    fixture: &Fixture,
) -> Result<(), BenchError> {
    let start = Instant::now();
    let mut iteration = 0usize;
    while start.elapsed() < duration {
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
    use super::{BenchError, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN};
    use q_periapt_core::{Error, Kem, ZeroizingBytes, SHARED_SECRET_LEN};

    unsafe extern "C" {
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
    pub(super) struct PortableMlKem768Expanded;

    fn require_status(status: i32, operation: &str) -> Result<(), Error> {
        if status == 0 {
            Ok(())
        } else {
            let _ = operation;
            Err(Error::Backend)
        }
    }

    impl Kem for PortableMlKem768Expanded {
        const C2PRI: bool = true;
        const COMPAT_XWING_SAFE: bool = false;

        fn algorithm(&self) -> &'static str {
            "ML-KEM-768(expanded-fips203-2400)/portable-evidence-reference"
        }

        fn encapsulate(
            &self,
            public_key: &[u8],
            randomness: &[u8],
            ciphertext: &mut [u8],
            shared_secret: &mut [u8],
        ) -> Result<(), Error> {
            let public_key: [u8; ML_KEM_768_PK_LEN] =
                public_key.try_into().map_err(|_| Error::InvalidLength)?;
            if randomness.len() != 32
                || ciphertext.len() != ML_KEM_768_CT_LEN
                || shared_secret.len() != SHARED_SECRET_LEN
            {
                return Err(Error::InvalidLength);
            }
            let mut randomness_owner = ZeroizingBytes::<32>::zeroed();
            randomness_owner.as_mut_bytes().copy_from_slice(randomness);
            let mut output_ciphertext = [0u8; ML_KEM_768_CT_LEN];
            let mut output_secret = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
            // SAFETY: the four exact-size arrays are live and non-overlapping.
            let status = unsafe {
                qpn_mlkem_evidence_portable_v1_2_0_768_encapsulate_derand(
                    output_ciphertext.as_mut_ptr(),
                    output_secret.as_mut_bytes().as_mut_ptr(),
                    public_key.as_ptr(),
                    randomness_owner.as_bytes().as_ptr(),
                )
            };
            require_status(status, "portable encapsulate")?;
            ciphertext.copy_from_slice(&output_ciphertext);
            shared_secret.copy_from_slice(output_secret.as_bytes());
            Ok(())
        }

        fn decapsulate(
            &self,
            expanded_key: &[u8],
            ciphertext: &[u8],
            shared_secret: &mut [u8],
        ) -> Result<(), Error> {
            let ciphertext: [u8; ML_KEM_768_CT_LEN] =
                ciphertext.try_into().map_err(|_| Error::InvalidLength)?;
            if expanded_key.len() != ML_KEM_768_SK_LEN || shared_secret.len() != SHARED_SECRET_LEN {
                return Err(Error::InvalidLength);
            }
            let mut expanded_key_owner = ZeroizingBytes::<ML_KEM_768_SK_LEN>::zeroed();
            expanded_key_owner
                .as_mut_bytes()
                .copy_from_slice(expanded_key);
            let mut output_secret = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
            // SAFETY: all pointers name exact-size, non-overlapping live arrays.
            let status = unsafe {
                qpn_mlkem_evidence_portable_v1_2_0_768_decapsulate(
                    output_secret.as_mut_bytes().as_mut_ptr(),
                    ciphertext.as_ptr(),
                    expanded_key_owner.as_bytes().as_ptr(),
                )
            };
            require_status(status, "portable decapsulate")?;
            shared_secret.copy_from_slice(output_secret.as_bytes());
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
type NativeExpandedMatchedKem<'a> = HybridKem<'a, MlKem768, X25519, Sha3_256Xof>;

#[cfg(qperiapt_performance_evidence)]
type PortableExpandedMatchedKem<'a> =
    HybridKem<'a, portable_reference::PortableMlKem768Expanded, X25519, Sha3_256Xof>;

#[cfg(qperiapt_performance_evidence)]
fn build_expanded_bound<'a, P: Kem>(
    pq: &'a P,
    trad: &'a X25519,
) -> Result<HybridKem<'a, P, X25519, Sha3_256Xof>, BenchError> {
    let inputs = MeasuredProfile::ContextBound.inputs();
    HybridKem::<_, _, Sha3_256Xof>::new(
        pq,
        trad,
        Profile::ContextBound,
        inputs.suite_id,
        inputs.policy_version,
    )
    .map_err(|error| kem_error("construct expanded-key ContextBound harness", error))
}

#[cfg(qperiapt_performance_evidence)]
struct ImplementationCorpusEntry {
    rand_pq: ZeroizingBytes<32>,
    rand_trad: ZeroizingBytes<32>,
    ct_pq: [u8; ML_KEM_768_CT_LEN],
    ct_trad: [u8; X25519_LEN],
    bound_secret: ZeroizingBytes<SHARED_SECRET_LEN>,
}

#[cfg(qperiapt_performance_evidence)]
struct ImplementationFixture {
    sk_pq: ZeroizingBytes<ML_KEM_768_SK_LEN>,
    pk_pq: [u8; ML_KEM_768_PK_LEN],
    sk_trad: ZeroizingBytes<X25519_LEN>,
    pk_trad: [u8; X25519_LEN],
    corpus: Vec<ImplementationCorpusEntry>,
}

#[cfg(qperiapt_performance_evidence)]
fn implementation_keygen_seed() -> ZeroizingBytes<ML_KEM_768_KEYGEN_SEED_LEN> {
    let left = ZeroizingBytes::from_bytes(derive32(11, 0));
    let right = ZeroizingBytes::from_bytes(derive32(11, 1));
    let mut seed = ZeroizingBytes::<ML_KEM_768_KEYGEN_SEED_LEN>::zeroed();
    let (left_output, right_output) = seed.as_mut_bytes().split_at_mut(32);
    left_output.copy_from_slice(left.as_bytes());
    right_output.copy_from_slice(right.as_bytes());
    seed
}

#[cfg(qperiapt_performance_evidence)]
fn build_implementation_fixture(
    native: &NativeExpandedMatchedKem<'_>,
) -> Result<ImplementationFixture, BenchError> {
    portable_reference::ensure_native_identity(ML_KEM_IMPLEMENTATION_ID)?;
    let keygen_seed = implementation_keygen_seed();
    let (sk_pq, pk_pq) = MlKem768::generate(*keygen_seed.as_bytes())
        .map_err(|error| kem_error("prepare expanded ML-KEM key pair", error))?;
    let sk_pq = ZeroizingBytes::from_bytes(sk_pq);
    let trad_seed = ZeroizingBytes::from_bytes(derive32(12, 0));
    let (sk_trad, pk_trad) = X25519::generate(*trad_seed.as_bytes());
    let sk_trad = ZeroizingBytes::from_bytes(sk_trad);
    let application_context = MeasuredProfile::ContextBound.inputs().application_context;
    let mut corpus = Vec::with_capacity(CORPUS_SIZE);
    for index in 0..CORPUS_SIZE {
        let rand_pq = ZeroizingBytes::from_bytes(derive32(13, index));
        let rand_trad = ZeroizingBytes::from_bytes(derive32(14, index));
        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let bound_secret = native
            .encapsulate(
                &pk_pq,
                &pk_trad,
                application_context,
                rand_pq.as_bytes(),
                rand_trad.as_bytes(),
                &mut ct_pq,
                &mut ct_trad,
            )
            .map_err(|error| kem_error("prepare expanded-key corpus", error))?;
        corpus.push(ImplementationCorpusEntry {
            rand_pq,
            rand_trad,
            ct_pq,
            ct_trad,
            bound_secret: ZeroizingBytes::from_bytes(*bound_secret.as_bytes()),
        });
    }
    Ok(ImplementationFixture {
        sk_pq,
        pk_pq,
        sk_trad,
        pk_trad,
        corpus,
    })
}

#[cfg(qperiapt_performance_evidence)]
fn verify_implementation_equivalence(
    native: &NativeExpandedMatchedKem<'_>,
    portable: &PortableExpandedMatchedKem<'_>,
    fixture: &ImplementationFixture,
) -> Result<Vec<EquivalenceRecord>, BenchError> {
    let application_context = MeasuredProfile::ContextBound.inputs().application_context;
    let mut records = Vec::with_capacity(CORPUS_SIZE * Operation::IMPLEMENTATION.len());
    for (case_id, entry) in fixture.corpus.iter().enumerate() {
        let mut native_ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut native_ct_trad = [0u8; X25519_LEN];
        let native_secret = native
            .encapsulate(
                &fixture.pk_pq,
                &fixture.pk_trad,
                application_context,
                entry.rand_pq.as_bytes(),
                entry.rand_trad.as_bytes(),
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
                application_context,
                entry.rand_pq.as_bytes(),
                entry.rand_trad.as_bytes(),
                &mut portable_ct_pq,
                &mut portable_ct_trad,
            )
            .map_err(|error| kem_error("portable equivalence encapsulation", error))?;
        if native_ct_pq != entry.ct_pq
            || native_ct_trad != entry.ct_trad
            || native_secret.as_bytes() != entry.bound_secret.as_bytes()
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
            application_context,
            entry.rand_pq.as_bytes(),
            entry.rand_trad.as_bytes(),
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
                fixture.sk_pq.as_bytes(),
                &entry.ct_pq,
                &fixture.pk_pq,
                fixture.sk_trad.as_bytes(),
                &entry.ct_trad,
                &fixture.pk_trad,
                application_context,
            )
            .map_err(|error| kem_error("native equivalence decapsulation", error))?;
        let portable_decapsulated = portable
            .decapsulate(
                fixture.sk_pq.as_bytes(),
                &entry.ct_pq,
                &fixture.pk_pq,
                fixture.sk_trad.as_bytes(),
                &entry.ct_trad,
                &fixture.pk_trad,
                application_context,
            )
            .map_err(|error| kem_error("portable equivalence decapsulation", error))?;
        if native_decapsulated.as_bytes() != entry.bound_secret.as_bytes()
            || native_decapsulated.as_bytes() != portable_decapsulated.as_bytes()
        {
            return Err(BenchError(format!(
                "native and portable decapsulation outputs differ for corpus case {case_id}"
            )));
        }
        // Both variants borrow the same RAII-owned private keys. Bind the public
        // decapsulation case without publishing a private-key-derived digest.
        let decapsulate_input = digest_parts(&[
            &entry.ct_pq,
            &fixture.pk_pq,
            &entry.ct_trad,
            &fixture.pk_trad,
            application_context,
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
    native: &NativeExpandedMatchedKem<'_>,
    portable: &PortableExpandedMatchedKem<'_>,
    fixture: &ImplementationFixture,
    corpus_index: usize,
) -> Result<(), BenchError> {
    let application_context = MeasuredProfile::ContextBound.inputs().application_context;
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
                            application_context,
                            entry.rand_pq.as_bytes(),
                            entry.rand_trad.as_bytes(),
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
                            application_context,
                            entry.rand_pq.as_bytes(),
                            entry.rand_trad.as_bytes(),
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
                            black_box(fixture.sk_pq.as_bytes()),
                            &entry.ct_pq,
                            &fixture.pk_pq,
                            fixture.sk_trad.as_bytes(),
                            &entry.ct_trad,
                            &fixture.pk_trad,
                            application_context,
                        )
                        .map_err(|error| kem_error("native decapsulation measurement", error))?,
                ),
                MeasuredImplementation::Portable => black_box(
                    portable
                        .decapsulate(
                            black_box(fixture.sk_pq.as_bytes()),
                            &entry.ct_pq,
                            &fixture.pk_pq,
                            fixture.sk_trad.as_bytes(),
                            &entry.ct_trad,
                            &fixture.pk_trad,
                            application_context,
                        )
                        .map_err(|error| kem_error("portable decapsulation measurement", error))?,
                ),
            };
        }
    }
    Ok(())
}

#[cfg(qperiapt_performance_evidence)]
fn warm_up_implementation_operation(
    duration: Duration,
    operation: Operation,
    native: &NativeExpandedMatchedKem<'_>,
    portable: &PortableExpandedMatchedKem<'_>,
    fixture: &ImplementationFixture,
) -> Result<(), BenchError> {
    let start = Instant::now();
    let mut iteration = 0usize;
    while start.elapsed() < duration {
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
        iteration = iteration.wrapping_add(1);
    }
    Ok(())
}

#[cfg(qperiapt_performance_evidence)]
fn collect_implementations(
    operation: Operation,
    samples: usize,
    native: &NativeExpandedMatchedKem<'_>,
    portable: &PortableExpandedMatchedKem<'_>,
    fixture: &ImplementationFixture,
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

fn build_contract() -> Option<BuildContract> {
    #[cfg(qperiapt_performance_evidence)]
    {
        let shared_c_build = |architecture: &'static str| CImplementationBuild {
            architecture,
            data_sections: true,
            function_sections: true,
            language_standard: env!("QPERIAPT_PERFORMANCE_C_LANGUAGE_STANDARD"),
            macos_deployment_target: env!("QPERIAPT_PERFORMANCE_MACOS_DEPLOYMENT_TARGET"),
            optimization: env!("QPERIAPT_PERFORMANCE_C_OPTIMIZATION"),
            position_independent_code: true,
            visibility: env!("QPERIAPT_PERFORMANCE_C_VISIBILITY"),
        };
        Some(BuildContract {
            c_implementations: CImplementationBuilds {
                product_native: shared_c_build(env!("QPERIAPT_PERFORMANCE_NATIVE_C_ARCHITECTURE")),
                portable_reference: shared_c_build(env!(
                    "QPERIAPT_PERFORMANCE_PORTABLE_C_ARCHITECTURE"
                )),
            },
            rust_harness: RustHarnessBuild {
                codegen_units: 1,
                lto: env!("QPERIAPT_PERFORMANCE_RUST_LTO"),
                optimization: env!("QPERIAPT_PERFORMANCE_RUST_OPTIMIZATION"),
            },
        })
    }
    #[cfg(not(qperiapt_performance_evidence))]
    {
        None
    }
}

fn implementation_contract() -> Option<ImplementationContract> {
    #[cfg(qperiapt_performance_evidence)]
    {
        Some(ImplementationContract {
            digest_algorithm: "SHA3-256",
            direction: "native/portable",
            equivalence_cases_per_operation: EquivalenceCaseCounts {
                encapsulate: CORPUS_SIZE,
                decapsulate: CORPUS_SIZE,
            },
            includes_ffi: false,
            includes_os_rng: false,
            key_format: IMPLEMENTATION_KEY_FORMAT,
            keypair_generation_count: 1,
            native_implementation_id: NATIVE_IMPLEMENTATION_ID,
            operations: ["encapsulate", "decapsulate"],
            portable_implementation_id: PORTABLE_REFERENCE_IMPLEMENTATION_ID,
            product_profile: "ContextBound",
            reference_scope: PORTABLE_REFERENCE_SCOPE,
            surface: IMPLEMENTATION_SURFACE,
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
    let bound_inputs = MeasuredProfile::ContextBound.inputs();
    let bound = HybridKem::<_, _, Sha3_256Xof>::new(
        &pq,
        &trad,
        Profile::ContextBound,
        bound_inputs.suite_id,
        bound_inputs.policy_version,
    )
    .map_err(|error| kem_error("construct ContextBound harness", error))?;
    let compat_inputs = MeasuredProfile::CompatXWing.inputs();
    let compat = HybridKem::<_, _, Sha3_256Xof>::new(
        &pq,
        &trad,
        Profile::CompatXWing,
        compat_inputs.suite_id,
        compat_inputs.policy_version,
    )
    .map_err(|error| kem_error("construct CompatXWing harness", error))?;
    let fixture = build_fixture(&bound, &compat)?;

    #[cfg(qperiapt_performance_evidence)]
    let native_expanded_pq = MlKem768;
    #[cfg(qperiapt_performance_evidence)]
    let native_expanded_bound = build_expanded_bound(&native_expanded_pq, &trad)?;
    #[cfg(qperiapt_performance_evidence)]
    let portable_expanded_pq = portable_reference::PortableMlKem768Expanded;
    #[cfg(qperiapt_performance_evidence)]
    let portable_expanded_bound = build_expanded_bound(&portable_expanded_pq, &trad)?;
    #[cfg(qperiapt_performance_evidence)]
    let implementation_fixture = build_implementation_fixture(&native_expanded_bound)?;
    #[cfg(qperiapt_performance_evidence)]
    let equivalence = verify_implementation_equivalence(
        &native_expanded_bound,
        &portable_expanded_bound,
        &implementation_fixture,
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
    for_each_warmed_operation(
        Operation::ALL,
        |operation| {
            warm_up_profile_operation(
                Duration::from_millis(args.warmup_ms),
                operation,
                &bound,
                &compat,
                &fixture,
            )
        },
        |operation| {
            collect_profiles(
                operation,
                args.samples,
                &bound,
                &compat,
                &fixture,
                &mut records,
            )
        },
    )?;
    #[cfg(qperiapt_performance_evidence)]
    for_each_warmed_operation(
        Operation::IMPLEMENTATION,
        |operation| {
            warm_up_implementation_operation(
                Duration::from_millis(args.warmup_ms),
                operation,
                &native_expanded_bound,
                &portable_expanded_bound,
                &implementation_fixture,
            )
        },
        |operation| {
            collect_implementations(
                operation,
                args.samples,
                &native_expanded_bound,
                &portable_expanded_bound,
                &implementation_fixture,
                &mut records,
            )
        },
    )?;

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
            warmup_scope: WARMUP_SCOPE,
            build_contract: build_contract(),
            profile_inputs: ProfileInputsRecord {
                context_bound: ProfileInputRecord {
                    suite_id_hex: hex(bound_inputs.suite_id)?,
                    policy_version: bound_inputs.policy_version,
                    application_context_hex: hex(bound_inputs.application_context)?,
                },
                compat_xwing: ProfileInputRecord {
                    suite_id_hex: hex(compat_inputs.suite_id)?,
                    policy_version: compat_inputs.policy_version,
                    application_context_hex: hex(compat_inputs.application_context)?,
                },
            },
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn every_operation_is_warmed_immediately_before_collection() {
        fn record(
            operations: impl IntoIterator<Item = Operation>,
        ) -> Vec<(&'static str, &'static str)> {
            let events = RefCell::new(Vec::new());
            for_each_warmed_operation(
                operations,
                |operation| {
                    events.borrow_mut().push(("warm-up", operation.name()));
                    Ok::<(), ()>(())
                },
                |operation| {
                    events.borrow_mut().push(("collect", operation.name()));
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
            events.into_inner()
        }

        assert_eq!(
            record(Operation::ALL),
            [
                ("warm-up", "combine"),
                ("collect", "combine"),
                ("warm-up", "encapsulate"),
                ("collect", "encapsulate"),
                ("warm-up", "decapsulate"),
                ("collect", "decapsulate"),
            ]
        );
        assert_eq!(
            record(Operation::IMPLEMENTATION),
            [
                ("warm-up", "encapsulate"),
                ("collect", "encapsulate"),
                ("warm-up", "decapsulate"),
                ("collect", "decapsulate"),
            ]
        );
    }
}
