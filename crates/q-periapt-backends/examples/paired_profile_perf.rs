//! Paired, matched-backend performance evidence for ContextBound vs CompatXWing.
//!
//! Both profiles use the exact same `MlKem768XWingSeed + X25519` backend, keys,
//! randomness corpus, ciphertexts, suite identifier, policy version, and application
//! context. CompatXWing intentionally ignores the extra committed fields; that is the
//! only profile-level difference being measured. Samples are ordered ABBA/BAAB so
//! frequency and thermal drift do not always favor one profile.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use q_periapt_backends::{
    MlKem768XWingSeed, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_XWING_SEED_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{combine, CombineInput, Kem, Profile, Xof256};
use q_periapt_kem::HybridKem;
use serde::Serialize;

const SCHEMA_VERSION: u32 = 2;
const BACKEND_ID: &str = "ML-KEM-768(seed-dk)+X25519/libcrux+x25519-dalek";
const SCHEDULE: &str = "ABBA/BAAB";
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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

#[derive(Clone, Copy)]
enum Operation {
    Combine,
    Encapsulate,
    Decapsulate,
}

impl Operation {
    const ALL: [Self; 3] = [Self::Combine, Self::Encapsulate, Self::Decapsulate];

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
    backend: &'static str,
    schedule: &'static str,
    corpus_size: usize,
    samples_per_profile_operation: usize,
    iterations_per_sample: IterationsPerSample,
    warmup_ms: u64,
    suite_id_hex: String,
    policy_version: u32,
    application_context_hex: String,
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
    operation: &'static str,
    profile: &'static str,
    pair_id: usize,
    schedule_index: usize,
    corpus_index: usize,
    elapsed_ns_total: u128,
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

struct CorpusEntry {
    rand_pq: [u8; 32],
    rand_trad: [u8; 32],
    ct_pq: [u8; ML_KEM_768_CT_LEN],
    ct_trad: [u8; X25519_LEN],
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
    let (sk_pq, pk_pq) = MlKem768XWingSeed::generate(derive32(1, 0));
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
            let mut pq = [0u8; 32];
            let mut trad = [0u8; 32];
            MlKem768XWingSeed
                .decapsulate(&sk_pq, &ct_pq, &mut pq)
                .map_err(|error| kem_error("prepare PQ shared secret", error))?;
            X25519
                .decapsulate(&sk_trad, &ct_trad, &mut trad)
                .map_err(|error| kem_error("prepare traditional shared secret", error))?;
            combine_ss_pq = pq;
            combine_ss_trad = trad;
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

fn run_once(
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

fn warm_up(
    duration: Duration,
    bound: &MatchedKem<'_>,
    compat: &MatchedKem<'_>,
    fixture: &Fixture,
) -> Result<(), BenchError> {
    let start = Instant::now();
    let mut iteration = 0usize;
    while start.elapsed() < duration {
        for operation in Operation::ALL {
            run_once(
                operation,
                MeasuredProfile::ContextBound,
                bound,
                compat,
                fixture,
                iteration % CORPUS_SIZE,
            )?;
            run_once(
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

fn collect_operation(
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
                black_box(run_once(
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
                operation: operation.name(),
                profile: profile.name(),
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
    warm_up(
        Duration::from_millis(args.warmup_ms),
        &bound,
        &compat,
        &fixture,
    )?;

    let capacity = args
        .samples
        .checked_mul(2)
        .and_then(|value| value.checked_mul(Operation::ALL.len()))
        .ok_or_else(|| BenchError("sample capacity overflow".into()))?;
    let mut records = Vec::with_capacity(capacity);
    for operation in Operation::ALL {
        collect_operation(
            operation,
            args.samples,
            &bound,
            &compat,
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
            backend: BACKEND_ID,
            schedule: SCHEDULE,
            corpus_size: CORPUS_SIZE,
            samples_per_profile_operation: args.samples,
            iterations_per_sample: IterationsPerSample {
                combine: Operation::Combine.iterations_per_sample(),
                encapsulate: Operation::Encapsulate.iterations_per_sample(),
                decapsulate: Operation::Decapsulate.iterations_per_sample(),
            },
            warmup_ms: args.warmup_ms,
            suite_id_hex: hex(SUITE_ID)?,
            policy_version: POLICY_VERSION,
            application_context_hex: hex(APPLICATION_CONTEXT)?,
        },
    )?;
    for record in &records {
        write_json_line(&mut writer, record)?;
    }
    writer.flush()?;
    eprintln!(
        "PAIRED_PROFILE_PERF_RAW_PASS samples={} records={} output={}",
        args.samples,
        records.len(),
        args.raw_out.display()
    );
    Ok(())
}
