//! Supporting operation-level timings for the exact paper-source backends.
//! Linux clocks; no network, storage, RNG acquisition, or protocol-delivery claim.
use q_periapt_backends::{MlDsa65, MlKem768, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN};
use q_periapt_core::Kem;
use q_periapt_sig::{Signer, Verifier};
use std::hint::black_box;
use std::io::{self, Write};

const CORPUS: usize = 64;
const SAMPLES: usize = 200;
const BATCH: usize = 8;
const WARMUP_BATCHES: usize = 32;
const MSG_LEN: usize = 1024;
const OP_NAMES: [&str; 7] = ["mlkem768_keygen", "mlkem768_encapsulate", "mlkem768_decapsulate", "mldsa65_keygen", "mldsa65_sign", "mldsa65_verify", "timer_control"];

#[repr(C)]
struct Timespec { tv_sec: i64, tv_nsec: i64 }
unsafe extern "C" { fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32; }
fn clock_ns(id: i32) -> u64 {
    let mut t = Timespec { tv_sec: 0, tv_nsec: 0 };
    // Linux x86_64: CLOCK_MONOTONIC_RAW=4, CLOCK_PROCESS_CPUTIME_ID=2.
    let rc = unsafe { clock_gettime(id, &mut t) };
    assert_eq!(rc, 0, "clock_gettime failed");
    (t.tv_sec as u64) * 1_000_000_000 + t.tv_nsec as u64
}

// Deterministic public benchmark input generation, outside every timed interval.
// This deliberately does not provide or claim a production RNG.
fn material<const N: usize>(case: usize, domain: u64) -> [u8; N] {
    let mut out = [0; N];
    let mut x = domain ^ (case as u64).wrapping_mul(0x9e3779b97f4a7c15);
    for byte in &mut out { x ^= x << 13; x ^= x >> 7; x ^= x << 17; *byte = x as u8; }
    out
}
struct Case {
    kem_seed: [u8; 64], kem_coins: [u8; 32], kem_sk: Vec<u8>, kem_pk: Vec<u8>, kem_ct: Vec<u8>,
    sig_seed: [u8; 32], sig_coins: [u8; 32], sig_sk: Vec<u8>, sig_pk: Vec<u8>, sig: Vec<u8>, msg: Vec<u8>,
}
fn corpus() -> Vec<Case> {
    (0..CORPUS).map(|i| {
        let kem_seed = material(i, 0x19ac41); let kem_coins = material(i, 0x34bf19);
        let (kem_sk, kem_pk) = MlKem768::generate(kem_seed).expect("KEM key generation");
        let mut kem_ct = vec![0; ML_KEM_768_CT_LEN]; let mut ss1 = [0; 32]; let mut ss2 = [0; 32];
        MlKem768.encapsulate(&kem_pk, &kem_coins, &mut kem_ct, &mut ss1).expect("encapsulation");
        MlKem768.decapsulate(&kem_sk, &kem_ct, &mut ss2).expect("decapsulation"); assert_eq!(ss1, ss2);
        let sig_seed = material(i, 0x49ca31); let sig_coins = material(i, 0x65df73);
        let (sig_sk, sig_pk) = MlDsa65::generate(sig_seed);
        let msg = material::<MSG_LEN>(i, 0x6ab2e9).to_vec(); let mut sig = vec![0; ML_DSA_65_SIG_LEN];
        assert_eq!(MlDsa65.sign(&sig_sk, &msg, &sig_coins, &mut sig).expect("signing"), ML_DSA_65_SIG_LEN);
        MlDsa65.verify(&sig_pk, &msg, &sig).expect("verification");
        let mut bad_msg = msg.clone(); bad_msg[0] ^= 1;
        assert!(MlDsa65.verify(&sig_pk, &bad_msg, &sig).is_err(), "negative signature control");
        Case { kem_seed, kem_coins, kem_sk: kem_sk.to_vec(), kem_pk: kem_pk.to_vec(), kem_ct,
               sig_seed, sig_coins, sig_sk: sig_sk.to_vec(), sig_pk: sig_pk.to_vec(), sig, msg }
    }).collect()
}
fn run(op: usize, c: &Case, ct: &mut [u8], ss: &mut [u8], sig: &mut [u8]) {
    match op {
        0 => { black_box(MlKem768::generate(black_box(c.kem_seed)).expect("keygen")); },
        1 => { MlKem768.encapsulate(black_box(&c.kem_pk), black_box(&c.kem_coins), ct, ss).expect("encaps"); black_box((&*ct, &*ss)); },
        2 => { MlKem768.decapsulate(black_box(&c.kem_sk), black_box(&c.kem_ct), ss).expect("decaps"); black_box(&*ss); },
        3 => { black_box(MlDsa65::generate(black_box(c.sig_seed))); },
        4 => { black_box(MlDsa65.sign(black_box(&c.sig_sk), black_box(&c.msg), black_box(&c.sig_coins), sig).expect("sign")); black_box(&*sig); },
        5 => { black_box(MlDsa65.verify(black_box(&c.sig_pk), black_box(&c.msg), black_box(&c.sig)).expect("verify")); },
        6 => { black_box(c.msg.as_slice()); },
        _ => unreachable!(),
    }
}
fn main() {
    let cases = corpus();
    let mut ct = vec![0; ML_KEM_768_CT_LEN]; let mut ss = [0; 32]; let mut sig = vec![0; ML_DSA_65_SIG_LEN];
    eprintln!("implementation={};corpus={CORPUS};samples={SAMPLES};batch={BATCH};warmup_batches={WARMUP_BATCHES};message_bytes={MSG_LEN};context_bytes=0;os_rng_inside_interval=false;negative_controls={CORPUS}", q_periapt_mlkem_native_sys::active_implementation_id());
    for op in 0..OP_NAMES.len() {
        for j in 0..WARMUP_BATCHES * BATCH { run(op, &cases[j % CORPUS], &mut ct, &mut ss, &mut sig); }
    }
    let mut rows = Vec::with_capacity(SAMPLES * OP_NAMES.len());
    // Rotate operations between blocks; each operation sees all 64 cases exactly 25 times.
    for sample in 0..SAMPLES {
        for slot in 0..OP_NAMES.len() {
            let op = (slot + sample) % OP_NAMES.len();
            let cpu0 = clock_ns(2); let wall0 = clock_ns(4);
            for j in 0..BATCH { run(op, &cases[(sample * BATCH + j) % CORPUS], &mut ct, &mut ss, &mut sig); }
            let wall1 = clock_ns(4); let cpu1 = clock_ns(2);
            rows.push((sample, slot, op, wall1 - wall0, cpu1 - cpu0));
        }
    }
    let mut out = io::BufWriter::new(io::stdout().lock());
    writeln!(out, "sample,order,operation,iterations,wall_ns,process_cpu_ns").unwrap();
    for (sample, slot, op, wall, cpu) in rows { writeln!(out, "{sample},{slot},{},{BATCH},{wall},{cpu}", OP_NAMES[op]).unwrap(); }
}
