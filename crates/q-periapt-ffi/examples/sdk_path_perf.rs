// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local diagnostic: paired existing ABI 2 vs owned Rust SDK calls.
//! Same authenticated ContextBound policy; setup/verification excluded from both.
//! Encapsulation includes platform RNG; both paths export the combined secret.
//! This is not a TLS/network benchmark.
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_ffi_abi2 as abi;
use q_periapt_policy::policy_signature_message;
use q_periapt_sdk::{Limits, Runtime};
use q_periapt_sig::Signer;
use std::{hint::black_box, time::Instant};

const POLICY: &[u8] = b"schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"ML-KEM-768\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n";

struct AbiKey {
    decision: [u8; 40],
    pq: ZeroizingBytes<2400>,
    pq_public: [u8; 1184],
    trad: ZeroizingBytes<32>,
    trad_public: [u8; 32],
}
impl AbiKey {
    fn new(signature: &[u8], root: &[u8]) -> Self {
        let mut key = Self {
            decision: [0; 40],
            pq: ZeroizingBytes::zeroed(),
            pq_public: [0; 1184],
            trad: ZeroizingBytes::zeroed(),
            trad_public: [0; 32],
        };
        // SAFETY: Every pointer references a live exact-sized array; output regions
        // are initialized and disjoint from each other and all input regions.
        unsafe {
            assert_eq!(
                abi::q_periapt_decision_from_signed_policy(
                    POLICY.as_ptr(),
                    POLICY.len(),
                    signature.as_ptr(),
                    signature.len(),
                    root.as_ptr(),
                    root.len(),
                    std::ptr::null(),
                    0,
                    key.decision.as_mut_ptr(),
                    40
                ),
                0
            );
            assert_eq!(
                abi::q_periapt_generate_keypair(
                    key.decision.as_ptr(),
                    40,
                    key.pq.as_mut_bytes().as_mut_ptr(),
                    2400,
                    key.pq_public.as_mut_ptr(),
                    1184,
                    key.trad.as_mut_bytes().as_mut_ptr(),
                    32,
                    key.trad_public.as_mut_ptr(),
                    32
                ),
                0
            );
        }
        key
    }
    fn encapsulate(&self, context: &[u8], pq_ct: &mut [u8; 1088], trad_ct: &mut [u8; 32]) {
        let mut secret = ZeroizingBytes::<32>::zeroed();
        // SAFETY: Borrowed arrays establish size, lifetime and output disjointness.
        let status = unsafe {
            abi::q_periapt_encapsulate(
                self.decision.as_ptr(),
                40,
                self.pq_public.as_ptr(),
                1184,
                self.trad_public.as_ptr(),
                32,
                context.as_ptr(),
                context.len(),
                pq_ct.as_mut_ptr(),
                1088,
                trad_ct.as_mut_ptr(),
                32,
                secret.as_mut_bytes().as_mut_ptr(),
                32,
            )
        };
        assert_eq!(status, 0);
        black_box(secret);
    }
    fn decapsulate(&self, context: &[u8], pq_ct: &[u8; 1088], trad_ct: &[u8; 32]) {
        let mut secret = ZeroizingBytes::<32>::zeroed();
        // SAFETY: All readable arrays remain live; secret is an independent output.
        let status = unsafe {
            abi::q_periapt_decapsulate(
                self.decision.as_ptr(),
                40,
                self.pq.as_bytes().as_ptr(),
                2400,
                pq_ct.as_ptr(),
                1088,
                self.pq_public.as_ptr(),
                1184,
                self.trad.as_bytes().as_ptr(),
                32,
                trad_ct.as_ptr(),
                32,
                self.trad_public.as_ptr(),
                32,
                context.as_ptr(),
                context.len(),
                secret.as_mut_bytes().as_mut_ptr(),
                32,
            )
        };
        assert_eq!(status, 0);
        black_box(secret);
    }
}

fn measure(f: &mut impl FnMut()) -> u128 {
    let start = Instant::now();
    f();
    start.elapsed().as_nanos()
}
fn paired(mut old: impl FnMut(), mut new: impl FnMut(), n: usize) -> (Vec<u128>, Vec<u128>) {
    for _ in 0..32 {
        old();
        new();
    }
    let (mut a, mut b) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for i in 0..n {
        if i % 2 == 0 {
            a.push(measure(&mut old));
            b.push(measure(&mut new));
        } else {
            b.push(measure(&mut new));
            a.push(measure(&mut old));
        }
    }
    (a, b)
}
fn percentile(sorted: &[u128], pct: usize) -> u128 {
    *sorted
        .get((sorted.len() - 1) * pct / 100)
        .expect("nonempty measured distribution")
}
fn report(operation: &str, context: usize, mut old: Vec<u128>, mut new: Vec<u128>) {
    // Preserve each raw paired observation in order before sorting summary copies.
    println!("{{\"operation\":\"{operation}\",\"context_bytes\":{context},\"abi2_raw_ns\":{old:?},\"owned_raw_ns\":{new:?}}}");
    old.sort_unstable();
    new.sort_unstable();
    eprintln!("{operation} context={context} ABI2 p50/p95/p99={}/{}/{} ns owned={}/{}/{} ns median_ratio={:.3}",
        percentile(&old,50),percentile(&old,95),percentile(&old,99),percentile(&new,50),percentile(&new,95),percentile(&new,99),percentile(&new,50) as f64 / percentile(&old,50) as f64);
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n: usize = std::env::args().nth(1).map_or(Ok(1000), |s| s.parse())?;
    if !(100..=5000).contains(&n) {
        return Err("sample count must be 100..=5000".into());
    }
    let (sk, root) = MlDsa65::generate([42; 32]);
    let mut signature = [0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &sk,
            &policy_signature_message(POLICY),
            &[0; 32],
            &mut signature,
        )
        .map_err(|_| "fixture signing failed")?;
    let abi_key = AbiKey::new(&signature, &root);
    let runtime = Runtime::from_signed_policy(POLICY, &signature, &root, None, Limits::default())?;
    let key = runtime.generate_key()?;
    eprintln!(
        "backend={} samples_per_path={n}; paired single-call wall times, no network",
        q_periapt_backends::ML_KEM_IMPLEMENTATION_ID
    );
    for len in [32, 4096, 65_536] {
        let context = vec![0x51; len];
        let mut ct_pq = [0; 1088];
        let mut ct_trad = [0; 32];
        abi_key.encapsulate(&context, &mut ct_pq, &mut ct_trad);
        let encapsulated = runtime.encapsulate(key.public_key()?, &context)?;
        let (a, b) = paired(
            || abi_key.decapsulate(&context, &ct_pq, &ct_trad),
            || {
                black_box(
                    key.decapsulate(&encapsulated.ciphertext, &context)
                        .expect("decap")
                        .export_for_protocol()
                        .expect("explicit export"),
                );
            },
            n,
        );
        report("decapsulate", len, a, b);
        let (a, b) = paired(
            || abi_key.encapsulate(&context, &mut ct_pq, &mut ct_trad),
            || {
                black_box(
                    runtime
                        .encapsulate(key.public_key().expect("public"), &context)
                        .expect("encap")
                        .secret
                        .export_for_protocol()
                        .expect("explicit export"),
                );
            },
            n,
        );
        report("encapsulate", len, a, b);
    }
    Ok(())
}
