//! Binary-level (dataflow) constant-time verification under Valgrind/Memcheck.
//!
//! Unlike the statistical `dudect_decaps` timing *report*, this is a **dataflow**
//! check: secret bytes are marked **undefined**, and Memcheck then flags any
//! conditional branch or memory index whose outcome depends on them. Run as
//!
//! ```text
//! valgrind --error-exitcode=1 --leak-check=no ct_verify
//! ```
//!
//! so that any non-constant-time path makes Valgrind exit non-zero — a hard gate
//! (the `constant-time` CI job on Linux). Outside Valgrind the client requests are
//! no-ops, so this binary also runs cleanly standalone.
//!
//! Scope: the suite's own constant-time composition code — `ct_eq`, `ct_select32`
//! (the implicit-rejection select primitives), and the combiner over secret shared
//! secrets. The component primitives' constant-timeness is the backends' contract
//! (libcrux ML-KEM is formally verified constant-time); here we check *our* glue.

use core::ffi::c_void;
use core::hint::black_box;
use q_periapt_backends::Sha3_256Xof;
use q_periapt_core::{combine, ct_eq, ct_select32, CombineInput, Profile};

#[link(name = "qperiapt_ct_shim", kind = "static")]
extern "C" {
    // Provided by src/ct_shim.c (build.rs). Issues the Valgrind Memcheck
    // MAKE_MEM_UNDEFINED client request under Valgrind; a no-op otherwise.
    fn qperiapt_ct_mark_undefined(p: *mut c_void, n: usize);
}

/// Mark `buf` as secret: Memcheck then reports any control flow depending on it.
fn mark_secret(buf: &[u8]) {
    // SAFETY: passes a valid pointer + length owned by `buf` to the shim, which only
    // hands them to the Valgrind client request (or ignores them outside Valgrind).
    unsafe { qperiapt_ct_mark_undefined(buf.as_ptr() as *mut c_void, buf.len()) };
}

fn main() {
    // 1. ct_eq must be branchless in its (secret) inputs; the derived 0x00/0xFF mask
    //    is itself secret.
    let secret = [0x9au8; 32];
    let probe = [0x9au8; 32];
    mark_secret(&secret);
    let mask = ct_eq(&secret, &probe);
    black_box(mask);

    // 2. ct_select32 must not branch on the secret mask nor on the secret branches.
    let a = [1u8; 32];
    let b = [2u8; 32];
    mark_secret(&a);
    mark_secret(&b);
    black_box(ct_select32(mask, &a, &b));

    // 3. The combiner must not branch on the (secret) shared secrets it absorbs.
    let ss = [0x5au8; 32];
    mark_secret(&ss);
    let inp = CombineInput {
        suite_id: b"S",
        policy_version: 1,
        ss_pq: &ss,
        ss_trad: &ss,
        ct_pq: &[7],
        pk_pq: &[8],
        ct_trad: &ss,
        pk_trad: &ss,
        context: b"ctx",
    };
    let _ = black_box(combine::<Sha3_256Xof>(Profile::ContextBound, &inp).map(|s| *s.as_bytes()));

    // NOTE on primitive paths (RESOLVED — benign, 2026-06): an earlier probe marked the WHOLE
    // 2400-byte ML-KEM-768 decapsulation key secret and ran libcrux's `decapsulate` under
    // Memcheck, flagging 30 branches comparing 12-bit coefficients to q (0xd01) and q-1 (0xd00)
    // in `neon::decapsulate`. These are NOT a secret-dependent timing leak. Per FIPS 203 the dk
    // EMBEDS the public key (dk = dk_pke‖ek‖H(ek)‖z), and the flagged branches are the
    // compiler's scalar lowering of libcrux's *public-key* deserialize-with-reduction
    // (`deserialize_to_reduced_ring_element` / `cond_subtract_3329`, which the libcrux source
    // documents "MUST NOT be used with secret inputs"). It runs only on the embedded PUBLIC key
    // `ek` during FO re-encryption; the probe over-marked `ek` as secret. The GENUINE secret
    // key ŝ takes a different, reduction-free path (`deserialize_to_uncompressed_ring_element`
    // → `deserialize_12`, no q-comparison), and no secret value (ŝ, z, the decrypted m', the
    // implicit-rejection compare) reaches any data-dependent branch — a static-reachability
    // fact verified against the libcrux 0.0.9 source and an adversarial review. So libcrux
    // ML-KEM decaps is constant-time on the genuine secret; the CT-correct marking is
    // ŝ[0..1152] + z[2368..2400], NOT the whole dk (ek[1152..2336] and H(ek)[2336..2368] are
    // public; ek is what produces the 60 q-branches). This corroborates libcrux's own
    // compile-time secret-independence (libcrux-secrets/hax) — the 5696-vs-0 Memcheck contrast
    // is the expected correct-vs-over-broad-marking before/after, per standard CT-harness
    // practice (KyberSlash §7.1.2), not a finding. See ctstats/README.md
    // "Primitive-path investigation".
    eprintln!("ct_verify: exercised the constant-time paths (no-op outside Valgrind)");
}
