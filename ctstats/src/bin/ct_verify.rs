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

    // NOTE on primitive paths: marking the ML-KEM *decapsulation key* secret and running
    // libcrux's `decapsulate` under Memcheck (aarch64, 2026-06) flags 30 sites / ~2848
    // reports, all in `libcrux_ml_kem::ind_cca::instantiations::neon::decapsulate`.
    // Isolating them (non-PIE build, exact runtime->file address mapping, objdump) shows
    // they are REAL conditional branches (b.cs/b.cc/b.ls/b.hi) comparing 12-bit coefficients
    // decoded from secret-key-derived bytes against the ML-KEM modulus q (0xd01 = 3329) and
    // q-1 (0xd00 = 3328) in a deserialize/serialize-with-reduction loop — i.e. a binary-level
    // secret-dependent branch, the exact source->assembly CT gap this gate exists to surface.
    // (No `udiv` / KyberSlash-class division and no secret-indexed load were flagged.)
    // This is NOT a csel/cmov false positive. Whether libcrux's source is CT-by-construction
    // and the compiler introduced the branch, and whether it is exploitable, is UNRESOLVED
    // and needs upstream follow-up. We do not gate the primitive here; we rely on libcrux's
    // source-level HACL* CT attestation as the primitive's assurance — a scoping choice, NOT
    // a refutation of these reports. See ctstats/README.md "Primitive-path investigation".
    eprintln!("ct_verify: exercised the constant-time paths (no-op outside Valgrind)");
}
