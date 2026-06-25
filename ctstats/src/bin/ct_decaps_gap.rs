//! Source→binary constant-time **gap probe** for ML-KEM-768 decapsulation.
//!
//! libcrux proves its ML-KEM secret-independent at the *source* level (the `libcrux-secrets`
//! typed discipline, machine-checked via hax/F*). This probe asks the orthogonal *binary*-level
//! question: does the compiler, on a given ISA backend, reintroduce a secret-dependent
//! branch/index/division on the **genuine secret** (ŝ + z) path despite that source guarantee?
//!
//! It marks **only** the genuinely-secret sub-fields of the FIPS-203 expanded dk and runs the
//! **real libcrux `decapsulate`** under Valgrind/Memcheck. Run as
//! `valgrind --error-exitcode=1 --track-origins=yes ct_decaps_gap <mode>`:
//!
//!   probe    mark ŝ[0..1152] + z[2368..2400] only           → EXPECT 0 flags (no gap)
//!   ek       mark ek[1152..2336] only                        → EXPECT ~30 q-branch flags
//!            (attribution: the flags are on the embedded *public* key reduction)
//!   wholedk  mark all 2400 bytes                             → EXPECT the ~5696/60 baseline
//!   control  mark a byte + a *deliberate* secret branch      → EXPECT a flag (harness sanity:
//!            if this is NOT caught, the gate is vacuous on this target)
//!
//! Outside Valgrind every `mark_secret` is a no-op, so the binary still builds/runs anywhere.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use core::ffi::c_void;
use core::hint::black_box;

use q_periapt_backends::{MlKem768, ML_KEM_768_CT_LEN, ML_KEM_768_SK_LEN};
use q_periapt_core::Kem;

// FIPS-203 ML-KEM-768 expanded dk layout: dk_pke/ŝ(1152) ‖ ek(1184) ‖ H(ek)(32) ‖ z(32).
const SHAT_END: usize = 1152; // ŝ / dk_pke      [0..1152]  (genuine secret)
const EK_OFF: usize = 1152; //   ek               [1152..2336] (public — produces the q-branches)
const EK_END: usize = 2336;
const Z_OFF: usize = 2368; //    z                [2368..2400] (genuine secret)

#[link(name = "qperiapt_ct_shim", kind = "static")]
extern "C" {
    fn qperiapt_ct_mark_undefined(p: *mut c_void, n: usize);
}

/// Mark `buf` secret (Memcheck `MAKE_MEM_UNDEFINED`); a no-op outside Valgrind.
fn mark_secret(buf: &[u8]) {
    // SAFETY: valid pointer+len owned by `buf`, handed only to the Valgrind client request.
    unsafe { qperiapt_ct_mark_undefined(buf.as_ptr() as *mut c_void, buf.len()) };
}

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "probe".to_string());

    // Fresh keypair; a valid ct (exercises decrypt→re-encrypt→accept, the ŝ path) and an
    // invalid ct (exercises implicit rejection, the z path).
    let (dk, ek) = MlKem768::generate([0x42; 64]);
    let mut ct_valid = [0u8; ML_KEM_768_CT_LEN];
    let mut ss_tmp = [0u8; 32];
    MlKem768
        .encapsulate(&ek, &[0x37; 32], &mut ct_valid, &mut ss_tmp)
        .unwrap();
    let mut ct_invalid = ct_valid;
    ct_invalid[0] ^= 0xFF;

    let dk_marked = dk; // owned copy whose sub-ranges we mark secret

    if mode == "control" {
        // Harness sanity: a deliberate secret-dependent **memory index** MUST be flagged by
        // Memcheck. (A naive `if secret&1` branch is unreliable — the optimizer can fold it into
        // branchless arithmetic, which is genuinely constant-time and correctly NOT flagged. A
        // secret-derived load address is the canonical, optimization-resistant leak.)
        let s0 = [dk[0]];
        mark_secret(&s0);
        // Force the marked byte through a *volatile* load so the optimizer cannot substitute
        // the known plaintext value (it proved s0 == [dk[0]]) nor fold the index into
        // branchless arithmetic — the load actually touches the marked memory.
        // SAFETY: s0 is a valid 1-byte array we own; marked undefined only for Memcheck.
        let idx = unsafe { core::ptr::read_volatile(s0.as_ptr()) } as usize;
        let mut table = [0u8; 256];
        let mut i = 0usize;
        while i < 256 {
            table[i] = i as u8;
            i += 1;
        }
        let table = black_box(table); // opaque: contents can't be constant-folded away
        black_box(table[idx]); // load from a secret-derived address — Memcheck MUST flag
        eprintln!("control: secret-indexed table load on ŝ[0] — Memcheck MUST flag it");
        return;
    }

    match mode.as_str() {
        "wholedk" => mark_secret(&dk_marked[..]),
        "ek" => mark_secret(&dk_marked[EK_OFF..EK_END]),
        _ => {
            // probe: only the genuine secret sub-fields.
            mark_secret(&dk_marked[0..SHAT_END]);
            mark_secret(&dk_marked[Z_OFF..ML_KEM_768_SK_LEN]);
        }
    }

    // Real libcrux decapsulate over the marked dk, both branches.
    let mut ss = [0u8; 32];
    MlKem768
        .decapsulate(&dk_marked, &ct_valid, &mut ss)
        .unwrap();
    black_box(ss);
    let mut ss2 = [0u8; 32];
    MlKem768
        .decapsulate(&dk_marked, &ct_invalid, &mut ss2)
        .unwrap();
    black_box(ss2);

    eprintln!(
        "{mode}: ran real libcrux decapsulate (valid+invalid ct) over the marked dk; \
         run under Memcheck to count secret-dependent branches"
    );
}
