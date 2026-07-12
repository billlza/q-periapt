//! Deliberately leaky source→binary discriminator for the Memcheck CT harness.
//!
//! This binary is a synthetic negative control, not a cryptographic primitive and not evidence
//! of a vulnerability in any production backend. It marks one byte secret and feeds it to an
//! explicit planted branch. Memcheck MUST report a positive error count; otherwise a zero from
//! `ct_decaps_gap probe` is vacuous on that target/toolchain.

use core::ffi::c_void;
use core::hint::black_box;

#[link(name = "qperiapt_ct_shim", kind = "static")]
unsafe extern "C" {
    fn qperiapt_ct_mark_undefined(p: *mut c_void, n: usize);
}

fn mark_secret(byte: &u8) {
    // SAFETY: `byte` is a valid one-byte object and the C shim only issues the Valgrind
    // MAKE_MEM_UNDEFINED client request. Outside Valgrind the shim is a no-op.
    unsafe { qperiapt_ct_mark_undefined(core::ptr::from_ref(byte).cast_mut().cast(), 1) };
}

#[inline(never)]
fn planted_secret_branch(secret: u8) -> u8 {
    if secret & 1 == 0 {
        black_box(0x3c)
    } else {
        black_box(0xc3)
    }
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("planted")) || args.next().is_some() {
        eprintln!("usage: ct_leaky_control planted");
        std::process::exit(2);
    }

    let secret = 0x01_u8;
    mark_secret(&secret);
    // A volatile read prevents the compiler from substituting the initialized value after the
    // Valgrind-only secrecy mark. The no-inline branch then remains an observable discriminator.
    // SAFETY: `secret` is a live, properly aligned `u8` object.
    let observed = unsafe { core::ptr::read_volatile(core::ptr::from_ref(&secret)) };
    black_box(planted_secret_branch(observed));
    eprintln!("synthetic control: planted secret-dependent branch; Memcheck MUST report >0");
}
