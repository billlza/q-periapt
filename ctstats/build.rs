//! Compiles the constant-time verification shim (`src/ct_shim.c`) only for the
//! `valgrind` feature. The shim issues the Valgrind Memcheck `MAKE_MEM_UNDEFINED`
//! client request when `valgrind/memcheck.h` is found (Linux CI with Valgrind),
//! and is a no-op otherwise — so the harness builds and runs on any host.

use std::env;
use std::path::Path;

fn main() {
    // Always compile the tiny shim (a no-op without the Valgrind header), so the
    // `qperiapt_ct_mark_undefined` symbol is unconditionally available regardless of
    // which feature unification Cargo builds. The `valgrind` feature only gates the
    // `ct_verify` *binary* (required-features), not this symbol.
    println!("cargo:rerun-if-changed=src/ct_shim.c");
    println!("cargo:rerun-if-env-changed=VALGRIND_INCLUDE");

    let mut build = cc::Build::new();
    build.file("src/ct_shim.c");

    // Define HAVE_VALGRIND when the Memcheck header is reachable (an explicit
    // VALGRIND_INCLUDE override, or one of the standard include roots).
    let mut have = false;
    if let Some(inc) = env::var_os("VALGRIND_INCLUDE") {
        build.include(&inc);
        have = true;
    } else if [
        "/usr/include",
        "/usr/local/include",
        "/opt/homebrew/include",
    ]
    .iter()
    .any(|root| Path::new(root).join("valgrind/memcheck.h").exists())
    {
        have = true;
    }
    if have {
        build.define("HAVE_VALGRIND", None);
    } else {
        println!(
            "cargo:warning=valgrind/memcheck.h not found; ct_verify shim is a no-op \
             (the dataflow constant-time check runs only under Valgrind)."
        );
    }
    build.compile("qperiapt_ct_shim");
}
