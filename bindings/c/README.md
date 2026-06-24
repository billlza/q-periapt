# C-ABI link smoke test

A real C program that **links against the built `q-periapt-ffi` library** and calls the
exported functions — proving the C calling convention works end-to-end, not just that the
header parses. This complements the Swift/Kotlin/WASM faces (which exercise the same ABI
through their own FFI layers) with a plain-C consumer.

## What it checks ([`smoke.c`](smoke.c))

| | Check | Proves |
|---|---|---|
| A | `q_periapt_combine()` reproduces a `ContextBound` reference vector byte-for-byte (same vector as [`../contextbound-vectors.txt`](../contextbound-vectors.txt)) | correctness survives the C ABI |
| B | `mlkem768_keypair` + `x25519_keypair` → `hybrid_encapsulate` → `hybrid_decapsulate`, asserting the two 32-byte secrets agree | the widest ABI surface (pointers, `size_t` lengths, `uint8_t`/`uint32_t` scalars, `int32_t` status) across four functions |
| C | a `NULL` pointer returns `Q_PERIAPT_ERR_NULL`; a wrong output length returns `Q_PERIAPT_ERR_LENGTH` | the length-checked, non-aborting status-code contract holds across the boundary |

Exit code `0` = all passed.

## Run it

**Windows (MSVC)** — links `q_periapt_ffi.dll` via its import library; locates the toolchain
through `vswhere`, so `cl.exe` need not be on `PATH`:

```bat
bindings\c\build-and-run.bat
```

**macOS / Linux** (clang or gcc) — links the cdylib with an embedded rpath:

```sh
sh bindings/c/build-and-run.sh
```

Both scripts build `q-periapt-ffi` (`--release`), compile `smoke.c` against
[`../../crates/q-periapt-ffi/include/q_periapt.h`](../../crates/q-periapt-ffi/include/q_periapt.h),
link the resulting library, and run the test.

## Status

Verified on **Windows 11 (x86_64-pc-windows-msvc, MSVC via VS Build Tools, Rust 1.96,
2026-06)**: all three checks pass linking the real `q_periapt_ffi.dll`. The `windows` CI job
builds the workspace; this link test is run via the script above.
