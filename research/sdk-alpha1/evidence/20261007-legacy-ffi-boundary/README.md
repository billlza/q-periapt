# Legacy C input-boundary validation

The four original policy/KEM entry points now check pointer arithmetic, public
input widths and size caps before constructing input slices. They reuse the
owner API's numeric range rule. ABI declarations, the 43 exported names, valid
operations and implicit rejection are unchanged.

The regression deliberately supplies an impossible input span ending beyond the
address space. The old source aborts or faults in isolated child processes; the
new source returns `ERR_LENGTH` and clears valid output regions. This input was
outside the old unsafe contract. The result is defensive boundary hardening,
not evidence of a remote exploit or validation of arbitrary dangling pointers.

`manifest.json` binds source bytes, commands, outcomes and the limits of this
capture. Rust 1.98.1 ran all 42 FFI tests in debug and release; strict Clippy
passed after replacing the test selector's explicit panic with a Result error.
The original failing lint logs are retained. The real release dylib passed both
C consumers, including the legacy consumer compiled with the frozen 0.1.5 header.
`HEADER.json` confirms unchanged declarations; `exports.json` matches every
name in the 0.2 ABI contract. Raw log text is stored in JSON with its digest.

Reproduce the source checks with `cargo test -p q-periapt-ffi`,
`cargo test --release -p q-periapt-ffi`, and
`cargo clippy -p q-periapt-ffi --all-targets -- -D warnings` under Rust 1.98.1.
`sh bindings/c/build-and-run.sh` builds and executes the two C consumers.
Installed archives, current-source CI and other platforms remain separate gates.
