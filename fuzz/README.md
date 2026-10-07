# Fuzzing (cargo-fuzz / libFuzzer)

A detached crate (its own `[workspace]`) so the nightly/libFuzzer-only targets do
not affect the stable `cargo build/clippy --workspace` gate.

The current targets fuzz the stateless combiner, its transport decoder and ML-KEM
decapsulation. They provide no coverage of a prekey/ratchet parser, persistent
state machine, retries, rollback, or multi-device concurrency. The Continuity
candidate's stateful fuzzing remains an open release requirement; see
[`../docs/CONTINUITY_RESEARCH.md`](../docs/CONTINUITY_RESEARCH.md).

## Targets

- **`combine`** — feeds arbitrary-length fields to `q_periapt_core::combine` (both
  profiles); asserts the combiner never panics and the length/encoding guards
  hold.
- **`mlkem_decapsulate`** — generates a valid ML-KEM-768 key, then decapsulates an
  arbitrary ciphertext; asserts decapsulation never panics and never errors
  (implicit rejection — no oracle) for any attacker-chosen ciphertext.
- **`transport`** — feeds unstructured bytes to the real
  `CombineInput::from_transport` decoder. Every accepted value must re-encode
  byte-for-byte, reject a truncated representation and reject trailing bytes.
  This is the legacy WASM combiner's actual decoder; the C `combine_raw` caller
  is test-only. It does not cover the SDK owner's full C or JavaScript API.

## Run

```sh
cargo +1.98.1 run --locked -p q-periapt-backends --example gen_fuzz_corpus
export CC=clang CXX=clang++
CFLAGS='-fsanitize=address -fno-omit-frame-pointer' \
  cargo +nightly-2026-10-07 fuzz build --fuzz-dir fuzz
for target in combine mlkem_decapsulate transport; do
  CFLAGS='-fsanitize=address -fno-omit-frame-pointer' \
    cargo +nightly-2026-10-07 fuzz run --fuzz-dir fuzz "$target" -- \
    -max_total_time=60 -timeout=10 -rss_limit_mb=1024 \
    -malloc_limit_mb=128 -max_len=65536 -seed=1 -print_final_stats=1
done
```

Use cargo-fuzz 0.13.2 and the pinned nightly with `rust-src`. Cargo-fuzz enables
AddressSanitizer, debug assertions and overflow checks by default; `CFLAGS` also
instruments the native C code. Assembly and external system libraries are not
thereby instrumented; the prebuilt Rust standard library is also outside this
instrumentation scope. These are memory-safety/robustness checks, not constant-time
tests or an exhaustive security result.

On macOS, select an upstream Clang with an ASan ABI compatible with the Rust
runtime, rather than mixing Apple Clang's versioned runtime interface with it.
Use the same deployment target for Rust and C/C++; inspect it with
`rustc +nightly-2026-10-07 --print deployment-target --target aarch64-apple-darwin`.
The local Apple Silicon setup selects existing LLVM Clang 22.1.8 through `CC` and
`CXX` and sets `MACOSX_DEPLOYMENT_TARGET=11.0`, matching that compiler query.
Neither this diagnostic configuration nor these flags change the SDK producer.

The CI `fuzz` job compiles all targets, checks deterministic seeds and then runs
each target for a bounded 60-second budget with explicit per-input, memory and
input-length limits. Nonzero exits fail the job. A successful command without
nonempty final execution statistics also fails. Logs, resulting corpora and crash
artifacts are retained, including on failure. This short run is a regression
check; longer campaigns and stateful Continuity coverage remain separate.
Historical execution counts from older dependency graphs are not current evidence.

## Seed corpus

`corpus/<target>/` holds the seed inputs libFuzzer starts mutation from. The
structured seeds are generated deterministically (and self-checked) by:

```sh
cargo run -p q-periapt-backends --example gen_fuzz_corpus   # from the workspace root
```

- **`mlkem_decapsulate`** (8 seeds, each `seed(64) ‖ ct(1088)`): valid ciphertexts
  under three keys (happy path), the boundary ciphertexts (all-zero, all-`0xff`,
  ascending), and — the security-critical case — *valid* ciphertexts with a single
  perturbed byte, which must still decapsulate to a pseudorandom secret (implicit
  rejection, no oracle). The generator asserts that invariant on every seed it writes.
- **`combine`** keeps its fuzzer-discovered corpus; the generator adds a few raw blobs
  (empty, zeros, `0xff`, ascending) that decode via `arbitrary` into edge-case field
  shapes. Each fuzz case exercises the raw Compat metadata-rejection path, a second
  canonical-empty Compat call that reaches its length/hash path, and the raw
  `ContextBound` path, so fail-closed metadata checks cannot starve deeper coverage.
- **`transport`** has ten checked seeds: three valid encodings (minimal,
  ContextBound-shaped and CompatXWing-shaped) plus empty/short input, trailing
  bytes, truncation, `u64::MAX` and `2^32` prefixes, and a wrong-sized version field.
  Each malformed seed is checked for rejection before it is written.
