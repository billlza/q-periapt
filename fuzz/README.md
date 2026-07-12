# Fuzzing (cargo-fuzz / libFuzzer)

A detached crate (its own `[workspace]`) so the nightly/libFuzzer-only targets do
not affect the stable `cargo build/clippy --workspace` gate.

The current targets fuzz only the stateless combiner and ML-KEM decapsulation. They
provide no coverage of a prekey/ratchet parser, persistent state machine, retries,
rollback, or multi-device concurrency. Those targets become mandatory only if the
future Continuity crate is implemented; see
[`../docs/CONTINUITY_RESEARCH.md`](../docs/CONTINUITY_RESEARCH.md).

## Targets

- **`combine`** — feeds arbitrary-length fields to `q_periapt_core::combine` (both
  profiles); asserts the combiner never panics and the length/encoding guards
  hold.
- **`mlkem_decapsulate`** — generates a valid ML-KEM-768 key, then decapsulates an
  arbitrary ciphertext; asserts decapsulation never panics and never errors
  (implicit rejection — no oracle) for any attacker-chosen ciphertext.

## Run

```sh
cargo +nightly fuzz run --fuzz-dir fuzz combine -- -max_total_time=60
cargo +nightly fuzz run --fuzz-dir fuzz mlkem_decapsulate -- -max_total_time=60
cargo +nightly fuzz build --fuzz-dir fuzz      # compile all targets (CI does this)
```

Both targets have been run locally (~350k execs each, no crashes). CI compiles
all targets in the `fuzz` job.

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
  shapes (e.g. empty fields hit the `CompatXWing`/`ContextBound` guard paths).
