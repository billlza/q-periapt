# Fuzzing (cargo-fuzz / libFuzzer)

A detached crate (its own `[workspace]`) so the nightly/libFuzzer-only targets do
not affect the stable `cargo build/clippy --workspace` gate.

## Targets

- **`combine`** — feeds arbitrary-length fields to `pqt_core::combine` (both
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
