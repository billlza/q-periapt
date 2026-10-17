# Isolated 64-byte encoding experiment

This is a modified SPQR execution reference, identified as
`experimental_chunk64`. It is **not** the pinned 32-byte implementation, a
component-conformance result, a Signal-compatible wire profile or the Continuity
product construction. The modified code does not inherit upstream formal results.
The original dependency and wire corpora remain unchanged.

`chunk64.patch` changes the public chunk array, polynomial lane count, compact
chunk codec and associated test helper from 32 to 64 bytes. The GF(2^16) field,
incremental ML-KEM-768 operations, authentication, KDFs, chain bounds and ratchet
transition code are unchanged. Precomputed interpolation tables additionally cover
the 2-, 15-, 17- and 18-point sizes needed by 64-byte chunks and the existing
tests. Bounds and annotations express the new lane count; no translated proof is
claimed. `chunk64-driver.patch` changes only the dependency location, declared
experiment identity, chunk-width evidence and public packet parser bound.

The two configurations run the same seven schedules, message count, seeded
randomness, initial fixture secret, loss/reorder/duplicate behavior and 84 passive
state-snapshot cases. Changed protocol progress consumes randomness at different
points, so this does not assert identical fresh key material across variants.
Both execute actual send/receive key agreement and the pending-KEM compromise
derivation. Neither includes application AEAD, network, disk durability or energy.

## Regression fixtures

The original 32-byte serialized libcrux issue-1275 states are retained verbatim.
The 64-byte variant explicitly rejects them; it does not migrate serialized
ratchets between formats. Its original byte-order regression is adapted to new
64-byte fixtures generated after eight alternating exchange steps, before
`encapsulate2`. The generator changes only the encoded encapsulation state's
legacy 16-bit byte order, leaving the final 32 random bytes unchanged. It verifies
that the input has valid, distinguishable error coefficients before doing so.
The resumed peers must agree on every message key and both reach epoch two.

The modified component suite runs **53 tests**: the original 52 test functions
with the affected fixture and chunk-count parameters updated, plus the explicit
old-format rejection test. No test is skipped. CI regenerates both new fixture
files and compares every byte with the patch's locked fixtures. The preparation
receipt hashes every copied and patched source, both patches, the clean repository
and the original upstream Git revision/tree. The upstream dependency lock remains
exactly unchanged; the driver lock changes only the SPQR Git-to-local source entry.

## Initial deterministic observations

Each schedule sends 2,048 messages. These are component protocol bytes, without
application framing or AEAD:

| Schedule | Final epochs, 32 B → 64 B | Mean bytes/send, 32 B → 64 B | Exposed keys after A's first send, 32 B → 64 B |
| --- | --- | --- | --- |
| Alternating | 24/23 → 46/45 | 32.150 → 58.971 | 172 → 88 |
| Loss | 20/21 → 40/39 | 31.957 → 58.336 | 198 → 102 |
| Reorder | 18/19 → 32/33 | 31.876 → 61.795 | 219 → 121 |
| Duplicate | 24/23 → 46/45 | 32.150 → 58.971 | 172 → 88 |
| 9:1 | 6/5 → 10/11 | 23.508 → 40.531 | 748 → 388 |
| Offline then exchange | 20/21 → 40/39 | 32.957 → 60.376 | 424 → 342 |
| One-way | 0/0 → 0/0 | 38.875 → 70.875 | 2,047 → 2,047 |

Peak frames increase from 37–39 to 69–71 bytes. The one-way counterexample remains:
wider chunks do not create fresh PQ progress without return traffic. The exposure
column is a retrospective derivation result for the stated passive attacker, not
a recovery deadline or proof that the remaining keys are unpredictable. Raw CPU
samples are retained separately; uncontrolled runs do not support a speedup or
energy claim. Whole-KEM controls, the full hybrid composition and active/repeated
compromise analysis remain necessary before selecting the product profile.

## Reproduction

From a clean, committed repository with the baseline reference already executed:

```sh
sh artifact/python-run.sh artifact/spqr_chunk64.py prepare target/chunk64-source
export CARGO_TARGET_DIR="$PWD/target/chunk64-build"
cargo test --manifest-path target/chunk64-source/upstream/Cargo.toml --locked
cargo clippy --manifest-path target/chunk64-source/driver/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path target/chunk64-source/driver/Cargo.toml --locked
mkdir target/chunk64-fixtures
cargo run --manifest-path target/chunk64-source/upstream/Cargo.toml --locked --features test-utils --example chunk64_regression_fixture -- target/chunk64-fixtures
cargo run --manifest-path target/chunk64-source/driver/Cargo.toml --locked --release -- target/chunk64-first
cargo run --manifest-path target/chunk64-source/driver/Cargo.toml --locked --release -- target/chunk64-repeated
sh artifact/python-run.sh artifact/spqr_chunk64.py verify \
  --directory target/chunk64-source --first target/chunk64-first \
  --repeated target/chunk64-repeated --baseline target/spqr-first \
  --binary "$CARGO_TARGET_DIR/release/q-periapt-spqr-reference" \
  --fixtures target/chunk64-fixtures
```

Outputs must be new directories. Preparation does not modify the original
upstream checkout. Verification rejects changed source/dependencies, profile
confusion, regenerated-fixture disagreement or deviation from the locked variant
corpus. Linux and macOS CI run the same complete sequence.
