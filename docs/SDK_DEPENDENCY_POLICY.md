# SDK dependency maintenance

Use the newest stable compiler and dependencies that pass the SDK's actual
contracts. Pin the selected versions and checksums for reproducible qualification.
A new upstream version is a candidate for validation, not evidence that all
known defects have disappeared. Beta/RC versions remain confined to explicitly
experimental components. Performance improvements require measured comparisons.

The 2026-09-29 refresh selects Rust 1.98.1 for every release producer, including
Windows, and Rust 1.90 for the product minimum. The minimum change permits redb
4.3.0; it is a support-contract change, not a workaround for a failed test.
The current source uses SHA3 0.12.0, SHAKE 0.1.0, P-256 0.14.0 in the isolated
Continuity candidate, rustix 1.1.5, cc 1.5.1 and updated compatible lock closures.
The standard-library notice is copied from the exact Rust 1.98.1 distribution.
Older notices and frozen results retain their original identities.

## Storage contract

redb 4.3 changes both storage APIs and locking behavior. The shared protected
file owner acquires its exclusive whole-file lock before inode/header checks.
Bounded and fault-injection backends propagate that lock and close operation.
Immediate durability setup failures propagate; two-phase commit remains enabled.
The store never resets an existing file on an open or format error.

New databases use file format v3. Existing format-v2 files require a separate
migration process and are rejected unchanged with `UpgradeRequired(2)` by the
new producer. No automatic migration is provided. A migration must preserve the
application schema and authenticated state and reconcile any independent witness;
format conversion alone cannot establish freshness. See [host storage](SDK_HOST_STORE.md).

## Deliberate version boundaries

- `fips204` 0.4.6 and `fips205` 0.4.1 still use their upstream SHA3 0.10 and
  rand_core 0.6 contracts. Their transitive traits cannot be replaced by forcing
  unrelated major versions. Both are the newest stable releases checked here.
- The development-only `ml-kem` 0.2.3 oracle compares every expanded secret-key
  byte. Version 0.3.2 does provide deterministic key generation and encapsulation,
  but deprecates the expanded-key export required by that assertion. Keep this
  oracle until a supported replacement preserves the same check; do not suppress
  deprecation warnings or remove the byte comparison merely to upgrade it.
- The SPQR and whole-KEM reference lockfiles identify fixed external comparison
  baselines. Updating them requires a separately identified experiment and new
  results. They are outside the product dependency graph.
- The CodeQL compatibility sysroot remains 1.94.0 for the pinned extractor;
  canonical compilation uses 1.98.1. A future extractor upgrade must retain the
  complete extraction and consistency checks.

Native ML-KEM 2.0.0, Kotlin 2.4.20, Gradle 9.8.0 and AGP 9.4.1 are identified
follow-up candidates in this refresh. Their integration and qualification are
separate from the completed Rust lock updates. Node's current stable release is
26.10.0, its current LTS patch is 24.21.0, and Python's latest stable patch is
3.14.7. Do not claim these build-tool updates have passed until their package and
runtime lanes have been exercised.

The local refresh evidence is retained under
`target/sdk-dependency-refresh-020-1/`: official Rust channel manifests, registry
index snapshots, compiler identities, dependency update logs, real old-format
file generation/rejection, tests and audits. A dirty local run is not a signed
release or a substitute for current-commit platform qualification.
