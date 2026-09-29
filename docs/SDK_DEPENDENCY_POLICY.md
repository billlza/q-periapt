# SDK dependency maintenance

Use the newest stable compiler and dependencies that pass the SDK's actual
contracts. Pin the selected versions and checksums for reproducible qualification.
A new upstream version is a candidate for validation, not evidence that all
known defects have disappeared. Beta/RC versions remain confined to explicitly
experimental components. Performance improvements require measured comparisons.

The 2026-09-29 refresh selects Rust 1.98.1 for every SDK release producer, including
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
- The legacy ten-crate maintenance proof keeps its exact Rust 1.96.1 receipt
  contract. It is distinct from the twelve-crate SDK 0.2 producer; frozen
  publications must remain verifiable without relabeling their compiler.
- The CodeQL compatibility sysroot remains 1.94.0 for the pinned extractor;
  canonical compilation uses 1.98.1. A future extractor upgrade must retain the
  complete extraction and consistency checks.

The current source also selects native ML-KEM 2.0.0, Kotlin 2.4.20, Gradle 9.8.0,
AGP 9.4.1, Node 26.10.0, npm 12.1.0, TypeScript 7.0.2 and Python 3.14.7.
CodeQL Action 4.38.2 is pinned to its immutable commit and linked CLI 2.27.1. The native import pins upstream commit
`d1b2fe782888bdb761a50336012923180be7f502` and its verified archive and per-file
hashes. Its new operation-specific error codes preserve strict public-key,
expanded-secret-key and implicit-rejection behavior; internal symbol namespaces
change to v2.0.0 while the public ABI stays 2. The original 0.1.5 native source
contract and receipts remain pinned to their original 1.2.0 implementation.

Android SDK and legacy receipt profiles have separate exact build-tool versions.
The AGP 9.4.1 optimized default rules were extracted through its actual public
`ProguardFiles.createProguardFile` API and are byte-identical to the retained
9.4.0 fixture. The Gradle distribution and wrapper are checksum-pinned.
Kotlin dependency checksums are generated once and then enforced by a separate
strict verification run. Node 24.0.0 remains the independent minimum-runtime
check; it is not the package producer. Fresh platform, package and runtime
qualification must bind this updated source before release.

The local refresh evidence is retained under
`target/sdk-dependency-refresh-020-1/`: official Rust channel manifests, registry
index snapshots, compiler identities, dependency update logs, real old-format
file generation/rejection, tests and audits. A dirty local run is not a signed
release or a substitute for current-commit platform qualification.
