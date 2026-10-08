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

The optional CLI `policy-store-migration` feature pins redb 2.6.4 solely for
explicit offline conversion of the original host policy image. That legacy
provider is absent from the default CLI and native SDK dependency graphs.
twox-hash 2.1.4 checks commit-slot corruption before dispatch; it does not supply
cryptographic authentication. This deliberate compatibility dependency does not
change the selected 4.3.0 runtime provider or authorize an old-reader fallback
inside a host process. See the [maintenance command](../crates/q-periapt-cli/README.md#offline-host-policy-store-upgrade).

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
- CodeQL 2.27.1 uses a 1.97.0 analysis sysroot matching its observed process-macro
  artifacts; canonical compilation uses 1.98.1. Retaining the former 1.94.0
  macro server caused an ABI mismatch and incomplete extraction of seven files.
  The updated pairing still must pass the complete extraction and consistency
  checks before any Rust result upload.

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
9.4.0 fixture. The Android producer retains Gradle 9.7.1: AGP 9.4.1 still calls
`Configuration.setVisible`, newly deprecated by Gradle 9.8.0. Both hosted Android
builds reached APK assembly but failed the existing zero-warning gate. The
published AGP source confirms these calls in `BasePlugin` and
`VariantDependenciesBuilder`. Keep the newest compatible Android pairing until
upstream removes those calls; do not suppress the warning. The standalone JVM
producer uses Gradle 9.8.0 with strict verification. Both Gradle distributions
and the Android wrapper are checksum-pinned.
Kotlin dependency checksums are generated once and then enforced by a separate
strict verification run. Node 24.0.0 remains the independent minimum-runtime
check; it is not the package producer. Fresh platform, package and runtime
qualification must bind this updated source before release.

## C dependency and compiler selection

The 2026-10-01 upstream check found the selected native implementation
[mlkem-native 2.0.0](https://github.com/pq-code-package/mlkem-native/releases/tag/v2.0.0),
TLS provider [aws-lc-rs 1.18.1](https://github.com/aws/aws-lc-rs/releases/tag/v1.18.1)
and C build driver [cc 1.5.1](https://github.com/rust-lang/cc-rs/releases/tag/cc-v1.5.1)
equal to their projects' latest stable releases. The workspace lock selects
aws-lc-sys 0.45.0 underneath aws-lc-rs. The C API shares these native/Rust owners;
it does not need another copy of the cryptographic protocol implementation.

Compiler and SDK selection are separate qualification inputs. The local host
reports Xcode 27.0 (27A266a) and Apple Clang 21.0.0 (clang-2100.3.34.2).
The isolated Continuity C collector resolves the macOS SDK explicitly: after
discarding inherited SDKROOT, directly invoking Xcode's resolved Clang failed to
find errno.h. It now passes the selected SDK with -isysroot and records the
compiler hash and SDK settings hash. Linux selects its actual system C compiler.
These choices establish build inputs, not an all-platform performance guarantee.

New C dependencies or compiler versions must preserve known-answer vectors,
strict key validation, implicit rejection, ABI and owner lifetime behavior, and
the existing constant-time checks. Compare the actual installed C path with the
retained baseline on each qualified architecture before claiming a speedup;
record tail latency, allocation and concurrency effects as applicable. The
unpublished Continuity C client has its own installed-package execution scope
and cannot extend the product ABI 2 support matrix merely by compiling.

## JVM executable selection after Gradle provisioning

The selected JDK must remain first on `PATH` after `setup-gradle`. The pinned
[provisioner](https://github.com/gradle/actions/blob/3f131e8634966bd73d06cc69884922b02e6faf92/sources/src/execution/provision.ts)
prepends the directory returned by executable lookup, including when the requested
Gradle already exists. The Ubuntu 22.04 image
[installer](https://github.com/actions/runner-images/blob/ubuntu22/20260927.309/images/ubuntu/scripts/build/install-java-tools.sh)
places its Gradle link in `/usr/bin`. Matching Gradle 9.8.0 therefore moves that
shared directory ahead of the JDK selected earlier, while `JAVA_HOME` remains
unchanged. A downloaded Gradle instead contributes its own private bin directory.

This difference explains the reproduced path mismatch between the two 4a78609
runner cohorts: the new image logs reuse of Gradle 9.8.0, while the older image
logs a download. The historical failing job did not print its final resolved
Java path; `/usr/bin/java` is inferred from the fixed action/image and the logged
branch, not presented as a direct path observation. The real installer rejected
`PATH java must match JAVA_HOME` before creating package output.

Both JVM-producing workflows now restore `$JAVA_HOME/bin` in the current step and
`GITHUB_PATH` after Gradle setup. They recheck exact `java` and `javac` selection,
record their command paths/versions, and execute Gradle before consumers. The
installed-package path check is unchanged. Regression tests run the actual shell
selection block and hardened Python path predicate, including omitted current-step
restoration, omitted next-step restoration and a missing selected compiler. Those
path fixtures do not execute a simulated JVM or establish SDK runtime success.
At `b4ee99f5`, the [actual installed-consumer job](https://github.com/billlza/q-periapt/actions/runs/36593465227/job/109492248708)
records the selected JDK paths, 17 source tests, passing installed Kotlin and Java
module-path consumers, and six native-loading negative controls. Both same-head
Kotlin jobs pass on Ubuntu image `20260920.303.1`, which downloads Gradle. This
qualifies that runtime path; a post-fix hosted result for the newer image's
preinstalled-Gradle branch remains separate from the local behavioral regression.

The local refresh evidence is retained under
`target/sdk-dependency-refresh-020-1/`: official Rust channel manifests, registry
index snapshots, compiler identities, dependency update logs, real old-format
file generation/rejection, tests and audits. A dirty local run is not a signed
release or a substitute for current-commit platform qualification.
