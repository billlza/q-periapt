# Q-Periapt Embedding Readiness

This note is the current integration contract for downstream projects such as SkyBridge. It is
deliberately stricter than a README quickstart and narrower than a product release promise.

It covers the implemented KEM/policy/binding faces only. It does not establish
identity-directory, prekey, ratchet, multi-device, recovery, or key-transparency
readiness. The future Q-Periapt Continuity plan is separate
([`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md)). Its `publish = false`
lifecycle model now checks trusted pairwise session/current-context admission and
preserves that authority across abstract reconstruction. It deliberately has no
context-advance API. It is not a product dependency,
does not authenticate its trusted genesis or authorize its caller-selected provider profile, and
proves no deployed protocol behavior; until a
real session crate and its own gates exist, this embedding command cannot be used as
a PQ3/Signal-parity claim.

## Current Gate

Run from the repository root:

```sh
sh artifact/embedding-readiness.sh
```

The WASM sub-gate compiles the portable C ML-KEM provider. Set
`CC_wasm32_unknown_unknown` to an **absolute path** to upstream LLVM Clang and
verify that `clang --print-targets` lists `wasm32`; Apple Clang is rejected. Use
`$(brew --prefix llvm)/bin/clang` on macOS or `/usr/bin/clang-18` on Linux. The
same variable is required by direct `cargo build --target wasm32-unknown-unknown`
and `wasm-pack test --node` invocations.

The Swift XCFramework sub-gate requires a clean worktree for release proof. During local diagnostics
on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1`; do not use that mode as
release provenance.

The Android AAR/JNI sub-gate also requires a clean worktree for release proof. During local
diagnostics on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1`; that mode proves local
packaging behavior only, not release provenance.

The optional Apple device matrix also requires a clean worktree for release proof. During local
hardware diagnostics on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1` when
generating proof and `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1` when reverifying it; that mode is
diagnostic only. Matrix schema v3 fixes the release requirement to distinct physical iPad and
iPhone entries; callers cannot weaken it to a single-device subset.

The gate fails closed and checks:

- locked Cargo metadata;
- isolated CPython 3.11+ dispatch for every live-worktree proof/package/device Python invocation, with
  user-site/`.pth`, caller `PYTHON*`, adjacent bytecode-cache, and Git-exclude hiding rejected;
- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo test --workspace --locked`;
- optional SLH-DSA backend tests;
- release `q-periapt-ffi` build;
- generated C header freshness against both `crates/q-periapt-ffi/include/q_periapt.h` and
  `bindings/swift/Sources/CQPeriapt/q_periapt.h`;
- C ABI link-and-run smoke;
- host C ABI release archive smoke through extracted dynamic/static pkg-config and CMake consumers,
  plus archive license text and CycloneDX CBOM/SBOM validation;
- Swift XCTest execution with the expected two passing ABI2 product tests;
- Swift XCFramework/binaryTarget pre-publication gate: universal macOS static slice, iOS device
  slice, iOS simulator slice, SwiftPM checksum, zip/path-safety checks, and an isolated binary
  consumer that executes three isolated ABI2 product checks without `../../target/release`
  linker flags;
- Android AAR/JNI pre-publication gate: four Rust Android `q-periapt-ffi` cdylib ABI slices
  (`arm64-v8a`, `x86_64`, `armeabi-v7a`, `x86`), JNI shim slices, `JNI_OnLoad`/`RegisterNatives`
  export-shape checks, native/JNI symbol and `DT_NEEDED` audits, deterministic AAR path-safety
  checks, Java facade `javac -Werror`, D8 conversion, and an isolated Java consumer compile;
- Kotlin/Panama FFM tests on JDK 22 or newer, loading a specific native library path;
- WASM Node tests, including runtime suite metadata;
- `artifact/proof-to-byte.sh` manifest validation.

To require physical Apple hardware evidence too:

```sh
QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1 \
QPERIAPT_DEVICE_RESULT_DIR=artifact/device-runs/<matrix-run-dir> \
sh artifact/embedding-readiness.sh
```

That matrix must contain one fresh physical iPad proof and one fresh physical iPhone proof. The
device lane is separate because it requires local Apple signing and attached devices; the default
embedding gate remains usable on hosts without Apple hardware.

To require Android runtime evidence too:

```sh
sh artifact/android-device-smoke.sh
QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1 sh artifact/embedding-readiness.sh
```

If no Android device is attached, the smoke can boot a local AVD:

```sh
QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_AVD=<avd-name> \
sh artifact/android-device-smoke.sh
```

The runtime lane is separate because it requires adb plus a booted emulator or physical Android
device. Clean-tree proof is the release contract; dirty runs must set
`QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1` and are diagnostic only.

## Local Release Index

After the package gates have produced their artifacts, build a local hash-bound index:

```sh
sh artifact/local-release-index.sh
```

Release mode requires a clean tree and rejects dirty package manifests. For local diagnostics on an
in-progress tree:

```sh
QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=1 \
QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX=1 \
QPERIAPT_DEVICE_RESULT_DIR=artifact/device-runs/<matrix-run-dir> \
QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1 \
sh artifact/local-release-index.sh
```

The index copies only the C archive, Swift XCFramework zip, Android AAR, and their manifests into
`target/qperiapt-local-release/<version>/<commit>/`. It may include sanitized Apple/Android proof
summaries, but it never copies raw device proof, build logs, provisioning profiles, `.xcresult`
bundles, UDIDs, or adb serials.

## Per-Face Status

| Face | Status | Boundary |
|---|---|---|
| Rust | The coordinated ten-crate set forms the release-ready `0.1.0-alpha.1` research-alpha source/crate line intended for crates.io publication. Source build and workspace tests pass under locked dependencies; `artifact/rust-publish-dry-run.sh` checks the crates.io allow/deny list, every downstream local patch, package file lists, and patched `cargo publish --dry-run`. It independently verifies the sys `.crate` fixed 124-entry upstream inventory and exact packaged 118-code-file hash subset (six upstream README files excluded), pinned license/provenance, forbidden paths and portable-only build surface, then audits the normalized backend graph with the sys crate patched in. | Registry publication by itself does not establish independent signed provenance, audit the vendored C provider, or promote the crates to production. Those remain production-promotion requirements. |
| C ABI | The release-ready research-alpha source/crate contract for `0.1.0-alpha.1` has a frozen machine-readable ABI2 authority: nine exact dynamic `q_periapt_*` exports, the same exact reserved public namespace for static archives, status/constants, 40/36-byte layouts, forbidden raw/deterministic public symbols, ABI-major header guard and platform identities. Static archives retain unsupported hidden `qpn_*` bridge link symbols, so hidden visibility is not access control and the embedding process is trusted. The host smoke harness covers signed policy, exact digest, ABI1 hard cut, OS-random key/encapsulation, context binding and atomic failure outputs. | This release line includes no platform C archive. Before binary distribution or production promotion, every claimed platform archive and release index must be rebuilt against one source digest, independently reviewed, and bound to clean signed or transparency-backed provenance. Windows archive proof, full third-party license inventory and public install docs remain open. |
| Swift | The SwiftPM ABI2 product harness, five-slice XCFramework isolated consumer, and physical matrix verifier are implemented. The wrapper exposes only signed-policy decision, OS-random atomic keys/encapsulation and decapsulation, with explicit secret wipes. | The recorded XCFramework and clean-tree iPad+iPhone matrix are historical after the backend/source migration. Both package and physical-device lanes must be rerun against the release source. Public URL/checksum, Apple distribution signing, and independent signed provenance remain required. |
| Android | The four-ABI AAR harness uses ABI-major FFI/JNI names and the same nine-symbol native product workflow, with export/SONAME/DT_NEEDED, Java/JNI warnings-as-errors, dex, signing, and isolated-consumer checks. | The recorded AAR predates the backend/source migration and must be rebuilt. Fresh ABI2 ART runtime proof is pending; the previous emulator proof is historical. Clean provenance, a CI-emulator/physical policy and downstream SkyBridge harnesses remain required. |
| Kotlin | Panama FFM source is migrated to ABI2 and requires an absolute ABI-major library path; the current machine has Temurin JDK 22.0.2. | The JDK 22+ test gate must pass on each release source; this is host JVM only and separate from Android. |
| WASM | Deterministic Node/WASM conformance tests and version/fixed-suite metadata remain. | WASM is a separately scoped caller-randomness conformance surface, not covered by the native ABI2 package contract; browser/package hardening remains open. |

The retired PQClean-HQC adapter is absent from every package above. Numeric suite code
`3` is a fail-closed tombstone, while `research/hqc-fips207-candidate` is a standalone
`publish = false` shadow with no ABI/package identity. The migration to the
portable-only `q-periapt-mlkem-native-sys` boundary over `mlkem-native` v1.2.0,
`fips204` 0.4.6, and `sha3` 0.10.9 changed the source digest and invalidated
every previously recorded package, device, matched-performance, and binary-CT proof.
It removed both the earlier `libcrux`/hax `proc-macro-error2` advisory edge and the
later `fips203` provider that failed the historical two-ISA binary-CT probe. The vendored
trust anchors are upstream commit `0ba906cb14b1c241476134d7403a811b382ca498`
and immutable GitHub commit archive SHA-256
`f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
`cargo audit --deny warnings` passes without an ignore for the Rust graph; it does
not inspect vendored C. ABI 2 is release-ready as a research-alpha source/Rust-crate
line intended for coordinated registry publication. Fresh same-source
package/device/performance evidence, independent
cryptographic, C/FFI and ABI review, clean signed or transparency-backed provenance,
and platform distribution signing remain hard requirements for production promotion
or a public binary-package claim.

## Apple Device Matrix

The full Apple family matrix means iPad plus iPhone, not just one attached device. A valid matrix
proof is source-bound, artifact-bound, run-bound, and device-family-bound:

- source hashes include the Apple proof scripts, Swift binding files, shared vectors, signed-policy
  vectors, named Rust workspace sources, and the canonical source-input digest after fixed
  generated-prefix exclusions;
- the proof records the git commit and whether the source tree was dirty when the proof was
  generated; release verification rejects dirty proof and a dirty current tree by default;
- app executable and iOS staticlib hashes are recorded and rechecked;
- clean provenance uses a fixed Git environment, rejects hidden index flags, and compares
  HEAD/index to actual tracked bytes and executable modes rather than trusting `git status`;
- each launch must copy back a result file from the app data container containing exactly one
  `QPERIAPT_DEVICE_PASS run-id=<32 hex chars>` marker;
- simulator output is never accepted;
- verification rejects stale proofs, proof inputs outside `artifact/device-runs`, and app/staticlib
  artifact paths outside the repository `target/` tree.

The active local device proof is identified by `artifact/results.json`; reviewers must supply its
run directory through `QPERIAPT_DEVICE_RESULT_DIR` and let `artifact/proof-to-byte.sh` reverify the
declared single-device or matrix mode. A proof is current only when its schema, selected input
hashes, canonical source digest, recomputed device commitment, single-snapshot child artifact
hashes, age, and dirty/clean policy all pass the live
verifier. Time-varying single-device and matrix currentness lives only in
`artifact/results.json`; this source document does not promote a named run. A dirty proof
(`source_tree_dirty=true`) is diagnostic evidence, not clean release provenance. Historical
iPad+iPhone matrix files remain historical whenever their schema or source digest differs; a current
matrix requires both physical lanes to be rerun at one accepted source snapshot. Any source-bound change immediately makes a
proof historical; legacy schema proofs and previously named run directories must not be described
as current merely because their files still exist. The raw run directory is ignored by
git because it contains local signing/profile/device metadata and should not be uploaded as a public
release artifact.

## Remaining Work Before Product Embedding

- Rust crate release surface: retain the coordinated dependency order for every
  subsequent version — `q-periapt-mlkem-native-sys`, core, KEM/signature traits,
  backends, policy, then the FFI/WASM/rustls leaves; the dependency-free CLI remains
  version-coordinated. A dirty diagnostic run is not release proof, and registry
  packages still need independently verifiable signed or transparency-backed
  provenance before production promotion.
- C ABI product surface: finish and verify `.so.2`, `.2.dylib`, ABI-major Windows,
  exact CMake/pkg-config, manifest/index semantics and platform compatibility negatives.
  ABI1 uses a deliberate hard cut—four-byte state is rejected and requires explicit
  host-authorized re-enrollment/reset, not an unverifiable synthetic migration. Then
  complete multi-target publishing, dependency license inventory and install docs.
- Swift product surface: publish the generated XCFramework package from a clean tree with public
  URL/checksum/provenance, and rerun the physical iPad+iPhone matrix against that same source state.
- Android product surface: rebuild the AAR for the migrated backend, then replace the historical, stale, pre-ABI2 emulator ART
  diagnostic with a current ABI2 runtime smoke, then promote it to clean release
  provenance, decide whether CI requires an emulator lane or whether physical Android devices are
  the release gate, and add downstream SkyBridge target-level harnesses. No
  current-source AAR or ABI2 ART proof exists yet.
- Downstream SkyBridge harness: one minimal integration test per target repository using the same
  shared vectors and policy files, so Q-Periapt proof does not get mistaken for downstream product
  proof.
- Stateful channel work, if selected: finish G1 beyond the current non-normative lifecycle model,
  then implement the reference and Continuity session lanes, formal state/storage models,
  model-to-Rust linkage, transactional persistence, and physical two-endpoint latency/energy/healing
  gates. This is a separate product and research milestone, not a missing packaging checkbox for
  the current library.
