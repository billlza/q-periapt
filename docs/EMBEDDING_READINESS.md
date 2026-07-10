# Q-Periapt Embedding Readiness

This note is the current integration contract for downstream projects such as SkyBridge. It is
deliberately stricter than a README quickstart and narrower than a product release promise.

## Current Gate

Run from the repository root:

```sh
sh artifact/embedding-readiness.sh
```

The Swift XCFramework sub-gate requires a clean worktree for release proof. During local diagnostics
on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1`; do not use that mode as
release provenance.

The Android AAR/JNI sub-gate also requires a clean worktree for release proof. During local
diagnostics on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1`; that mode proves local
packaging behavior only, not release provenance.

The optional Apple device matrix also requires a clean worktree for release proof. During local
hardware diagnostics on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1` when
generating proof and `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1` when reverifying it; that mode is
diagnostic only.

The gate fails closed and checks:

- locked Cargo metadata;
- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo test --workspace --locked`;
- optional SLH-DSA/HQC backend tests;
- release `q-periapt-ffi` build;
- generated C header freshness against both `crates/q-periapt-ffi/include/q_periapt.h` and
  `bindings/swift/Sources/CQPeriapt/q_periapt.h`;
- C ABI link-and-run smoke;
- host C ABI release archive smoke through extracted dynamic/static pkg-config and CMake consumers,
  plus archive license text and CycloneDX CBOM/SBOM validation;
- Swift XCTest execution with the expected seven passing tests;
- Swift XCFramework/binaryTarget pre-publication gate: universal macOS static slice, iOS device
  slice, iOS simulator slice, SwiftPM checksum, zip/path-safety checks, and an isolated binary
  consumer that executes the same expected seven passing tests without `../../target/release`
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
| Rust | Source build and workspace tests pass under locked dependencies; `artifact/rust-publish-dry-run.sh` checks the crates.io publish allow/deny list, package file lists, and patched `cargo publish --dry-run` for every publishable crate. | Crates are not uploaded; first public release still requires a clean tree, registry publish order, and release provenance for the actual crates.io versions. |
| C ABI | Release cdylib/staticlib builds; generated header is freshness-checked; runtime ABI/version/suite metadata is exposed; C smoke links and runs; `artifact/c-package.sh` creates a host archive and verifies extracted dynamic/static pkg-config plus CMake consumers, project license texts, and CycloneDX CBOM/SBOM. | Host archive proof is now present, but multi-target release publishing, Windows archive shape, full third-party dependency license inventory, and install docs still need hardening before being liboqs-like. |
| Swift | SwiftPM tests pass on macOS; `artifact/swift-xcframework.sh` builds and verifies a SwiftPM `binaryTarget` XCFramework through an isolated consumer; physical iPad+iPhone runner links the iOS staticlib and emits run-bound `QPERIAPT_DEVICE_PASS` when rerun against the current source tree. | The XCFramework gate is still pre-publication: no public URL/checksum release has been uploaded, and dirty diagnostic runs are not clean release proof. Raw device proof artifacts stay local and must not be published as release artifacts. |
| Android | `artifact/android-aar.sh` builds a deterministic AAR from the Rust C ABI plus a JNI shim, checks all four ABI slices, audits archive paths, dexes the Java facade, and compiles an isolated consumer. `artifact/android-device-smoke.sh` then installs a temporary APK on ART and runs the same metadata, shared-vector, combiner, CompatXWing, signed-policy rollback/tamper, and fail-closed negative checks through the Android Java facade. | The current runtime proof is local emulator evidence, not a clean public release artifact. Product readiness still needs a clean-tree Android runtime proof, a CI emulator policy or documented physical-device lane, and downstream SkyBridge target-level harnesses. |
| Kotlin | JVM/Panama FFM tests pass on JDK 22+; the wrapper requires `-Dqperiapt.lib` to name an absolute native library path and validates ABI/suite metadata on init. | This is host JVM only; it is intentionally separate from the Android AAR/JNI surface. |
| WASM | Node `wasm-pack` tests pass and expose version/fixed-suite metadata. | Browser/package publishing is not yet a release contract. |

## Apple Device Matrix

The full Apple family matrix means iPad plus iPhone, not just one attached device. A valid matrix
proof is source-bound, artifact-bound, run-bound, and device-family-bound:

- source hashes include the Apple proof scripts, Swift binding files, shared vectors, signed-policy
  vectors, and the Rust workspace build-input tree;
- the proof records the git commit and whether the source tree was dirty when the proof was
  generated; release verification rejects dirty proof and a dirty current tree by default;
- app executable and iOS staticlib hashes are recorded and rechecked;
- each launch must copy back a result file from the app data container containing exactly one
  `QPERIAPT_DEVICE_PASS run-id=<32 hex chars>` marker;
- simulator output is never accepted;
- verification rejects stale proofs, proof inputs outside `artifact/device-runs`, and app/staticlib
  artifact paths outside the repository `target/` tree.

The current local Xcode 27 beta matrix proof recorded in `artifact/results.json` is
`artifact/device-runs/xcode27-matrix-20260709T195437Z-c5fe98b3/apple-device-matrix-proof.json`.
It covers one physical iPad and one physical iPhone, and `artifact/proof-to-byte.sh` reverified it
with `QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX=1` during the same Xcode 27 gate run. That run is dirty
diagnostic evidence (`source_tree_dirty=true`), not clean release provenance. It becomes historical
evidence as soon as any source-bound proof input changes; the gate rejects stale proof until the
matrix is rerun against the current tree. Proofs generated before the git/dirty provenance fields
were added are historical only and must be rerun before being used with the current verifier. The
raw run directory is ignored by git because it contains local signing/profile/device metadata and
should not be uploaded as a public release artifact.

## Remaining Work Before Product Embedding

- Publishable Rust crate surface: actual crates.io upload sequence and release provenance. The local
  contract exists, but a dirty diagnostic run is not release proof and dependency crates still need
  registry-order publication.
- C ABI product surface: multi-target release publishing, Windows archive shape, full third-party
  dependency license inventory, and install docs.
- Swift product surface: publish the generated XCFramework package from a clean tree with public
  URL/checksum/provenance, and rerun the physical iPad+iPhone matrix against that same source state.
- Android product surface: promote the runtime smoke from local diagnostic proof to clean release
  provenance, decide whether CI requires an emulator lane or whether physical Android devices are
  the release gate, and add downstream SkyBridge target-level harnesses. The AAR/JNI package proof
  and local ART runtime proof now exist.
- Downstream SkyBridge harness: one minimal integration test per target repository using the same
  shared vectors and policy files, so Q-Periapt proof does not get mistaken for downstream product
  proof.
