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
| Rust | Source build and workspace tests pass under locked dependencies; `artifact/rust-publish-dry-run.sh` checks the crates.io publish allow/deny list, package file lists, and patched `cargo publish --dry-run` for every publishable crate. | Crates are not uploaded; first public release still requires a clean tree, registry publish order, and release provenance for the actual crates.io versions. |
| C ABI | Package `0.1.0-alpha.1` now has a frozen machine-readable ABI2 authority: nine exact product exports, status/constants, 40/36-byte layouts, forbidden raw/deterministic symbols, ABI-major header guard and platform identities. The host C product smoke proves signed policy, exact digest, ABI1 hard cut, OS-random key/encapsulation, context binding and atomic failure outputs. | Public release remains blocked until the ABI2 C archive passes on every supported platform, release-index semantics bind every face, dependency audit is warning-clean, and clean signed provenance exists. Windows archive proof, full third-party license inventory and public install docs remain open. |
| Swift | Current SwiftPM ABI2 product tests and a clean-tree, source-bound single-iPad install/launch/private-container-result diagnostic pass; the five-slice XCFramework isolated consumer passes on its recorded source. The wrapper exposes only signed-policy decision, OS-random atomic keys/encapsulation and decapsulation, with explicit secret wipes. | The paired iPad+iPhone proof still predates the current source. A fresh paired clean run, public URL/checksum, and independent signed provenance remain required. |
| Android | The four-ABI AAR uses ABI-major FFI/JNI names and the same nine-symbol native product workflow; export/SONAME/DT_NEEDED checks, Java/JNI warnings-as-errors, dex, signing and isolated consumer pass. | Fresh ABI2 ART runtime proof is pending; the previous emulator proof is historical. Clean provenance, a CI-emulator/physical policy and downstream SkyBridge harnesses remain required. |
| Kotlin | Panama FFM source is migrated to ABI2 and requires an absolute ABI-major library path. | JDK 22+ test verification is pending on this machine (only JDK 21 is installed); this is host JVM only and separate from Android. |
| WASM | Deterministic Node/WASM conformance tests and version/fixed-suite metadata remain. | WASM is a separately scoped caller-randomness conformance surface, not covered by the native ABI2 package contract; browser/package hardening remains open. |

The retired PQClean-HQC adapter is absent from every package above. Numeric suite code
`3` is a fail-closed tombstone, while `research/hqc-fips207-candidate` is a standalone
`publish = false` shadow with no ABI/package identity. The same source change invalidated
all earlier matched-performance proofs; no fresh controlled-host proof exists yet. ABI 2 remains unpublished, and the unsuppressed
upstream `proc-macro-error2` advisory through libcrux/hax is still a hard release blocker.

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

- Publishable Rust crate surface: actual crates.io upload sequence and release provenance. The local
  contract exists, but a dirty diagnostic run is not release proof and dependency crates still need
  registry-order publication.
- C ABI product surface: finish and verify `.so.2`, `.2.dylib`, ABI-major Windows,
  exact CMake/pkg-config, manifest/index semantics and platform compatibility negatives.
  ABI1 uses a deliberate hard cut—four-byte state is rejected and requires explicit
  host-authorized re-enrollment/reset, not an unverifiable synthetic migration. Then
  complete multi-target publishing, dependency license inventory and install docs.
- Swift product surface: publish the generated XCFramework package from a clean tree with public
  URL/checksum/provenance, and rerun the physical iPad+iPhone matrix against that same source state.
- Android product surface: replace the historical, stale, pre-ABI2 emulator ART
  diagnostic with a current ABI2 runtime smoke, then promote it to clean release
  provenance, decide whether CI requires an emulator lane or whether physical Android devices are
  the release gate, and add downstream SkyBridge target-level harnesses. The current
  AAR/JNI package proof exists; no current-source ABI2 ART proof exists yet.
- Downstream SkyBridge harness: one minimal integration test per target repository using the same
  shared vectors and policy files, so Q-Periapt proof does not get mistaken for downstream product
  proof.
- Stateful channel work, if selected: finish G1 beyond the current non-normative lifecycle model,
  then implement the reference and Continuity session lanes, formal state/storage models,
  model-to-Rust linkage, transactional persistence, and physical two-endpoint latency/energy/healing
  gates. This is a separate product and research milestone, not a missing packaging checkbox for
  the current library.
