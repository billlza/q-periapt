# Artifact evaluation guide

This artifact backs the paper's claims in three layers, ordered by cost and dependency weight. A
reviewer with only Rust installed can run **Tier 1** in ~10 minutes; **Tier 2** reproduces the CI
gates in ~1 hour given a few extra toolchains; **Tier 3** reproduces the hardware-dependent
measurements (network shaping, binary constant-time) and needs specific hosts.

All commands run from the repository root. `cargo` ≥ 1.85 is the only hard prerequisite for Tier 1.

## Quick start — one command

```sh
sh artifact/smoke.sh
sh artifact/proof-to-byte.sh
```

Runs the minimal closed loop (core tests, shared/reference vectors, the C-ABI face + a real C
link-and-run, the WASM face's shared vector on the host, a real loopback TLS 1.3 handshake over the
hybrid group, and the EasyCrypt no-`admit` gate) and prints `ALL PASS` (exit 0). Needs only a Rust
toolchain and a C compiler — no Docker, wasm-pack, Node, or network beyond cargo's dependency fetch.
`proof-to-byte.sh` additionally validates the committed proof/vector hashes in
[`artifact/results.json`](artifact/results.json), then runs the same smoke unless
`QPERIAPT_SKIP_SMOKE=1` is set.

The expected per-step counts, toolchain, footprint sizes, and data-file pointers are pinned in
[`artifact/results.json`](artifact/results.json) (every value measured, so drift is visible). A
frozen historical capture is in [`artifact/ci-snapshot.log`](artifact/ci-snapshot.log); it is useful
for provenance, but the current clean gate is the live command output, not that historical log.

---

## Tier 1 — 10-minute smoke test (Rust only)

Verifies the core composition logic, the six-method conformance matrix (host side), and the
no-admit proof gate. No C toolchain, Docker, or network required.

```sh
cargo test --workspace            # 107 tests: KATs, ACVP, differential, proptests, FFI/WASM host vectors
cargo fmt --all --check           # formatting gate
! grep -rnE 'admit|sorry' --include='*.ec' formal/easycrypt/   # no proof holes (always-on hard gate)
```

Expected: all tests pass; the grep finds nothing (exit 0 via the `!`). This establishes byte-identical
KATs, NIST ACVP conformance, the independent-crate differential checks, and that the committed
EasyCrypt proof has no `admit`/`sorry`.

The dk-format separation (Theorem 1, item 5) is witnessed by a runnable example — both the
expanded-`dk` break and its seed-`dk` negative control, against real libcrux:

```sh
cargo run -p q-periapt-backends --example binding_dk_format_witness
```

It prints, for two distinct ML-KEM public keys: over expanded-`dk` the lean (X-Wing-shaped)
combiner collides on K-PK while `ContextBound` does not; over seed-`dk` (z re-derived from a 32-byte
seed, as deployed X-Wing mandates) the attack vector is closed. The same two checks run as the
`binding_keyformat_separation` integration test under Tier 1's `cargo test`.

## Tier 2 — ~1 hour, reproduce the CI gates

Adds the optional backends, the **hermetic EasyCrypt machine-check**, the language bindings, and the
cross-target builds. Extra prerequisites in parentheses.

```sh
cargo clippy --workspace --all-targets -- -D warnings                  # lint gate
cargo test -p q-periapt-backends --features slh-dsa,hqc                # SLH-DSA + HQC (needs a C toolchain)

# Hermetic binding proof (needs Docker). Builds a pinned EasyCrypt r2026.06 image and re-checks the
# proof + the deleted-hypothesis necessity controls as a HARD gate:
docker build -f formal/Dockerfile -t q-periapt-ec .
docker run --rm -v "$PWD/formal/easycrypt:/src:ro" q-periapt-ec \
    opam exec -- sh -c 'mkdir -p /tmp/ec && cp -r /src/. /tmp/ec && cd /tmp/ec && rm -f *.eco \
        && easycrypt BindingViaCR.ec && sh negative-controls.sh'

sh bindings/c/build-and-run.sh                                         # C-ABI link smoke (needs cc)
cargo build -p q-periapt-wasm --target wasm32-unknown-unknown          # wasm32 (needs the target)
cargo build -p q-periapt-core --target thumbv7em-none-eabihf           # no_std embedded (needs the target)
```

Optional binding faces (each needs its own toolchain): `swift test --package-path bindings/swift`
(Swift); `sh artifact/android-aar.sh` (Android AAR/JNI package proof, Android SDK/NDK + Rust Android
targets); the Kotlin/Panama FFM tests (JDK ≥ 22 + gradle); `wasm-pack test --node
crates/q-periapt-wasm` (wasm-pack + Node). The full GitHub Actions workflow in
`.github/workflows/ci.yml` is the canonical list; `formal-hermetic` is the proof hard gate.

### Consumer embedding readiness gate

For downstream consumers that want the current "download/build/use" contract rather than only the
paper smoke, run:

```sh
sh artifact/embedding-readiness.sh
```

This is fail-closed and warning-clean: it checks locked Cargo metadata, `cargo fmt`, warning-denied
clippy, workspace tests, optional SLH-DSA/HQC backend tests, release C-ABI build, generated-header
freshness (`cbindgen` output must match both the C and Swift vendored headers), the C link-and-run
smoke with runtime ABI/suite metadata, host C release archive proof (`artifact/c-package.sh`) through
extracted dynamic/static pkg-config and CMake consumers plus archive license/CBOM/SBOM validation,
Swift XCTest count, Swift XCFramework/binaryTarget pre-publication proof
(`artifact/swift-xcframework.sh`) through an isolated binary consumer, Android AAR/JNI packaging
proof (`artifact/android-aar.sh`) with four ABI slices, native/JNI symbol audits, dex conversion, and
an isolated Java consumer compile, Kotlin/Panama tests with explicit native library loading, WASM
Node tests, and `proof-to-byte.sh`. The Rust crate release
surface has a separate pre-publication gate,
`sh artifact/rust-publish-dry-run.sh`, which requires a clean tree by default, validates the
publish allow/deny list, checks package file lists, and runs patched `cargo publish --dry-run`
for each publishable crate. The Swift XCFramework gate also requires a clean tree by default; set
`QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1` only for local diagnostics. Set
`QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1` plus `QPERIAPT_DEVICE_RESULT_DIR=<matrix-run-dir>` to also
require a fresh iPad+iPhone matrix proof. Set `QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1` after
running `artifact/android-device-smoke.sh` to require a fresh emulator or physical-Android runtime
proof too. Passing this gate proves that the current source tree can be embedded through the
existing faces and that the host C archive is consumable after extraction. After those package gates
have produced artifacts, `sh artifact/local-release-index.sh` creates a local hash-bound index under
`target/qperiapt-local-release/<version>/<commit>/` over the C archive, Swift XCFramework zip, and
Android AAR. Release mode requires a clean tree. Set `QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=1` only for
diagnostic indexes; optional Apple/Android runtime evidence is included as sanitized proof summaries,
never as copied raw device logs or profiles. This is still not a full
multi-platform release claim: Swift still needs an actual public XCFramework
URL/checksum/provenance and fresh device-matrix proof for the same source state, Android still needs
clean-tree release provenance plus CI/physical-device policy before a product-ready runtime claim,
Rust still needs actual registry-order publishing/provenance, and the C archive still needs
multi-target publishing plus Windows archive shape and full third-party dependency license inventory
beyond the current Cargo.lock-derived SBOM.

## Tier 3 — hardware-dependent measurements

These produce the paper's primary network table and the binary constant-time discriminator. They
need specific hosts and privileges, and are **not** required to validate the security claims.

- **Bare-metal time-to-session (Table VI).** A quiesced bare-metal **Linux x86-64** host, root (for
  `tc netem` + CPU pinning), and Rust. `sudo sh camera-ready-bare-metal.sh 2>&1 | tee out.txt`
  (~20 min). Output format matches `paper/camera-ready-results.txt`. On a virtualized host the
  RTT-0 medians are noisier (the paper labels that run supporting, not primary).
- **Source→binary constant-time discriminator (§V-A).** Valgrind/Memcheck on **x86-64 or aarch64
  Linux** (native or a Linux container; not under nested emulation). `sh ctstats/scripts/ct-gap-probe.sh`
  via Docker, or build `ct_decaps_gap`/`ct_hqc_gap` with `--features valgrind` and run under
  `valgrind`. Expect ML-KEM `probe=0` vs HQC `>0` (the discrimination is the signal; raw counts are
  ISA-dependent).
- **Symbolic provers.** `make` under `formal/tamarin/` and `formal/proverif/` (Tamarin 1.10 + maude;
  ProVerif 2.05 via opam). CI hard-gates both lemma/query presence and full `make prove`.
- **Apple device binding smoke.** `sh artifact/apple-device-smoke.sh` runs the macOS native Swift
  binding tests, builds the Rust `aarch64-apple-ios` staticlib, builds a host-app runner for a
  physical iPhone/iPad, installs it, and accepts only an on-device
  `QPERIAPT_DEVICE_PASS run-id=<32 hex chars>` marker plus the matching run-bound
  result file copied from the app data container and a structured single-device
  proof JSON. The proof JSON binds the run id, source
  hashes including the signed-policy vector and the Rust workspace build-input tree,
  git commit and source-tree dirty status,
  app/staticlib hashes, Xcode build log hash,
  copied marker hash, provisioning profile
  validity, codesign entitlements, static Rust FFI linkage, and the weak AppIntents link used for
  Xcode 27 warning-clean app builds. Verification rejects proof inputs outside
  `artifact/device-runs` and app/staticlib paths outside `target`.
  `QPERIAPT_DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer` pins the Xcode 27 beta
  lane without changing global `xcode-select`. This lane requires local signing. Set
  `DEVELOPMENT_TEAM`, set `QPERIAPT_IOS_DEVICE_ID` when more than one physical device is connected,
  and set `QPERIAPT_ALLOW_PROVISIONING_UPDATES=1` only when automatic profile changes are intended;
  otherwise the lane fails closed rather than falling back to a simulator. By default,
  `artifact/proof-to-byte.sh` does not require local signing hardware; set
  `QPERIAPT_REQUIRE_APPLE_DEVICE=1` on `artifact/proof-to-byte.sh` to require and re-verify the
  single-device proof; stale evidence is rejected after `QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS`
  (default: 86400). For iPhone+iPad family coverage, use the matrix lane:
  `QPERIAPT_IOS_DEVICE_MATRIX='ipad:<ipad-udid>,iphone:<iphone-udid>' sh artifact/apple-device-matrix.sh`.
  The matrix lane writes one proof per device plus `apple-device-matrix-proof.json`, and
  `QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX=1 sh artifact/proof-to-byte.sh` verifies that both physical
  families are present, fresh, source-bound, and artifact-bound. For beta/GM readiness, prefer
  `artifact/apple-device-xcode27-gate.sh`: with `QPERIAPT_IOS_DEVICE_ID` it runs the single-device
  gate; with `QPERIAPT_IOS_DEVICE_MATRIX` it runs the iPhone+iPad matrix gate.
  By default, Apple device proof requires a clean tree. Use
  `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1` only to generate local diagnostic proof, and
  `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1` only to reverify that diagnostic proof.
- **Android runtime binding smoke.** `sh artifact/android-device-smoke.sh` first rebuilds and audits
  the Android AAR, then creates a temporary debuggable APK that consumes the AAR on ART, installs it
  on an adb device or emulator, and accepts only a run-bound
  `QPERIAPT_ANDROID_DEVICE_PASS run-id=<32 hex chars> tests=8` marker copied from the app-private
  files directory. The eight runtime checks cover ABI/suite metadata, shared-vector encap/decap,
  six combiner vectors, CompatXWing seed-keypair roundtrip, signed-policy accept/rollback/tamper,
  ContextBound empty-context rejection, and uint32 boundary rejection. The proof JSON records hashed
  adb serial and build fingerprint only, hashes the AAR/APK/result/logcat/source inputs, and is
  reverified with `QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 sh artifact/proof-to-byte.sh`. By default this
  lane requires a clean tree; use `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1` and
  `QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF=1` only for local diagnostics. To boot a local AVD,
  set `QPERIAPT_ANDROID_BOOT_AVD=1 QPERIAPT_ANDROID_AVD=<avd-name>`.
- **Footprint (platform-dependent).** `sh paper/footprint.sh` writes `paper/footprint.csv` for the
  host it runs on (cdylib + WASM module sizes).
