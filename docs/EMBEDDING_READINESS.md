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

Credentialed Apple distribution is a separate lane: `artifact/swift-xcframework-release.sh`
creates a detached worktree at one frozen source commit, Developer ID-signs only the outer
XCFramework, validates warning-free final SwiftPM links and matching-architecture execution for
both macOS `arm64` and `x86_64`, and validates generic iOS device/simulator link consumers. It then
requires the exact static-only ZIP layout and emits hash-bound `APPLE_DISTRIBUTION.json` evidence.
Because this payload has no standalone executable or notarizable bundle, notarization is recorded
as not applicable, never as Accepted; the final consuming macOS product retains its own signing and
notarization duty. Public currentness is selected by `artifact/results.json`.

The Android AAR/JNI sub-gate also requires a clean worktree for release proof. During local
diagnostics on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1`; that mode proves local
packaging behavior only, not release provenance.

The optional Apple device matrix also requires a clean worktree for release proof. During local
hardware diagnostics on an in-progress tree, set `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1` when
generating proof and `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1` when reverifying it; that mode is
diagnostic only. Matrix schema v5 fixes the release requirement to a wired physical iPad and a
distinct local-network physical iPhone, each backed by a schema-v4 child proof and the same
trusted-local Xcode installation receipt; callers cannot
weaken it to another transport or a single-device subset. Device-writing lanes never auto-select
hardware: a single-device run requires `QPERIAPT_IOS_DEVICE_ID`, and a matrix capture requires
`QPERIAPT_IOS_DEVICE_MATRIX=ipad:<udid>,iphone:<udid>`. The runner uses a random run-scoped bundle
identifier, rejects bundle-identifier overrides, checks all installed app classes, and verifies
removal of only its own app before emitting proof. Automatic provisioning and device registration remain disabled
unless the caller explicitly opts into those separate account mutations.

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
- Swift source-tree XCTest execution with the expected two passing ABI2 product tests;
- Swift XCFramework/binaryTarget pre-publication gate: universal macOS static slice, iOS device
  slice, iOS simulator slice, SwiftPM checksum, zip/path-safety checks, and an isolated binary
  consumer that executes three isolated ABI2 product checks without `../../target/release`
  linker flags, plus warning-free per-architecture macOS and generic iOS device/simulator final-link
  probes whose selected `.a` bytes must match the exact archive slices; the credentialed release
  lane also executes both macOS probes in the matching architecture execution modes;
- Android AAR/JNI pre-publication gate: four Rust Android `q-periapt-ffi` cdylib ABI slices
  (`arm64-v8a`, `x86_64`, `armeabi-v7a`, `x86`), JNI shim slices, `JNI_OnLoad`/`RegisterNatives`
  export-shape checks, native/JNI symbol and `DT_NEEDED` audits, canonical AAR archive-structure
  and path-safety checks for the built payload, Java facade `javac -Werror`, D8 conversion,
  and an isolated Java consumer compile. Canonical archive structure does not claim cross-host
  bit reproducibility of the compiled payload;
- Kotlin/Panama FFM tests on JDK 22 or newer, loading a specific native library path;
- WASM Node tests, including runtime suite metadata;
- `artifact/proof-to-byte.sh` manifest validation.

To require physical Apple hardware evidence too:

```sh
QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1 \
QPERIAPT_DEVICE_RESULT_DIR=/absolute/path/to/artifact/device-runs/<matrix-run-dir> \
sh artifact/embedding-readiness.sh
```

That matrix must contain one fresh physical iPad proof and one fresh physical iPhone proof. The
device lane is separate because it requires local Apple signing and attached devices; the default
embedding gate remains usable on hosts without Apple hardware.

The canonical Android release runtime is a script-owned, cold-boot
`arm64-v8a` Android 15 / API 35 AVD with 16 KiB pages, build-tools 36.0.0,
release mode, and the exact AAR produced from the same clean source snapshot. Produce that AAR and
run it on the AVD before creating any release index:

```sh
(
set -eu
sh artifact/android-aar.sh

aar="$PWD/target/qperiapt-android-aar/q-periapt-android-0.1.1/q-periapt-android-0.1.1.aar"
aar_manifest="$PWD/target/qperiapt-android-aar/q-periapt-android-0.1.1/MANIFEST.json"
avd_home=$(sh artifact/python-run.sh artifact/android_bounded_command.py avd-home-path)
avd_name=$(sh artifact/python-run.sh artifact/android_bounded_command.py runtime-avd-name \
  --adb-profile macos-account --device-abi arm64-v8a)
test "$avd_name" = QPeriapt_Release_16K_API_35_V1
umask 077

# One-time, no-replace provisioning. If this fixed private root already exists,
# validate and reuse it; never overwrite it or fall back to ~/.android/avd.
if [ ! -e "$avd_home" ] && [ ! -L "$avd_home" ]; then
  mkdir "$avd_home"
  chmod 700 "$avd_home"
  ANDROID_AVD_HOME="$avd_home" avdmanager create avd \
    --name "$avd_name" \
    --package "system-images;android-35;google_apis_ps16k;arm64-v8a" \
    --device pixel_6 <<'AVD_INPUT'
no
AVD_INPUT
fi
sh artifact/python-run.sh artifact/android_device_proof.py verify-avd-home \
  --avd-home "$avd_home" \
  --adb-profile macos-account \
  --device-abi arm64-v8a

QPERIAPT_ANDROID_ADB_PROFILE=macos-account \
QPERIAPT_ANDROID_RELEASE_MODE=1 \
QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator \
QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a \
QPERIAPT_ANDROID_EXPECT_PAGE_SIZE=16384 \
QPERIAPT_ANDROID_EXPECT_SDK=35 \
QPERIAPT_ANDROID_EXISTING_AAR="$aar" \
QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST="$aar_manifest" \
QPERIAPT_ANDROID_EXPECTED_AAR_SHA256="$(shasum -a 256 "$aar" | awk '{print $1}')" \
QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256="$(shasum -a 256 "$aar_manifest" | awk '{print $1}')" \
sh artifact/android-device-smoke.sh
)
```

Provisioning is no-replace: a pre-existing invalid root fails closed and must be investigated rather
than overwritten. If the fixed fallback root `~/.android/avd` exists, it must be current-user-owned,
non-symlink, and not writable by group or other users; its existing parent chain must meet the same
ownership/writeability boundary, and macOS allow ACLs are also rejected. In all
cases the derived private name must be absent there. The producer never chmods or deletes it, and
unrelated historical AVDs may remain. The derived name alone
is not evidence: admission also depends on descriptor-safe private-tree validation and the observed,
proof-bound ABI, SDK, page size, release mode, and build-tools values. After the smoke reports its
immutable run id, finish the release transaction in
this order, without a source-changing edit between steps:

```sh
QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id> \
sh artifact/local-release-index.sh
sh artifact/local-release-consumer-smoke.sh

# After one evidence-only artifact/results.json successor selects the exact AAR,
# AVD run, first index, emitted receipt, and (for production) physical proof:
QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1 \
QPERIAPT_EMBED_REQUIRE_ANDROID_PHYSICAL_RUNTIME=1 \
QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER=1 \
QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<physical-run-id>/proof/qperiapt-android-device-proof.json \
sh artifact/embedding-readiness.sh
```

`artifact/local-release-consumer-smoke.sh` is a producer: only after both extracted dynamic and
static C consumers pass does it append a receipt. The final embedding invocation never produces or
repairs that receipt. Its Android options enter a distinct read-only final mode before any package
producer or build tool runs. The script makes one bound `proof-to-byte` verification with the AAR,
canonical AVD, and local index/receipt requirements enabled against one pinned
`artifact/results.json` digest, prints `EMBEDDING_ANDROID_BOUND_VERIFY_PASS` with explicit
`canonical`, `physical`, and `local_release_consumer` bits, and exits. This
ordering is mandatory: running `android-aar.sh` after the evidence-only successor would overwrite
the fixed target AAR with successor-commit bytes and invalidate its selected source binding. For
the production aggregate, also set `QPERIAPT_EMBED_REQUIRE_ANDROID_PHYSICAL_RUNTIME=1` and
`QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF=<selected-physical-proof>` in the same invocation.

The same harness also supports an explicitly selected physical device. A clean proof over the same
source and exact AAR is an additional production-promotion requirement; it is not the canonical
Android release selector and cannot replace the arm64/API-35/16-KiB AVD in the release index or
canonical runtime gate. The independent `android_physical_runtime` results section and
manifest-bound verifier are implemented: `current_clean_tree_physical_pass` binds the physical
proof's exact path/hash, clean source commit/digest, current AAR/manifest bytes, device facts, and
passing test set without weakening the canonical section. A physical device may truthfully be API
36 with 4 KiB pages and run outside Android release mode; its required invariant is a clean source
snapshot and the exact same AAR/manifest bytes, not imitation of the canonical AVD parameters.
Dirty runs may set
`QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1` for diagnosis, but a dirty Android proof can never be
selected by manifest-bound `proof-to-byte`.

For production, complete the real physical run before the results successor and have that same
successor select the proof under `android_physical_runtime`. The Android production aggregate must
then require both independent runtime gates in the same pinned-manifest invocation:

```sh
QPERIAPT_REQUIRE_ANDROID_AAR=1 \
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<canonical-run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME=1 \
QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<physical-run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER=1 \
sh artifact/proof-to-byte.sh
```

The two proofs are non-interchangeable. The physical gate fixes freshness to 86,400 seconds and
emits `PROOF_TO_BYTE_ANDROID_PHYSICAL_RUNTIME_PASS`; the aggregate finalizer emits
`PROOF_TO_BYTE_ANDROID_LOCAL_PRODUCTION_GATE_PASS` only when AAR, canonical runtime, physical
runtime, and local-consumer states all equal 1 on a clean source snapshot. This is a local
production gate, not Maven publication, signed public provenance, or a generic all-platform release
attestation. A simultaneous full Apple/core local-candidate pass uses the distinct
`PROOF_TO_BYTE_APPLE_ANDROID_LOCAL_CANDIDATE_PASS` final marker rather than implying that the
Android-only marker is generic. Production remains pending unless a current-source physical run is
actually captured and selected; `artifact/results.json` plus the bound marker are the currentness
authority rather than this prose.

The runtime lane is separate because it requires adb plus a booted emulator or physical Android
device. External devices require an exact serial and `physical` expectation; the canonical AVD is
accepted only when the script starts and binds the cold-boot emulator with a read-only userdata
overlay. The smoke refuses to replace an existing exact package, validates the installed
APK bytes and signer before cleanup, reconciles unknown outcomes with bounded stable observations,
and captures only run-bounded tag output without clearing global logcat
buffers. The fixed current-account home and its `.android` identity directory must be
non-symlink, owner-controlled, and not group/other writable; owner-protected key files
and an already authorized target are mandatory. macOS deny-only ACLs are accepted, but
any allow ACL is rejected. Caller-supplied adb routing/discovery overrides are rejected, and
the default IPv4/IPv6 endpoints must already be absent; the script never stops or reuses a
global server. It owns one mode-0700, allow-ACL-free private `localfilesystem:` socket under
`/tmp`, routes every client explicitly, disables mDNS/auto-connect, and freezes server PID/start,
executable, key, endpoint, transport environment, and mDNS-disabled status before selection and
after the final query. Physical proof is restricted to one explicit USB serial. The AVD lane disables
USB and automatic emulator scanning; it fixes external adb to the run-owned snapshot and private Unix
socket, redirects the native notifier from 5037 to closed loopback port 5586, and registers only the
freshly PID-bound fixed listener pair through the private socket. Four no-replace checkpoint receipts
record IPv4/IPv6 `ECONNREFUSED` for 5037 and 5586 at emulator pre-exec, post-registration, runtime
pre-cleanup, and post-cleanup. Its localhost emulator transport still requires an exclusive trusted
evidence host. Current schema-v6 proof and schema-v2 bundle contain those checkpoint bytes plus a
raw-value-omitting, source-bound admission receipt for external-adb routing, the native-notifier
policy, backend, fixed ports, listener, exact registration response, and private-adb identities; raw
HOME/key/socket/UID/PID/serial values are excluded. This remains trusted-local control-plane evidence,
not independent hostile-builder attestation. App, AVD, private-server, and socket cleanup must complete before proof publication in
the append-only `target/qperiapt-android-device-smoke-runs/<run-id>/` tree; failures leave no accepted
proof or PASS marker, never change an earlier selected run, and never trigger raw-PID TERM/KILL.
Authorization prompts are not part of the proof lane. A stable, account-private
host/account-scoped open-file lock serializes all checkouts before a unique run root is created. A
durable whole-runtime receipt binds the originating run, adb snapshot, endpoint, server, and optional
emulator before a long-lived child releases that lock. The children retain the registered descriptor
with close-on-exec set through receipt registration; the kernel closes it only when the fixed exec
succeeds, so a later lane can acquire it and strictly recover an interrupted runtime. Capability creation
defers HUP/INT/TERM until its private state is armed or removed. Same-boot recovery revalidates exact
process/listener identities, shuts an owned AVD through its authenticated console independently of
private adb, and protocol-stops any still-live private server; confirmed prior-boot recovery is
offline-only. The socket directory is reconciled from mode 0700 through the schema-v5 runtime phases
to `ADB_SEALED` plus actual mode 0500 before any adb client. Schema-v4 runtime receipts are rejected
rather than implicitly migrated. Normal publication requires accepted protocol shutdown requests and
zero child exit statuses; recovery may finalize an exact identity already proven absent, but never
turns that interrupted run into a PASS. The console-token bytes are not persisted. Unsafe receipt,
filesystem, listener, or path mismatches are preserved and rejected for operator review; a PID/start-
token mismatch is treated as the exact owned process being absent and is never signalled. Device loss can
still leave app cleanup unresolved. The checkpoint receipts establish only that the exact IPv4/IPv6
connect attempts were refused; they do not continuously reserve 5037/5586 or prove the absence of
traffic between checkpoints, so the exclusive trusted-host requirement remains. The fixed emulator
argv omits gRPC enablement; the listener receipt binds the required
console/adb pair and is not an exhaustive claim about every TCP listener of the emulator process.
All adb/lsof activity is selected from a finite Android operation table backed by one private
run capability. The shared bounded-process module is import-only and exposes no arbitrary command or
output-path CLI. Capability creation consumes the fixed-profile SDK adb from one opened descriptor
while hashing and copying it into a fixed, run-owned mode-0500 executable under the private work
directory. All later client/server execution and identity verification uses that snapshot, closing an
ordinary SDK-path replacement window after capability creation. adb is selected only from the fixed
`auto`, `macos-account`, `linux-account`, `linux-system`, or `linux-opt` profiles via
`QPERIAPT_ANDROID_ADB_PROFILE`; arbitrary `QPERIAPT_ADB` paths are rejected. This is trusted-local
reliability hardening, not protection against hostile same-UID modification; that boundary requires a
separate account or isolated runner with a read-only checkout.

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
QPERIAPT_DEVICE_RESULT_DIR=/absolute/path/to/artifact/device-runs/<matrix-run-dir> \
QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id> \
sh artifact/local-release-index.sh
```

The Android selector is mandatory when inclusion is enabled and is used only to derive the fixed
immutable run proof path. Arbitrary proof paths, newest-run discovery, and legacy fallback are rejected.
The release channel admits the canonical AVD runtime lane only: emulator, arm64-v8a, API 35,
16 KiB pages, and release mode. Explicit physical proofs remain separately verifiable but are not
substituted for this release-index contract.

The release transaction is append-only and ordered: produce the exact current-source AAR; execute
that AAR on the canonical AVD; create the first release index with
`QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1` and the exact run id; execute the extracted
dynamic and static C consumers to emit one receipt; then make one evidence-only
`artifact/results.json` successor that selects the AAR, AVD proof, index, and receipt together.
Only after that successor exists may `proof-to-byte` or the opt-in embedding gate verify the bound
transaction. Final verification is read-only with respect to receipts; regenerating an index or
consumer receipt during verification would create different bytes and is not accepted as repair.

The index copies only the C archive, Swift XCFramework zip, Android AAR, and their manifests into
`target/qperiapt-local-release/<channel>/<version>/<commit>/`. It may include raw-value-omitting Apple/Android proof
summaries, but it never copies raw device proof, build logs, provisioning profiles, `.xcresult`
bundles, UDIDs, or adb serials. Index schema 5 includes the verified Android page size,
release-candidate mode, passing result, and fixed external-adb/native-notifier admission in its
raw-value-omitting summary, and accepts only the current C schema-2, Swift schema-5, and Android
schema-4 package envelopes and rejects signed Swift input because the local index does not carry its
Apple distribution evidence. Artifact boundaries name the required leaf gate and explicitly record
that no leaf receipt or cryptographic attestation is embedded. This is an aggregation gate over package outputs already checked by
their leaf gates, not an independent binary verifier or a signature over mutable `target/` content;
durable provenance still requires the results-only evidence successor or an external release
attestation.
The emitter and consumer use their installed repository root and fixed per-channel pointer; they do
not accept arbitrary root, index, or output paths. Local-store and consumer directories are mode 0700,
while package copies, manifests, checksums, indexes, and pointers are mode 0600. Each
`<channel>/<version>/<commit>` tree is immutable once created, and the authoritative channel
pointer changes only after a unique private sibling staging tree has been completely verified and
published with native atomic no-replace semantics. macOS uses `renameatx_np(RENAME_EXCL)`, Linux uses
`renameat2(RENAME_NOREPLACE)`, and unsupported hosts/filesystems fail closed without an overwrite
fallback. Re-emitting an already verified identity with the exact requested proof selectors is an
idempotent success without rewriting its tree or canonical pointer. A pre-publication interruption can
leave an unselected private staging directory, never a partially published identity; the next
serialized emit removes only an exactly named, current-user-owned mode-0700 remnant. If `SIGKILL` or
host loss occurs after the final rename but before pointer commit, the next emit fully verifies the
exact final tree and idempotently advances the pointer. Corrupt, permission-invalid, or
proof-selector-mismatched trees remain untouched for investigation and fail without changing the old
pointer. An exact owned private-writer remnant from that window is removed only after this complete
verification, and an already matching pointer still retries the parent-directory sync before success.
These are trusted-local integrity guarantees and do not resist a hostile same-UID process. A later
public publication step must deliberately create its own public-permission artifact set.

The ML-KEM implementation below every native face is now target-selected at compile
time. Exactly `aarch64-apple-darwin`, `aarch64-apple-ios`,
`aarch64-apple-ios-sim`, `aarch64-unknown-linux-gnu`, and
`aarch64-linux-android`, all little-endian, use upstream AArch64 native arithmetic
plus a fixed per-target FIPS 202 assembly profile (Armv8.4-A SHA3 x1/x2 on the
two Apple Silicon slices, Armv8-A scalar x1 and scalar/Neon x4 elsewhere). Every
other target remains portable C, including x86, Windows/MSVC, Wasm, and
freestanding builds. There is no runtime dispatch. This is an
internal implementation selection: ABI 2 exports/layouts, ML-KEM key/ciphertext
formats, and combiner wire bytes remain unchanged.

## Per-Face Status

| Face | Status | Boundary |
|---|---|---|
| Rust | The coordinated ten-crate set forms the pre-publication package-ready `0.1.1` stable-version source/crate line; **no crate has been uploaded to crates.io yet**. Source build and workspace tests pass under locked dependencies; `artifact/rust-publish-contract.sh` checks the crates.io allow/deny list, every downstream local patch, package file lists, and registry-bound `cargo package` plus rebuilt-archive verification while rejecting every Cargo warning and never invoking an upload command. It independently verifies the sys `.crate` fixed 124-entry upstream inventory and exact packaged 118-code-file hash subset (six upstream README files excluded), pinned license/provenance, forbidden paths and the fixed target-selected native/portable build surface, then audits the normalized backend graph with the sys crate patched in. | The no-upload contract does not prove crates.io upload-API acceptance, crate-name ownership, publishing credentials or authorization, server-side policy acceptance, or a registry receipt. Registry publication would still not establish independent signed provenance, audit the vendored C/assembly provider, or promote the crates to production. Those remain separate requirements. |
| rustls (direct Rust) | The Compat client keeps the stable serialized private key as a 32-byte seed, expands it exactly once per in-flight handshake into a non-Clone zeroizing 2,400-byte prepared owner, and reuses that owner for completion. Concurrent handshakes have independent key owners. | This is process-local Rust integration only. The process-global group registry holds a stateless preparer, not secret keys; there is no global/shared secret-key cache, persistence-format change, or C-ABI prepared-key entry point. Each active handshake owns about 2.4 KiB of expanded secret-key storage until completion or abandonment. |
| C ABI | The stable-version C ABI source contract for `0.1.1` has a frozen machine-readable ABI2 authority: nine exact dynamic `q_periapt_*` exports, the same exact reserved public namespace for static archives, status/constants, 40/36-byte layouts, forbidden raw/deterministic public symbols, ABI-major header guard and platform identities. The first dynamically allocated Rust-owned policy-bound-context copy is reserved before sensitive bytes are written and wiped by one RAII owner on normal return, error, or unwind. Static archives retain unsupported hidden `qpn_*` bridge link symbols, so hidden visibility is not access control and the embedding process is trusted. Target-selected ML-KEM remains below this boundary and does not change ABI 2, keys, or wire bytes. The host smoke harness covers signed policy, exact digest, ABI1 hard cut, OS-random key/encapsulation, context binding and atomic failure outputs. | The RAII guarantee does not cover caller buffers, host-language/FFI marshalling copies, registers, paging, process abort, or full-runtime erasure. Historical `abi2-platforms-v0.1.0-alpha.2-r2` receipts describe their exact portable-derived Linux/Windows artifacts, not a current target-selected rebuild. The stable tag-bound candidate pipeline must rebuild and validate the formally supported target-specific native consumers and attested provenance and bind them to `PLATFORM_DISTRIBUTION.json`/`SHA256SUMS`; public/current status requires a fresh verified receipt. Windows remains an unsupported CI diagnostic and is excluded from this stable asset set until an Authenticode producer/verifier and external certificate/TSA gates exist. Production promotion still needs independent review and clean signed or transparency-backed source provenance; deb/rpm/MSIX registry packaging remains separate. |
| Swift | The SwiftPM ABI2 product harness, five-slice XCFramework isolated consumer, credentialed Developer ID static-SDK lane, and physical matrix verifier are implemented. The wrapper exposes only signed-policy decision, OS-random atomic keys/encapsulation and decapsulation, with explicit secret wipes. | `artifact/results.json` binds historical signed XCFramework receipts to their exact artifacts. Target selection changed the source and the three little-endian AArch64 Apple slices now use the native backend, so previous package/device proof is stale for the current build. A fresh target-specific XCFramework transaction and iPad+iPhone evidence are required. The static SDK remains non-notarizable `binaryTarget` material rather than a complete Git-URL Swift package; consuming apps retain signing/provisioning and macOS notarization duties. |
| Android | The four-ABI AAR harness uses ABI-major FFI/JNI names and the same nine-symbol native product workflow, with export/SONAME/DT_NEEDED, Java/JNI warnings-as-errors, dex, signing, and isolated-consumer checks. In the current source, arm64-v8a selects the fixed native AArch64 backend while armeabi-v7a/x86/x86_64 remain portable. | The previously recorded AAR/runtime receipt is historical after target selection. Live-tree release currentness requires a newly rebuilt source-bound AAR, clean arm64-v8a/API-35/16-KiB release-mode AVD, first index, consumer receipt, results successor, and read-only bound gate (`ANDROID-RUNTIME-DIAGNOSTIC-CURRENTNESS`). An independent results-selected physical gate is implemented and cannot replace the canonical AVD; production requires both. Maven Central publication and downstream SkyBridge harnesses remain unclaimed. |
| Kotlin | Panama FFM is migrated to ABI2, requires an absolute ABI-major library path, and passes the current JDK 22 warning-failing CI lane. | This is host JVM evidence only and remains separate from Android runtime. |
| WASM | Both the lean default and signed-policy feature execute their deterministic conformance tests on Node/WASM. | WASM is a separately scoped caller-randomness conformance surface, not covered by the native ABI2 package contract; browser/package hardening remains open. |

The retired PQClean-HQC adapter is absent from every package above. Numeric suite code
`3` is a fail-closed tombstone, while `research/hqc-fips207-candidate` is a standalone
`publish = false` shadow with no ABI/package identity. The earlier migration to
portable `mlkem-native` v1.2.0, `fips204` 0.4.6, and `sha3` 0.10.9 removed the
former provider. The subsequent fixed target-selection migration changed the source
digest again and invalidated every portable-derived package, device,
matched-performance, and binary-CT proof for the current source.
It removed both the earlier `libcrux`/hax `proc-macro-error2` advisory edge and the
later `fips203` provider that failed the historical two-ISA binary-CT probe. The vendored
trust anchors are upstream commit `0ba906cb14b1c241476134d7403a811b382ca498`
and immutable GitHub commit archive SHA-256
`f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
Upstream HOL-Light evidence applies only to selected upstream assembly
source/object routines under its stated preconditions; it does not prove downstream
reassembly, this Rust/C integration, the full ABI, or the packages above. A local
dirty native/portable diagnostic motivated a primitive/hybrid-core performance hypothesis,
but it has no checked-in canonical-source/toolchain-bound raw and
analysis bundle and is not release evidence. The current release gate uses raw
schema v5, proof schema v8, and budget schema v10: one same-process ABBA/BAAB slot
preserves the ContextBound/CompatXWing profile estimand with strict fixed
ContextBound inputs and canonical `[]`/`0`/`[]` CompatXWing inputs, and separately
requires byte-equivalent native/portable ContextBound `hybrid_core` encapsulation and
decapsulation over one generated `expanded_fips203_2400` keypair, with the same key
bytes/coins/corpus supplied to both implementations, with
p50/p95 upper ratios at most 0.95 and p99 at most 1.0. The proof additionally binds
the same O3/PIC/Armv8-A/macOS-11 C codegen contract, the O3/thin-LTO/one-codegen-unit
Rust harness, the stable Rust/Cargo 1.96.1 producer, selected SDK/toolchain, final
harness binary, portable reference archive, and canonical source. Each
estimand/operation is warmed independently immediately before its collection. The
implementation estimand excludes FFI and OS RNG and is not a complete ABI, rustls,
or competitor-performance result. Exact results require a fresh current-source proof selected by
`artifact/results.json`.
`cargo audit --deny warnings` passes without an ignore for the Rust graph; it does
not inspect vendored C. ABI 2 is the stable-version source/Rust-crate line; registry
publication remains separately receipt-gated. The local package contract does
not prove crates.io upload-API acceptance, crate-name ownership, publishing credentials
or authorization, server-side policy acceptance, or a registry receipt. Its
stable binary targets are the Apple `v0.1.1` XCFramework and the
`abi2-platforms-v0.1.1` Android/Linux packages; only their
verified receipts may assert public, immutable and current status
(see `artifact/stable-release-notes.md` for scope, verification, and explicit
non-goals). Fresh same-source device/performance evidence, independent cryptographic,
C/FFI and ABI review, clean signed or transparency-backed source provenance,
registry publication (crates.io/Maven/deb/rpm/MSIX), and a future signed Windows lane
remain hard requirements for production promotion.

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

- Rust crate pre-publication package surface: retain the coordinated dependency order for every
  subsequent version — `q-periapt-mlkem-native-sys`, core, KEM/signature traits,
  backends, policy, then the FFI/WASM/rustls leaves; the dependency-free CLI remains
  version-coordinated. A dirty diagnostic run is not release proof, and registry
  packages still need independently verifiable signed or transparency-backed
  provenance before production promotion.
- C ABI product surface: rebuild the `.so.2` Linux x86_64-portable/aarch64-native
  archives and ABI-major portable Windows archive with the exact CMake/pkg-config
  target for a new publication transaction; they become public/current only through
  its verified receipt. `.2.dylib` remains a host-gate artifact outside
  the published platform set. ABI1 uses a deliberate hard cut—four-byte state is
  rejected and requires explicit host-authorized re-enrollment/reset, not an
  unverifiable synthetic migration. Remaining: deb/rpm/MSIX registry packaging,
  Windows Authenticode, and public install docs beyond the release notes.
- Swift product surface: rebuild all slices so the three allowlisted AArch64 targets
  select native while x86_64 remains portable; then publish and remotely re-download the exact
  signed static-only XCFramework with URL/checksum/provenance, then verify a URL-based
  `binaryTarget` consumer. The ZIP does not contain the Swift wrapper package; consumers must bind
  the wrapper to the same source commit. Rerun the physical iPad+iPhone matrix before production
  promotion; the final macOS product's notarization does not replace device execution evidence.
- Android product surface: rebuild the target-selected AAR (native arm64-v8a,
  portable armeabi-v7a/x86/x86_64) for the
  `abi2-platforms-v0.1.1` target with an API 35 / 16 KiB-page emulator
  runtime-evidence bundle executed on the exact AAR; public/current status requires the
  verified receipt. The ABI2 ART smoke must be
  rerun against the live source tree whenever it advances; `artifact/results.json`
  selects whether the latest clean-tree rerun is current
  (`ANDROID-RUNTIME-DIAGNOSTIC-CURRENTNESS`). The local release-index slot always requires the
  canonical arm64-v8a API 35 / 16 KiB release-mode AVD; a physical proof cannot replace it. CI runs
  a real x86_64 API-35/16-KiB ART package-face job on every push and pull request, but that
  architecture-specific CI evidence is not interchangeable with the canonical release AVD.
  The independent `android_physical_runtime` results selection and manifest-bound gate are
  implemented. Production requires canonical and physical runtime states both equal 1 over the same
  clean source and exact AAR; without that selected real physical run, the aggregate remains
  pending. Remaining after the local aggregate: publish to Maven Central and add downstream
  SkyBridge target-level harnesses.
- Downstream SkyBridge harness: one minimal integration test per target repository using the same
  shared vectors and policy files, so Q-Periapt proof does not get mistaken for downstream product
  proof.
- Stateful channel work, if selected: finish G1 beyond the current non-normative lifecycle model,
  then implement the reference and Continuity session lanes, formal state/storage models,
  model-to-Rust linkage, transactional persistence, and physical two-endpoint latency/energy/healing
  gates. This is a separate product and research milestone, not a missing packaging checkbox for
  the current library.
