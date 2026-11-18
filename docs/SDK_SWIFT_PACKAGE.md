# Swift SDK package profile

[Download the complete Swift SDK.](https://github.com/billlza/q-periapt/releases/download/v0.2.0/QPeriapt-Swift-SDK-0.2.0.zip)

```sh
curl -fLO https://github.com/billlza/q-periapt/releases/download/v0.2.0/QPeriapt-Swift-SDK-0.2.0.zip
unzip QPeriapt-Swift-SDK-0.2.0.zip
```

Add the extracted `QPeriapt` folder as a local Swift package and select `QPeriaptSDK`.
For persistent sessions in the same target, add the [Apple Continuity r1 package](https://github.com/billlza/q-periapt/releases/download/continuity-apple-v0.2.0-r1/QPeriaptContinuity-Apple-0.2.0-r1.zip).
The [SwiftPM example](SDK_GETTING_STARTED.md#swift-package-selection) shows both dependencies.

## Build from source

The shared Apple builder has an explicit `sdk-020` profile. It packages both
the owned `QPeriaptSDK` and retained `QPeriaptHybrid` Swift products with static
XCFramework slices. The C ABI remains **2**, with the closed 51-function SDK
table and the original nine declarations/status values/library names retained.

```sh
sh artifact/swift-xcframework.sh --profile sdk-020
```

The producer runs on Apple Silicon and requires the pinned Rust/Cargo version,
cbindgen, Xcode and four Apple Rust targets: `aarch64-apple-darwin`,
`aarch64-apple-ios`, `aarch64-apple-ios-sim` and `x86_64-apple-ios`.
Intel macOS is outside the 0.2.0 support matrix. The ordinary profile requires a clean checkout;
local uncommitted implementation checks can explicitly select diagnostic mode:

```sh
QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1 \
QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR="$PWD/target/sdk-apple-new-attempt" \
sh artifact/swift-xcframework.sh --profile sdk-020
```

The SDK output directory must be fresh. Failed attempts are retained. Source
digests before and after construction cover Rust build inputs, Swift wrappers,
consumer fixtures, package tools, ABI definitions and shipped notices. An
observed change fails construction; a dirty HEAD alone cannot identify these
uncommitted bytes. Native compilation uses macOS 13 and iOS 16 consistently in
Rust and C dependencies, rather than inheriting the installed SDK's minimum.
The small Cargo rustc wrapper distinguishes explicit SDK targets from host
build scripts/procedural macros. Host tools retain the compiler's host default;
they are not delivered as SDK slices. Fresh isolated builds reproduced a
Rust 1.96.1/Xcode 27 host macro failure when the macOS 13 setting leaked into
those tools: the system loader rejected a misaligned Mach-O LINKEDIT string
pool, despite a valid ad-hoc signature. Host/target separation passes the same
fresh-build check; it does not patch the external linker or weaken the SDK floor.

The output directory contains `CQPeriapt.xcframework.zip` and the complete
`QPeriapt-Swift-SDK-0.2.0.zip`. Extract the latter and add `QPeriapt` as a
local Swift package dependency. Select `QPeriaptSDK`, or `QPeriaptHybrid` for the
compatibility API. The package declares its system `iconv` linkage; consumers
need neither a Rust installation nor source-checkout library search paths.

The complete ZIP contains wrappers, all binary slices, the native 37-asset
CBOM, workspace lock SBOM, per-target Cargo dependency notices, mlkem-native
notices and the Rust standard-library copyright notice. The latter is copied
verbatim from Rust 1.98.1's `share/doc/rust/COPYRIGHT-library.html`, SHA-256
`68129500b616d5838629e68f55ff3aed5e096dacf60ce9eb41bbe599a563afa6`.
Inventory scopes are specified in [SDK_CBOM.md](SDK_CBOM.md); a workspace SBOM
is not an exact per-slice linked-code inventory.

`PACKAGE_CONTENTS.json` hashes a closed payload, including all notices. The
separate `MANIFEST.json` and `SHA256SUMS` accompany the distributable ZIPs. The
manifest binds source, toolchain, package hashes and actual consumer logs.
The finalizer also requires the digest of the already checked XCFramework ZIP.
Every installed binary, header, module map and XCFramework plist must match
that immutable ZIP snapshot before and after the installed consumer runs.
Rehashing `PACKAGE_CONTENTS.json` cannot authorize different native bytes. The
complete SDK ZIP and original XCFramework ZIP are rechecked after installation.
A ZIP left by an interrupted/failed attempt without the completed manifest and
success markers does not establish a successful package check.

The producer checks every architecture separately, preserving the existing
thin-archive symbol parser and duplicate/missing/extra-symbol rejection. It then
links real Swift executables for macOS arm64, iOS arm64 and simulator
arm64/x86_64, checking the final platform/minimum version and selected archive
bytes. Generic iOS destinations perform compilation/linking only; they do not
launch a simulator or establish physical-device execution.
The macOS gate uses the default SwiftPM engine and a linker-generated object
map to identify the selected static library, followed by exact-byte comparison
and final executable checks. It does not depend on the former `Copying` and
`Linking` progress messages or select a deprecated engine to reproduce them.

The host XCTest consumer exercises public API calls for owner roundtrips,
purpose derivation, explicit expert transfer, signed revocation, invalid TLS
identity rejection and persistent policy recovery/rollback refusal. A separate
consumer is generated outside the source checkout from the exact complete ZIP;
it repeats the runtime tests, verifies the selected archive and rejects source
paths in its build output. This is local host installation evidence, not the
Swift/macOS-to-Rust/Linux reference-connection acceptance gate.

The local build profile produces an unsigned archive. The [signed 0.2.0 Apple
release](https://github.com/billlza/q-periapt/releases/tag/v0.2.0) and its checksums identify the distributed bytes. See the
[release-readiness ledger](SDK_0_2_RELEASE_READINESS.md) for outstanding gates.

The 2026-09-26 local unsigned run completed the full producer. Its complete SDK
ZIP is 19,628,007 bytes, SHA-256
`0dbe19e850f286308e94dcca559336d611814e2bd67f7e12e15a1e74709c133c`.
All five architecture links and both four-test host consumer runs pass. Xcode's
scheme inventory is retained, and only the known executable/package scheme is
admitted. The [checkpoint](../research/sdk-alpha1/evidence/20260926-apple-sdk-pipeline/manifest.json)
also preserves the earlier failed attempts and the original-accept/fixed-reject
native-payload mutation, rather than treating packaging success as a security
proof. The earlier component-only package remains a separate historical result.
