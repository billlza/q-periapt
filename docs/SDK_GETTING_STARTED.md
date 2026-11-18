# Choose and integrate Q-Periapt

Q-Periapt **0.2.0** was published on 17 November 2026. Get Rust packages
from [crates.io](https://crates.io/crates/q-periapt-sdk/0.2.0), the Swift SDK from the
[Apple release](https://github.com/billlza/q-periapt/releases/tag/v0.2.0), and the other SDKs and Continuity packages from
the [platform release](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0). Verify GitHub downloads against
`SHA256SUMS` on the corresponding release page. The
[verified cohort](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) records the source and package identities.

Some 0.2.0 archives include a README written before publication. To check the
version in the public registry, run `cargo info q-periapt-sdk@0.2.0 --registry crates-io`.
The release links above identify the matching platform downloads.

## Choose your language

| Platform | Download | Installation |
| --- | --- | --- |
| Rust | [q-periapt-sdk](https://crates.io/crates/q-periapt-sdk/0.2.0) · [all twelve crates](SDK_RUST_PACKAGE.md#install-from-cratesio) | In your Cargo project run `cargo add 'q-periapt-sdk@=0.2.0'`. Minimum Rust 1.90. |
| CLI | [q-periapt-cli](https://crates.io/crates/q-periapt-cli/0.2.0) | `cargo install --locked --version 0.2.0 q-periapt-cli`, then `qperiapt --help`. |
| C / C++ | [Apple Silicon](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-c-abi2-0.2.0-aarch64-apple-darwin.tar.gz) · [Linux x86_64](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-c-abi2-0.2.0-x86_64-unknown-linux-gnu.tar.gz) · [Linux arm64](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-c-abi2-0.2.0-aarch64-unknown-linux-gnu.tar.gz) · [Windows x64 MSVC](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-c-abi2-0.2.0-x86_64-pc-windows-msvc.zip) | Extract the archive for your target. Follow the [pkg-config/CMake example](SDK_C_PACKAGE.md) or [Windows instructions](SDK_WINDOWS_PACKAGE.md). |
| Swift | [Complete Swift package](https://github.com/billlza/q-periapt/releases/download/v0.2.0/QPeriapt-Swift-SDK-0.2.0.zip) | Run `unzip QPeriapt-Swift-SDK-0.2.0.zip`. Add the extracted `QPeriapt` folder as a local Swift package and select the `QPeriaptSDK` product. [Swift guide](SDK_SWIFT_PACKAGE.md). |
| Android | [SDK with Maven repository](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-android-sdk-0.2.0.tar.gz) · [AAR](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-android-0.2.0.aar) | Run `tar -xzf q-periapt-android-sdk-0.2.0.tar.gz`. Add the extracted `q-periapt-android-sdk-0.2.0/maven` repository and `implementation("dev.qperiapt:q-periapt-android:0.2.0")`. [Gradle example](../bindings/android/PackageREADME.md). |
| Kotlin/JVM | [GNU/Linux x86_64 JVM bundle](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-jvm-0.2.0-x86_64-unknown-linux-gnu.tar.gz) | Run `tar -xzf q-periapt-jvm-0.2.0-x86_64-unknown-linux-gnu.tar.gz`. Configure its `maven/` and native library on JDK 25 as shown in the [JVM guide](../bindings/kotlin/PackageREADME.md). Use `implementation("dev.qperiapt:q-periapt-hybrid:0.2.0")`. |
| JavaScript / TypeScript | [npm tarball](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-sdk-wasm-0.2.0.tgz) | `npm install https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-sdk-wasm-0.2.0.tgz`. See the [Node and browser examples](../crates/q-periapt-sdk-wasm/PackageREADME.md). |

The SDK exposes 51 functions under native ABI 2. Use matching 0.2.0 wrappers
and libraries. For persistent sessions and multi-device recovery, choose a
[Continuity download and first-use guide](continuity/README.md#start-an-integration).
Its Rust crate is a GitHub source archive and its native interface is `qpc-owner/1`.

## Swift package selection

On Apple Silicon with Xcode 27.2 and Swift 6.4.2, an application can build
and run with either released Apple package on its own. Adding both
`QPeriaptSDK` and `QPeriaptContinuity` to one SwiftPM executable fails in the
default build system. Both XCFrameworks produce `include/module.modulemap` in
the Release products directory. Choose the package for the API your app uses.

## First integration

Provision a trusted ML-DSA-65 policy root and a signed policy through your
application's authenticated configuration. Construct the verified runtime,
persist its trusted state, then generate a key owner. Use its public key in your
authenticated peer protocol and keep the private owner inside the SDK. Derive
an application key with a named purpose; export protocol bytes only when the
application cipher needs them. Close owners explicitly when finished. The
[ownership contract](SDK_OWNERSHIP.md) explains errors and cancellation per
language, and the [host store](SDK_HOST_STORE.md) provides durable policy state
for Rust, C and Swift.

The SDK C persistent-runtime entry points currently support macOS and Linux;
their Windows calls explicitly report an unsupported platform. Separately, the
Rust host-store and native Continuity implementation support private storage on
local NTFS under the [host-store ownership/DACL contract](SDK_HOST_STORE.md).
The retained
[Windows qualification](continuity/PRODUCT_ADMISSION.md#hosted-windows-qualification-2026-11-06)
records that native storage and lifecycle evidence. A Windows application using
the SDK C runtime must still supply durable policy-state storage before relying
on rollback protection across restarts.

The checked-in policies, roots and TLS identities are public test material for
examples. They do not provision an application's trust. Runtime revocation
rejects later owner operations; it cannot erase secret bytes already exported
to application memory. Ordinary calls obtain platform cryptographic randomness
and have no deterministic or classic-only fallback.

For an authenticated connection, choose the
[standard TLS entry](SDK_STANDARD_TLS.md) when the peer implements standard
TLS 1.3/X25519MLKEM768. Choose the [reference SDK connection](SDK_CONNECTION.md)
when both peers implement Q-Periapt's separate application-policy confirmation.
The reference is a bounded request/response connection. Persistent session and
device recovery use the separate [Continuity lifecycle](continuity/README.md#start-an-integration).
The [installed Swift/macOS to Rust/Linux checkpoint](../research/sdk-alpha1/evidence/20261008-installed-macos-linux-connection/README.md)
passes twelve connection cases with separate persistent stores. Its Linux peer
runs natively in a local VM on the same physical Mac; independent physical hosts
and an independent implementation of the application protocol remain unqualified.

The [release evidence](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) identifies the exact packages, installed
consumer checks and qualification scope. Development checkpoints in the
[readiness ledger](SDK_0_2_RELEASE_READINESS.md) retain their original dates.
