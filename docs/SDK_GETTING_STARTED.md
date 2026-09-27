# Choose and integrate Q-Periapt

Use **0.2.0-alpha.1** to evaluate the owned-key SDK in this source tree. It is
unpublished; obtain a locally built candidate from the matching package guide
below. Do not request this version from a public registry yet.

Use the published **0.1.5** distributions when you need the existing released
API. Android and GNU/Linux use
[platform revision r4](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.5-r4),
published on 2026-09-08 from `7ed1f96a7ec33732f02a989dd5a4669cdcce39ad`.
Its [verification record](https://github.com/billlza/q-periapt/blob/abi2-platforms-v0.1.5-r4-verified/artifact/results.json)
is separate from the original cohort. The Apple `v0.1.5` distribution and
crates.io `0.1.5` packages remain the existing releases; r4 does not replace them.

| Version field | Meaning |
| --- | --- |
| Library/package `0.2.0-alpha.1` | Current development SDK with runtime, key and secret owners. |
| Native ABI **2** | Calling conventions, original nine declarations, existing status values and library identities remain compatible. |
| SDK export profile | Alpha packages contain exactly 43 C exports. The released 0.1.5 profile contains nine. New wrappers require the alpha SDK exports. |
| Platform revision `r4` | Packaging/runtime maintenance for library 0.1.5; it is neither ABI 4 nor library 0.2.0. |

## Choose your language

These are local alpha candidates. The verification column describes execution
already observed, rather than treating a declared deployment target as tested.

| Application | Installation and first example | Current validation |
| --- | --- | --- |
| Rust | [Rust package guide](SDK_RUST_PACKAGE.md); [public API consumer](../bindings/rust/SDKPackageConsumer/src/lib.rs). Use source path dependencies for development, or the exact supplied `.crate` cohort with the guide's external-consumer setup. | macOS ARM64 public APIs run on Rust 1.85.0 and 1.96.1. Full repository development uses 1.96.1. Other minimum-toolchain targets remain open. |
| C | Extract the [C SDK archive](SDK_C_PACKAGE.md), then link `qperiapt-abi2` through pkg-config or `QPeriaptABI2` through CMake. Windows uses its [separate SDK profile](SDK_WINDOWS_PACKAGE.md). Start from the shipped `sdk_smoke.c`. | Installed shared/static macOS ARM64 consumers run. GNU/Linux and native Windows alpha execution remain open. |
| Swift | Extract `QPeriapt-Swift-SDK-0.2.0-alpha.1.zip`, add its `QPeriapt` folder as a local Swift package, and select `QPeriaptSDK`. See the [Swift guide](SDK_SWIFT_PACKAGE.md). | Installed macOS ARM64 calls and TCP connection run. macOS 13/iOS 16 are build floors; minimum-OS and physical-device execution remain open. |
| Kotlin/JVM | Add the supplied local Maven repository and `dev.qperiapt:q-periapt-hybrid:0.2.0-alpha.1`; supply its matching ABI 2 native library. See [JVM installation](../bindings/kotlin/PackageREADME.md). | JDK 25 installed Maven consumer runs on macOS ARM64. Other native platforms remain open. |
| Android | Use the supplied AAR or local Maven coordinate `dev.qperiapt:q-periapt-android:0.2.0-alpha.1`. See [Android installation](../bindings/android/PackageREADME.md). | Four native ABIs packaged; full/minimal R8 application builds pass. API 23 is declared, but current alpha ART/device execution is pending. |
| JavaScript/TypeScript | `npm install ./q-periapt-sdk-wasm-0.2.0-alpha.1.tgz`; use the [Node/browser quickstart](../crates/q-periapt-sdk-wasm/PackageREADME.md). | Node 24.0.0/26.3.0 and Chrome 153/Firefox 156 have installed-package execution on macOS ARM64, including browser windows and dedicated module Workers. [Browser evidence and limits](SDK_BROWSER_RUNTIME.md) include Firefox host diagnostics and Safari's disabled automation setting. Other hosts, mobile/minimum browsers, bundlers and other Worker types remain open. |

The older `QPeriaptHybrid` compatibility API and deterministic WASM test surface
remain available. Start new owned-key integrations with the product entries
above. Do not combine an alpha wrapper with a nine-export 0.1.5 native library
merely because both say ABI 2.

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

The supplied persistent-store adapter currently supports macOS and Linux.
Windows store calls explicitly report an unsupported platform; a Windows host
must provide its own durable policy-state storage before relying on rollback
protection across restarts.

The checked-in policies, roots and TLS identities are public test material for
examples. They do not provision an application's trust. Runtime revocation
rejects later owner operations; it cannot erase secret bytes already exported
to application memory. Ordinary calls obtain platform cryptographic randomness
and have no deterministic or classic-only fallback.

For an authenticated connection, choose the
[standard TLS entry](SDK_STANDARD_TLS.md) when the peer implements standard
TLS 1.3/X25519MLKEM768. Choose the [reference SDK connection](SDK_CONNECTION.md)
when both peers implement Q-Periapt's separate application-policy confirmation.
The reference is a bounded request/response connection; it does not provide the
future Continuity recovery protocol. The required installed Swift/macOS to
Rust/Linux reference execution remains open.

The [readiness ledger](SDK_0_2_RELEASE_READINESS.md) records the remaining release
work. Package creation and the local checks above do not establish independent
security review, a complete platform matrix or formal 0.2.0 release readiness.
