# Retained iOS simulator architecture matrix

The Continuity Apple packager now preserves the existing iOS simulator support
promised by [the 0.2.0 release scope](../../../../docs/continuity/RELEASE_0_2_SCOPE.md):
four Rust targets produce three XCFramework slices, with arm64 and x86_64 in
the simulator slice. macOS remains Apple Silicon only. This closes a concrete
packaging omission in the preceding three-arm64-target candidate; it does not
add Intel macOS support or another device-runtime requirement.

The retained old helper on `19ef66febb4687b34657b02082dd50ff95ee7ed6` omitted
`x86_64-apple-ios` and rejected that target's exact Cargo artifact. Two contract
regressions produced one failure and one error. The corrected helper passes
both, all ten Apple package/linkage tests and fifty related package/profile
checks. Missing, duplicated, wrong-platform and wrong-architecture inventories,
substituted native bytes and wrong linker paths continue to reject.

Actual qualification ran on source
`e5ceec379c502333dcaea8d0ad4790556f40cc5e` for 562.681 seconds. Its parent
limit was 9,000 seconds; the existing 900-second and 16-MiB-per-stream component
limits and warning checks remained unchanged. All 35 command receipts passed.

| Rust target | Actual boundary |
| --- | --- |
| `aarch64-apple-darwin` | Native static library, extracted Swift package consumer, exact linked archive and installed owner probe |
| `aarch64-apple-ios` | Native static library and iOS arm64 consumer build/link |
| `aarch64-apple-ios-sim` | Native static library, fat-slice byte readback and arm64 simulator consumer build/link |
| `x86_64-apple-ios` | Native static library, fat-slice byte readback and x86_64 simulator consumer build/link |

Each thin library has the exact candidate owner export set. After `lipo`
combination, extracting each simulator architecture reproduces its original
thin-library SHA-256. Xcode consumers for both architectures select the same
verified fat archive, SHA-256
`461dc420ead5c0badd2b273990c784ff7f88bf8053f2d15626860015916bfb3e`;
their link maps and final executable architectures are checked separately.
The iOS results are build/link evidence, not simulator or physical-device
execution. The macOS probe executes the actual installed binary interface.

The four-target Apple archive has 30,419,262 bytes and SHA-256
`99bc45143c5039b2190b293a1d2982199ce0d797af97b51f4fa2be2e1dc0dc05`.
All 905 shipped files were reread against `PACKAGE_CONTENTS.json`; each target
has its resolved license closure. The same admitted C source and maintenance
SDK archives were copied into a separate outside-checkout directory. Producer
`f560d803c43a24fff222daa5e5e5bd623bfdf874` retains report SHA-256
`93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8`.
The only selected input differences from the completed foundation are the two
Apple helpers, Apple package README and CI workflow. No Rust protocol or Swift
owner implementation changed; the preceding
[full Swift lifecycle result](../20261105-continuity-swift-maintenance/README.md)
keeps its own original source/package identity.

Rust 1.98.1 was copied to a task-private toolchain. The missing x86_64 iOS
standard library was checked against that compiler's existing official channel
manifest and archive SHA-256
`e31f61ee797e63e9ab2a381a8efbe8a3fb37987f04e4f92eae2930a2dc6f68cf`.
No global toolchain installation was performed. Original toolchain files,
foundation C source and selected qualification inputs remained unchanged.

`CAPTURE.zip` preserves 168 members, including the exact Apple package,
all command streams/receipts, before/after contract tests, original/corrected
helper sources and preparation identities. Its 30,712,030 bytes have SHA-256
`41ef62cbdc4d6372f115dee69253aafa176072d159e602d43c8713b79c212039`.
Every capture member was reread byte-for-byte. `READBACK.json` records the
consumer identities and scope; `FILES.json` binds every retained member.

This closes the local retained-architecture packaging gap for this source.
It does not close hosted CI, iOS runtime, Kotlin/Android, other platform/device
qualification, formal product ABI admission, external review or release. No
remote branch or workflow was changed.
