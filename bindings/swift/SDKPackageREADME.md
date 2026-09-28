# QPeriapt Swift SDK 0.2.0

This package provides `QPeriaptSDK` (owned runtime, keys and standard hybrid TLS
connections) and the retained byte-oriented `QPeriaptHybrid` compatibility API.
The native ABI remains **2**. It contains static XCFramework slices for macOS
13+ (arm64/x86_64) and iOS 16+ (arm64 device, arm64/x86_64 simulator).

Add this unpacked folder as a local Swift package dependency and select the
`QPeriaptSDK` product. It includes the binary target and Swift wrappers; it does
not require Rust, development linker flags or a checkout of the source project.
Your final app has its own signing and provisioning requirements.

Use a trust root and signed policy from your application's trusted provisioning
channel. No sample root or private key is installed by this package. On macOS,
`QPeriaptPersistentRuntime.provision` explicitly creates a new policy store;
`open` requires an existing store and reconciles the configured signed policy
against its stored rollback floor. Supply an absolute path through real
directories, with an existing owner-only 0700 parent directory.

```swift
import QPeriaptSDK

let store = try await QPeriaptPersistentRuntime.open(
    at: policyStorePath, policy: signedPolicy, signature: policySignature,
    trustRoot: pinnedPolicyRoot)
let key = try store.runtime.generateKey()
let publicKey = try key.publicKey()
// Send the public key through your authenticated application protocol.
try key.close()
try await store.close()
```

Close owners on both success and error paths. A cancelled persistent operation
may have committed: reopen with the latest requested signed policy instead of
assuming rollback. A policy update returns a new owner and revokes the old epoch.
The macOS persistent-store API explicitly reports unsupported on iOS. An iOS
host constructs `QPeriaptRuntime` with its pinned root and protected stored state,
then durably accepts `trustedState()` before admitting key use; it also owns
root-scoped compare/persist coordination for policy updates.

Private key bytes stay owned by the SDK unless the caller deliberately uses
`QPeriaptExpert`. Derived/combined secret export is explicit; returned Swift
arrays and any copies must be erased by the caller. Handles protect ownership
and ordinary API use, and do not isolate malicious code in the same process.

`QPeriaptClient` requires an explicit local certificate/key, pinned peer leaf
certificate and application context. Its standard TLS 1.3 path uses
X25519MLKEM768 with mutual certificate authentication, followed by application
policy/context confirmation. It has no classic fallback or automatic request
replay. TLS certificate authentication need not use PQ signatures. This SDK
does not provide a ratchet, multi-device session service or exactly-once RPC.

This is a 0.2.0 release candidate. Consult the accompanying package manifest for the
actual source, platform checks and signing state. Packaging/link success is not
physical-device validation or release approval.

`PACKAGE_CONTENTS.json` binds the contents of this folder. The separate
`MANIFEST.json` alongside the downloadable ZIP records the checks actually run.
The package includes the native algorithm CBOM, workspace SBOM, target-specific
Cargo dependency notices and the Rust 1.96.1 standard-library copyright notice.
These inventories describe the packaged algorithms, dependencies and license notices.
