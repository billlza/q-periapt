# QPeriapt Continuity for Apple platforms

Add the extracted `QPeriaptContinuity` directory as a local Swift package, select
the `QPeriaptContinuity` product, and `import QPeriaptContinuity`. It contains the
Swift interface and native XCFramework. Consumers need no Rust toolchain, C
header search paths or library search paths.

This unpublished candidate supports macOS arm64, iOS arm64 and iOS simulator
arm64, with macOS 13 / iOS 16 source deployment floors and Swift 6. It does not
include Intel Apple slices. The `qpc-owner/1` interface remains distinct from the
product SDK ABI 2; packaging does not freeze that candidate protocol or ABI.

Create an app-owned private directory, use its absolute canonical path, and
supply independently authenticated trust, policy and enrollment inputs through
`ContinuityConfiguration`. Reopen the original installation after interruption;
missing, inaccessible or invalid state is not permission to recreate identity.
Cancel and join active work before throwing `close`; Busy preserves ownership.
The host chooses iOS Data Protection and background-execution policy. Closing an
owner does not promise forensic erasure of retained storage or caller memory.

`PACKAGE_CONTENTS.json` identifies every shipped member. `LICENSES/<target>`
contains the resolved third-party notices for each native target; the Rust
standard-library copyright and license texts are also included. Build/runtime
qualification receipts are separate from the installed package.
