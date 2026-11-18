# QPeriapt Continuity for Apple platforms

[Download the 0.2.0 Apple Continuity package.](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/QPeriaptContinuity-Apple-0.2.0.zip)

```sh
curl -fLO https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/QPeriaptContinuity-Apple-0.2.0.zip
unzip QPeriaptContinuity-Apple-0.2.0.zip
```

Add the extracted `QPeriaptContinuity` directory as a local Swift package, select
the `QPeriaptContinuity` product, and `import QPeriaptContinuity`. It contains the
Swift interface and native XCFramework. Consumers need no Rust toolchain, C
header search paths or library search paths.

The package includes slices for macOS arm64, iOS arm64 and iOS simulator
arm64 and x86_64, with macOS 13 / iOS 16 source deployment floors and Swift 6.
The simulator architectures share one XCFramework slice; macOS supports Apple
Silicon only. The `qpc-owner/1` interface remains distinct from the
product SDK ABI 2. The [release record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) identifies the 0.2.0 interface and source.

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
