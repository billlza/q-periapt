# Reproducible Apple binary-package producer checkpoint

The canonical installed-source qualification now builds and consumes one
`QPeriaptContinuity-Apple-candidate.zip` for macOS arm64, iOS arm64 and iOS simulator
arm64. The existing Swift CI job selects `--with-apple-package`; Intel Apple
slices are not built. This checkpoint is based on implementation commit
`330ecc3757bd599cb00d29d0245c8c0004004092`.

The local final producer invocation passed, and its extracted-package consumers
passed Release builds with Swift 6 strict concurrency and warnings as errors.
Consumers have no custom SDK header/library search paths and no Rust toolchain
requirement. Link maps and selected static-library hashes bind all three final
executables to the corresponding packaged slice. The macOS executable and an
installed iOS 27.0 simulator app both execute the public native-owner probe:
cancelled open returns 302, creates no state, and a closed owner returns 2.
The simulator was created for this run and deleted afterward.

## Artifact and repeatability

The package is 21,899,999 bytes, with SHA-256:

```text
61fa752f429c599220a90d0f70b6fcdeeb09dd4634ded08ae14fee146afdc75a
```

Its 686 files include the Swift library, three-slice static XCFramework,
`qpc_owner.h` / module map, root licenses, resolved target-specific third-party
notices, mlkem-native notices, and the pinned Rust standard-library copyright and
license texts. Each native slice has exactly 152 owner exports. Extraction uses
the existing bounded deterministic archive reader, followed by exact member,
header, platform, library and license verification.

Two distinct native builds produced identical native archives but initially
produced different XCFramework `AvailableLibraries` array orders. The producer
now sorts that metadata inventory and serializes its keys canonically, without
changing any native archive. Both prior packages normalize to the same archive;
a fresh complete producer invocation generated exactly that expected SHA-256.
This is same-host/toolchain repeatability evidence, not a cross-toolchain claim.

The ZIP remains under `target/continuity-apple-package-stable/` locally and is an
output of the Swift CI artifact upload. Its bytes are not duplicated into Git.
The public [CHECKS.json](CHECKS.json) pins it. [CAPTURE.zip](CAPTURE.zip) includes
120 hashed members plus its manifest: producer/consumer source, build and symbol
logs, selected link maps, input identities, contents inventory, simulator runtime
logs and verification receipts. Every member hash is reread. Capture SHA-256:

```text
4ac81e8ece1b95374629550b2dd34d77e3ec918fc1ccaec38b16b53f084405fe
```

## Checks and corrected failures

Sixty relevant Python tests passed across the Apple package, Apple SDK profile,
Continuity package/Swift consumers, Swift minimum-toolchain guard and proof-input
inventory. The new rejection cases cover missing/extra/duplicate native exports,
wrong Cargo manifest/profile/target outputs, unsupported/duplicate/missing
slices, altered headers/modules/package members, symlinks and substituted linker
inputs. A path alias is admitted only when it resolves to the exact selected
library and executable; another file with the same bytes is refused.

The first consumer attempt exposed a shared link-map output path between the
app and package target. Each target now has a distinct output path. Xcode's
`/var` spelling of `/private/var` was then handled by exact file-identity checks.
The first simulator attempt was refused by `simctl` before application launch;
the documented `--arch=arm64` form succeeded. Failed attempts remain in their
local diagnostic directories and are not counted as successful qualification.
Workflow lint has the same two `ubuntu-26.04` runner-label diagnostics at the
baseline and current source; no new diagnostic was introduced.

The source readiness check passed on the implementation commit. The actual
commands and producer inputs are retained in the capture. The final local runs
used the repository Python entrypoint for `run.py`, `run_simulator.py` and
`capture.py` under `target/continuity-apple-package-stable/`.

## Scope

The local integration verified 503 current compilable inputs, the current C
manifest with exact installed-package patches, and the normalized dependency
resolution. It did not rerun the complete parent Rust/C process cohort locally;
the CI entry point requires that cohort before invoking this package step.
The newly wired hosted CI run remains a separate gate until it completes.

The simulator runtime result is a cancellation/close/native-link probe, not a
complete enrollment, network or persistence lifecycle trace. This exact new
archive has not yet run on a physical iOS device. Earlier physical iPhone/iPad
lifecycle and Complete-protection records keep their exact package/binary scope.
The `qpc-owner/1` interface and protocol remain candidates, separate from ABI 2.
No release, registry publication or broader 0.2.0 completion is asserted.
