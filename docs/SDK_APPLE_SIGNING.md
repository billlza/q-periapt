# SDK 0.2.0 Apple origin signing

The existing Apple release entry point accepts an explicit `sdk-020` profile.
It builds the SDK's Apple Silicon macOS, iOS device and two iOS simulator
targets from one clean source commit, signs the static XCFramework, and
rebuilds the complete Swift package around those exact signed bytes.
The no-argument entry point retains the separate 0.1.5 contract.

```sh
QPERIAPT_APPLE_RELEASE_CONFIRM=v0.2.0 \
QPERIAPT_APPLE_RELEASE_SOURCE_COMMIT=<selected-clean-commit> \
sh artifact/swift-xcframework-release.sh --profile sdk-020
```

Use a standalone checkout with its own `.git` directory. The wrapper creates
an isolated detached build checkout and rechecks its source identity before
completion. It rejects dirty builds, compiler overrides, missing target
components, source changes and existing state for the same source commit.
The selected compiler is Rust/Cargo 1.98.1, with Xcode 27.2 build 27B52 and
Apple Swift 6.4.2. The wrapper pins Developer ID team `YKUPL7Z869`, identity
SHA-1 `4C727F97A10E1721685E13D339D04047265EECCF` and certificate SHA-256
`6c8412fd1c9faeb286eefe4518d20d500ed911cfe5695020f125b73b89a509b3`.
An unavailable or different identity fails; there is no ad-hoc signing path.

Signature evidence uses schema 2 with `profile: sdk-020`; static distribution
evidence uses schema 4. Both require the SDK's exact slice inventory. The
distribution binds the signed ZIP, every static library and `CodeResources`.
Historical signature and publication readers do not admit these new schemas.
The signed Swift contents manifest uses schema 2 and
`signature_required: true`; unsigned schema-1 contents cannot substitute for it.

The build runs strict signature verification before and after ZIP extraction.
It also installs the complete Swift package outside the checkout, verifies the
signature before and after its six public API tests, and compares SwiftPM's
selected static archive with the installed macOS slice. The existing iOS
linkage, native export, license, BOM and build-path checks still run.

Successful output is retained below
`target/qperiapt-swift-sdk-020-release/<source-commit>/`, with five distribution
files, consumer/signing evidence and a separate completion record under
`target/qperiapt-apple-sdk-020-release-worktrees/<source-commit>/completed.json`.
An incomplete attempt retains its source and diagnostics instead of deleting
the failure record. Existing output is never replaced by the SDK profile.

This operation signs the SDK's distribution origin. It does not create a tag,
upload a release, publish Cargo packages, sign the separate Continuity companion,
or complete product admission. The new evidence retains
`release_claim_eligible: false` and `publication_performed: false`. Static SDK
payloads do not receive an application notarization claim; final applications
retain their signing, provisioning and notarization responsibilities.
