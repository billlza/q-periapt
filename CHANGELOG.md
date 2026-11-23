# Changelog

This log describes public release changes and current documentation corrections.
The [evidence index](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
connects each release to its source, packages, proofs and measurements.

## Unreleased

### Documentation

- Add a public evidence index with absolute links to the verified 0.2.0 release,
  versioned API documentation, formal arguments, measured datasets and installed
  consumer records.
- Clarify the difference between completed source/platform qualification,
  retained-byte readback and later public package verification.
- Give all twelve publishable crates explicit docs.rs metadata and package-local
  READMEs, with a packaging regression guard that rejects relative documentation
  links to files absent from the crate archive.
- Record that frozen 0.2.0 crate READMEs contain some pre-publication status text
  and repository-relative links. Maintained guides supplement those package
  READMEs; already published archives and historical receipts remain unchanged.

## Apple Continuity 0.2.0 r1 — 2026-11-18

[Release and downloads](https://github.com/billlza/q-periapt/releases/tag/continuity-apple-v0.2.0-r1)
· [packaging record](https://github.com/billlza/q-periapt/releases/download/continuity-apple-v0.2.0-r1/APPLE_PACKAGING_REVISION.json)
· [consumer verification](https://github.com/billlza/q-periapt/releases/download/continuity-apple-v0.2.0-r1/SWIFTPM_VERIFICATION.json)

- Correct the Apple Continuity package's C module-map placement and private
  implementation symbols so that an application can link the Swift SDK and
  Continuity together. Continuity-only applications remain supported.
- Retain the public Swift module/product names and the 158-function
  `qpc-owner/1` C interface. This is an Apple packaging revision of 0.2.0.
- Record SDK-only, Continuity-only and combined macOS arm64 applications running
  in Debug and Release with Xcode 27.2. The combined application also ran on an
  arm64 iOS 27.1 simulator and linked for iOS device arm64 and simulator
  arm64/x86_64. The attached record identifies those exact checks.

For an existing original Continuity installation, extract r1 into a fresh folder
so the former root module map is removed. The maintained
[Swift integration guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_GETTING_STARTED.md#swift-package-selection)
shows the two matching packages and product selections.

## 0.2.0 — 2026-11-17

[Apple SDK release](https://github.com/billlza/q-periapt/releases/tag/v0.2.0)
· [SDK and Continuity platform release](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0)
· [verified cohort](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/VERIFIED_COHORT.json)

- Publish all twelve coordinated `0.2.0` Rust SDK crates to crates.io. The
  [registry receipt](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/registry/crates-io-v0.2.0-publication-receipt.json)
  records their exact non-yanked versions; the maintained
  [Rust guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_RUST_PACKAGE.md#install-from-cratesio)
  lists every package and installation command.
- Release the owned-key SDK, durable host policy store, native ABI 2 bindings,
  complete Swift SDK and coordinated native, Android, JVM and WASM distributions.
- Release the separate Continuity packages for persistent sessions, fresh-PQ
  rekeying, recovery and device lifecycle under their admitted protocol/storage
  profiles. Its `qpc-owner/1` interface remains separate from SDK ABI 2, and its
  Rust archive is distributed through GitHub outside the twelve-crate registry
  cohort.
- Freeze 21 package identities against source
  [`af4618c8065d7133adfb86e1d116577089161ff0`](https://github.com/billlza/q-periapt/tree/af4618c8065d7133adfb86e1d116577089161ff0).
  The [admission](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/ADMISSION.json)
  links the selected CI, CodeQL, internal review, signing, platform and
  installed-consumer qualifications. The
  [72-job CI qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/ci.json)
  records successful run 44036376133 and the PR-head/producer-source mapping.
- Verify both original GitHub releases and all 67 admitted public assets, plus
  twelve anonymous registry archive downloads. The
  [publication record](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/README.md)
  preserves those observations and the original scope of runtime qualifications.

The research manuscripts, formal models and dated measurements are indexed
separately in the [evidence index](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md).
Their source and proof assumptions remain those of the cited artifacts.

## Earlier releases

The [GitHub release history](https://github.com/billlza/q-periapt/releases)
retains the earlier distributions. The
[0.1.5 verified cohort](https://github.com/billlza/q-periapt/tree/v0.1.5-verified-cohort)
and [0.1.5 Android/Linux r4 record](https://github.com/billlza/q-periapt/tree/abi2-platforms-v0.1.5-r4-verified)
identify their original packages and receipts.
