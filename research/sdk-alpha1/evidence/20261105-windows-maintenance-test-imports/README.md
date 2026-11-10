# Windows publication-test compilation repair

[Windows job 127182901069](https://github.com/billlza/q-periapt/actions/runs/42008993679/job/127182901069)
failed on `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20` while compiling
`q-periapt-host-store` tests. Six compiler errors precede test execution.
The maintenance refactor in `f560d803` removed `OwnedPrivateDirectory` and
`OsStr` from the parent module's imports and replaced the old same-parent
`rename_directory` helper with `rename_directory_to`. The Windows tests still
depended on those parent imports and the old helper name.

The repair explicitly imports the two types in `windows_tests.rs` and calls
`rename_directory_to` with the same original parent as both source and
destination parent. This keeps the existing wrapper's original-directory
identity checks and late native deletion-handle acquisition. No production code,
test assertions, admission checks, timeout or test selection was weakened.

| Actual local check | Result | Elapsed |
| --- | --- | ---: |
| Unmodified `cargo check --tests --target x86_64-pc-windows-gnu` | Exit 101; same six errors | 8.827s |
| Repaired command, same target and flags | Exit 0 | 0.557s |
| `cargo clippy --tests --target x86_64-pc-windows-gnu -- -D warnings` | Exit 0, no warnings | 1.833s |
| `cargo fmt -p q-periapt-host-store -- --check` | Exit 0 | 0.174s |

All Cargo checks use locked offline dependencies, Rust 1.98.1, two build jobs,
the existing private Windows GNU standard library and LLVM-MinGW C toolchain.
Target warnings are denied. Each command retains a 900-second bound and
16-MiB stream limits. Two emitted dependency records include the actual Windows
test module. Source identities are unchanged during each command, and the global
Rust toolchain manifest is unchanged. The earlier
[maintenance evidence](../20261104-managed-publication-maintenance/README.md)
only checked the Windows library; it did not cover this test module.

This establishes local red/green **Windows-target type checking**. It does not
establish MSVC compilation, linking, Windows execution or NTFS behavior after the
repair. Those remain pending a subsequent hosted wave. No new test was written
to mirror the import fix; the unchanged previously failing test module provides
the regression.

## Consequence for the next producer

The same wave's [SDK producer 127182900240](https://github.com/billlza/q-periapt/actions/runs/42008993679/job/127182900240)
completed and uploaded artifact **13406782037**: 5,959,069 bytes, SHA-256
`a8e626e0fb27d849727e25b725d9d171ff8a4da2bdf069df20fe6a29cc76f845`.
Its 115 ZIP members were checked, and all **12** crate archives match their
recorded sizes, digests, member inventories and clean `ff072bd6` VCS identities.
The archived four-test SDK consumer stdout passes the existing exact-name
verifier. This consumer uses archive-derived path patches outside the checkout;
it is not a public-registry installation. The full original artifact is retained
inside this capsule.

The actual `RUST_SDK_PACKAGE.json` digest is
`b79a596f3f011bc547bbbf21a88763ef887b6a506cfcf8dfad3b5c9bd28bca56`.
Its workspace digest is
`ef0a49c67ca697b8bb8c6c9df309e668cc5367e62692fe66d8c37c60fab52137`.
The host-store crate **contains the old Windows test file**. Although the repair
is test-only, that file participates in the package source identity. The fixed
workspace digest is
`c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
The existing report validator accepts the downloaded report against the clean
`ff072bd6` source and rejects it against the repaired workspace with the exact
source-identity error. This is an observed contract rejection, not an inferred
compatibility failure or a failed SDK producer.

The first local artifact reader mistook the report's integer `consumer.tests`
for a list. Its original reader and a labeled tool-return failure observation
are retained. The corrected reader uses the actual schema and verifies the
original named-test stdout; no producer or native test was rerun for that reader
correction.

Keep the current CI wave running. A clean SDK producer for the repaired workspace
must complete and be verified before its report is used for the later focused
Android lane. The old Android SDK pin remains unchanged. The concurrent local
Android host JNI qualifier still runs on immutable `ff072bd6`; its eventual
readback must record this exact test-only source delta and keep its qualification
scoped to that original cohort.

`CAPTURE.zip` preserves the complete hosted Windows failure, local red/green,
Clippy/format commands and logs, source before/after, exact patch, tool provenance,
dependency records, both SDK producer logs, downloaded SDK artifact and source
identity rejection. All 51 members were reread: **6,249,852 bytes**, SHA-256
`dfee7f74a1dacfccc695451921cd70e4cf154a1c525d8d0931829a248e700c1f`.
`FILES.json` and `READBACK.json` bind the contents and remaining platform limits.
