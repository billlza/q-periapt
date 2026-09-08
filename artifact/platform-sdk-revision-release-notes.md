# ABI 2 / 0.1.5 SDK revision r3

This source prepares `abi2-platforms-v0.1.5-r3`. It is a separately reviewed SDK
product revision; it does not establish that any new asset has been built or
published. Consumers must select the eventual complete independent receipt and
`abi2-platforms-v0.1.5-r3-verified` record.

The reviewed product commit is
`97907371efdda0b629b738f5261c9db149b03875`, tree
`719de4a213f26b00034c62ba9014d5102e5586f4`. Its JNI and JDK 25 FFM bindings reject
incorrect fixed-format inputs before native copies, preserving operation error
codes and secret-buffer cleanup. Two additive policy-length constants extend
the ABI 2 headers; dynamic symbols, algorithm and wire formats remain unchanged.
The already published crates.io 0.1.5 package is immutable and is not replaced.
Its bytes do not acquire the new source constants retrospectively.

The original verified 0.1.5 cohort and r2 remain separate immutable history.
The r2 profile, schema 1 wrapper, product-source rule, release text, state roots,
journals and existing claims retain their meanings. Never reuse them for r3.

## Product and results lineage

Freeze a clean reviewed tooling source S3 containing the reviewed product
commit in its ancestry. `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo`,
`crates` and the entire `bindings` tree must equal that product commit exactly.
The r3 verifier checks both the pinned product tree and this path equality.
There is no product-drift flag or arbitrary revision selector. A further product
change requires a new reviewed product decision before producing evidence.

Use the existing source producers and schema 5 source-results assembler to
form R3, the direct results-only child of S3. Complete all current source-stage
inputs, including Rust no-upload package evidence, all Swift Apple targets and
the isolated consumer, Android AAR/canonical proof and C archive consumption.
Source-stage package and runtime records identify S3. Old published artifacts
or proofs cannot be relabeled with S3. This source-stage gate does not upload
crates or create a new signed Apple release.

The producer tag `abi2-platforms-v0.1.5-r3` identifies R3. Its exact CI, six-language
CodeQL, both binary-CT jobs and source-security observations remain mandatory.
Keep actual historical analysis counts separate from the empty open-alert gate;
never describe dismissed or historical results as a zero total.

## Candidate products and Android proof

The original tag workflow, selected with `--profile maintenance-r3`, produces
the same four candidate products: Android AAR, Android MANIFEST, Linux x86_64
archive and Linux aarch64 archive. The single candidate provenance statement
still covers those four products plus `CANDIDATE_SHA256SUMS` and
`ABI2_SOURCE_SECURITY_GATE.json`. Both native Linux archive consumers remain
required. Unknown tags and profiles fail closed.

Run a fresh canonical API 35 arm64-v8a / 16 KiB Android acceptance against that
exact R3 AAR. Run both `agp_full_release` and `agp_minimal_release` independently,
with different run IDs and the same R3 source and AAR digests. Preserve the
existing SDK, NDK, signing, raw event, test and cleanup requirements. Neither
source-stage Android proof nor a client application's API 37 acceptance can
replace this exact candidate proof.

`android_maintenance_bundle.py --profile maintenance-r3` packages the completed
canonical schema 2 ZIP and both complete AGP closures in the existing schema 3
envelope with an explicit r3 profile. Its verifier rejects a different profile
before SDK verification. The nested canonical verifier remains a separate
mandatory gate. The full/minimal AGP records cannot substitute for one another.

Assemble the exact seven public assets with
`platform_distribution.py --profile maintenance-r3 assemble`. Use the existing
strict candidate, source, archive, asset and runtime checks without exceptions.

## Independent publication and verification

Create the pending receipt with
`platform_stable_publication.py --profile maintenance-r3 pending`. The r3
schema 2 maintenance wrapper contains the exact original `base_cohort`, the
fixed `reviewed_product` commit/tree, the complete publication and its status.
The nested publication preserves all existing candidate and runtime evidence.

Use `release_receipt_finalizer.py finalize-maintenance --profile maintenance-r3`
with the exact current results digest and `--platform-receipt`. Install its
emitted bytes as the direct results-only child P3, and run `verify-installed`.
Only `platform_v0_1_5_r3` may be added or promoted; all other results and retained
publication entries must be unchanged. Do not mix r2 and r3 current-source
receipts in one provenance record.

The existing publisher takes `--profile maintenance-r3` and a clean installed
P3 `--repository-root`. Its separate account-derived state directory is
`github-platform-v0.1.5-r3`, and it shares the original account lock with stable
and r2. It admits only nine remote actions: create one platform draft, upload
seven assets, publish that release. Apple remains a read-only original
reference and latest remains v0.1.5. The existing explicit HTTP CONNECT proxy
option and constrained credential boundary remain available.

Never reset a claim or journal to recover from a failed observation. Preserve
UNKNOWN, perform the existing read-only status/reconciliation, and continue
only after the exact remote state resolves the original intent. An action that
may have taken effect must not be retransmitted.

After complete publisher verification, perform fresh `collect` with the r3
profile from the exact R3 verifier. Re-download and deeply validate all seven
assets, release attestation, immutable/public/non-prerelease state, canonical
runtime and both AGP closures. Save the new fixed leaf
`platform-v0.1.5-r3-publication-receipt.json`. Independent anonymous observations
are new evidence; never modify historical raw fields or receipt digests.

Finalize the verified receipt into the direct results-only Q3 child of P3,
then run `verify-installed` and `verify-maintenance --profile maintenance-r3`.
Only this fully verified Q3 may receive `abi2-platforms-v0.1.5-r3-verified`.
Use a newly prepared single-ref executor with all actual pins selected; preserve
one-write admission, two fresh remote verifications, the producer tag and
read-only recovery after an unknown push result. Prior r2 executor claims are
not reusable.

Client adoption is a subsequent exact-asset check. Android must rebuild with
the r3 AAR and validate the selected final APK on its host/device. Kotlin uses
the reviewed JDK 25 binding source; this platform release does not assert Maven
publication. Existing Rust registry and signed Apple artifacts remain their
actual published versions. Local tests, emulator success and a login screen do
not establish physical-device, authenticated pairing or cross-host acceptance.
