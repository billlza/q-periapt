# 0.2.0 admission preparation — 16 November 2026

The current candidate identity inventory verifies **21 package rows across all
eight agreed release roles**, the **51 SDK ABI 2 exports** and the separate
**158 Continuity `qpc-owner/1` exports**. The capture independently checks
**62 selected source files against their exact Git blobs**. It uses the current
`q-periapt-continuity` `0.2.0` identity and a schema-2 specification inventory.

This checkpoint prepares the package graph while the selected hosted CI cohort
continues. The manifest selects **zero built artifacts and zero assessment
receipts**. Its budgets and C interface remain unfrozen, and no separately
emitted compiled descriptor is selected. Successful identity verification does
not record product admission or publication.

## Independently selected identities

| Input | Identity |
| --- | --- |
| Source commit | `8abbf8d2e73a27af7794528fd92d13fe3be2942d` |
| Source tree | `733e2e6e17be2241d85264ea5e15e07a35f04527` |
| Manifest SHA-256 | `4f4b8c034adbb32abbc25856c762f759671be3d4de532e918783c271fb8268f7` |
| Specification inventory SHA-256 | `90268033a927806d313198045ebc499de503633656106130fa0dcaf16e87ec73` |
| Lock schema | `2` |
| Stage | `candidate` |
| Product version / SDK ABI | `0.2.0` / `2` |

`CAPTURE.json` retains the actual capture time, interpreter, capture-script
digest, original verifier inputs, each selected source blob and its SHA-256.
The inventory was executed against an isolated snapshot of the selected source
while release-preparation edits continued in a separate working tree. The
source comparison concerns the enumerated inputs; it makes no whole-checkout
cleanliness claim.

## Package graph and actual definitions

The inventory contains the twelve SDK Cargo publishers, the formal Continuity
source package, the browser Cargo bridge and npm `/web` surface, and the
reference-service Cargo implementation. Five prepared distribution identity
documents complete the native, Swift, Kotlin, Android and service roles:

| Role | Selected package identity | Source of the prepared identity |
| --- | --- | --- |
| Native companion | `q-periapt-continuity-native` `0.2.0` | Current native producer constants and engine dependency |
| Swift | `QPeriaptContinuity` `0.2.0` | Current four-target Apple producer |
| Kotlin/JVM | `q-periapt-continuity-kotlin` `0.2.0`, group `dev.qperiapt` | Current Gradle project name/version and installed consumer |
| Android | `q-periapt-continuity-android` `0.2.0`, group `dev.qperiapt` | Current AAR distribution producer and native-companion dependency |
| Services | `q-periapt-continuity-services` `0.2.0` | Current service producer and engine dependency |

The five files under `distributions/` are **prepared candidate identity
projections**. They are not successful producer output, signed packages or
qualification reports. Their artifact lists are empty, as are every package
row's artifact and assessment lists. `CAPTURE.json` pins the actual producer or
Gradle definitions used for each projection and explicitly records that the
capture invoked no producer.

The Swift and Kotlin rows depend directly on the engine and retain their
`continuity_c` interface binding: their producers build or consume their own
qualified C owner, without consuming the Linux native distribution archive.
Android retains its producer's explicit native-companion dependency.

The `reference-service` Cargo row truthfully retains its implemented `0.0.0`
research identity. Formal release assembly selects the separate `0.2.0`
service distribution row and omits that additional source-only Cargo row from
the released package graph; it does not rename the reference application's
Cargo crate. The existing service distribution contract already adopts this
separation.

`SPEC_LOCK.json` includes seven primary normative roles and 24 supporting
contracts. The supporting set adds the adopted workload budget, compatibility
policy and selected distribution contracts to the earlier candidate inventory.
Its schema-2 package-graph commitment separates stable distribution identities
from per-build artifact pins. Both freeze flags remain false.

## Hosted Rust readback

The accompanying `RUST_PACKAGE_READBACK.json` records the independent reopening
of the selected hosted Rust artifact. The original producer records are retained
as `HOSTED_RUST_SDK_PACKAGE.json`, `HOSTED_RUST_DRY_RUN.json` and
`HOSTED_RUST_MSRV.json`.

Those records concern the same selected source and its twelve actual SDK
archives. Their original scope and archive identities are retained separately
from the artifact-empty candidate inventory above. A future assembled manifest
must bind the selected archive bytes and original completed reports explicitly;
the current inventory does not infer those selections from this README.

The independent readback checks every archive's size, SHA-256, complete member
list, Cargo identity and VCS commit. All 20 separately pinned package-source
files match the selected Git blobs, and the canonical digest over 389 Rust
workspace files matches the producer record. The linked hosted dry-run reports
`local_inputs_verified` with twelve planned crates and no upload attempts.

## Review and validation preparation

`CODEQL_READBACK.json` pins the current Python analysis archive and inspected
source files. `CODEQL_SINK_REVIEW.md` disposes of all 24 related origins at the
shared command sink and two synthetic test-fixture findings. Other raw analysis
results retain their individual review scope. The
[internal admission assessment](../../../../docs/continuity/RELEASE_0_2_INTERNAL_ASSESSMENT.md)
records the separate bootstrap, retained-state, workload and compatibility
source correspondence.

The prepared wire-contract and C ABI readers now support an explicit `release`
validation stage, while their default candidate checks remain strict. This
prepares the actual freeze procedure without changing the product's current
descriptor or declaration flags. `VALIDATION.json` records the executed
regressions and the local toolchain limitation separately from the hosted
native-package results.

## Verification and reproduction

`VERIFICATION.json` is the successful output of the existing manifest verifier:
57 checked files, 21 package rows, all eight roles present, zero selected
artifacts, no assessment records and no compiled-descriptor match.

With the selected source bytes and these inventory documents under one root:

```sh
sh artifact/python-run.sh artifact/continuity_release_manifest.py \
  --root "$PWD" \
  --manifest research/sdk-alpha1/evidence/20261116-release020-admission/MANIFEST.json \
  --manifest-sha256 4f4b8c034adbb32abbc25856c762f759671be3d4de532e918783c271fb8268f7 \
  --source-commit 8abbf8d2e73a27af7794528fd92d13fe3be2942d \
  --source-tree 733e2e6e17be2241d85264ea5e15e07a35f04527 \
  --stage candidate
```

The retained `capture.py` regenerates the inventory from the selected source.
It requires independently supplied commit/tree selectors, verifies every
enumerated source input against the corresponding Git blob before and after
verification, and creates output files with exclusive creation. To retain a
second capture, select a fresh repository-relative output directory; changing
that directory changes the path-bound inventory digests. For a source snapshot
without Git metadata, `--source-repository` names the separate repository that
supplies the selected Git objects. The script never derives expected source
identities from its generated manifest.

## Remaining admission work

Bind the actual selected native, Apple, Kotlin, Android, browser and service
archives and their applicable completed qualification records; retain internal
review findings and rechecks for the selected source; and apply the coordinated
contract/compiled-descriptor/interface freeze with the final normative lock.
The original journaled publication tools then retain the actual publication
and readback receipts. These dependencies remain governed by the current
requirements in `docs/SDK_0_2_RELEASE_READINESS.md` and the admission plan.
