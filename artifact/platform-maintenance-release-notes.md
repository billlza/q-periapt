# Q-Periapt 0.1.5 platform packaging revision r2 — candidate

This source change prepares `abi2-platforms-v0.1.5-r2`. It does not establish a
published release or passing native, AGP or device evidence. Product SemVer stays
`0.1.5` and the public ABI stays 2. The Android manifest package and exact JNI
consumer rules are corrected by the existing AAR producer. Both GNU/Linux
archives are rebuilt with that AAR from the same new source; old Linux archives
must never be relabeled with the new source identity.

The frozen predecessor is Q `cc21bc1cadac5148aadfd98f1c6b0e4acbbb0c06` at
`v0.1.5-verified-cohort`, whose exact results SHA-256 is
`90f5faed852311a59f388eaf79072c4887aa9cb3e68a78ac4a2e0ea0acf6844f`.
The new independent verified record is `abi2-platforms-v0.1.5-r2-verified`.
Neither that name nor this maintenance receipt represents a replacement
Apple/platform/crates.io cohort. All original receipts, registry archives,
GitHub assets and annotated tags remain unchanged.

## Source and candidate

Freeze a reviewed clean source S2. Its product Cargo manifests, lock, toolchain,
`.cargo` inputs, crates, Android JNI and Java code must equal the original product
source S. The local source verifier checks this boundary explicitly; changes to
those inputs require a separately reviewed product release, not an r2 exception.
The policy service is not a published crate and is outside the platform package.

Use the existing source producers, source-results assembler and installed-result
verification to create the direct results-only successor R2. Preserve the current
Rust no-upload evidence required by that source gate; do not use its newly
packaged local archives as uploads for the already published 0.1.5 crate versions.
The source gate and exact-R2 CI, CodeQL, binary-CT and candidate provenance remain
mandatory. The existing candidate workflow explicitly accepts the r2 annotated
tag with `--profile maintenance-r2` and the same exact four candidate products.
The candidate completion receipt has an explicit schema 2 and r2 identity; the
r1 completion receipt remains schema 1 with its original fields. A shared bounded
candidate cache may retain both, but must validate every declared schema before
selecting the requested profile. Unknown or damaged historical entries fail.

Keep the two source identities and evidence sets separate. The source-results
assembler consumes the local Rust no-upload handoff, AAR, canonical Android proof,
schema-5 local index with its exact Android summary, and one C archive consumer
from S2. That index requires every package face, including Swift, to identify S2.
Run the ordinary credential-free `sh artifact/swift-xcframework.sh` producer at
S2 with all five Apple targets and its isolated consumer before assembling the
index; the old R/Q Swift outputs cannot supply this source-stage input. A new
signed Apple release is not required for platform maintenance publication.
R2 is the direct results-only successor and has a different Git commit. The tag
workflow then builds the public candidate AAR/manifest and both Linux archives at R2.
Collect a new canonical Android proof and both AGP profiles against that exact
R2 candidate AAR. Public runtime proofs identify R2, not S2; source-stage runtime
proofs or Linux builds cannot be promoted into the public distribution.

Run each collector from its own declared source checkout. The formal CLI rejects
another `--root` before accessing its evidence or tools. SDK/tool path arguments
select only existing registered Android SDK roots and the installed NDK r29 under
that same SDK; they do not authorize a separate executable. This read-only SDK
selection does not inspect ADB or acquire device state. The AGP collector uses
the account database's home directory plus `.gradle`; a different
`GRADLE_USER_HOME` is explicitly unsupported by this internal collector.
`JAVA_HOME` must be the canonical JVM home reported by Gradle. A mismatch retains
the raw version output and rejects the build before `assemble`.
The explicit AGP proof paths must identify an existing immutable run layout in
that checkout. Their fixed filename and canonical run ID are admitted before any
JSON read; an external path or traversal does not enter the evidence reader.

Before creating the new tag, independently verify that it is absent and that the
active no-bypass update/deletion rules preserve every old stable tag plus:

- `abi2-platforms-v0.1.5-r2`
- `v0.1.5-verified-cohort`
- `abi2-platforms-v0.1.5-r2-verified`

Candidate verification uses the existing wrapper with an explicit profile:

```sh
sh artifact/verify-platform-candidate.sh --profile maintenance-r2 \
  "$candidate_directory" "$tag_commit" "$candidate_projection"
```

## Public runtime evidence

The outside distribution still has exactly seven assets. The Android evidence ZIP
uses the explicit r2 envelope schema 3: it contains the unchanged complete schema-2
canonical runtime ZIP and closed `agp_full_release` and `agp_minimal_release`
evidence directories. The r1 bundle schema and interpreter remain unchanged.

Both AGP consumers build and execute the exact corrected AAR without application
keep-rule repairs. Their proof, build receipt, APK/DEX and complete public build,
runtime and cleanup verification inputs are included. Public diagnostic files
use the explicit `known-path-roots-v1` normalization policy: only declared private
directory roots are replaced; rules, diagnostics, status and test results are
preserved. The receipt distinguishes private raw digests from normalized public
digests. Private original diagnostic logs remain in their owned run directory and
are not advertised as ZIP contents. Unknown private paths are rejected. The
new unpublished AGP schema uses `build-jvm.json` from the actual JavaCompile task
in place of the redundant independent Java probe. It binds task JVM properties
and compiler selection to the real Gradle Launcher/Daemon JVM output, requires
compiler forking to be disabled and requires successful JavaCompile/R8 execution.
It does not retain an empty compatibility field or relabel Gradle output as
`java -version`. No r1 schema or historical proof is migrated.
The consumer-owned verifier checks the exported closure again after download;
a projection alone cannot establish this
gate. The two runs must have distinct run IDs, the same source tree and the same
AAR and AAR-manifest digests. The minimal app must preserve all nine native
registrations and the JNI exception callback while calling only runtimeVersion.
Fresh verification replays signature, alignment, DEX and manifest inspection on
each AGP APK with its recorded SDK tools. It requires Build Tools `36.0.0`; the
existing explicit `apksigner` and `zipalign` arguments must select that same SDK
directory. The canonical runtime APK is verified separately and cannot substitute
for either AGP consumer APK. Download verification does not start Gradle, ADB or a
device.

Build the r2 envelope only from completed canonical and AGP proofs, using
`artifact/android_maintenance_bundle.py`. Then assemble the seven assets with
`artifact/platform_distribution.py --profile maintenance-r2 assemble` and the
same explicit tool/path arguments as the stable runbook. The distribution
collector uses `--profile maintenance-r2` for both `pending` and `collect`.
Pending evidence, including both AGP consumer records, must remain unchanged
when the independent maintenance receipt advances to verified.

## Publication and installed evidence

The original three-domain state machine remains pinned to r1. Use
`release_receipt_finalizer.py finalize-maintenance` with the exact results digest
and `--platform-receipt` to install the separate pending maintenance leaf. Install
its emitted bytes as a direct results-only child P2 and run the unchanged
`verify-installed` command with the exact parent and results pins.

The existing GitHub publisher selects its explicitly different maintenance plan:

```sh
sh artifact/python-run.sh artifact/stable_github_publication.py \
  --profile maintenance-r2 prepare "$pending_results_sha256"
```

It observes the original Apple release as an immutable read-only reference.
No Apple creation, asset upload or publication request exists in this plan.
The only nine actions create the new platform draft, upload its seven assets,
and publish it without advancing `latest` from `v0.1.5`. The fixed r2 state root
has its own journal and also holds the original account publication lock, whose
existing authority must be present. Do not relocate, reset or replace either
journal. Unknown outcomes retain the existing reconciliation semantics and cannot
be turned into automatic retries.

An authorized real execution additionally requires the exact prepared plan and
results digests and these maintenance-specific acknowledgements:

```text
--ack-draft-barrier I_ACKNOWLEDGE_PLATFORM_REVISION_DRAFT_BEFORE_UPLOAD
--ack-publication-order I_ACKNOWLEDGE_ORIGINAL_RELEASES_REMAIN_UNCHANGED
```

After publication, collect a fresh immutable release/asset attestation and fresh
downloads from a clean R2 verifier checkout. Deep verification must validate the
entire schema-3 envelope and both exported AGP closures. Finalize that verified
receipt with `finalize-maintenance`, install the exact emitted results-only child,
then run `verify-installed` and `verify-maintenance`. Only that verified record may
be assigned the new `abi2-platforms-v0.1.5-r2-verified` tag and selected by consumers.

The local `latest-release.json` SemVer pointer does not gain a same-version update
exception. Use an isolated candidate root and an explicit revision download URL.
A later shared revision-aware selector would require its own explicit schema
migration. Physical-device and independent product-promotion claims keep their
existing separate gates.
