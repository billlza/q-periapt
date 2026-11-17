# SDK 0.2.0 GitHub publication

`artifact/sdk_github_publication.py` admits the coordinated SDK and Continuity
cohort into `stable_github_publication.py`. It reuses the existing private
staging, account lock, durable intent/reconciliation/outcome journal, exact
remote-transition checks and bounded pinned-file-descriptor transport. The
legacy 0.1.5 and maintenance schemas retain their original defaults and byte
pins. The new plan kind is `qperiapt.sdk_github_publication_plan`, schema 1.

## Source and admission authority

The operator first selects the qualified source commit **S** and its actual
tree. A direct child **R** adds only regular release-evidence files under
`release/0.2.0/`; it cannot modify S or replace existing evidence. Both annotated
release tags point to R. Producer and qualification records continue to name S.
The clean publication checkout must remain at R throughout the transaction.

R contains canonical `release/0.2.0/ADMISSION.json`, whose independently selected
SHA-256 binds:

- The release-mode `RELEASE_MANIFEST.json`, original package artifacts,
  separate SDK C ABI 2 and Continuity `qpc-owner/1` interfaces, and frozen
  normative lock.
- The selected CI, CodeQL, internal-review, Apple-signing, Windows-lifecycle,
  service, independent-implementation, installed-coverage and package-readback
  decisions. Each records its scope and pins the original retained reports.
- Both sorted public asset inventories with exact paths, sizes and digests.

An admission document is the maintainer's source-bound release decision. Its
`completed` qualification records must be produced from actual execution and
review. The publisher checks their source, inventory and committed byte pins;
it does not rerun every qualification or infer a cryptographic theorem from a
status field. The existing manifest verifier still reports identity consistency
with `release_claim_eligible: false` and `publication_performed: false`.

Preparation opens the complete selected input tree, runs the release-manifest
verifier, checks all selected package archives are in the public inventory, and
compares normative/package metadata with their actual committed blobs. It then
copies exact archive bytes into private staging. Once preparation completes,
subsequent actions use the committed admission and staged files; disposable
producer directories are not publication authority.

Keep `RELEASE_EVIDENCE.zip` free of self references: it contains the original
qualification records, manifest and required source/contract inputs. The later
admission and public checksum inventory bind that archive's digest outside it.

## Public releases and local state

| Release | Public inventory | Latest policy |
| --- | --- | --- |
| `v0.2.0` | `APPLE_DISTRIBUTION.json`, `CQPeriapt.xcframework.zip`, `MANIFEST.json`, `QPeriapt-Swift-SDK-0.2.0.zip`, `SHA256SUMS` | Advances latest from `v0.1.5`. |
| `abi2-platforms-v0.2.0` | Exact admitted platform/Continuity archives, `RELEASE_EVIDENCE.zip` and `SHA256SUMS`; at most 80 assets | Leaves latest at `v0.2.0`. |

Each asset is bounded to 256 MiB and the existing manifest input aggregate is
bounded to 4 GiB. Both empty drafts must exist before any upload. The complete
Apple prefix precedes platform uploads, and both complete drafts precede either
publication. Public releases must be immutable. Protection must retain all
twenty historical stable/verification/maintenance tags and cover the two new
tags plus `v0.2.0-verified-cohort`, with no update/deletion bypass.

SDK state is account-derived
`~/.q-periapt/publication-state/github-sdk-v0.2.0`. The original GitHub account
lock is also held, so different version namespaces cannot publish concurrently.
On a new machine, preparation may create the original empty private lock;
it does not synthesize an old plan or publication receipt. Interrupted or
ambiguous mutations retain their journal and are never blindly retried.

The explicit `sdk-020` CLI profile selects the canonical passwd account's
`.local/bin/gh`. Its SHA-256 is
`5f8d7527e2bdf584249b030cdd1550c91d75e8afb40aa3c11573d416817a1260`,
the exact macOS ARM64 executable from GitHub CLI 2.103.3's official immutable
release archive. The profile refuses other bytes, path/metadata drift and
unknown profile names. The original CLI selection remains the legacy default.

## Operator commands

Use the repository's pinned Python launcher and an existing GitHub credential
in the selected child process. Credentials are never command-line arguments or
receipt fields. Paths below are placeholders for the actual clean checkout and
qualified input tree; do not use an authoring checkout with uncommitted work.

```sh
sh artifact/python-run.sh artifact/sdk_github_publication.py prepare \
  --repository-root /absolute/release-checkout \
  --input-root /absolute/qualified-inputs \
  --admission-sha256 ADMISSION_SHA256

sh artifact/python-run.sh artifact/sdk_github_publication.py publish \
  --repository-root /absolute/release-checkout \
  --admission-sha256 ADMISSION_SHA256 --plan-sha256 PLAN_SHA256 \
  --execute-real-github-mutation \
  --draft-barrier-ack I_ACKNOWLEDGE_BOTH_DRAFTS_BEFORE_ASSET_UPLOAD \
  --publication-order-ack I_ACKNOWLEDGE_APPLE_THEN_PLATFORM_PUBLICATION

sh artifact/python-run.sh artifact/sdk_github_publication.py verify \
  --repository-root /absolute/release-checkout \
  --verification-root /absolute/existing-owned-private-directory
```

`status` reads the durable transaction and current remote state. `verify`
additionally runs the pinned CLI's cryptographic release-attestation verifier
for both releases, checks exact tag/asset subjects, freshly downloads every
asset, and resamples remote authority and all retained bytes. Each attempt has
a fresh private directory. Only a complete attempt writes
`PUBLICATION_VERIFICATION.json`; failed or partial observations remain without
a completion receipt. Installed-consumer execution and Apple signing checks
retain their own original qualification records.

The twelve crates.io uploads remain in `artifact/rust_sdk_publication.py` with
their separate namespace, dependency order, exact uploader and dual API/index
checksum reconciliation. GitHub completion does not claim registry completion.
