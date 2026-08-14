# Q-Periapt 0.1.0-alpha.3 — ABI 2 research prerelease

This prerelease keeps the public C ABI at major version 2 and the exact nine-symbol
export surface. It advances the package version from `0.1.0-alpha.2` to
`0.1.0-alpha.3`; it is not an ABI 2.1 change and requires no ABI migration.

The release plan uses two independently verifiable GitHub transactions for the
same product SemVer. Each becomes public/current only after its verified receipt
records the immutable release:

- Apple: `v0.1.0-alpha.3-r1`
- Android, GNU/Linux, and Windows: `abi2-platforms-v0.1.0-alpha.3-r1`

The earlier alpha.2 tags and receipts remain immutable historical evidence. They
are not rewritten or promoted as alpha.3 evidence.

## Reliability and security hardening

The alpha.3 source line strengthens the Android release transaction without
weakening package ownership checks:

- installed-package state and installed-APK ownership are observed through fixed,
  typed, bounded operations;
- an APK is accepted only after consecutive exact path-and-byte observations and
  exact signer verification;
- cleanup alternates package-state and ownership observations under one total
  deadline, retains the single-uninstall invariant, and fails closed when state
  cannot be established;
- a script-owned emulator can perform at most one receipt-, process-, listener-,
  console-, and private-ADB-bound transport registration recovery before starting
  package convergence again;
- failure diagnostics publish only bounded sanitized state tokens and path hashes,
  not raw ADB output, device identifiers, host paths, credentials, or signing data.

These changes improve reliability and reduce ambiguous cleanup failures. This
release does not claim a performance improvement; the separately tracked
performance evidence remains stale until a fresh performance run is selected.

## Assets and tested scope

- Apple: a Developer ID-signed, static-only XCFramework for macOS, iOS devices,
  and iOS simulators, plus its exact distribution evidence, manifest, and checksum
  file. Notarization is not applicable to this SDK payload; final applications
  retain their own signing, provisioning, and notarization responsibilities.
- Android: one AAR with `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64` JNI
  libraries, exact ABI 2 exports, ELF hardening, and 16 KiB load alignment. The
  platform target includes a source- and AAR-bound API 35 arm64 16 KiB emulator runtime
  evidence bundle.
- GNU/Linux: x86_64 and aarch64 C SDK archives with shared/static libraries,
  headers, ABI contract, pkg-config/CMake metadata, SBOM/CBOM, licenses, GLIBC
  ceiling checks, and native consumers.
- Windows: an x64 MSVC C SDK ZIP with DLL/import/static libraries, headers,
  CMake metadata, SBOM/CBOM, licenses, PE/REPRO checks, and `/W4 /WX` consumers.
  It remains an unsigned experimental prerelease without Authenticode.

Each platform candidate package is produced by the tag-bound workflow and covered
by GitHub build provenance. Final manifests and checksum sets bind the selected
assets; post-publication consumers re-download and verify the immutable releases.

## Verification

Before assembling the non-Apple platform distribution, place the exact six-subject
CI candidate transaction below the fixed private candidate-input root and write its
sanitized projection below the separate fixed private projection root:

```sh
candidate_inputs=$PWD/target/abi2-platform-candidate-inputs
candidate_projections=$PWD/target/abi2-platform-candidate-projections
(umask 077 && mkdir -p "$candidate_inputs" "$candidate_projections")
chmod 0700 "$candidate_inputs" "$candidate_projections"
candidate_dir=$candidate_inputs/alpha3-platform-candidate
tag_commit=$(git rev-parse --verify \
  'refs/tags/abi2-platforms-v0.1.0-alpha.3-r1^{commit}')
projection_parent=$(umask 077 && \
  mktemp -d "$candidate_projections/transaction.XXXXXXXX")
chmod 0700 "$projection_parent"
projection=$projection_parent/candidate-attestation-projection.json
sh artifact/verify-platform-candidate.sh \
  "$candidate_dir" "$tag_commit" "$projection"
```

The verifier records one private preflight snapshot, runs the six exact GitHub
attestation checks, then re-samples the candidate with the same parser. It publishes
the `0600` projection with exclusive creation only when every result contains the
same statement, verification record, run, and timestamp and the candidate bytes are
unchanged. The fixed input, projection, and raw-verification roots must be owned by
the current user with mode `0700`; the verifier fails before Git or GitHub when a
path escapes those roots. Raw GitHub responses remain in a script-owned `0700`
directory under `target/abi2-platform-candidate-verification/raw`; neither their
path nor their contents appear in the success marker.

Publication receipts advance through `pending` before `verified`; a domain receipt
never edits `artifact/results.json` directly. First bind the two pending receipts to
their private candidate/completion evidence. The platform verifier must be a clean
standalone checkout named `M` with its own non-symlink `.git` directory:

```sh
platform_tag=abi2-platforms-v0.1.0-alpha.3-r1
platform_worktree_root=$PWD/target/abi2-platform-publication-worktrees
(umask 077 && mkdir -p "$platform_worktree_root")
chmod 0700 "$platform_worktree_root"
test ! -e "$platform_worktree_root/M"
(umask 077 && git clone --no-local "$PWD" "$platform_worktree_root/M")
git -C "$platform_worktree_root/M" checkout --detach "$platform_tag"
test -z "$(git -C "$platform_worktree_root/M" status --porcelain=v1 \
  --untracked-files=all)"
sh artifact/python-run.sh artifact/platform_alpha3_publication.py pending \
  --candidate-projection "$projection" \
  --verifier-checkout "$platform_worktree_root/M"

apple_tag=v0.1.0-alpha.3-r1
source_commit=$(git rev-parse --verify "refs/tags/$apple_tag^{commit}")
apple_worktrees=$PWD/target/qperiapt-apple-release-worktrees
completed=$apple_worktrees/$source_commit/completed.json
sh artifact/python-run.sh artifact/apple_alpha3_publication.py pending \
  "$completed"
```

Set `platform_pending_receipt` and `apple_pending_receipt` to `$PWD/` plus the
repo-relative `receipt=`/`path=` values printed by those commands. Pin the current
results bytes and ask the neutral finalizer for a separate pending results
candidate. Review that candidate and advance it through the normal results-only
commit; neither receipt is itself a results file:

```sh
results_sha256=$(shasum -a 256 artifact/results.json | awk '{print $1}')
sh artifact/python-run.sh artifact/release_receipt_finalizer.py finalize \
  "$results_sha256" \
  --apple-receipt "$apple_pending_receipt" \
  --platform-receipt "$platform_pending_receipt"
```

After selecting that pending candidate, run the external consumer from its clean
verifier checkout with the seven existing `QPERIAPT_SWIFT_BINARY_*` pins. Map
`QPERIAPT_SWIFT_BINARY_CHECKSUM`, `QPERIAPT_SWIFT_BINARY_SHA256`,
`QPERIAPT_SWIFT_BINARY_APPLE_DISTRIBUTION_SHA256`,
`QPERIAPT_SWIFT_BINARY_MANIFEST_SHA256`,
`QPERIAPT_SWIFT_BINARY_SHA256SUMS_SHA256`, and
`QPERIAPT_SWIFT_BINARY_SOURCE_COMMIT` to the current pending distribution's
`swiftpm_checksum`, `artifact_sha256`, `apple_distribution_evidence_sha256`,
`manifest_sha256`, `checksums_sha256`, and `source_commit` respectively.
`QPERIAPT_SWIFT_BINARY_URL` is exactly
`https://github.com/billlza/q-periapt/releases/download/v0.1.0-alpha.3-r1/CQPeriapt.xcframework.zip`.
These are cross-checked facts, not new caller claims:

```sh
/bin/sh artifact/swift-xcframework-remote-consumer.sh
```

The script accepts no arguments. It snapshots and pins the startup
`artifact/results.json` internally, performs the remote checks, and invokes the
receipt emitter only from that source-bound snapshot. Its
`APPLE_REMOTE_CONSUMER_RECEIPT_PASS` marker reports the fixed path under
`target/qperiapt-swift-remote-consumer-runs/transaction.<fresh>/`.
That marker and leaf are the atomic evidence commit. The terminal
`SWIFT_REMOTE_BINARY_CONSUMER_PASS` marker is emitted only after the source
snapshots are removed and the global lock is released. If the script exits 125
with `remote-consumer receipt committed with incomplete durability` or
`remote-consumer receipt committed but post-commit cleanup failed`, the atomic
no-replace visibility point completed for the intended receipt bytes. The
failure means the current named path identity, availability, or durability is
not established by that marker alone. Preserve the transaction and independently
verify its current leaf and bytes read-only; the reported receipt SHA-256 binds
the bytes at the visibility point, not the later pathname state. The run's
durability or hygiene failure still requires handling, and the nonzero script
run must not be recorded as a PASS. A distinct exit-125 `remote-consumer receipt
visibility indeterminate` diagnostic preserves the entire transaction and global
lock for read-only inspection and manual disposition. In that state,
`intended_receipt_sha256` records only the bytes that the emitter attempted to
publish; it does not confirm that the named leaf exists with those bytes. Do not
clean, retry, finalize, or record a PASS from either failed transaction until its
state has been resolved explicitly.

After the Apple prerelease is immutable, collect its five-subject GitHub release
attestation into disjoint private raw and projection transactions:

```sh
apple_verification=$PWD/target/qperiapt-apple-release-verification
apple_raw_root=$apple_verification/raw
apple_projection_root=$apple_verification/projections
(umask 077 && mkdir -p "$apple_raw_root" "$apple_projection_root")
chmod 0700 "$apple_verification" "$apple_raw_root" "$apple_projection_root"
release_id=$(gh release view "$apple_tag" --repo billlza/q-periapt \
  --json databaseId --jq .databaseId)
tag_object=$(git rev-parse --verify "refs/tags/$apple_tag")
apple_transaction=release-$release_id-UNIQUE_OPERATOR_TRANSACTION
apple_raw=$apple_raw_root/$apple_transaction
test ! -e "$apple_raw"
apple_projection_parent=$(umask 077 && \
  mktemp -d "$apple_projection_root/transaction.XXXXXXXX")
chmod 0700 "$apple_projection_parent"
apple_projection=$apple_projection_parent/apple-github-release-verification.json
sh artifact/python-run.sh artifact/apple_release_verification.py collect \
  "$completed" "$release_id" "$tag_object" "$apple_raw" "$apple_projection"
```

Set `apple_remote_receipt` to `$PWD/` plus the emitted repo-relative path. Promote
Apple, then collect the platform release into fresh absent raw/download paths. Set
the four Android variables below to canonical absolute executable paths from the
fixed SDK/NDK installation selected for this transaction:

```sh
pending_results_sha256=$(shasum -a 256 artifact/results.json | awk '{print $1}')
sh artifact/python-run.sh artifact/apple_alpha3_publication.py promote \
  "$pending_results_sha256" "$apple_projection" "$apple_remote_receipt"

platform_transaction=release-UNIQUE_OPERATOR_TRANSACTION
platform_raw=$PWD/target/abi2-platform-publication-verification/raw/$platform_transaction
platform_downloads=$PWD/target/abi2-platform-publication-verification/downloads/$platform_transaction
test ! -e "$platform_raw" && test ! -e "$platform_downloads"
sh artifact/python-run.sh artifact/platform_alpha3_publication.py collect \
  --pending-receipt "$platform_pending_receipt" \
  --verifier-checkout "$platform_worktree_root/M" \
  --raw-directory "$platform_raw" \
  --download-directory "$platform_downloads" \
  --android-llvm-nm "$android_llvm_nm" \
  --android-llvm-readelf "$android_llvm_readelf" \
  --android-apksigner "$android_apksigner" \
  --android-zipalign "$android_zipalign"
```

Set `apple_verified_receipt` and `platform_verified_receipt` to `$PWD/` plus their
printed repo-relative paths. Finalize against the still-pinned pending results;
after selecting the reviewed verified candidate, `verify` is read-only and
idempotent:

```sh
sh artifact/python-run.sh artifact/release_receipt_finalizer.py finalize \
  "$pending_results_sha256" \
  --apple-receipt "$apple_verified_receipt" \
  --platform-receipt "$platform_verified_receipt"

verified_results_sha256=$(shasum -a 256 artifact/results.json | awk '{print $1}')
sh artifact/python-run.sh artifact/release_receipt_finalizer.py verify \
  "$verified_results_sha256" \
  --apple-receipt "$apple_verified_receipt" \
  --platform-receipt "$platform_verified_receipt"
```

Both collectors use bounded pre/post `PUBLIC` repository and immutable prerelease
views around exact release attestation checks. Platform collection then streams all
eight assets into one new private directory, rechecks their size/hash inventory,
and runs the deep verifier from `M`; GitHub CLI authentication may be configured,
so this is not an anonymous-availability claim. All receipt, raw, download,
projection, remote-consumer, and results-candidate outputs stay below fixed roots.
A failed raw/download collection requires a new transaction leaf. Successful
outputs are no-replace; already-selected receipts are checked only with `verify`.

```sh
gh release verify v0.1.0-alpha.3-r1 --repo billlza/q-periapt
gh release verify-asset v0.1.0-alpha.3-r1 ./CQPeriapt.xcframework.zip \
  --repo billlza/q-periapt

gh release verify abi2-platforms-v0.1.0-alpha.3-r1 --repo billlza/q-periapt
gh release verify-asset abi2-platforms-v0.1.0-alpha.3-r1 ./PATH_TO_ASSET \
  --repo billlza/q-periapt
```

## Explicit boundaries

This research prerelease does not claim crates.io or Maven Central publication,
deb/rpm/MSIX publication, Windows Authenticode, current Android physical-device
coverage, current performance evidence, independent cryptographic certification,
FIPS validation, hostile-host attestation, or production readiness. Those remain
separate release, credential, hardware, benchmark, audit, or certification gates.
