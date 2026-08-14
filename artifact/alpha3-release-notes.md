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

Before assembling the non-Apple platform distribution, verify the exact six-subject
CI candidate transaction and write its sanitized projection to a caller-selected,
private, previously absent output path:

```sh
candidate_dir=/absolute/path/to/alpha3-platform-candidate
tag_commit=$(git rev-parse --verify \
  'refs/tags/abi2-platforms-v0.1.0-alpha.3-r1^{commit}')
mkdir -p target
projection_parent=$(umask 077 && \
  mktemp -d "$PWD/target/abi2-platform-candidate-projection.XXXXXXXX")
chmod 0700 "$projection_parent"
projection=$projection_parent/candidate-attestation-projection.json
sh artifact/verify-platform-candidate.sh \
  "$candidate_dir" "$tag_commit" "$projection"
```

The verifier records one private preflight snapshot, runs the six exact GitHub
attestation checks, then re-samples the candidate with the same parser. It publishes
the `0600` projection with exclusive creation only when every result contains the
same statement, verification record, run, and timestamp and the candidate bytes are
unchanged. Raw GitHub responses remain in a script-owned `0700` directory under
`target`; neither their path nor their contents appear in the success marker.

After the Apple GitHub prerelease is immutable and its fresh remote consumer check
has completed, use the private source-bound completion ledger as the exact four-asset
expectation while collecting GitHub release metadata and its five-subject release
attestation. The raw, ledger, and projection paths must be separate trees:

```sh
apple_tag=v0.1.0-alpha.3-r1
completed=/absolute/path/to/apple-release/completed.json
release_id=$(gh release view "$apple_tag" --repo billlza/q-periapt \
  --json databaseId --jq .databaseId)
tag_object=$(git rev-parse --verify "refs/tags/$apple_tag")
mkdir -p target
raw=$PWD/target/apple-github-release-raw-$release_id
test ! -e "$raw"
apple_projection_parent=$(umask 077 && \
  mktemp -d "$PWD/target/apple-github-release-projection.XXXXXXXX")
chmod 0700 "$apple_projection_parent"
apple_projection=$apple_projection_parent/apple-github-release-verification.json
sh artifact/python-run.sh artifact/apple_release_verification.py collect \
  "$completed" "$release_id" "$tag_object" "$raw" "$apple_projection"
```

The adapter verifies the annotated tag object and peeled commit before and after the
remote transaction. It requires the fixed repository to be `PUBLIC` in matching
bounded pre/post observations, and requires stable security-relevant release fields
from the bounded `gh release view` observations around `gh release verify`. Mutable
download-count telemetry is validated but excluded from the stability comparison.
The five raw files remain `0600` under the new `0700` raw directory. Only after those
samples agree does it exclusively create a `0600` PII-safe projection. Its
`publication` member is the exact pure receipt-contract shape; the four asset hashes
and TimestampAuthority metadata remain alongside it for adapter self-verification.

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
