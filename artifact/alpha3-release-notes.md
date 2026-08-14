# Q-Periapt 0.1.0-alpha.3 — ABI 2 research prerelease

This prerelease keeps the public C ABI at major version 2 and the exact nine-symbol
export surface. It advances the package version from `0.1.0-alpha.2` to
`0.1.0-alpha.3`; it is not an ABI 2.1 change and requires no ABI migration.

The release is published as two independently verifiable GitHub transactions for
the same product SemVer:

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
  release includes a source- and AAR-bound API 35 arm64 16 KiB emulator runtime
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
