# Q-Periapt ABI 2 platform distribution — 0.1.0-alpha.2-r1

This immutable prerelease extends the existing ABI 2 alpha to Android, GNU/Linux,
and Windows without changing the ABI or product version. The one-off `r1`
distribution revision exists because the immutable Apple `v0.1.0-alpha.2` release
cannot be rewritten. The next normal release returns all platforms to one SemVer
release line.

Android and GNU/Linux native code in this revision is built with the source-pinned
Rust 1.96.1 patch release. Windows is built with the exact Rust 1.97.0 stable
toolchain because it contains the upstream MSVC informational-output classifier
fix required to retain strict `linker_messages` enforcement while producing the
DLL import library. Each platform checks and records its exact rustc and Cargo
identity. This bounded Windows build-input difference is removed at the next
normal release after the common toolchain has passed the full platform matrix.

## Assets and tested scope

- Android: one AAR containing `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`
  JNI libraries built with stable NDK r29. Every ELF has 16 KiB load alignment,
  the exact nine-symbol ABI 2 export surface, RELRO/NOW/NX, no text relocations,
  and no RPATH/RUNPATH. The runtime evidence bundle executes the exact public AAR
  on the official Android 15 / API 35 `google_apis_ps16k` `arm64-v8a` emulator
  with 16 KiB pages. The proof and evidence-bundle manifests bind the measured
  integer device SDK (`35`) as well as ABI and page size.
- GNU/Linux: native x86_64 and aarch64 SDK archives. Each includes the shared and
  static libraries, ABI-major headers, exact-version pkg-config and CMake config,
  ABI contract, SBOM/CBOM, and license material. Native consumers validate both
  archives in the attested candidate CI. The packages enforce a GLIBC 2.35 ceiling
  and a fixed system-library dependency set.
- Windows: an x64 MSVC SDK ZIP with DLL, import library, separate static library,
  ABI-major headers, exact-version CMake config, ABI contract, SBOM/CBOM, license
  material, and `/W4 /WX` native-consumer validation in the attested candidate CI.

The immutable Apple
[`v0.1.0-alpha.2`](https://github.com/billlza/q-periapt/releases/tag/v0.1.0-alpha.2)
release was built with Rust 1.96.0. It remains available only as historical,
attested evidence and must not be treated as the patched-toolchain Apple build.
The separately signed Apple revision `v0.1.0-alpha.2-r1`, rebuilt with Rust
1.96.1, supersedes it for testing and integration.

## Integrity and trust boundary

All assets are bound by `PLATFORM_DISTRIBUTION.json`, `SHA256SUMS`, the annotated
release tag, and GitHub's immutable release attestation. The CI-built package
assets additionally have GitHub build provenance attestations. Verify the release
and any downloaded release asset with:

### Release consumers

```sh
gh release verify abi2-platforms-v0.1.0-alpha.2-r1 --repo billlza/q-periapt
gh release verify-asset abi2-platforms-v0.1.0-alpha.2-r1 ./PATH_TO_ASSET \
  --repo billlza/q-periapt
```

### Release operator before assembly

The release operator must verify all five CI-built packages plus the candidate
checksum manifest (six attested subjects total) before adding locally generated
Android runtime evidence and assembling the final release:

```sh
TAG_COMMIT=$(git rev-list -n 1 abi2-platforms-v0.1.0-alpha.2-r1)
CANDIDATE_DIR=$(cd ./candidate && pwd -P)
sh artifact/verify-platform-candidate.sh "$CANDIDATE_DIR" "$TAG_COMMIT"

# Equivalent per-asset policy enforced by the script:
gh attestation verify ./CI_BUILT_ASSET \
  --repo billlza/q-periapt \
  --signer-workflow billlza/q-periapt/.github/workflows/abi2-platform-candidate.yml \
  --signer-digest "$TAG_COMMIT" \
  --source-ref refs/tags/abi2-platforms-v0.1.0-alpha.2-r1 \
  --source-digest "$TAG_COMMIT" \
  --deny-self-hosted-runners
```

The Windows binaries are intentionally an **unsigned experimental prerelease**.
No trusted Windows Authenticode credential was available. GitHub attestations and
SHA-256 prove origin and integrity but do not replace Authenticode publisher trust.

## Explicitly outside this prerelease

This release does not claim Maven Central, crates.io, deb/rpm/MSIX publication,
Windows Authenticode, Android physical-device coverage, independent cryptographic
certification, or FIPS validation. Those are separate distribution, credential,
hardware, or certification workstreams and are not silently represented as done.
