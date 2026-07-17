# C ABI 2 product smoke

This is a real C program that links the built `q-periapt-ffi` product library and
calls its frozen ABI 2 surface. It proves the C calling convention, strict header,
signed-policy gate, OS-random key generation, ContextBound round trip, and atomic
failure behavior end to end. It is not only a header parse.

The ABI 2 `cdylib`/DLL dynamic export table contains exactly nine
`q_periapt_*` symbols: five metadata functions,
`q_periapt_decision_from_signed_policy`, `q_periapt_generate_keypair`,
`q_periapt_encapsulate`, and `q_periapt_decapsulate`. Raw KEM, raw combiner, and
profile-selection entry points are deliberately not exported from the product ABI;
their deterministic KATs remain Rust-core evidence.

The static archive has a necessarily different boundary: only the reserved public
`q_periapt_*` namespace is constrained to those nine names. It also contains hidden,
versioned `qpn_mlkem_bridge_*` link symbols needed by the safe Rust adapter. They are
absent from the public header, unsupported, and may change without ABI notice, but a
same-process static consumer can deliberately declare and link them by name. Hidden
visibility is not access control for a static archive. A native caller can also forge
decision bytes, so both static embedding and the decision descriptor assume a trusted
same-address-space caller; this ABI is a misuse-resistance/network-downgrade boundary,
not process isolation.

The ABI remains stateless KEM/policy plumbing. It does not expose identity,
prekeys, ratchets, persistence, multi-device state, or recovery, so a passing C
smoke is not session-protocol evidence. Continuity has separate research and gates
in [`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).

## What the smoke proves

[`smoke.c`](smoke.c) and the public
[`signed_policy_fixture.h`](signed_policy_fixture.h) check:

1. Runtime ABI, package version, fixed suite, and status names match the header.
2. A valid ML-DSA-signed policy produces the exact ABI 2 decision layout; trusted
   state reapplication succeeds, signature tampering fails closed, and output is
   cleared on failure.
3. A legacy ABI 1 four-byte policy state is rejected with `Q_PERIAPT_ERR_LENGTH`.
   There is no automatic state conversion; an authorized host must explicitly
   re-enroll or reset from the exact signed policy.
4. Policy-gated OS-random key generation, encapsulation, and decapsulation agree;
   application context changes the derived secret; a low-order X25519 keyshare
   fails atomically with ciphertext and secret outputs cleared.

Exit code `0` and `ALL PASS` mean every check passed.

## Direct source-tree smoke

macOS or Linux:

```sh
sh bindings/c/build-and-run.sh
```

Windows with MSVC:

```bat
bindings\c\build-and-run.bat
```

Both scripts build the ABI-major Rust library basename
`q_periapt_ffi_abi2`, compile with warnings as errors, link it, and run the same
product smoke. The Windows command requires a real Windows/MSVC run; a macOS pass
does not prove PE exports or import-library naming.

## ABI-major release archive

From the repository root:

```sh
sh artifact/c-package.sh
```

The gate creates
`target/qperiapt-c-abi2/q-periapt-c-abi2-<semver>-<host>.tar.gz`. The package has
no ABI 1/unversioned aliases or symlinks and contains:

- `include/qperiapt/abi2/q_periapt.h` and the signed-policy fixture;
- `libq_periapt_ffi.2.dylib` on macOS with install name, compatibility version,
  and current version fixed to ABI 2, or `libq_periapt_ffi.so.2` on Linux with
  SONAME `libq_periapt_ffi.so.2`;
- `libq_periapt_ffi_abi2.a` for static consumers;
- pkg-config modules `qperiapt-abi2` and `qperiapt-abi2-static`;
- CMake package `QPeriaptABI2`, requested as
  `find_package(QPeriaptABI2 2.0.0 EXACT CONFIG REQUIRED)`, with targets
  `QPeriaptABI2::qperiapt` and `QPeriaptABI2::qperiapt_static`;
- the frozen machine-readable ABI contract, CBOM/SBOM, licenses, manifest, and
  checksums.

The CMake ABI compatibility version is `2.0.0`; the prerelease semver is exposed
separately as `QPeriaptABI2_RELEASE_VERSION`. Manifest schema 2 binds the embedded
contract hash, exact platform runtime identity, and the dynamic export-set digest. The
`contract_path` field names the repository trust root at
`crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json`; `embedded_contract_path`
names its byte-identical archive copy at
`share/q-periapt/abi/q-periapt-c-abi-v2.json`. Both must hash to
`contract_sha256`. The
export digest is SHA-256 over UTF-8
`"\n".join(sorted(exact_export_names)) + "\n"`.

After safe extraction and checksum/file-set validation, the gate re-runs the ABI
contract verifier and compiles/runs dynamic and static consumers through both
pkg-config and CMake with warnings as errors. It also proves the legacy pkg-config
and CMake package names do not resolve from the archive.

Only the host platform executed by the gate is proven. macOS verification checks
the Mach-O dynamic exports and install-name/current/compatibility identity; Linux
verification checks ELF dynamic exports and SONAME. Static verification separately
checks that the public `q_periapt_*` namespace is exact-nine; it does not claim that
the archive has only nine total link symbols or that internal bridge symbols are
physically inaccessible.

## Published SDK archives

Beyond the local host gate, prebuilt C SDK archives are published in the immutable
`abi2-platforms-v0.1.0-alpha.2-r2` GitHub prerelease: Linux x86_64 and aarch64
tarballs (GLIBC 2.35 ceiling, fixed system-library dependency set) and a Windows
x64 MSVC ZIP with DLL, import library, and separate static library. Each carries
ABI-major headers, exact-version pkg-config (Linux) and CMake configs, the frozen
ABI contract, SBOM/CBOM, and license material, and was validated by `/W4 /WX` or
warnings-as-errors native consumers in the attested candidate CI. The Windows
archive is an **unsigned experimental prerelease** (no Authenticode); Windows
consumers must select `/MD` (`MultiThreadedDLL`) to match the static library's
frozen `msvcrt` contract. Verify assets with `gh release verify-asset` against
`PLATFORM_DISTRIBUTION.json` and `SHA256SUMS`; see
[`../../artifact/abi2-platform-release-notes.md`](../../artifact/abi2-platform-release-notes.md).
deb/rpm/MSIX registry packaging is explicitly not claimed.
