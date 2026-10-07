# C SDK package profile

The shared C packager has a `sdk-020` profile for 0.2.0. ABI major
remains **2**, including the original nine declarations/status values and native
library identities. Its separate schema-3 package manifest requires the exact
43-export SDK contract and the native 37-asset CBOM. Historical schema-2 / 0.1.5
packages retain their own profile and cannot substitute for this SDK.
Windows uses a [separate MSVC producer and manifest](SDK_WINDOWS_PACKAGE.md).

```sh
sh artifact/c-package.sh --profile sdk-020
```

The 0.2.0 producer supports native Apple Silicon macOS and 64-bit GNU Linux targets.
Intel macOS is outside the support matrix. The observed local
run is macOS ARM64; Linux execution is still pending. A release build requires
a clean standalone Git checkout. A diagnostic build can explicitly use
`QPERIAPT_ALLOW_DIRTY_C_PACKAGE=1` and a fresh `QPERIAPT_C_PACKAGE_OUT_DIR` under
that checkout's `target` directory. The existing provenance guard still rejects
linked worktrees. The local run used a separately copied, byte-matched build
checkout and recorded the dirty state; no commit or publication was performed.

The archive installs headers under `include/qperiapt/abi2`, shared/static
libraries under `lib`, `qperiapt-abi2` and `qperiapt-abi2-static` pkg-config
modules, and `QPeriaptABI2` CMake targets. ABI compatibility version `2.0.0`
is distinct from package version `0.2.0`; the latter is available as
`QPeriaptABI2_RELEASE_VERSION`. Both versions are checked by the consumers.
The package supplies required native static link flags, without source-checkout
library paths. The macOS library's install name is `@rpath/libq_periapt_ffi.2.dylib`;
its compatibility/current versions remain `2.0.0`.

After extracting the archive, a consumer can use:

```sh
PKG_CONFIG_PATH="$PWD/lib/pkgconfig" PKG_CONFIG_LIBDIR="$PWD/lib/pkgconfig" \
  pkg-config --cflags --libs qperiapt-abi2 > sdk.flags
cc -std=c11 -Wall -Wextra -Wpedantic -Werror share/q-periapt/sdk_smoke.c \
  @sdk.flags -o sdk-smoke
./sdk-smoke
```

`sdk_smoke.c` exercises runtime verification, owned keys, explicit expert
transfer, purpose derivation, quotas, revocation and policy transitions. The
bundled policy roots/signatures are public test material; production hosts
must provision their own root and durably maintain the authenticated state.
See [ownership](SDK_OWNERSHIP.md), [persistence](SDK_HOST_STORE.md) and
[connection semantics](SDK_CONNECTION.md). Returned/exported secret byte copies
remain the caller's responsibility. Handles do not isolate hostile native code
inside the same process.

The same producer tests all of the following after extraction outside its
source checkout: legacy and owned APIs through both pkg-config linkage modes,
a consumer compiled against the frozen 0.1.5 header, and four CMake tests using
the shared and static imported targets. It rejects the retired unversioned
package names and an incorrect CMake ABI compatibility version. An immutable
manifest/outer archive digest is pinned before extraction and rechecked after
execution; rehashing a changed installed payload cannot silently replace it.
Source-byte fingerprints are compared before and after the build.

The native CBOM, complete workspace-lock SBOM, 72 target-specific Cargo dependency
notices in the observed macOS build, vendored provider notices and Rust 1.96.1
standard-library notices are included. The closed payload has 166 files plus its
manifest/checksum file. The workspace SBOM is not an exact per-target code census;
the inventory boundaries in [SDK_CBOM.md](SDK_CBOM.md) apply.

Public archive revalidation uses the same `--profile sdk-020` argument with
`QPERIAPT_C_PACKAGE_VERIFY_ARCHIVE` and explicit expected archive, manifest,
contract, target and version values. It rejects a dirty diagnostic source image
even when all supplied digests match. Local negative controls observe rejection
for an incorrect archive digest, target, manifest digest and dirty source.
A positive clean-source public run and Linux hosted execution remain pending;
the current candidate must not be relabeled as clean release evidence.

The [2026-09-26 checkpoint](../research/sdk-alpha1/evidence/20260926-c-sdk-package/manifest.json)
records the actual local producer/installation run, three independent dynamic
loader observations, source identities and failures. The source-only Linux
profile mutation tests do not establish native Linux execution, GLIBC/runtime
qualification, CT/performance results or a signed release.

The retained macOS ARM64 diagnostic archive is 5,870,014 bytes, SHA-256
`e7ee6c8ea2ba8de9ea0f4bff374bab42007c0835bfca7e52aac3c5807dd93453`.
Its source/version/target identity is in the accompanying manifest; it is not
interchangeable with earlier attempts having the same prerelease version.

The [2026-09-27 C/JVM refresh](../research/sdk-alpha1/evidence/20260927-sdk-current-c-jvm/manifest.json)
rebuilds this macOS ARM64 package from the current source after the borrowed
public-key storage change. Its archive SHA-256 is
`8aa7605e8d810bb7669a913964da64f37eeaf60bfd84cb3695f60b52c85bb0e1`;
its manifest is
`8054f02d91da3802d73e79faf4c15de20cd9e151aa19cf4989626afc701e3f55`.
All four external pkg-config consumers, the frozen-header consumer and four
CMake tests pass. This exact archive is also consumed by the refreshed JVM
bundle, including an observed Java load of its extracted native library.
The ABI stays 2; clean-source release, other platforms and security/performance
qualification remain separate from this dirty local diagnostic.
