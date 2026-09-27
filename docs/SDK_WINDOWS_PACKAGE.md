# Windows SDK package profile

The Windows producer and verifier have an explicit `sdk-alpha1` profile for
**0.2.0-alpha.1**, with ABI major **2** and exactly 43 C exports. The original
nine declarations, status values and library filenames remain compatible.
The default `legacy` profile still describes 0.1.5 with nine exports; it cannot
admit an alpha archive. Use the explicit profile in both build and verify modes.

This profile is implemented but **native Windows qualification is pending**.
Hosted MSVC builds have reached the package boundary; the first native attempts
exposed SDK-specific static dependencies and nine unintended jitterentropy DLL
exports from AWS-LC 0.45.0. The fixes still require a complete native build,
archive verification and installed consumer run on both Windows runners.
Neither a Windows alpha ZIP nor an Authenticode signature has been qualified.
The candidate manifest explicitly records
`release_claim_eligible: false`; it does not claim publication or attestation.

## Build from frozen source

Run in a clean standalone Windows x64 checkout containing the matching alpha
source. Use PowerShell 7, Git, CPython 3.11 or newer, CMake/CTest, Visual Studio's
x64 MSVC tools and Windows SDK, cbindgen 0.29.4, and Rust **1.97.0** with its
`llvm-tools` component. The producer verifies the exact Rust version and x64
host, and resolves MSVC tools from a single trusted Visual Studio installation.
The existing ambient Cargo/build configuration guards remain enforced.

```powershell
artifact/windows-package.ps1 -Profile sdk-alpha1
```

The default archive is
`target/qperiapt-windows-sdk-alpha1/q-periapt-c-abi2-0.2.0-alpha.1-x86_64-pc-windows-msvc.zip`.
If an attempt already exists, keep it and select a fresh `-OutputRoot` below
this checkout's `target` directory. There is no dirty-source bypass. This is a
source-freeze requirement, not an instruction to commit other work or erase
uncommitted changes.

The producer fetches the locked dependencies into its own Cargo cache without
copying ambient configuration or credentials. Subsequent native, BOM and license
collection steps use that cache offline. The cache is a separate temporary
directory; both it and the source root have explicit, non-overlapping path maps.
The C maps also cover their Windows 8.3 aliases: the pinned AWS-LC build script
[converts its source and output paths to that spelling](https://github.com/aws/aws-lc-rs/pull/1081).
A native MSVC preflight requires both long and short forms of `__FILE__` to map
to the intended relative prefix. The final binary scan rejects both producer
spellings and the original Cargo cache; the latter is scanned to detect
unexpected reuse and is not added as an allowed/remapped dependency source.
Missing offline dependencies, compiler/linker diagnostics and changed source
identities fail the build. The checked-in Rust standard-library notice must
match the selected toolchain's actual `COPYRIGHT-library.html` bytes.

AWS-LC is built from the locked bundled sources as a private static dependency.
The x64 MSVC build uses its crate-specific `AWS_LC_SYS_CFLAGS` setting to expand
only the `dllexport` modifier to an empty modifier. This prevents the upstream
jitterentropy header from adding its internal functions to the SDK DLL table;
`dllimport`, alignment, noinline, entropy collection and crypto code are retained.
The final DLL must still export exactly the same 43 SDK functions. No symbols
are added to the ABI allowlist, and this export setting does not rewrite binary
sections or dependency sources. The C build helper applies the same setting. Direct Cargo builds
of a Windows C DLL need these target-scoped settings as well; ordinary Rust
library consumers do not require a C export table.

```powershell
$env:AWS_LC_SYS_STATIC_x86_64_pc_windows_msvc = "1"
$env:AWS_LC_SYS_USE_SYSTEM_x86_64_pc_windows_msvc = "0"
$env:AWS_LC_SYS_CFLAGS_x86_64_pc_windows_msvc = "/Ddllexport="
cargo +1.97.0 build --locked --release -p q-periapt-ffi
```

Use those settings only for the direct Cargo invocation. The package producer
rejects ambient AWS-LC build overrides and sets/restores its own scoped values.

The distribution static archive is a separate copy of the compiler output.
The packager replaces only the filename bytes in COFF
[FILE auxiliary records](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-4-files)
with a fixed placeholder in an intermediate copy, without moving any bytes.
It then strips debug sections only from the reviewed CodeView-bearing NASM
layout using the matching Rust toolchain's LLVM tools. Plain objects, including
MSVC's volatile-access metadata, and short DLL imports must remain byte-identical
to the intermediate copy. Other CodeView layouts are also preserved and must
pass the final path scan; no unknown linker metadata is rewritten. LLVM
rebuilds the archive index, retaining member order
and duplicates; archive labels are canonical basenames, never host input paths.
This also removes upstream build paths in ring's prebuilt CodeView debug data.
The producer retains the original archive and requires its hash and every
external symbol's name, type, value and size to remain unchanged. The final copy must
pass the full path scan, static-link dependency checks and installed C
consumers; debug removal does not authorize a failed scan or missing symbol.

The SDK's exact native static-link tuple adds `bcrypt.lib` and `advapi32.lib`,
required by ring's getrandom 0.2 Windows backend, ahead of the historical tuple.
Legacy package parsing retains the original dependency contract.

The closed schema-4 manifest binds the SDK header/contract, frozen 0.1.5 header,
consumer sources, 37-asset native SDK CBOM, workspace SBOM, target-specific
third-party notices and Rust 1.97.0 standard-library notice. Existing PE checks
still require x64, relocation evidence, ASLR/NX and reproducible-link metadata;
absolute producer paths, unexpected DLL dependencies and payload substitution
remain rejected. These checks do not constitute a constant-time or security audit.
The import library must contain exactly the 43 callable SDK symbols and their
43 import-address symbols. DLL/static-archive export checks remain separate;
testing a subset of functions does not establish the complete import surface.

## Consume the extracted package

The filenames stay `bin/q_periapt_ffi_abi2.dll`,
`lib/q_periapt_ffi_abi2.lib` (import library) and
`lib/q_periapt_ffi_abi2_static.lib` (static library).
Use the installed `include/qperiapt/abi2` headers. CMake consumers use:

```cmake
cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0091 NEW)
project(SdkConsumer C)
find_package(QPeriaptABI2 2.0.0 EXACT CONFIG REQUIRED)
if(NOT QPeriaptABI2_RELEASE_VERSION STREQUAL "0.2.0-alpha.1")
  message(FATAL_ERROR "A matching alpha SDK is required")
endif()
add_executable(sdk-consumer sdk_smoke.c)
target_compile_features(sdk-consumer PRIVATE c_std_11)
target_compile_options(sdk-consumer PRIVATE /W4 /WX)
target_link_options(sdk-consumer PRIVATE /WX)
set_property(TARGET sdk-consumer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
target_link_libraries(sdk-consumer PRIVATE QPeriaptABI2::qperiapt)
add_custom_command(TARGET sdk-consumer POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$<TARGET_FILE:QPeriaptABI2::qperiapt>" "$<TARGET_FILE_DIR:sdk-consumer>")
```

Copy the shipped `share/q-periapt/sdk_smoke.c` into the consumer source directory
and configure with `-DCMAKE_PREFIX_PATH=<extracted-package>`. For static linkage,
select `QPeriaptABI2::qperiapt_static` and omit the DLL copy command. The static
library still uses the dynamic MSVC runtime (`/MD` / `MultiThreadedDLL`), and its
imported target supplies the required native libraries. `/MT` and `/MTd` are
incompatible. CMake ABI compatibility version `2.0.0` is distinct from the
library/package version `0.2.0-alpha.1`.

Owner operations use platform randomness and verified policy input. The shipped
policies and roots are public test material. Applications must provision their
own authenticated trust root and durable policy state. Windows persistent-store
entry points currently return `Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM` and clear the
output handle; no filesystem fallback is provided. The Windows consumer checks
this contract before exercising in-memory owners. See
[ownership](SDK_OWNERSHIP.md) and [host persistence](SDK_HOST_STORE.md).

## Revalidate an archive

Use digests and source identities obtained through a trusted producer record,
not values selected by an untrusted archive itself:

```powershell
artifact/windows-package.ps1 -Profile sdk-alpha1 -Mode VerifyArchive `
  -Archive $archive `
  -ExpectedSha256 $trustedArchiveSha256 `
  -ExpectedManifestSha256 $trustedManifestSha256 `
  -ExpectedContractSha256 $trustedContractSha256 `
  -ExpectedGitCommit $trustedCommit `
  -ExpectedGitTree $trustedTree
```

The verifier extracts to a fresh temporary directory outside the checkout and
links/runs four direct consumers: legacy and owner APIs, each dynamically and
statically. Legacy consumers compile against the frozen 0.1.5 header. Four
additional CMake tests cover those APIs and linkage modes. The selected DLL is
copied beside dynamic executables and checked after execution; static consumers
must not depend on it. An incompatible CRT and wrong CMake compatibility version
are negative controls. Package verification and the outer archive digest are
rechecked after consumption. Failed attempts and outside consumer directories
are retained.

Both `windows-latest` and `windows-2022` CI jobs select this SDK profile, with
their previous source/toolchain checks and separate clean archive consumption.
Their native execution is still an open gate. The current
[release ledger](SDK_0_2_RELEASE_READINESS.md) also retains Linux, device,
minimum-runtime, performance/CT, independent-review and distribution gates.
