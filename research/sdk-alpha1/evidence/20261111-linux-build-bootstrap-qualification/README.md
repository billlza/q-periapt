# Five-runner Linux build bootstrap qualification

Run [43057408847](https://github.com/billlza/q-periapt/actions/runs/43057408847),
attempt 1, completed successfully on all five runners. The five original ZIPs
match their GitHub artifact sizes and SHA-256 digests; all 25 expected receipts
were read back. Each runner checked out source
`251bc2ab4cc488543a5516785f3ac9788b681a0b`, tree
`19a5a6abb8942f146f0f8b3f0cc7d9bd4ad272f1`, and passed the final clean-source check.

## Actual consumers and timings

All five runners compiled the repository's existing
`bindings/c/ContinuityPackageConsumer/witness_tls_peer.c` through CMake and
PkgConfig, with C11 and warnings treated as errors, then executed its identity
consumer through CTest. Every platform passed 1/1 tests, with matching OpenSSL
header and runtime version output.

| Runner | Image version | CMake / pkg-config | OpenSSL | Checkout | CMake consumer | Job total |
| --- | --- | --- | --- | ---: | ---: | ---: |
| Ubuntu 22.04 x86_64 | 20261101.347.1 | 3.31.6 / 1.8.0 | 3.0.2 | 186 s | 3 s | 193 s |
| Ubuntu 22.04 ARM64 | 20261101.179.1 | 3.31.6 / 0.29.2 | 3.0.2 | 234 s | 5 s | 244 s |
| Ubuntu 24.04 x86_64 | 20261101.360.1 | 3.31.6 / 1.8.1 | 3.0.13 | 314 s | 8 s | 379 s |
| Ubuntu 24.04 ARM64 | 20261101.172.1 | 3.31.6 / 1.8.1 | 3.0.13 | 173 s | 4 s | 200 s |
| Ubuntu 26.04 x86_64 | 20261101.186.1 | 4.4.5 / 2.5.1 | 3.5.5 | 172 s | 2 s | 178 s |

The table uses GitHub's step/job timestamps at one-second resolution. The
retained `/usr/bin/time` receipts give the following measured dependency times:

| Operation | Wall time | Execution result |
| --- | ---: | --- |
| Fixed protoc download, authentication, version and schema | 0.79 s | libprotoc 3.21.12; standard timestamp schema import compiled |
| Ubuntu 24 x86 cross-compiler/QEMU APT update and install | 42.07 s | AArch64 and RISC-V compiled and executed successfully under QEMU |
| Ubuntu 24 ARM Valgrind APT update and install | 14.30 s | Compiled Memcheck client executed with zero errors/contexts |

The protoc receipt records 1,585,982 archive bytes and SHA-256
`3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8`.
Its generated descriptor SHA-256,
`5f6b77aa321f19c4ba89552f04b8302b642d9cb4db4d2c8ac148c207305f0e43`,
matches the independent local execution. The following workflow step verified
that `command -v protoc` resolves to the exported PROTOC, checked its exact
version, compiled and executed an OpenSSL-linked C program, and compiled a
nonempty wasm32 object with runner clang 18.1.3.

The cross lane accepted all four Noble InRelease pockets from the Linux Kernel
Archives mirror under the fixed helper's Ubuntu archive keyring/Signed-By and
authenticated APT policy. GCC 13.3.0 compiled both targets; QEMU 8.2.2 executed
both binaries, each producing `CROSS_CONSUMER_OK`. The ARM lane used the OCF
Ubuntu Ports mirror with the same policy, installed Valgrind 3.22.0, compiled a
program using its actual Memcheck header/client request, and reported
`ERROR SUMMARY: 0 errors from 0 contexts`.

These are observed times from this run. Checkout accounts for most of the
remaining job duration; it is reported separately from dependency preparation.

## Source and SDK integration

The diagnostic commit is `6a9b8bcfc10855db8b7487c3b463aa394afbc5ee`, tree
`8629a09ddd64447627b3c34ce891b91ef3926b14`. `WORKFLOW.yml` retains its exact
6,911-byte workflow, Git blob `0808228c97da7423ddc913218c24abf3ba2dc89f`.
`SOURCE_CONTRACT.json` fixes the source/diagnostic identities and eight executed
or locally tested source-file pins. The two small dependency helpers are also
retained as exact source snapshots.

SDK integration commit
[`2f42d2ce913421f9b7a7df39fbc56845d55717de`](https://github.com/billlza/q-periapt/commit/2f42d2ce913421f9b7a7df39fbc56845d55717de),
tree `81e8aa8047e9e54e9f98ea18fc25c616cb557425`, directly follows the qualified
source. Its complete changed-file list consists of three existing Markdown
files: `artifact/codeql_summary_projection.md`,
`docs/SDK_0_2_RELEASE_READINESS.md`, and `docs/SDK_INTERNAL_REVIEW.md`.
The implementation and workflow inputs therefore remain the qualified source
bytes. The original integration commit API response is retained.

## Retained evidence and independent readback

`artifacts/` contains all five original ZIPs, totaling 14,652 bytes; `jobs/`
contains the five complete original job logs. The final run/jobs/artifact API
receipts, public source/diagnostic commit identities, SDK integration mapping,
member hashes and all stage times accompany them.

`local/` retains the original 15 passing protoc/workflow controls, the original
local protoc receipt, and the 13 APT fixture controls with their procedure.
`LOCAL_VALIDATION.json` records the official protoc release/asset identity and
hashes of the larger originals retained separately. The older upstream release
API has no digest field; the fixed protoc SHA-256 was calculated from the
official HTTPS bytes and checked in both local and hosted execution. Full
protoc and package-index archives are not duplicated in this packet.

Run `python3 readback.py` in this directory to validate the retained original
ZIPs, member sets, source identities, all job/step outcomes, compiler/consumer
receipts, exact local-to-hosted descriptor equality, and integration mapping.
The script only reads retained evidence and writes `READBACK.json` and
`ARTIFACT_MEMBERS.json`; it starts no download, compiler, APT or query process.
`MANIFEST.sha256` identifies every retained file except the manifest itself.
