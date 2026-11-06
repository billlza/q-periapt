# Current Android arm64 candidate AAR: build and independent static readback

The candidate at `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8` now has a
source-bound Android arm64 AAR built from the actual installed SDK and candidate
archives. A separate reader reopens the resulting AAR and verifies its native
libraries, Java classes, JNI declarations, consumer rules and licenses. This is
build/static evidence; APK consumption, ART execution and execution on the
already accepted phone remain separate requirements.

## Inputs and successful output

The matching SDK report has SHA-256
`1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`.
The driver installs nine SDK archives and the candidate outside the checkout,
validates the installed dependency graph, and copies the existing C and Android
consumer sources. The 1,401 package input files are unchanged. No product source,
cryptographic primitive, native API or protocol changes in this experiment.

Rust 1.98.1 and NDK `29.0.14206865` build the Release `aarch64-linux-android`
libraries at the existing API 23 compile floor. The strict Clippy and native
compiler checks pass. Java sources compile with the existing private JDK
25.0.5+8, `--release 11` and warnings denied. This compile floor does not establish
API 23 runtime qualification.

The successful `package-02/q-periapt-continuity-android-0.0.0.aar` contains 229
members and is 10,697,112 bytes, SHA-256
`a21d016d0cbe69dc7bb363c488ce9d984017625ea811c17218dea4e60ab66c7e`.

| Actual AAR member | Bytes | SHA-256 |
| --- | ---: | --- |
| C library | 7,593,672 | `0da4666ab9585381f90962b09cbaa44267af725fc0f59cb664278d873810b290` |
| JNI library | 77,888 | `a66d3f18d2fba081d79681e654f84270791f5feaa317841dc8abaaf1aeb6f4d5` |
| `classes.jar` | See package inventory | `4d4c77e63975a693155e3693e6c76349e8df54c930af3a807b31529800126d0a` |

The independent readback checks all 158 C exports, the JNI library's sole
`JNI_OnLoad` export, exact SONAME and dependency sets, RELRO/NOW, non-executable
stack, stripped sections and no RPATH/RUNPATH/TEXTREL. Every LOAD segment meets
the 16 KiB alignment requirement. Both Android notes identify API 23 and NDK
`r29/14206865`; release binary scans pass. ELF alignment alone is not a 16 KiB
device or APK-installation result.

All 131 classes from 68 Java files match the class bytes in the current host-JNI
build. `javap` descriptors match all 23 native registrations and three static
callbacks in the actual C source. This byte comparison does not assert that the
still-running aggregate host-JNI gate has finished. The original keep rule and
target-specific third-party license inventory are also checked.

## Preserved failure and correction

The first native build passed compilation and ELF checks, but its independent
release scan rejected the C library for an embedded account-root path from
`rustls-0.23.46/src/server/hs.rs` in the Cargo registry. The diagnostic driver had
remapped its outside consumer directory but omitted the account-root remapping
already required by the existing Android release producer. The initial AAR,
binary bytes, command logs and failure remain in the capsule.

The corrected driver remaps both paths, under unchanged source, dependency and
tool pins, and now runs the release scan before reporting native-build success.
A fresh native build, package and independent readback pass. No scanner rule is
relaxed. [PATH_REMAP_FAILURE.json](PATH_REMAP_FAILURE.json) records the initial
binary digest, byte offset and redacted source-path classification.

## Private tool preparation

NDK r29 is the existing repository pin, selected from the official Android
repository metadata rather than upgraded. Its 1,049,519,838-byte download matches
the publisher SHA-1 before extraction. Its observed SHA-256 is
`ce5e4b100ec5fe5be4eb3edcb2c02528824ff9cda3860f5304619be6c3da34d3`.
The archive path/type/link checks, installed file inventory and notices are
retained. Although the NDK directory is named `darwin-x86_64`, its universal Clang
contains and executes the arm64 slice; this is not Intel Mac adaptation.

A project-private copy of the existing Rust 1.98.1 toolchain receives only the
matching Android standard library. The original toolchain remains unchanged;
there is no global installation or rustup registration. The first download was
truncated and failed the original SHA-256. Full decompression confirmed premature
EOF; the origin/cache/transfer cause is not established. The failed bytes and
diagnostics remain local. Official checksum and release metadata independently
confirm the same pin. One bounded fresh attempt produces 29,448,296 bytes with
SHA-256 `d7c4949bb77b007bed188c9b15b8267a3222dc9b9c517f05d1899f9e885fb79e`.
Only that verified archive is installed; no checksum or acceptance rule changes.

## Retention and remaining acceptance

[CAPTURE.zip](CAPTURE.zip) contains 707 byte-verified members and is 11,107,856
bytes, SHA-256
`bf8531f2b2ede8c9c5f554b9a086fc2af30acf771dacb19aa9ac4f2e50d7bb1b`.
It retains both AARs, build and readback reports/logs, diagnostic drivers, relevant
source/readers, tool preparation receipts and notices. [FILES.json](FILES.json)
pins every member; [READBACK.json](READBACK.json) is the separate successful
readback of the actual second AAR. Every captured member was reread after capture;
the tool-dependent independent reader ran against the actual AAR before capture.
No archive-only repetition of the native tools is claimed.

The large NDK and Rust downloads, including the unique failed Rust download, are
kept locally at the paths in [CAPTURE.json](CAPTURE.json). This capsule includes
their verification records, not those large tool archives. It contains no phone
inventory, device-account data or generated private protocol stores.

Only `arm64-v8a` is built here. This does not qualify the base SDK's other ABI
lanes, freeze a support matrix, admit Continuity into product ABI 2 or publish a
package. The candidate still uses `qpc-owner/1` and version `0.0.0`. Actual APK
consumption, applicable shrinker/runtime boundaries and the accepted phone's
necessary final-change validation remain open, alongside the full release
requirements. No second phone, API 36 requirement or device action is introduced.
