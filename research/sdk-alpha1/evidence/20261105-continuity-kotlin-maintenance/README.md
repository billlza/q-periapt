# Installed Kotlin/JVM maintenance-cohort qualification

The complete existing Kotlin/JVM Debug and Release qualifiers passed over the
[completed installed Rust/C foundation](../20261104-continuity-c-maintenance/README.md).
The run started at 2026-11-05 02:30:50 UTC and finished at 06:35:34 UTC:
14,684.181 seconds within the original 18,000-second parent budget. Component
limits remained 900 seconds; JVM command streams retain their stricter 8-MiB
limit, within the shared native command helper's 16-MiB ceiling. No timeout or
stream limit was increased.

The clean qualification checkout is `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`.
Its SDK producer is `f560d803c43a24fff222daa5e5e5bd623bfdf874`, report SHA-256
`93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8`.
Original source inputs, tool installations, SDK archives, C sources, native
binaries and reused build receipts stayed unchanged. The comparison with local
HEAD `852c3108927c7248fa356e2092364b860268a8a3` names six changed selected files
and two added candidate test files: CI export/artifact ordering, Apple packaging
and its consumer/README, and native test-only sources. The selected native
production, C/Kotlin runtime and Kotlin qualifier inputs match. This evidence
remains the named maintenance cohort; it does not run the current candidate's
complete native test suite or qualify a final release.

Both profiles run the installed Kotlin consumer against the archive-derived
native peers. The retained execution includes communication and recovery,
configuration, enrollment/publication, credential and policy maintenance,
account/root lifecycle, retirement, cleanup, explicit cancellation and calibrated
process/fault scenarios. Serial and G1 each execute the existing selected
lifecycle and owner-GC paths in both profiles. This is macOS arm64 with JDK 25
and Gradle 9.8.0; other JVMs and Android ART remain separate.

Three owner-test invocations (publication build, installed Debug, installed
Release) each pass the same 79 cases in 15 suites; the 45 XML reports were
strictly reread. These are three executions of that case inventory, not 237
different tests. Four publication traces were replayed against the exact 85
retained public files per profile/collector. All 74 public-file manifests and
the installed launchers, JARs and native libraries were hash-checked.

The 229 top-level command receipts comprise six copied native-build receipts,
193 new successful commands and 30 new expected rejections. The latter are 15
loader/access/raw-construction negative controls per profile. All 30 exit 1,
emit the required diagnostic and have empty stdout. No unexpected nonzero exit
was observed. The standalone `verify_negative_receipts.py` checks these outcomes
directly from the sealed volumes; `NEGATIVE_READBACK.json` retains its result.
Nested fault and interruption outcomes still use their original scenario
validators and are not reclassified by a zero-exit-only rule.

The capture retains 42,997 selected original output files, totaling 591,974,470
bytes before compression. Every file is covered by the explicit CI upload
selection, every archive member was reread byte-for-byte, and `FILES.json` maps
members to volumes and hashes. All eight volumes remain below 100 MiB:

| Volume | Bytes | Members | SHA-256 |
| --- | ---: | ---: | --- |
| `CAPTURE.zip` | 6,256,087 | 57 | `a5169a50c0e502e2f99f317b346ccc1d8efb271bbae3e066a864e00be51099d2` |
| `DEBUG.zip` | 19,903,522 | 13,335 | `283501abbc425680e0f086279c2cd62b324c1f673da494650647425b5c16cb64` |
| `DEBUG_G1.zip` | 30,335,046 | 4,073 | `459f15a70c25e0c9b28c7ea59e9ebcfbc5d9b71f95f29a263aadcf6e03ff5431` |
| `DEBUG_SERIAL.zip` | 30,373,927 | 4,073 | `b4444389823fb488aaaca17d5eb558e7a07f9fa1f3390e1a116a0ec3232169bd` |
| `PACKAGES.zip` | 10,292,407 | 2 | `cbdca9f645d1db3f689af935546675685b14cfd3bc0c0210a658ece7fbe7fddf` |
| `RELEASE.zip` | 19,956,487 | 13,335 | `534feedb90fed7464d36836cf2197e1c6c8c6bbc94f4ce259bed082a7364f6e5` |
| `RELEASE_G1.zip` | 30,350,936 | 4,073 | `e36393d2b9e8e079274322cffd221e05551d6c8681458c7ea2eb18cb5c40335e` |
| `RELEASE_SERIAL.zip` | 30,392,802 | 4,073 | `3304e2f416efc3affe6cb27481db5287cca5fbc63d7264981c6561bfb71fc5a7` |

`READBACK.json` records provenance, input differences, test/public readbacks and
scope. `ADDITIONAL_SHA256.json` binds the separate rejection-readback script and
result. Private installations, stores and credentials are excluded.

This closes the named local installed Kotlin cohort. Android host JNI,
physical-device/emulator runtime, GNU/Linux, final hosted CI, product ABI
admission, the multi-epoch proof, external review and release remain separate.
No workflow, remote branch or release was changed.
