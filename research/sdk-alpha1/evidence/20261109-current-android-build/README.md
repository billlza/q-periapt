# Current-source Continuity Android build integration

This increment connects the formal 0.2.0 assembler to a current-source native
and Java producer. The installed-Android workflow adds an independent
`continuity-android-aar-arm64` job against its existing selected SDK cohort.
Successful execution produces original compilation receipts, an input selection,
the Maven/AAR capsule, and an independent reopening result.

The retained 6 November capsule was recovered and verified byte-for-byte before
the build recipe was adapted. `RECIPE_PROVENANCE.json` records its 11,107,856-byte
size, SHA-256, Git blob identity, 707-member inventory, successful driver hashes
and native Cargo/Clippy/strip command comparisons. The historical `0.0.0`
libraries are evidence of that recipe; the new producer does not consume them.

## Implemented behavior

The producer admits the exact SDK report, packages the current 0.2.0 engine,
and builds a fresh installed C/JNI source graph outside the checkout. It carries
the corrected account-root and private-build path remapping, API 23/NDK r29
tool selection, 16 KiB linker geometry, strict compiler/Clippy settings and
Java 25 `--release 11` compilation into explicit inputs. Source/tool/lockfile
rereads and the existing 158-export, JNI descriptor, class, ELF and license
readers precede successful receipts. The assembler also now includes the four
current mlkem-native vendor notices retained by the historical producer.

Independent code review identified two issues before publication: failure
streams were lost on the shared command helper's timeout path, and inherited
Git selectors could reach candidate source enumeration. The producer now
retains bounded partial streams and typed failure receipts, uses explicit
command budgets, strips inherited Git configuration, invokes fixed Git against
the admitted checkout, and compares its result with the captured inventory.
The final fixed command ceilings sum to 8,340 seconds; the CI job separately
limits setup, execution and artifact retention to 210 minutes.

## Validation

The hardened Python entrypoint passed **35 tests**: 14 producer controls and
21 assembler controls. These include complete simulated compilation through
the real AAR/Maven writer and independent reader, changed-source rejection,
native/Java failure propagation, exact vendor notices, explicit toolchain
selection and inherited-environment rejection. A real short subprocess timeout
verified retention of stdout, stderr and the typed timeout receipt. The workflow
parsed as YAML and all six Bash run blocks passed `bash -n`.

`VALIDATION.json` and the original test streams identify this implementation
validation. Native and Java compiler outputs in the orchestration tests are
explicitly synthetic. Actual compilation of the selected source is the new CI
job's execution step; its `BUILD.json`, native/class receipts and capsule hashes
provide the corresponding artifact evidence. Installed AAR/R8 and ART/device
execution attach to those exact outputs in their existing qualification lanes.
