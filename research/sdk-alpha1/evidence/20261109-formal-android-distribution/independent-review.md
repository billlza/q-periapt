# Independent review: Continuity Android 0.2.0 distribution

**Disposition: passed for the bounded local assembly and static readback increment.**
The final source/test/document bytes are listed in `independent-review.json`.
The reviewed implementation connects the selected formal identity to AAR/Maven
construction and the existing release-manifest distribution schema. All findings
raised during this review have verified fixes.

## Verified result

The producer binds an independently supplied selection hash to six distinct input
snapshots and their original compilation reports. It binds the clean source
checkout by commit, Git tree and canonical SHA-256, reads Java sources from one
captured inventory, and hashes the exact 76 consumed source snapshots, including
68 main Java files, into its final source check. AAR, Maven, source-archive and
receipt verification use exact inventories and byte pins. The completed local
capsule contains 19 payload files plus its separately selectable assessment.

I independently compared all 23 JNI registration descriptors to their actual C
prototypes and Java native declarations; all match. The three callback descriptors
also match their Java definitions. The class reader checks bounded classfile
framing and package/JNI identities. The selected C ABI snapshot/header and export
set remain the current 158-function owner interface.

The shared ELF guard now checks power-of-two alignment and congruent file offset
and virtual address, in addition to its 16 KiB minimum. The producer also checks
binary LOAD table bounds, file/memory ranges, API 23 and NDK identity notes,
SONAME/dependencies, release sections and linker protections. I inspected the
retained 6 November `READBACK.json` to confirm the exact current Android dependency
sets; its `0.0.0` artifact identity and original hashes remain historical evidence.

## Findings closed

| Finding | Verified correction |
| --- | --- |
| The inherited shared ELF guard accepted `p_align = 0x6000` and incongruent LOAD offset/address values. | `android_elf.verify_program_headers` rejects both cases, with focused regressions; the new binary reader independently enforces the same geometry. |
| A replace/read/restore of a Java source could leave the worktree unchanged while packaging different captured bytes. | The final canonical digest uses the consumed snapshots. An independent copied-Git fixture now changes the bound digest after transient capture even though the original clean disk contents have been restored. |
| Live Java enumeration could omit a temporarily missing tracked file and still match the restored checkout. | One captured path list drives both source reads and identity checks. Missing captured files fail; a shortened list is rejected after restoration. |
| A failed output readback could leave a producer-created partial capsule. | Exclusive creation establishes output ownership; caught write/readback errors and Python interrupts remove that directory. A regression also confirms pre-existing output and sibling evidence remain intact. |

## Independent execution

I ran the documented hardened source-only launcher:

```sh
sh artifact/python-run.sh -m unittest -v \
  test_continuity_android_distribution test_android_elf
```

All **64 tests passed** in 6.811 seconds. The composed test executes production and
separate readback using a real temporary Git fixture and explicit LLVM inspection
doubles, checks the existing release verifier's acceptance of
`PACKAGE_IDENTITY.json`, and rejects native-input or selection changes between
initial capture and final reread. The pinned `independent-tests.log` records that
run. The parent reviewer separately recorded the same five production/test file
hashes before and after its own successful 64-test run.

The additional `independent_controls.py` takes the repository root as its sole
argument. I ran it with isolated Python startup, disabled bytecode writes and a
fresh private bytecode prefix. Its pinned result records the two copied-source
race controls, an additional shortened-inventory control, eight archive
path/duplicate/mode/size faults, shared ELF geometry cases and the independent
C/Java JNI correspondence check.

This evidence establishes the construction/static-verification increment.
Synthetic ELF/class fixtures and LLVM doubles are identified explicitly; fresh
Android native/Java compilation and installed consumer, R8 and device execution
remain attached to their own selected artifact reports. The producer retains
those distinctions in its assessment and performs no registry publication.
Fresh output ownership and cleanup are local workspace guarantees; process-loss
recovery is handled by complete capsule verification, as documented.
