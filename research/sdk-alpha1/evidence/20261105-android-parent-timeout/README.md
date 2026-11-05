# Android host JNI parent-budget failure

The original run did **not** qualify the complete Android host JNI cohort. Its
fixed 18,000-second parent budget expired at 2026-11-05 11:57:52 UTC while
`android-jni-release-joint-cycle` was running. The parent started at
06:57:52 UTC and reported 18,000.014 seconds elapsed. Component limits remained
900 seconds and 16 MiB per stream. No bound was increased and no test was
skipped or relabelled as successful.

The output contains 111 terminal command receipts with return code zero: six
reused native-foundation build receipts and 105 commands completed during this
run. The driver stream has 106 starts and 105 ends. The last command receipt
has no return code; its stdout only records six tests still running. Neither
`DRIVER_RESULT.json` nor `ANDROID_JNI_CONSUMER.json` exists. These are command
counts, not a claim that the aggregate test suite passed.

The qualified source attempt is
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`, using the immutable installed C
foundation and real host JNI bridge on macOS arm64. This is not Android ART,
an emulator, AAR device execution, or a release acceptance result.

## Cleanup observation and minimal reproduction

Although the parent error reported `cleanup_ambiguous: false`, an actual owned
test process remained in a separate process group, PID/PGID 64151, reparented
to PID 1. Its exact executable and arguments matched the interrupted Release
cycle. At 12:00:14 UTC it was explicitly terminated with SIGTERM; the follow-up
process inventory was empty. Its later execution cannot complete the original
expired qualification. The original timeout record is unchanged.

The process primitive creates a new session for every bounded child and kills
the parent's unreaped process group with SIGKILL on timeout. In this nested
orchestration, that kills the intermediate Python owner before its cleanup can
reach a lower independent group. The parent's group cleanup flag does not
establish cleanup of the whole orchestration.

An isolated two-second reproduction using the unchanged
`artifact/bounded_process.py` reproduced a live lower group after the outer
timeout, again with `cleanup_ambiguous: false`. It used only small Python
processes and no product state. The lower group was explicitly terminated and
its disappearance verified. Source SHA-256:
`7657c29d707fc8b7685cfec7f0be43615868543ba42345c8626fdb04d00cfa45`.
This confirms the composition failure; no process-supervision repair is claimed
in this evidence commit.

The first small reproduction incorrectly assumed the leaf interpreter's PID
must equal its group ID despite the shell bootstrap. Its failed assertion,
leaf metadata and cleanup result are retained. The corrected reproduction
checks the actual group membership. The first archive reader also mistook
file prefixes for directory matches after stripping `/**`; the corrected
reader preserves the trailing directory separator and still requires equality
with the entire actual output file set.

## Preserved artifacts

All 29,197 output files were selected by the existing workflow's public
artifact patterns. Eight completed public manifests were checked against their
closed file inventories. The three archives were CRC checked and every member
read back against the original file and `FILES.json` hash. Private fixture
keys and mutable private storage remain on the local test installation and are
not exported. The unexecuted complete-run sealer remains retained; its success
conditions were not relaxed to admit this timeout.

| Archive | Bytes | Members | SHA-256 |
| --- | ---: | ---: | --- |
| CAPTURE.zip | 2,372,072 | 54 | `a0a72b30b28e7b6102e4899b3f4cabc5bca1ccffd672c124d9416aa3bec4a682` |
| DEBUG.zip | 34,720,179 | 15,520 | `9216e36dcd1428f0a3d688e74347b8868053a69e282999def4728ea3ac059d6c` |
| RELEASE.zip | 32,646,598 | 13,656 | `b56a68d8006f4311c879d8ef980f2e89c7b4731b04427dba1fa2b392cdf6710f` |

Remaining work includes safe nested cancellation/cleanup, a bounded validation
plan for the unfinished cycle, and actual aggregate/platform acceptance. The
partial results are retained as evidence, not converted into completion.
