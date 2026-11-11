# Current installed Debug host-JNI qualification

The original Debug Rust/C/host-JNI partition completes at source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Its controller exits zero at
2026-11-06 03:01:23 UTC, after 13,441.95 seconds, with empty stderr.
Independent checks bind its installed inputs and actual binaries and reproduce
twenty public outcome groups. A further archive-only execution uses the captured
reader source and public records and obtains the same results.

Together with the separately retained [Release partition](../20261106-current-jni-release/README.md),
both current local host-JNI profiles have completed. [PAIR_IDENTITY.json](PAIR_IDENTITY.json)
checks their identical 1,401 source inputs, 146 JNI adapter sources, SDK report,
candidate archive and Java JAR. This pair relation is not the original complete
six-partition Swift/Kotlin/JNI coverage join.

The original report retains `partition_completed=true`, `completed=false` and
`build_profiles=["debug"]`. Requested consumers remain Rust, C and `AndroidJNI`.
The run uses the original component gates and 900-second component limits, with
no custom test selection or increased timeout. The earlier `ff072` aggregate
timeout remains failed on its original lineage.

## Execution and byte identity

- The SDK report digest is
  `1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`.
  The candidate digest is
  `0730aa20794527b3947dc4734bf82d48516294c42018dc8dfd23ebc5f42fc2a6`,
  with 769 members. Both installed consumer graphs, their candidate trees and
  their nine SDK trees are checked against the actual archives.
- The 70-test harness catalog is exact. Its 67 JNI-specific tests pass in 36
  invocations, without duplicate tests. The three shared Rust fixture entries
  remain outside this JNI census. The separate actual `BridgeProbe` invocation
  passes with `-Xcheck:jni` and empty stderr.
- All seven actual native binaries are verified and retained, totaling
  65,703,872 bytes before compression: C library, JNI bridge, C receiver,
  policy-target client, Android test helper and two recovery helpers.
  The JNI bridge digest is
  `dc30c73cad363ee074fba86cb2353ab9c6880aa298849a05a427350aeedbbe6c`.
- The JAR contains 131 Java 11 classes, with digest
  `4d4c77e63975a693155e3693e6c76349e8df54c930af3a807b31529800126d0a`.
  All 51 actual test-class files and the selected JDK identity are checked.

The original readers reproduce registration, message retry, rekey, reverse
callbacks, cancellation, account delivery/recovery, retirement, five root-change
routes, roster changes, policy/credential renewal, pending-write recovery,
required-Witness outcomes and successive joint-policy cycles. Each reader
retains its original process counts, identity, effect and refusal checks.
Process interruption is not relabeled as physical power loss, and same-host
execution is not cross-host or Android ART evidence.

## Public capture and replay

[CAPTURE.zip](CAPTURE.zip) contains 16,096 members and is 68,428,550 bytes.
Its SHA-256 is
`34d8bd3844f51a3a6b748be5911d7dd7d9e7d8a5986371ae298ff63ef39f1cf1`.
It retains final reports, original public exports and command receipts, the seven
native binaries, Java classes, ten consumed archives, relevant source/readers
and controllers. Private runtime stores and generated private keys are excluded.
[FILES.json](FILES.json) pins every member; all members are reread after capture.

[IDENTITY.json](IDENTITY.json) records the source/package/native checks.
[PUBLIC_READBACK.json](PUBLIC_READBACK.json) records the first twenty-group
readback, including 4,376 reconstructed public files and 69 Git-matched reader
modules. Its receipt-only labels delimit that public reader; the identity check
separately verifies the actual binary bytes.

The archive replay materializes 15,543 original public/report/command members
and 461 source members. It extracts the original source-only Python dispatcher,
changes only the mapper's input directory to the extracted records, and runs
the same original reader functions. All twenty outcomes and the complete
readback record equal the initial result. It does not invoke a native workload
or access the private runtime.

[ARCHIVE_REPLAY.json](ARCHIVE_REPLAY.json) retains that result;
[ARCHIVE_CHECKS.json](ARCHIVE_CHECKS.json) and
[STANDALONE_REPLAY.json](STANDALONE_REPLAY.json) describe the same single
captured-source-only replay, not two separate executions.
The [mapper](archive_replay.py), [replay driver](replay-capsule.py), command and
stdout/stderr are retained. To repeat it, copy `CAPTURE.zip`, `CAPTURE.json` and
`FILES.json` into a fresh directory, then run the driver through the repository's
isolated `artifact/python-run.sh` with the copied absolute capsule/manifest paths
and a fresh work-directory path. The driver exclusively creates result files
beside that copied capsule and does not overwrite the retained results here.

The Debug capture adapts the already validated Release capture's explicit
profile/report paths. It does not copy or relabel Release execution evidence.
Release-specific diagnostic failures remain in the Release capsule. No product
source or original validator is changed.

This closes the current Debug partition and establishes both local host-JNI
profiles at the stated source. Android AAR/APK builds, actual ART/device
execution, the complete foreign-profile join, final hosted CI, resource budgets,
protocol proof, contract/ABI admission, external review and authorized release
retain their separate requirements.
