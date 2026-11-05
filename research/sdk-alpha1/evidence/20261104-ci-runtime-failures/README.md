# Current installed and Android CI failures

The 09:44 UTC GitHub connector refresh retained all generated jobs for the
current #117/#118 heads and the latest separate independent run. Across the
twelve current-head runs there were 249 successful, 63 queued, 12 running,
six failed and two skipped jobs. Pending, failed and skipped work is not a pass.
The #117 Windows lifecycle run completed all eight jobs successfully; that
result has its own source/platform scope. No workflow was triggered or rerun.

The retained 10:19 UTC refresh has 258 successes, 63 queued, two running,
seven failures and two skipped jobs across those same twelve runs. The two
remaining running jobs execute the Debug capacity scenario. The separate
independent run remains at two successes and two queued jobs on `adaaeb49`.
Both PR heads are unchanged. This refresh preserves the earlier snapshot.

At 10:37:14–10:37:19 UTC, both remaining capacity jobs had completed successfully:
`126446853903` and `126446832265`. The twelve-run totals are now 260 successes,
63 queued, seven failures and two skipped jobs, with none running. The separate
independent run still has two successes and two queued jobs. Queued work keeps
the current effective wave open; no next wave or bounded retry has been started.

Four installed Rust/C jobs now demonstrate the P0 acceptance omission in CI:

| Run / job | Actual checkout from the job log | Failure |
| --- | --- | --- |
| `41791511701` / `126449257936` | `475cd23923e45819b01b6041c91c44540ec056ec` | OpenSSL server exchange census |
| `41791519877` / `126456505939` | PR merge `9aa535b48b464ec4d4a8b5a4b20221049a6067b9` | OpenSSL server exchange census |
| `41791854684` / `126463649638` | `6084f3bfb09333f6b66291b38809ed512296a27b` | OpenSSL server exchange census |
| `41791861104` / `126489776539` | PR merge `59bde0fd1a268de4d0e183c33bf3fc5e09c9be97` | OpenSSL server exchange census |

Each complete log ends at the old exact-count validator, after the native test
command completed. The old collector did not export the rejected server report
and trace, so these logs do not independently disclose the hosted count. The
[local Debug/Release reproduction](../20261104-openssl-witness-census/README.md)
observes exactly 146 and checks the old/new validators against the same bytes.
The correction is prepared on the #117 lineage at `232ace17` and merged into
the local directory work without rewriting either lineage. Parent-line checker
regressions also pass. Hosted execution of that correction remains pending;
rerunning unchanged old code would not resolve this defect.

Two Android API 35 / x86_64 / 16-KiB jobs have distinct failure records:

- Push job `126459839388`, checkout `6084f3bf`, first returned all three full
  consumer instrumentation results. The minimal consumer's APK installation
  then reported success and one exact readback. Subsequent copies returned
  2,952,704 and zero bytes instead of 13,817,559, followed by loss of the owned
  emulator transport. Its single existing transport recovery did not restore
  stable observations. The minimal workload did not execute and app cleanup
  remained unresolved. Artifact `13310700754` preserves both run directories.
- PR job `126480103487`, merge checkout `59bde0fd1a268de4d0e183c33bf3fc5e09c9be97`,
  failed during full-consumer instrumentation. The guest logs record a
  `system_server` SIGSEGV, a framework `NoSuchMethodError` in `GnssNative`, and
  SystemUI's `DeadSystemException`. `system_server` changed from PID 549 to 4777
  while the retained kernel boot identity stayed unchanged. No SDK pass was
  admitted. Artifact `13310830544` retains the original observations.

These are observed guest-framework and transport failures, consistent with the
already documented [environment limitation](../../../../docs/SDK_ANDROID_RUNTIME.md).
They do not establish the underlying image/ART defect or a causal relationship
between lowmemorykiller activity and transport loss. Point memory samples are
not peak usage; kernel counter units are not inferred from application page size.
No RAM, deadline, page-size, ABI or physical-device requirement was changed.
The result is separate from macOS host JNI and physical Android qualification.

The bounded recovery plan is one rerun of each failed emulator job after the
current effective wave ends, keeping the exact input and acceptance contracts.
A repeated failure is retained and investigated, not automatically looped or
counted as a product pass. The previous policy-maintenance download failure
(`126463649767`, `ECONNRESET`) remains separately recorded in the
[earlier audit](../20261104-ci-audit/README.md), with the same one-job retry bound.

`CLASSIFICATION.json` records the exact jobs, checkout IDs, diagnostic hashes and
recovery boundaries. `CAPTURE.zip` retains the original thirteen complete job
inventories, five complete failure logs, both original Android diagnostic ZIPs
and snapshot index. Its `refresh-1019` directory adds thirteen refreshed job
inventories, the fourth installed-failure log and an index with current PR heads.
The `refresh-1038` directory retains the thirteen inventories and exact observation
interval of the 10:37 refresh. All 50 members were read back byte-for-byte;
`SHA256.json` pins them. The signed temporary download URLs are not retained.

## Later Android-labelled host prerequisite failure

The 22:33:57 UTC refresh contains 287 successful, 31 queued, four running,
eight failed and two skipped jobs across the same twelve runs. The newly finished
[Android Release job 126489776722](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/126489776722)
is a **fifth observed P0 count-check failure**. Its metadata head is `6084f3bf`;
the actual package receipt and checkout use PR merge
`59bde0fd1a268de4d0e183c33bf3fc5e09c9be97`.

The full traceback stops inside `qualify_c` at the old OpenSSL server expectation
`report["witness_exchanges"] == 142`. The retained native Release command finished
in 3.01 seconds with one test passed, zero failures and empty stderr; the subsequent
collector rejected its report. `C_CONSUMER.json` and `CONTINUITY_PACKAGE.json`
both remain incomplete. The Android JNI qualifier had not been entered, and no
Android consumer receipt exists in the artifact. This is a macOS C/OpenSSL
prerequisite failure, not an Android emulator or physical-device failure.

Artifact `13367958301` contains 17,722 members, 47,614,735 bytes, SHA-256
`75ff00efb06f1c20bbfd4bc0156c28ff5cf8af9b6747fa618e9d18a55061261d`.
The complete downloaded artifact remains local. As in the earlier failed jobs,
the old collector did not export the rejected private server report or negotiation
trace. Therefore this job does not independently establish the hosted numerical
count; the exact 146 observation remains the separately identified local evidence.

`late-android-release/CAPTURE.zip` preserves the complete job log, job and wave
inventories, both incomplete receipts and the exact native command records.
Its 12 members were reread byte-for-byte; its SHA-256 is
`599f7f6978ffd8ac0403da83dafab446bb694858d70719d3513228ca244d16e5`.
An initial read-only preparation wrongly required ZIP member enumeration order;
that failed assertion is retained, and the final capture checks the exact set and
each original member's bytes. No runtime verifier or test was changed.
The effective wave remains open. No cancellation, rerun, push or new wave was
performed; unchanged old code is not rerun as a remedy for this count omission.

## Three additional host prerequisite failures

At 23:21:10 UTC, the same twelve runs contain 287 successful, 30 queued, two
running, 11 failed and two skipped jobs. Both PR heads remain at the task's
original `475cd239` / `6084f3bf` commits. Three further completed logs stop at
the old `report["witness_exchanges"] == 142` check inside `qualify_c`:

| Job | Label | Actual checkout |
| --- | --- | --- |
| [126489776791](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/126489776791) | Kotlin Debug | `59bde0fd1a268de4d0e183c33bf3fc5e09c9be97` |
| [126463649748](https://github.com/billlza/q-periapt/actions/runs/41791854684/job/126463649748) | Android Release | `6084f3bfb09333f6b66291b38809ed512296a27b` |
| [126463649756](https://github.com/billlza/q-periapt/actions/runs/41791854684/job/126463649756) | Android Debug | `6084f3bfb09333f6b66291b38809ed512296a27b` |

The exact terminal error in all three is `OpenSSL server exchange census
differs`. This brings the observed instances of the existing P0 validator defect
to eight. The labels do not turn these macOS C/OpenSSL prerequisite failures
into Kotlin, Android JNI, emulator or physical-device results. The rejected
report and trace are not present in the complete job logs, so no hosted count
or native test-result assertion is added by this capture.

`late-host-prerequisites/CAPTURE.zip` preserves all three complete logs, their
job metadata and the twelve-run inventory. The ten members were read back
byte-for-byte; the 128,303-byte ZIP has SHA-256
`ae8d3b3ddae3909e06c5e83121333ec2eb279210e7d6e1b836aa1e641e7e915a`.
Artifact IDs and upload digests are retained as reported in the logs; those
three artifacts were not downloaded for this classification. The correction's
separate local execution evidence remains linked above. The wave is still open,
and no push, rerun, cancellation or new workflow was performed.

At 23:38:11 UTC, push-side [Kotlin Debug job 126463649730](https://github.com/billlza/q-periapt/actions/runs/41791854684/job/126463649730)
had also failed at that same C/OpenSSL check on checkout `6084f3bf`. Its complete
traceback is the ninth observed instance of the P0 omission. The twelve-run
inventory now contains 287 successful, 30 queued, one running, 12 failed and two
skipped jobs; the wave remains open. This adds no Kotlin runtime or hosted-count
claim. `late-kotlin-debug/CAPTURE.zip` retains the complete log, job and wave
inventories and classification. All six members were reread; its 97,461 bytes
have SHA-256 `2b7bb005229fc6135a223fc957840db4f47f40205170d880ce0d0733a4830312`.
No remote workflow or branch was changed.

At 2026-11-05 00:14:35 UTC, PR-side [Android Debug job 126489776821](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/126489776821)
has the same old-count failure on merge checkout `59bde0fd`. The complete log
therefore records the tenth observed P0 checker failure, without disclosing the
hosted count or establishing Android JNI execution. The twelve-run snapshot has
287 successes, 30 queued, 13 failures and two skips, with no job currently running.
Queued work still keeps this effective wave open. `late-android-debug/CAPTURE.zip`
retains the complete log, metadata and snapshot: six verified members, 96,266 bytes,
SHA-256 `d9b871eb02e536fa49e283b8faa062570fa3a055f592c38116329748fdfad276`.

Separately, the corrected maintenance cohort has now passed the
[complete local installed Rust/C Debug+Release gate](../20261104-continuity-c-maintenance/README.md),
including exact 146-server/2-client OpenSSL readback in both profiles. This is
new local evidence for its explicitly pinned source, not a reinterpretation of
any failed hosted job. No queued job was cancelled or counted as passed.

At 2026-11-05 01:44:27 UTC, PR-side [Swift Debug job 126489776864](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/126489776864)
has completed with the same old `== 142` C/OpenSSL prerequisite error on merge
checkout `59bde0fd`. This is the eleventh observed P0 checker failure. The
traceback stops inside `qualify_c`, before the Swift consumer runs; the complete
log still does not disclose the hosted server count. Its upload metadata records
artifact 13379233502, 47,532,656 bytes, digest
`d84f915e5747d8f78963b7911f12f67375ca1948aa12780a8d18620df670ee5d`.
That artifact was not downloaded for this classification.

The latest snapshot contains 288 successes, 25 queued, three running, 14 failures
and two skips. It refreshes all four open CI runs and both unchanged PR heads;
the eight completed runs' terminal job rows are explicitly retained from the
preceding inventory. `late-swift-debug/CAPTURE.zip` preserves the full decoded
job log, step metadata, snapshot and classification. All six members were
reread: 28,614 bytes, SHA-256
`92bf77064b36a80889fb3d5bfec001048b5a644c0bcca0d96b88517b590b17ae`.
The wave remains open. This capture performs no push, rerun, cancellation or
new workflow; it adds no Swift runtime acceptance claim for that hosted job.

At 2026-11-05 02:29:53 UTC, push-side [Swift Debug job 126463649821](https://github.com/billlza/q-periapt/actions/runs/41791854684/job/126463649821)
has also failed at the old `== 142` C/OpenSSL prerequisite on actual checkout
`6084f3bfb09333f6b66291b38809ed512296a27b`. This is the twelfth observed P0
checker failure. The full log identifies the failed check but does not disclose
the hosted server count, and it does not establish Swift consumer execution.
Upload metadata records artifact 13382448786, 47,530,052 bytes, digest
`0c167b833ca03c5983533a86ae4033cc4621236e67c01e7967eaa4063580cc10`;
that artifact was not downloaded for this classification.

All twelve run inventories were refreshed: 288 successes, 25 queued, two
running, 15 failures and two skips. `late-swift-push-debug/CAPTURE.zip` preserves
the complete decoded log, job/step metadata, snapshot and classification.
All six members were reread: 32,614 bytes, SHA-256
`ce63941ae42b324ac814857325dd098a58c7b3d5ee5d7a05cc0c8b8f3b24a007`.
The effective wave remains open; no push, rerun, cancellation or new workflow
was performed. The separate [local Swift maintenance result](../20261105-continuity-swift-maintenance/README.md)
qualifies only its named source and execution boundaries.

At 2026-11-05 02:44:09 UTC, push-side [Kotlin Release job 126463649783](https://github.com/billlza/q-periapt/actions/runs/41791854684/job/126463649783)
has failed at the same old `== 142` C/OpenSSL prerequisite on actual checkout
`6084f3bf`. This is the thirteenth observed P0 checker failure. The full log
does not disclose the hosted server count or establish Kotlin consumer
execution. Upload metadata records artifact 13383322821, 47,602,089 bytes,
digest `ab1b25e1c81271b0f50abf34cc4a35a531a528b85c1c510b5fdc6f255382b473`;
that artifact was not downloaded for this classification.

The snapshot refreshes the four open CI runs and retains terminal rows from
the preceding twelve-run inventory: 288 successes, 23 queued, three running,
16 failures and two skips. PR metadata is explicitly retained from the 02:29
snapshot. `late-kotlin-release/CAPTURE.zip` preserves the complete decoded log,
job/step metadata, snapshot and classification: six reread members, 31,720 bytes,
SHA-256 `8f7ac603d136f43263d599897380ac1cd2b72c86cdc1f8908223162812f694b5`.
The wave remains open and no push, rerun, cancellation or new workflow occurred.
