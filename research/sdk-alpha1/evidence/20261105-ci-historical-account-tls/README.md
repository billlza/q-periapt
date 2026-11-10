# Historical queue: account TLS prerequisite failures

This readback follows the [current-head terminal inventory](../20261105-ci-wave-readiness/README.md).
It concerns older runs on the same publication branch, not a new qualification
of either current head or the proposed corrected source. The twelve current-head
runs retain their previously recorded 336 terminal jobs and 27 P0 checker failures.
The two newly read foreign-labelled failures here use an older account-TLS census;
they are not added to that exact-142 P0 count.

| Job | Actual checkout | Observed result |
| --- | --- | --- |
| [126268252580, Android Release](https://github.com/billlza/q-periapt/actions/runs/41724505316/job/126268252580) | `7e3a89faf2c79cd9111128b06e41d3ef503f063c` | C prerequisite rejected by account TLS phase-workload verifier |
| [126266162426, Swift Release](https://github.com/billlza/q-periapt/actions/runs/41724563802/job/126266162426) | `ea0a9c08d00356266c8ec23c6848b3bd0097f15b` | Same C prerequisite and verifier failure |
| [127156928118, coverage join](https://github.com/billlza/q-periapt/actions/runs/41724505316/job/127156928118) | `7e3a89fa` | Six named artifacts downloaded; partition completion/schema/claim predicate rejected |

Both full foreign-job logs fail in `qualify_c` before their foreign consumer is
qualified. The exact push and merge account-TLS validator/exporter bytes are
identical. Their old C bootstrap expectation is 121, alongside unchanged later
phase counts; Swift/Kotlin offsets are 127/126. Commit `69ed5b42` already corrects
the authenticated READY census, and is an ancestor of both prepared next-wave
commits. The later local [Rust/C qualification](../20261104-continuity-c-maintenance/README.md)
completed on `ff072bd6`. None of that reconstructs a missing hosted measurement.

The GitHub connector downloaded Android-labelled artifact **13401893480**.
Its 32,122,337 bytes match the upload SHA-256
`14c44eec973c539125f1ff75c4f872a2a000073071ce6a0156180953fc51d4ff`.
All 7,675 archive members pass CRC readback. The retained C test receipt is exit
zero: exactly `tls::account_cleanup_keeps_original_authority_over_mutual_tls`
passes in 9.58 seconds, with eight other cases filtered and empty stderr.
The separate C receipt and package receipt both remain incomplete with the
phase-workload failure; the package has no attached C or Android success result.
Thus a passing native scenario did not turn the rejected package into a pass.

The archive contains neither `account-tls-phases` nor the selected account-TLS
public directory. Source order explains this: full verification occurs before
`export_selected`, so the rejection prevents that export. The actual hosted
phase counts therefore remain unavailable. The source and existing correction
identify the outdated acceptance rule, but this record does not claim to have
observed a hosted count of 129 or to have independently isolated its numeric
delta. There is no observed JNI, ART or simulator failure in these two logs.

The Swift artifact was **not** downloaded. Its upload log reports ID
13403870843, 32,124,394 bytes and SHA-256
`3b9fb64257fa91c842d13ab1c3c26d74b41b24cbbdac190c244ecb43c87159b0`.
The coverage join's first input is Swift Debug by the pinned source order;
which conjunct of its compound guard failed is not established by that console
log. It does not upload successful coverage output.

By the 09:41 UTC readback, the push run's 70 jobs are terminal. The historical
PR run still has **126266162501, Android Release**, running since 08:54:14 UTC.
Repository-wide discovery reports that one active run; queued, waiting, pending
and requested collections are empty at their recorded inspections. This is a
snapshot, not permission to assume a later empty queue. No new wave was pushed,
rerun or cancelled. Refresh queue and remote refs before using the prepared
normal atomic fast-forward operation.

The capsule also pins all 16 workflows at `ff072bd6` for trigger review. Both
prepared updates leave the focused Android workflow and its SDK selection paths
unchanged. Main CI's registry publication operation is a dry run; the ABI platform
candidate workflow requires explicit named tag pushes. The prepared operation
updates two branch refs only. No release, tag or registry publication is authorized
by these inspections. Verify the new hosted SDK producer before changing the
later focused Android input pin.

`CAPTURE.zip` retains three complete job logs, queue snapshots, source-pinned
validators/exporters, selected original artifact members and the full member
catalogue, plus the next-wave workflow sources and prior preparation. All 52
members were reread: 613,865 bytes, SHA-256
`3dedfc707905f3479b81385d58a34361063c153904a924f15d138341e3fa10f9`.
The full downloaded container remains under
`target/continuity-historical-queue-closeout/artifact-13401893480.zip`; it is not
duplicated inside this capsule. `FILES.json` and `SOURCE_AUDIT.json` bind the
retained content and scope. No final platform or release acceptance is claimed.

The [next-wave readback](../20261105-ci-corrected-source-wave/README.md) records
the final historical Android/coverage results, the verified empty queue and the
subsequent normal atomic branch update. This capsule's earlier one-job-running
snapshot remains unchanged.
