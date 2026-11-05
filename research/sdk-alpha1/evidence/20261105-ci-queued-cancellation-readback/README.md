# Queued cancellation and another Kotlin prerequisite failure

The 2026-11-05 07:53:31 UTC snapshot contains 298 successes, 29 failures,
four running jobs, one cancellation and two skips across the original 334 jobs.
Both remaining main-run inventories were refreshed; the ten terminal runs and
07:25 PR metadata remain explicitly reused. The effective wave is still open.

[PR #117 merge Kotlin Release job 126456506355](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456506355)
is now terminal `cancelled`. The previous snapshot showed it queued. Its retained
metadata has no steps, runner ID zero and an empty runner name. The API timestamp
span is 86,401 seconds, from 2026-11-04 07:48:57 to 2026-11-05 07:48:58 UTC;
this is not observed execution time. No consumer or runner execution is established.

The job-log request returns `404 BlobNotFound`. The connector does not support
the linked check-run endpoint, so it did not provide annotation evidence. The
cancellation cause and actor remain unestablished. The current
[GitHub limits page](https://docs.github.com/en/actions/reference/limits) labels
its 24-hour queue limit as self-hosted; this record does not apply that statement
as proof of the cause of this `macos-15` cancellation. This task issued no cancel,
rerun or replacement workflow. Cancellation is neither a test failure nor a pass.

[Push Kotlin Debug job 126449258004](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449258004)
failed on actual checkout `475cd23923e45819b01b6041c91c44540ec056ec` at the old
exact `== 142` C/OpenSSL server census. This is the twenty-third observed P0
checker failure. Its full traceback does not expose the hosted numeric count or
establish Kotlin consumer execution. The corrected exact-146 source retains its
separate local verification; this old hosted checkout does not validate it.

The failed job reports artifact 13396984430, 47,538,730 bytes,
SHA-256 `88a1e9a2d4ca6403e5864688c671861d3889434db000d1ffe6df4fcf81e19c02`.
It was not downloaded locally. `CAPTURE.zip` retains the full Kotlin log,
complete snapshot, changed jobs, both original connector error responses and
classifier. All 8 members were reread: 118,605 bytes,
SHA-256 `729a9e168b9375c19f9c1a059c79c7168d8b93d7714028a823acddb6e82ed87c`.
No remote mutation or release claim was made.
