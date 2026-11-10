# Original-source Debug coverage and another Swift prerequisite failure

The 2026-11-05 06:21:58 UTC snapshot refreshes the two remaining nonterminal
PR #117 main-CI job inventories, retaining ten terminal inventories from the
previous capture. It contains 334 jobs: 296 successes, 23 failures, five running,
eight queued and two skips. The separately captured PR metadata confirms the
unchanged heads `475cd239` and `6084f3bf`; both PRs remain open.

[PR #117 push capacity job 126445737820](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126445737820)
passed on actual checkout `475cd23923e45819b01b6041c91c44540ec056ec`. It executes
the one selected account-roster fanout/removal capacity test, with 1,450 other
library tests filtered. Its runtime is 1,685.14 seconds. The shell prints the
same successful summary again with `grep`; that second line is not a second
test execution. The native result upload succeeded: artifact 13391108014,
33,371 bytes, digest
`6e46246dafeb0052827182b374e6215ca313ebca79aa22e9b08db890bfd3cb0e`.

The readback compares actual test-name sets against the previously captured
[same-source Debug suite and Release run](../20261105-ci-native-swift-readback/README.md).
The 1,450 Debug-suite library names and the single capacity name have zero
overlap; their union equals all 1,451 Release-library names. The five additional
candidate stages (4, 2, 4, 3 and 19 cases) and the two SDK stages (27 and 4 cases)
also have identical executed name sets across those Debug/Release jobs. Thus
the named old source has actual Debug coverage of the same 1,483 candidate and
31 SDK cases seen in its Release run. This is test-inventory coverage, not a
new claim about complete platform qualification, final-source admission or a
product resource budget. The local alias/aggregate-copy additions remain outside
these old hosted inventories.

[PR #117 merge Swift Debug job 126456506032](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456506032)
failed on actual merge `9aa535b48b464ec4d4a8b5a4b20221049a6067b9` in the old
exact `== 142` C/OpenSSL server-census prerequisite. This is the seventeenth
observed P0 checker failure. The log does not disclose the hosted count or
establish Swift consumer execution. Its reported artifact is 13392931434,
47,516,539 bytes, digest
`6381cba701ffced5a7a6a17ffbcdce6a2ece0442c4b1f7b5d6433bd2b71e2d6c`.

Neither archive was downloaded locally. `CAPTURE.zip` preserves both complete
decoded logs, job/step metadata, snapshot, refreshed PR metadata, the classifier
and exact-name-set readback. Its references to the earlier suite/Release logs
include their hashes and original capsule. All nine members were reread:
203,658 bytes, SHA-256
`5a689566d2eb4a2f633608ad0d84bfad52d217c36ff71b6a628c364092d28e1e`.
The wave remains open. No push, rerun, cancellation or new workflow was performed.
