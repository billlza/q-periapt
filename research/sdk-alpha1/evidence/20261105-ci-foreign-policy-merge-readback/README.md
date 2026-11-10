# Original-wave merge policy maintenance and Android prerequisite

The 2026-11-05 07:47:07 UTC snapshot refreshes the two remaining PR #117 main
job inventories. The latest fresh PR metadata, captured at 07:25:25 UTC, keeps
heads `475cd239` and `6084f3bf` open and unchanged. Ten terminal run inventories
remain retained. Counts are 298 successes, 28 failures, five running, one queued
and two skips across 334 jobs. The effective wave remains open.

[Merge policy-maintenance job 126456506050](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456506050)
passes on actual checkout `9aa535b48b464ec4d4a8b5a4b20221049a6067b9`.
The logged report binds source and builder to that merge and records extracted
Apple-Silicon execution on Darwin 24.6.0. Minimum-macOS execution remains false,
as do publication and release eligibility. The package archive digest is
`45dbd7e614683f93f2bd5ed9e4bccc48524d6920cf3da49acdce20acec4c2670`.

[Push Android Release job 126449257971](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449257971)
fails on actual checkout `475cd23923e45819b01b6041c91c44540ec056ec` in the old
exact `== 142` C/OpenSSL server-census prerequisite. This is the twenty-second
observed P0 checker failure. The full traceback does not disclose the hosted
numeric count or establish Android consumer execution; it is not an emulator or
device fault. The separately validated exact-146 local correction was not
present in this old hosted checkout.

| Job | Reported artifact | Bytes | Upload SHA-256 |
| --- | ---: | ---: | --- |
| 126456506050 | 13397096944 | 1,269,808 | `f19b11eeec5b780ab8bb9e1a3d0e27dc82563a2835286a036720d9de4bd9c971` |
| 126449257971 | 13396861247 | 47,581,853 | `36a48a475064be6e89165aad8c2efb0e3824bd86b9fe9a002877ae4ad67f6701` |

Neither upload container was downloaded locally. `CAPTURE.zip` retains both
full decoded logs, the complete snapshot, changed jobs and classifier. All
7 members were reread: 130,219 bytes, SHA-256
`82a0253ab7e95e2512cf11ca1b03af067e1c048571131c9c3c656433c3d9d2bd`.
The upload digests above are not the maintenance package's inner archive digest.
No push, rerun, cancellation or new workflow was performed.
