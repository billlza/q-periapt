# Original-wave foreign prerequisites and policy maintenance

The 2026-11-05 06:56:43 UTC readback refreshes both remaining nonterminal PR #117
main-CI inventories. Ten terminal run inventories remain explicitly reused from
the [06:21 snapshot](../20261105-ci-debug-capacity-readback/README.md). Across
334 jobs there are 297 successes, 27 failures, five running, three queued and
two skips. PR metadata is reused from that prior capture rather than claimed as
a new head observation. The effective wave remains open.

Four newly completed failures stop at the old exact `== 142` OpenSSL server
census in the shared C prerequisite. Full traceback and actual checkout identity
are retained. They bring the observed P0 checker failures from 17 to 21. Their
logs neither disclose the hosted numeric exchange count nor establish Kotlin or
Android consumer execution. These are not Android emulator/device failures.
The corrected exact-146 implementation has its separate completed local Rust/C
qualification; this unchanged old remote source does not test that correction.

The push-side Apple-Silicon policy-maintenance package passes at
`475cd23923e45819b01b6041c91c44540ec056ec`. Its logged package report records
an extracted installation, unchanged sources and execution on Darwin 24.6.0
arm64. The declared macOS deployment target is 13.0, but
`minimum_os_execution_qualified` remains false. Its package archive digest is
`d7c7f64d33977b5c809796424daea884917460ea12d8e7bc97c6965b45b31183`;
the different upload-container digests below must not be substituted for it.
No publication or final release qualification is claimed.

| Job | Scope | Checkout | Result | Reported artifact | Bytes | Upload SHA-256 |
| --- | --- | --- | --- | ---: | ---: | --- |
| [126449257926](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449257926) | continuity-installed-android-debug | `475cd239` | failure | 13395115444 | 47,510,197 | `30985a69ee7a484558aceb7b6050db79454b13b74a2af34d50e111f4da275797` |
| [126449257992](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449257992) | continuity-installed-kotlin-release | `475cd239` | failure | 13393893915 | 47,604,981 | `f1ee8aa737f3954630d1a7c9b00b034a0b2c403b14393da2793e0fa7b68280cc` |
| [126449258002](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449258002) | policy-maintenance-package (macos-15, aarch64-apple-darwin) | `475cd239` | success | 13393548964 | 1,271,739 | `dbe8683a24742ff3db1b429394b8f84e4ba8ade2515d98f7dd37a2d9472fedba` |
| [126456505946](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456505946) | continuity-installed-android-release | `9aa535b4` | failure | 13394435288 | 47,598,804 | `e3893476e5ee1cf77b69c8d6f7fd047fbd7e42bfa8261fa2dfc889ef186d56a0` |
| [126456505984](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456505984) | continuity-installed-android-debug | `9aa535b4` | failure | 13394282833 | 47,519,053 | `5fabbeafcb5355d5cb2a4044acfdfe9e7608fb24425ddea85e7c4fad753a6917` |

These five artifact containers were not downloaded locally. `CAPTURE.zip`
retains the five full decoded logs, all job/step rows in the snapshot, the
observed changes and classifier. All 10 members were reread:
176,343 bytes, SHA-256
`b6411977d850e3190f44f500fa8629ef22093e52387ef97097bcd93150755a16`.
No push, rerun, cancellation or new workflow was performed.
