# Swift installed-consumer job budget — 2026-10-17

The second attempt of [job 117365014060](https://github.com/billlza/q-periapt/actions/runs/38861869698/job/117365014060)
at `9f1c7f62` reaches its 210-minute job budget and is cancelled. The installed
consumer step runs from 09:38:40 to 13:08:05 UTC. This is a terminal incomplete
qualification, not a successful run or a queued-runner cancellation.

The retained [artifact 12102042201](https://github.com/billlza/q-periapt/actions/runs/38861869698/artifacts/12102042201)
is downloaded once and verified against its API size and SHA-256:
167,714,095 bytes, `6afb65c170f9d66be4a955aad8af2c08cbdf70c1f3f2acf06c1c0bc6f91571b6`.
Its 54,219 members include 304 completed top-level command receipts, all returning
zero. `C_CONSUMER.json` reports completion. Swift contributes 60 completed debug
commands and 13 release commands; their reported Rust-test durations sum to
2847.15 and 1433.06 seconds respectively. These sums exclude other commands and
are not the entire job duration. ZIP member times are retained separately from
test-reported durations.

The last completed command is the release `managed_policy_credential_tls_fixed`
case at 13:05:10, reporting 185.58 seconds of test execution. Earlier neighboring
release cases also keep completing at roughly three-minute intervals. The
`qualify_swift` source still requires the remainder of release qualification and
its separate minimum-toolchain root lifecycle check. No final
`SWIFT_CONSUMER.json` is present. Thus the evidence supports a total-budget
mismatch while the serial real-expiry matrix is progressing; it does not support
claiming a hang, ignoring remaining tests or admitting the partial Swift result.

The workflow now uses the existing 330-minute foreign-consumer budget for Swift
as well as Kotlin/Android. Every native prerequisite, both build profiles,
minimum-toolchain check, protocol assertion and SDK timeout remains. Individual
commands retain the same 900-second limit. This does not guarantee completion
within 330 minutes; a terminal current-source result is still required. The 23
existing package/Swift-consumer contract tests pass after the configuration edit.

[OBSERVATION.json](OBSERVATION.json) and
[COMPLETED_COMMANDS.json](COMPLETED_COMMANDS.json) retain the exact observation
and bounded command census. The full original artifact and raw job logs remain
under `target/continuity-codeql-9c65-terminal-20261016/old-swift-terminal-368/`.
Separately, [CURRENT_CI.json](CURRENT_CI.json) records actual Windows, check and
audit success for both push and PR runs at `68e05c56`; both runs still have other
work pending. Neither that subset nor this budget correction closes the full CI
or 0.2.0 release gate.
