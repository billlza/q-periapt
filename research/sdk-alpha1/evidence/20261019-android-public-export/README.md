# Android public export completeness

Readback of successful Android JNI Debug and Release jobs in
[run 39129232908](https://github.com/billlza/q-periapt/actions/runs/39129232908)
found two export gaps at `23280124efd2f0f3003d4ce85e3db665f6ec8a25`:

- The local credential manifest omitted the twelve baseline lifecycle records
  needed by its own reader, including original/retried registration requests.
- The upload pattern selected top-level `.public` files but omitted nested
  `inputs/` records, including policy-target subdirectories.

Each terminal archive lacks 50 required local public files across its two trust
profiles. The successful runtime receipts remain intact; those archives cannot
support a complete public replay of this route. They are not rewritten or treated
as failed device tests. This lane runs host JNI on macOS arm64; existing physical
Android acceptance is a separate retained result.

The fix adds the baseline public inventory to the local credential export and
adds a narrow recursive upload pattern for the generated Android public-input
directories. Private configuration files remain outside that selection. Two
regression tests check public-only replay and the actual workflow's file patterns,
including a two-level policy-target path.

The original export reproduction failed in both checks: missing baseline data
prevented replay, and 26 synthetic nested inputs were absent from the upload set.
The same reproduction passes after the repair. All 102 Android helper tests
passed, and `git diff --check` passed. Full-workflow actionlint still reports two
existing unknown `ubuntu-26.04` labels; baseline and changed output are byte for
byte identical. No labels, assertions or lint rules were weakened.

`CAPTURE.zip` contains 54 members and 1,972,916 bytes, SHA-256
`8cd160ee45afe082014de393e45da8f456fac35f0265e1c173b9c8cd5d65e84a`.
It retains the old terminal inventories and receipts, exact missing-file lists,
failed readback, red/green controls, test/lint outputs and source changes. Full
terminal archives remain locally retained and identifiable through their GitHub
artifact IDs and SHA-256 digests in `CHECKS.json`.

This qualifies the local export correction. It does not claim a fresh hosted
artifact containing these files, a complete six-partition join, new device
execution, or release admission. Runtime and ABI code are unchanged.
