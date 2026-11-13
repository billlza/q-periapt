# Q-Periapt targeted CI and dependency readback — 2026-11-11

## Source identities

- Integration: `8bdb36698c9d955de8c71a41179d11d224f696e0`.
- Main used for dependency comparison: `48d0fb9a5651b50494ec33d025dda52bd2ff5eae`.
- Canonical paper: `11e113f27d7708474cd55713d4a22cc028f80944`.
- Scope: exact integration check inventory; seven additional old-source generic runs absent from the prior 17-run audit; all 14 failed-job logs; six dependency PRs with complete changed-file patches.

## Exact integration CI observation

At 03:09–03:11 UTC, the remote integration ref remained at the source above. All 130 check runs were read using both pages: 128 queued, 2 successful, 0 failed. Each generic run (`42917560978` push, `42917588037` PR) contained 56 jobs: 55 queued and one successful `abi2-windows-package-2022` job. All 33 main-required contexts were present. The Android runtime matrix and installed-consumer matrices had not materialized; their AAR and Rust-publish prerequisite jobs had runner_id=0 and no steps. This observation is not a finished CI qualification.

Full current-source inventory: `integration-check-inventory.json`.

## Newly completed old-source failures

| Run | Source | Success / failure / cancelled | Failed check job | Failed runtime or coverage job | Installed partitions cancelled without a runner |
|---|---|---:|---:|---:|---:|
| 42754204081 | bee17822 | 32 / 2 / 0 | 129624662319 | 129779610363 (Android 16K) | N/A |
| 42640883163 | aaebe334 | 59 / 2 / 10 | 129241356187 | 130111632080 | 6 / 6 |
| 42640875301 | aaebe334 | 60 / 2 / 9 | 129241323885 | 130093775352 | 6 / 6 |
| 42635384067 | de4fbce0 | 58 / 2 / 11 | 129222043769 | 130158286346 | 5 / 6 |
| 42634858474 | 747c45ba | 59 / 2 / 10 | 129220215787 | 130089193552 | 5 / 6 |
| 42634083989 | 62f67a89 | 59 / 2 / 10 | 129217536539 | 130096623316 | 5 / 6 |
| 42634029494 | 62f67a89 | 60 / 2 / 9 | 129217346267 | 130092507075 | 5 / 6 |

The six SDK-source `check` failures combine the previously diagnosed workflow sparse-checkout scanner error with two `IndependentPackageTests` errors: `counterpart product dependencies differ`. The two original counterpart tests pass on integration `8bdb3669` (2/2, 0.029 s); a separate replay also passes (2/2, 0.017 s, `current-counterpart-regressions.log`). Current dependency admission includes the source's core and host-store edges. Every old installed-consumer cancellation has runner_id=0, zero steps, and a 24-hour timestamp span. The corresponding coverage joins correctly report a missing/duplicated/unexpected partition set; these cancellations are not consumer execution failures.

The paper check fails `test_tracked_inventory_is_nonempty_and_nul_terminated` with `tracked Rust source count must be 106, got 154`. Canonical paper `11e113f` subsequently passed the complete 48-test CodeQL-quality module, including its real tracked inventory of 106 current plus 68 archived Rust sources (`canonical-paper-codeql-quality.log`).

Structured attribution and complete run/job identities: `readback.json`. Raw logs for every failed job: `logs/job-<job_id>.log.gz`.

## Android 16K old failure and current protection

The old paper job installed the APK successfully and observed the exact installed path twice. `adb-start.log` then records `cmd: Failure calling service activity: Broken pipe (32)`; the start command returned 224. Cleanup recovered from one failed query, uninstalled successfully, and observed package absence three times. This identifies a failed guest activity-service command call. The artifact has no guest logcat, app exit-info or tombstone to identify the underlying system or APK cause.

Original diagnostic ZIP: `android-bee17822-diagnostics.zip`; SHA-256 `eafcaa406999dbf7a5b2b94e9f96ae565706480b7621e6e282dfc149e6550aec`.

PR #163 merged as integration `8bdb3669`. Compared directly with `bee17822`, it adds a pre-install framework gate: live settings/package replies and the same live system_server boot ID, PID and start time for at least three consecutive observations across at least five seconds, within one 120-second deadline. A failed query or changed identity resets the stable interval. This covers framework instability during the pre-install admission window. The old activity failure occurred after install; its artifact does not establish whether instability was already present at admission or arose afterward.

Current code performs one activity-start command. On failure, it retains the start log and gathers run-bound app logcat, owned-emulator app exit-info, state and guest diagnostics, then exits unsuccessfully. No retries, fallback, gate reduction, or remote runs were added in this readback.

Exact source hashes, sequence and guard semantics: `android-readiness-comparison.json`. Focused current-source regression output: `current-android-readiness-focused.log`.

## Dependency PR diff review and closeout

| PR | Requested target | main 48d0fb9 | integration 8bdb3669 | Recorded disposition |
|---|---|---|---|---|
| #9 | getrandom 0.4.3 for three consumers | all three manifests and lock edges match | matches | Closed unmerged at 03:18:36 UTC as duplicate |
| #10 | rustls 0.23.43 | 0.23.46 | 0.23.46 | Closed unmerged at 03:18:37 UTC as superseded |
| #12 | toml 1.1.4 plus five auxiliary records | target versions/checksums match; manifest uses `1` rather than `1.1` | toml 1.1.6; auxiliary target records match | Closed unmerged at 03:18:39 UTC as duplicate upgrade |
| #21 | CodeQL analyze 4.37.7 | 4.37.6 | coordinated 4.38.2 pin | Open; newer replacement is integration-only |
| #83 | cc 1.4.4 | 1.2.67 | 1.5.1 under sdk-020 qualification | Open; newer replacement is integration-only |
| #84 | redb 4.2.0 | 2.6.3 | policy-agent/host-store 4.3.0 | Open; newer replacement is integration-only |

The `redb 2.6.4` record still in integration is the explicitly aliased optional legacy migration provider in the CLI; it is not the policy-agent dependency. PR #12 is a functional duplicate of the locked upgrade, not an identical textual manifest patch.

Complete six-PR patch/manifest/lock comparison: `dependency-pr-diff-review.json`. The three closure states, timestamps, `merged=false`, and source-bound resolution paragraphs were independently read back through GitHub and saved in `dependency-closeout.json`.

## Evidence preservation

The compressed raw logs preserve their original bytes. `evidence-manifest.json`
records the stored and uncompressed SHA-256 values and sizes. The source-bound
readback retains the original runtime paths; the files named above are the
durable copies. The original Android diagnostic ZIP is retained unchanged.

No workflow was rerun during this review. The duplicate dependency closures
were read back independently and are recorded as closed, unmerged PRs.

## Current paper run and remaining source-context defect

At 03:24 UTC, canonical paper `11e113f` had 37 successful checks, two
failed check records (Rust analysis and its aggregate CodeQL record), and
three queued checks. Thirty-two of the 33 required contexts passed;
`bindings-swift` was still queued. The successful checks include the manuscript
build and the complete generic `check`. `paper-check-inventory.json` retains
all 42 records.

Rust job `129965837798`, run `42855086715`, used CLI 2.26.2 and
`rust-queries 0.1.39`. All 38 suite queries completed, including full
SummaryStats in 1m58s. The subsequent quality check rejected incomplete
successful source extraction. Its missing-path message prints the first eight
paths, while the raw extraction log reports missing semantic project context
for all 68 frozen archive sources. The extractor received all 174 inputs but
only found the current root, fuzz and HQC Cargo manifests.

This is a distinct current-source context defect. The passing 48 inventory
unit tests establish the corrected source census and pin checks; they do not
constitute a successful hosted extraction. `paper-codeql-11e113f.log.gz`
retains the decoded GitHub job log; the manifest identifies the stored text
bytes and their compressed representation.

## Additional functional PR review

PR #110 merged into `integration/sdk-020` as
`866029211e0ed85cbf71be51f0beecbd3184713e`. Its refreshed candidate
`c04f4bbc9d8e14b62929021d942593597b7740f7` contains the remaining
two-file recovery correction: admit the structural Swift consumer verifier
and explicitly reject the XCFramework producer. The added positive case
first reproduced the omission; all 54 recovery/publication contract tests
then passed. The separate prefix `additional-` identifies the patch, before
log, successful regression log and remote merge readback.

PR #40 remains open. Its decoded nine-file patch changes Finished values
from a keyed-prefix SHA3 construction to HMAC-SHA3-256, including protocol
vectors and a formal contract. The actual source change is absent from both
reviewed branches. Its encoded transfer workflow was not executed;
`additional-pr40-source-comparison.json` records the exact current source
objects and proposed textual differences.
