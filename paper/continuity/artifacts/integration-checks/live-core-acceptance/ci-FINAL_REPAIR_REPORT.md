# Android owned-cleanup repair

## Delivered changes

The reproduced host-control defect is repaired in two isolated local commits. The candidate patch is based directly on the current 0.2.0 source. The main patch also carries the candidate's existing, narrowly typed observation-deadline handling. Neither commit was pushed by this agent.

| Profile | Base | Local commit | Tree | Patch |
| --- | --- | --- | --- | --- |
| 0.2.0 candidate | `1c68aa666db22d36ee136be1ec712545a9e74f03` | `e84727d2d1d8610d8b9eaf64294d9edbf86176f2` | `094a14b23984b3c8d4fbb976a23ab1c6981733af` | `candidate-cleanup-recovery.patch` |
| Main maintenance | `2ccb162ef30a8a2dce077aea9f74cd7ab6a37614` | `57bc8792dc0fee3b14d4981d0015f026ebc8627f` | `133e33e5f309de0f840a487789bfabb05b6fd8b6` | `main-cleanup-recovery.patch` |

The machine-readable identities, patch and test-log digests, unchanged results digests, exact source-gate markers, and clean-worktree receipts are in `FINAL_PATCH_RECEIPT.json`. Source repositories are `/workspace/scratch/83c4961eae79/ci-followup` and `/workspace/scratch/83c4961eae79/ci-followup-main`. The standing shared paper and candidate checkouts were read only.

### Reproduced failure and repair

The paper-head push run [42429788635, job 128576629677](https://github.com/billlza/q-periapt/actions/runs/42429788635/job/128576629677), at source `da521d8388f5f0c64697387bf80b0b5b7837fb34`, reached two exact, same-path cleanup APK observations and signer verification. Its uninstall returned `cmd: Failure calling service package: Broken pipe (32)`. The journal then repeatedly recorded `uninstall=still-present-after-request`. The original controller set `ANDROID_APP_UNINSTALL_REQUESTED=1` for every command outcome, so a failed request permanently excluded another authorization attempt while the package remained present. The full job log is `paper-job-128576629677.log`; the preserved diagnostics archive has SHA-256 `88d22d27afbcb8a974c94da7d89e65d399f6e0879e4955b6d91b8b974a47ef31`.

The repair keeps the existing 45-second cleanup deadline. An ordinary failed uninstall makes the next request eligible only after two fresh, exact APK observations at the original authorized path and a fresh signer check. A first-attempt path digest remains pinned across cleanup invocations; a changed path stops cleanup with a structural failure. The existing capability checks still bind device routing and the owned ADB server. Exit statuses 2, 129, 130, and 143 return immediately and retain the request flag, preventing a later cleanup invocation from reissuing that request. A zero-returning uninstall also retains the flag; subsequent package-state observations must establish the original three consecutive absences. The eight-observation rule for an unconfirmed install remains intact. Command success alone establishes no absence fact.

The patch adds seven command-level regression tests to the existing shell harness. The causal reproducer makes the simulated package disappear only when the second uninstall actually succeeds. The original shell function fails that scenario (`candidate_red_reproducer.log`); the patched function passes (`candidate_green_reproducer.log` and the final focused suite). The remaining tests check fresh-observation requirements, changed paths, mismatched bytes or structural identity failure, signer failure, exhausted budget, and structural/signal statuses. The former test of a permanently failed request was narrowed to the preserved rule for a successful request that leaves the package present.

### Main-compatible deadline handling

The same paper failure later exhausted the owned-listener validation budget. Main classified that pure observation-budget exhaustion as a structural failure. The candidate already distinguishes this condition using `AdbValidationDeadlineExpired`. The main patch transplants that exception, the remaining-budget helper, the two composite observation functions, and ten existing candidate boundary tests. All four AST nodes match the candidate implementation.

The two exact expiry reproducers fail on unchanged main and pass after the transplant (`main_deadline_red_reproducer.log`, `main_deadline_green_reproducer.log`). Pure expiry yields an inconclusive typed observation, discards a rejected APK copy, and establishes no package or ownership fact. Mixed structural failures, exception notes, nonfinite input, and failed copy cleanup retain their original fatal behavior. No time limit was increased.

## Validation

| Check | Candidate | Main |
| --- | --- | --- |
| Cleanup-focused existing/new tests | 36 passed | 31 passed |
| Package-state, installed-APK, and deadline tests | 40 passed | 32 passed |
| Shell syntax and Git whitespace checks | Passed | Passed |
| Real clean-source gate | Passed, `sdk-020` | Passed, `initial` |
| Independent patch review | Passed | Passed |

The independent review is recorded separately in `/workspace/scratch/83c4961eae79/readiness_audit/CLEANUP_PATCH_REVIEW.md` and its JSON receipt.

The complete two-module local runs were attempted and retained: candidate ran 356 tests; main ran 315. Each reported 14 failures, 15 errors, and 3 skips. Their failing cases exercise live Unix sockets, process identity, or UID-dependent fixtures. This execution environment rejects `AF_UNIX` socket creation with `EPERM`, lacks the process's `/proc/<pid>` entry, and runs with UID 0, colliding with an existing negative identity fixture. These failures are retained in `candidate_android_tests.log` and `main_android_tests.log`; no test, assertion, CI selector, or failure gate was removed or weakened. Hosted full-suite and actual emulator validation remain required for the new published head. There is no local Rust or emulator execution claim.

### Exact source-results state

Both official source-gate commands were run against their committed, fully materialized, clean isolated trees. No historical result or proof-input manifest was edited.

```text
SDK_SOURCE_READINESS_PASS profile=sdk-020 commit=e84727d2d1d8610d8b9eaf64294d9edbf86176f2 results_sha256=9974f5a3d2cb754817aa857a10859582d329c97edd61a44d41a2fb701d564bda current_proof_inputs=256 historical_proof_inputs=249 release_claim_eligible=false
SOURCE_TRANSITION_READINESS_PASS mode=initial commit=57bc8792dc0fee3b14d4981d0015f026ebc8627f results_sha256=55bcbeb597873996a64f9f1e0a9f4b1f84d8bc08cc62e033f08b7ef7bdf9d943 proof_inputs=249 declared_delta=59
```

The candidate SDK profile captures the current source inventory while preserving the frozen historical ledger. Main is already in the legitimate initial state created by the prior reopen operation; changes to these existing source paths need no additional reopen. The gates verify the resulting source identities, without treating historical release evidence as evidence for new code. The 14 transient archive copies that appeared during the new isolated checkout's full materialization were preserved outside its Git tree; their exact inventory is in `isolated_materialization_temporary_files.json`. They are outside the report bundle and all original shared-checkout temporary files remain untouched.

## Original 0.2.0 failures remain a distinct runtime question

The two failed candidate jobs are [PR job 128498707969](https://github.com/billlza/q-periapt/actions/runs/42402999612/job/128498707969) and [push job 128496914346](https://github.com/billlza/q-periapt/actions/runs/42402990119/job/128496914346), both on reported head `1c68aa666db22d36ee136be1ec712545a9e74f03`. In each, full SDK instrumentation and minimal runtime instrumentation passed. Cleanup then received truncated APK streams and lost the emulator transport before it could authorize an uninstall. Their uninstall logs are empty. The repaired Broken-pipe path had therefore not been reached in these original failures.

The bounded follow-up source/log audit supports a sharper attribution boundary:

* The PR cleanup copied 4,556,288 of 13,817,559 bytes and, after one permitted transport recovery, zero bytes. The push cleanup copied 8,192 bytes; that run had already used its one recovery after an 11,091,456-byte postinstall copy.
* In `_observe_installed_apk`, the recorded `bytes-mismatch` diagnostic is emitted only after the bounded write returns normally and the raw ADB client returns zero. A host wrapper timeout or nonzero child result instead returns `pull-failed`; its rejected file is removed. Thus these specific diagnostics exclude that wrapper's timeout/kill error path as the cause of the copied bytes. The stream reader waits for EOF and child termination before returning a successful result.
* Guest `adbd` write failures coincide with the truncated-copy records and are followed by host ADB read failures: PR guest 19:55:56.061 / host 19:55:56.466, then guest 19:56:08.282 / host 19:56:08.687; push guest 19:29:14.449 / host 19:29:15.223. Archive entry timestamps have only two-second resolution, so they establish the adjacent interval, not subsecond causal ordering.
* The same host ADB server PID persists until final cleanup: PR PID 8096 is killed at 19:57:40.487; push PID 7909 at 19:31:02.226. The retained logs therefore do not show an early `kill-server` causing the truncation.
* The PR guest has an earlier system-server SIGSEGV and a later GMS SIGSEGV. The corresponding push interval has no fatal-signal record and continues to show system activity. This supports a guest/transport availability failure, while leaving the initiator and lower-level cause of the disconnection undetermined. The evidence does not select RAM, timeout tuning, an emulator crash, or a host subprocess-cleanup bug as a common causal explanation.

The exact sample metadata and selected guest/host events are in `original_truncation_boundary_receipt.json`. No additional source repair for this unresolved cause is justified by the retained evidence. Actual execution on the new integrated head is the next check that can close those candidate runtime failures; the independently successful maintenance Android jobs do not substitute for it.

## Current workflow and rerun state

At the last full pagination, 2026-11-08 01:08:23 UTC, PR run 42402999612 had 61 successful, 1 failed, 4 in-progress, 2 queued, and 1 skipped jobs. Push run 42402990119 had 64 successful, 1 failed, 1 in-progress, 2 queued, and 1 skipped jobs. The only failed jobs were the two Android jobs above. The six other workflows in the earlier complete eight-workflow/174-job inventory had succeeded.

The original workflow runs remained active/queued, so GitHub's single-job rerun prerequisite was unmet. This task made no rerun POST and cancelled no job. `jobs_010823.json` preserves all 69 jobs' completeness counts and the exact unresolved-job identities for each main run. The parent owns publication of the repair and tracking of the next hosted result.

A final eligibility read at 2026-11-08 01:16:43 UTC still returned `status=queued`, `conclusion=null`, and `run_attempt=1` for both original runs. `final_rerun_eligibility.json` records those exact responses; a single-job retry was still unavailable at handoff.
