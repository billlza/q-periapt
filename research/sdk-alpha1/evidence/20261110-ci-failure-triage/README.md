# CI failure readback and Android framework readiness

This checkpoint identifies the failures reported on 10 November against their
original source revisions and separates those completed runs from the current
integration and manuscript checks. The retained inventory covers all 17 failed
`ci.yml` runs created from 9 November through the readback at
**2026-11-10 22:21:49 UTC**: 1,131 jobs, including 37 failed jobs. Every failed
job log and every jobs page in this cohort was inspected.

## Completed failure classification

| Failed jobs | Cause | Source resolution |
| ---: | --- | --- |
| 9 | A one-shot Python command check interpreted a checkout sparse-file-list entry as a command. | Fixed by [`92597c3d`](https://github.com/billlza/q-periapt/commit/92597c3d370256b5c03e5d1e662101a7601ef916), already included in integration `b524f068`. |
| 4 | An older C caller-lifetime control failed to compile. | Explicit device output storage in [`8aadcc89`](https://github.com/billlza/q-periapt/commit/8aadcc89d431876a19ac66059b836de2b0238378) is already included in `b524f068`. |
| 15 | The installed-consumer aggregate received an incomplete partition set. | 80 dependent mobile partitions had no assigned runner or executed step and were cancelled at 24 hours, within one second. The aggregate correctly rejected incomplete coverage. |
| 8 | External Python, Gradle, Maude, Tamarin or opam downloads ended in HTTP 504 after installer retries. | The failed preparation steps did not execute their downstream code tests. The inventory retains each original run and job. |
| 1 | The API 35 / 16K guest framework restarted after reporting boot completion; APK installation reached an unavailable settings provider. | The captured startup sequence motivates the bounded framework-readiness repair described below. |

The original C lifetime control and one-shot scanner both pass on exact
integration source `b524f06866ce6e85d8018368547090732bc7075b` (two tests).
The same original scanner test passes on canonical manuscript source
`11e113f27d7708474cd55713d4a22cc028f80944` (one test). Its four workflow
inputs match the corresponding PR merge source; the earlier sparse-list input
is absent there. Commands and results are retained in
[`local-regressions.json`](local-regressions.json).

The complete per-run and per-job record, including source SHAs, failed steps,
runner allocation and cancellation timestamps, is
[`failure-inventory.json`](failure-inventory.json).

## Android startup evidence

The original [run 42607941238](https://github.com/billlza/q-periapt/actions/runs/42607941238)
used source `22efc230e26b1dc670049d3229113405ff9f6977`. Its
[16K job 129237626771](https://github.com/billlza/q-periapt/actions/runs/42607941238/job/129237626771)
built and signed the APK, checked the AAR/ELF inputs and observed the selected
16K guest. Installation then failed while creating a package session:

```text
java.lang.IllegalStateException: Cannot access system provider: 'settings' before system providers are installed!
```

The original guest logs establish this sequence on 9 November:

| UTC | Observation |
| --- | --- |
| 19:56:34 | `sys.boot_completed=1`. |
| 19:56:36 | `system_server` PID 569 receives SIGSEGV in system AppSearch protobuf ODEX. |
| 19:56:48 | The installer reaches the missing settings provider during the restarted framework. |
| 19:56:49 | `system_server` PID 2474 receives SIGSEGV in ART `ClassLinker::ResolveMethod`. |
| 19:56:59 | A subsequent framework reports boot completion. |

The pre-install state already contains PID 2474; the failure state records that
same PID as a zombie. Available guest memory in those two snapshots is
3,282,808 kB and 3,206,480 kB respectively. These snapshots identify the observed
state; they do not identify the cause of the guest native crashes.

The existing startup gate reads `sys.boot_completed` and `vold.decrypt`. Those
properties alone admitted this sequence. A successful package-absence query
also preceded the failed settings-provider access. Framework readiness therefore
needs a direct provider observation and a stable, responsive framework before
the single installation attempt.

The original 134,142-byte artifact is retained byte-for-byte as
[`android-startup-diagnostics.zip`](android-startup-diagnostics.zip); its artifact
ID and SHA-256 are recorded in the inventory. It includes the install exception,
guest and crash logcat, package observations, and before/failure state snapshots.

## Implemented startup repair

The owned-emulator path now runs `wait-framework-ready` immediately before
arming installation cleanup and attempting installation. Each observation
accesses the settings provider, locates the Android system package, confirms
the smoke package is absent, and checks boot/decryption state. Readiness
requires at least three valid observations over at least five seconds with
the same guest boot ID, `system_server` PID and process start time. The process
must be live; zombie, exited and stopped states do not enter installation.

Before and after each guest query, the controller rechecks its owned emulator,
private ADB server, receipt and listeners. Queries share a 120-second admission
budget and each guest query is capped at five seconds. A recovered startup
query starts a fresh stability window. Existing synchronous host identity
reads consume that budget; the deadline does not interrupt an operating-system
file read in progress. The original single install attempt and subsequent
package ownership, runtime and cleanup checks remain in sequence.

Original guest output is retained in `adb-framework-readiness.log`. A startup
failure preserves its exit status and captures the crash diagnostics before
installation is armed. Both successful and failed evidence collection retain
the guest console, so a recovered startup does not erase earlier framework
crashes. The physical-device path continues to use its existing admission.

## Additional current-source license guard repair

The focused source checks found a separate, reproducible defect in `b524f068`:
the SDK license guard expected three calls, while the current workflows already
contain four. The original test fails with `4 != 3`, as retained in
[`baseline-license-guard.log`](baseline-license-guard.log).

The repaired guard checks the exact distribution: two calls in `ci.yml`, one in
`abi2-platform-candidate.yml`, and one in `continuity-android-installed.yml`.
The bounded 64-answer input, invocation and variable cleanup must each have
that same distribution. The existing infinite-input and swallowed-error
rejections remain active. Independent review and the original test pass; see
[`license-guard-review.json`](license-guard-review.json).

## Repair validation

The controller and shell regressions cover the captured provider exception,
sticky boot property, repeated framework restart, PID reuse, guest reboot,
dead/stopped processes, ownership changes, exhausted deadlines and physical
device admission. The [readiness review](readiness-review.json) retains the
independent 12-test run, 23 parser fault cases, three additional deadline cases
and byte-identical comparisons of the three existing native diagnostic
commands. The [workflow and physical-device run](workflow-physical.log) passes
all 11 tests, including actual export and replay through the physical-proof
validators.

The complete two-module run executes 365 tests. Twelve pre-existing test methods
encounter this environment's refusal to create `AF_UNIX` sockets, producing
10 failures and 11 errors across their subcases; three existing skips remain.
The original `b524f068` code reproduces the same socket failure. The
[full log](full-android-modules.log) and
[baseline reproduction](baseline-socket-environment.log) retain these outcomes.
The hosted Android runtime executes the actual emulator and installation
sequence for the published candidate.

The final [combined-source command](combined-source-test-command.json) and
[test log](combined-source-tests.log) bind the focused rerun after the already
merged Java and attestation pins were synchronized: **20 tests pass**. Its source parent is
`1095e98a07d60b5cde8b18d8f58f3fa257beb7ce`. The readiness implementation and
shell source retain their independently reviewed SHA-256 identities.

## Current-source and CodeQL checkpoints

At the inventory timestamp, integration `b524f068` has 140 checks: one completed
Windows package check and 139 queued checks. Canonical paper `11e113f2` has one
completed Windows package check and 39 queued checks. These current revisions
have their own hosted qualification; the late-completing failures above retain
their original source identities.

The [targeted queue readback](queue-snapshot.json) at 22:25:33 UTC verifies that
the six installed partitions use the available `macos-15` label and depend on
`rust-publish-contract`. That prerequisite is queued in each current run, so
the downstream matrix has not yet been created. There is no environment hold
or job-specific concurrency limit, and the push and PR workflow groups differ.
The current push run has also assigned a runner to its Ubuntu 26.04 TLS
interoperability job. The visible scheduling records establish where the wait
occurs; they do not expose an account or platform scheduling cause.

The CodeQL readback at **22:19:12 UTC** is retained in
[`codeql-snapshot.json`](codeql-snapshot.json). Its earlier macOS receipt-fixture
failure is fixed by canonical temporary-path resolution in
[`c59b2677`](https://github.com/billlza/q-periapt/commit/c59b2677d66b9091b4b7f5b24d523cde21608653),
an ancestor of `b524f068`. The full-query timeout remains the subject of
[controlled run 42822797947](https://github.com/billlza/q-periapt/actions/runs/42822797947).
Both heap allocations have assigned runners, passed input/tool checks and are
executing the complete 39-query stage. Their query-stage starts are 18:53:38 and
18:55:48 UTC, with the original 18,000-second budget. The completed resource
samples and completeness comparator determine the next performance change.

The six installed-consumer partitions, source-matched aggregate, complete
CodeQL query set and protected-main checks remain the qualification inputs.
