# Completed hosted cohort and CI repair checkpoint — 2026-11-07

Source: `228c944fc476e3e57d6c08063cacb19bca5b360e`  
Git tree: `498b7efa0f9565fe910d73c8368b2a40377d5aa4`  
PR #118 merge: `57d4358f4e3946e336bc7fba2b59b71875592435`, with the same tree.

## Completed execution

The [main push run](https://github.com/billlza/q-periapt/actions/runs/42324117363)
completed at 10:15 UTC. Installed Rust/C and all six Swift, Kotlin and Android JNI
Debug/Release partitions passed. The aggregate coverage verifier downloaded and
verified the six original archives and accepted their source-matched reports at
10:15:01 UTC.

The original `continuity-installed-coverage.zip` is retained here. Its SHA-256 is
`cf786786632bc019b1b307bb98c058632e17dc835ab8a5d35b66619b281bcc06`.
Its sole JSON member records six completed partitions, the exact source commit,
each original report digest and the Rust report digest.

| Workflow | Run | Completed results |
| --- | --- | --- |
| Main push CI | [42324117363](https://github.com/billlza/q-periapt/actions/runs/42324117363) | 67 successful, two failed, one dependency skip |
| Reference account | [42324128069](https://github.com/billlza/q-periapt/actions/runs/42324128069) | 10/10 successful |
| Focused regressions | [42324128011](https://github.com/billlza/q-periapt/actions/runs/42324128011) | 2/2 successful |
| Installed Windows lifecycle | [42324128005](https://github.com/billlza/q-periapt/actions/runs/42324128005) | 8/8 successful |
| Directory lease contract | [42324127879](https://github.com/billlza/q-periapt/actions/runs/42324127879) | 2/2 successful |
| Installed Android JNI | [42324117361](https://github.com/billlza/q-periapt/actions/runs/42324117361) | 2/2 successful |

[CI_READBACK.json](CI_READBACK.json) retains all materialized job identities and
outcomes, selected original artifact digests and the observation timestamp.
At 10:33:07 UTC, the [parallel PR run](https://github.com/billlza/q-periapt/actions/runs/42324128013)
had 58 successful, three failed, five running, two queued and one skipped job.
Its coverage join had not yet materialized. The workflow-level `queued` label
therefore does not describe all of its jobs. This checkpoint preserves those
observed execution states.

## Failure attribution and repair

### Tooling guard

The push tooling job executed 3,414 tests: 3,410 passed, one failed and three were
skipped. The failed assertion is
`AndroidDeviceProofProvenanceTests.test_android_runtime_documentation_requires_explicit_run_selectors`:
two newly added `|| :` diagnostic call sites violated the existing no-swallow
guard. The prepared three-line shell repair explicitly retains the original
structural status 2 and unresolved-cleanup status 1. Diagnostic-output failure is
propagated to those same failure branches.

### Push Android 16 KiB runtime

[Job 128257895212](https://github.com/billlza/q-periapt/actions/runs/42324117363/job/128257895212)
built, signed and installed the full-consumer APK. The first ownership readback
matched the 13,838,288-byte APK; the next read returned 11,810,304 bytes. Host and
guest logs record ADB transport loss. One bounded recovery completed, followed
by a zero-byte read and another transport loss. Remaining observations could not
converge. The final ownership guard exhausted the existing deadline and returned
structural status 2; instrumentation had not started.

The original diagnostics are retained as `push-android16k-diagnostics.zip`:
184,855 bytes, SHA-256
`dbdf159f498fc8491696aa6a509e17d2ad6f2641a498a3ef46498593ae6e7dba`,
from artifact 13556046151. The guest stayed alive and retained the same boot ID;
the underlying cause of transport termination is unestablished.

The prepared Python repair makes a pure, unannotated
`AdbValidationDeadlineExpired` return `retryable:deadline-exhausted` after removal
of the rejected APK copy. Structural errors, attached failure information,
postcheck errors and copy-removal failures retain their fatal paths. The same
absolute deadline is passed through both guards and observation. The existing
shell deadline, consecutive exact-copy/signature requirements and one-shot
transport recovery remain in force; a nonconvergent runtime remains failed.

### PR Android 16 KiB runtime

[Job 128260593107](https://github.com/billlza/q-periapt/actions/runs/42324128013/job/128260593107)
passed two exact ownership readbacks and reached the instrumentation command.
The guest log then records `system_server` PID 992 receiving SIGSEGV at
02:21:25.418, a fatal system-process exception, and zygote exiting after that
system server terminated. The instrumentation command failed at 02:21:29.242.
Cleanup subsequently verified the original APK, uninstalled it and observed
three consecutive absent-package samples; the retained primary status is 1.

The original diagnostics are retained as `pr-android16k-diagnostics.zip`:
174,838 bytes, SHA-256
`193434556316316c29186e60cdd201a096041a7cfe927309b9b934968736e5da`,
from artifact 13556511676. `emulator-crash-logcat.txt` and the observation journal
contain the crash and cleanup evidence. The exact instrumentation output was
absent from both downloaded runtime archives, and the ultimate cause of the
framework crash is unestablished.

### PR macOS runner

[Job 128255605388](https://github.com/billlza/q-periapt/actions/runs/42324128013/job/128255605388)
has a GitHub check annotation identifying hosted-runner communication loss.
The elapsed 81 minutes 41 seconds is below its configured 90-minute job budget.
The annotation does not identify the underlying CPU, memory or network cause.
The push run's corresponding macOS suite passed; both outcomes retain their own
execution identities.

## Local validation of the prepared repair

Python 3.12.14 executed eight diagnostic/guard regression methods and all
19 installed-APK observation methods successfully. The latter include five new
methods covering real listener-budget expiry after an exact copy, both guard
positions, mixed structural errors, attached error notes and failed copy cleanup.
The listener-expiry case reproduced the old failure before the repair.

`sh -n artifact/android-device-smoke.sh` and `git diff --check` also passed.
Independent source review checked the same deadline, fail-closed rejection and
unchanged transport-recovery count. These are the local validation results for
the prepared patch; the original CI jobs remain recorded above.

## Release disposition

This closes the waiting hosted installed-profile checkpoint on the recorded
source. The aggregate coverage receipt keeps `release_claim_eligible=false`
and `publication_performed=false`, consistent with the current candidate
contract. Formal package identities, the adopted protocol/storage contract,
preview compatibility and the final release manifest follow the existing
[0.2.0 scope](../../../../docs/continuity/RELEASE_0_2_SCOPE.md).

The agreed API 37 single-phone acceptance is already satisfied. The existing
[Android environment disposition](../../../../docs/SDK_ANDROID_RUNTIME.md)
keeps extended emulator-root-cause work suspended; the two failed jobs remain
retained. No additional phone or stable emulator is added as a product gate.

The parallel PR wave remains active at this checkpoint. The prepared repair is
kept separate until the standing sequential-wave rule permits the next branch
submission. No rerun or cancellation was issued while collecting this evidence.
