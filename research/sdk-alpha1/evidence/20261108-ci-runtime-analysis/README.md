# CI extraction, diagnostics and Android runtime repair

The inspected integration head is `72acaaccde1ca9ea27e5af022da5fbce932ed4e9`.
Maintenance PR #120 passed all 75 check runs at
`2ccb162ef30a8a2dce077aea9f74cd7ab6a37614` and was merged as
`c74b1c7ad2173353a297f965ad735639dbd3958b`.

## Observed failures and corresponding changes

The native and macOS Rust CodeQL jobs reject the extraction inventory because
`crates/q-periapt-host-store/src/filesystem/maintenance/attempt/tests.rs` is
absent from successfully extracted paths. Native artifact `13601703606` records
the unresolved `panic_2021` expansion inside the inactive Windows-only
`assert!` at original line 737. The common non-success assertion now follows
the child's `wait()`, and Unix retains its exact SIGKILL assertion. The source
coverage gate and original test outcomes remain required.

The WASM analysis job `128604106093` reached its 18,000-second execution bound.
The original command wrapper wrote captured streams only after success, so
its failure artifact omitted emitted query progress. The wrapper now streams
both bounded outputs to new evidence files and preserves the original failure
receipt. An independent workflow artifact retains raw query logs before the
database archive is assembled. The prior full diagnostics artifact
`13609897355` is 600,073,757 bytes; the current download interface rejects
archives larger than 536,870,912 bytes. Current-query completion and its
performance diagnosis remain open. No query, threat model, resource budget,
deadline or publication threshold was changed.

Android job `128614763157` in workflow run `42439010947` completed both full and
minimal instrumentation. Minimal cleanup then encountered an exact APK
readback mismatch followed by unavailable ADB transport. Artifact `13602108468`
retains both executions. Its emulator log selects 2,560 MiB RAM; guest logcat
records sustained low-memory-killer activity affecting system applications and
a phone-process SIGSEGV. These observations motivate an explicit 4,096 MiB
allocation for the hosted Linux/x86_64/API-35/16-KiB profile. The allocation is
fixed in the owned emulator argv. The API-23 and macOS profiles keep their
configured memory. Exact APK/path/signer checks, operation deadlines, cleanup
authorization and failure propagation remain in force. Fresh hosted execution
will determine whether this resource correction closes the observed failure.

The macOS candidate and account jobs separately failed while downloading
the pinned Python 3.14.7 runtime with HTTP 504. Their application code did not
cause that setup failure. The new source cohort will execute the same pinned
setup and the original tests.

## Local validation

All 116 existing CodeQL preflight tests pass through the isolated repository
Python launcher. The expanded real-child timeout test preserves both streams,
records the timeout, and produces no successful analysis receipt. Running the
old command implementation reproduces the missing-output defect.

The three emulator exec-boundary cases pass, checking receipt creation,
failure preservation, the hosted 16-KiB RAM arguments and unchanged API-23/macOS
selection. The new hosted case fails against the original `exec_emulator`
at the expected missing-memory-argument assertion. Python syntax, workflow YAML
and whitespace checks pass.

The complete Android test module is not locally qualified in this execution
environment. Native process-identity fixtures fail before their intended
boundary because the process namespace reports PID 14 while `/proc/14` is
absent. The original process-identity contract is retained. Complete runtime
and native CodeQL extraction results must come from the new hosted cohort.
The unchanged historical results ledger has SHA-256
`9974f5a3d2cb754817aa857a10859582d329c97edd61a44d41a2fb701d564bda`.

## References

- [Native Rust analysis](https://github.com/billlza/q-periapt/actions/runs/42439010975/job/128604105917)
- [macOS Rust analysis](https://github.com/billlza/q-periapt/actions/runs/42439010975/job/128604106085)
- [WASM Rust analysis](https://github.com/billlza/q-periapt/actions/runs/42439010975/job/128604106093)
- [Android 16-KiB runtime](https://github.com/billlza/q-periapt/actions/runs/42439010947/job/128614763157)
- [Android emulator RAM option](https://developer.android.com/studio/run/emulator-commandline)
