# Migration error-path lease release

The offline policy-store migration coordinator now explicitly releases its
original file lease after all provider references have gone away, on both success
and error paths. The current provider finishes its sync work while that lease
remains owned by the coordinator. Close errors enter the existing typed I/O
tracker; a successful unlock cannot hide an earlier failure. No retry, timeout,
file-admission, commit, or test assertion has been weakened.

This follows push CI run 37940902612, job 113854726213, at source
`f4b35dcb237fa44ef92f7700f1f1fd9e6575e1f7`. The Apple Silicon migration step
failed in `io_errors_across_both_providers_remain_typed_and_never_report_success`
with `exclusive file lease: DatabaseAlreadyOpen`. The surrounding Swift job name
does not locate the failure in Swift code. Its complete job log is retained.

The exact unmodified source passed a local run. A separate deterministic macOS
experiment retained a duplicate of the admitted open file description, injected
an early I/O error, and confirmed that the Rust backend owner had died through a
Weak reference. A competing open still failed until the retained descriptor was
dropped. The regression requiring immediate lease release failed before the
coordinator repair and passed after it, with identical test-source hashes.
This establishes a concrete missing-cleanup path. It does not prove which
descriptor, process-spawn window, or fault ordinal occurred on the CI runner.

The first repair candidate added a second close after provider close. The
existing independent-competitor test correctly rejected that extra close because
the lease was already released. The final implementation has one coordinator
release after provider shutdown; the failed candidate is retained in the capture.

Validation of the final source:

- macOS arm64 Debug and Release: 12 tests each, including the new regression.
- Native Linux arm64, GCC 12.2, Rust 1.98.1: 12 tests, including the Linux legacy
  flock admission case. This is an isolated VM/container run, not emulation.
- Each full run preserved 48 independent competitor refusals, 37 partial-write
  failures, 232 typed I/O fault cases and 126 process-exit cuts.
- Strict Clippy with migration enabled, Rust 1.90 all-targets checking, and
  formatting passed. The existing Linux VM/container were restored to stopped.

`VERIFIED.json` binds the tested source files and commands; `CAPTURE.json` binds
the raw logs and manifests in `CAPTURES.zip`. Sixteen first-install configuration
prototype tests are a separate work stream and are not included in this repair.
The CI rerun and full 0.2.0 release gates remain open. Do not supersede the
in-progress f4 Rust CodeQL analysis until its quality/upload results and retained
diagnostic artifact have been collected.
