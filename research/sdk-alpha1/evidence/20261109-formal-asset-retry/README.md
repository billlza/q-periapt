# Bounded recovery from formal-tool asset download failures

The ProVerif setup in [run 42554253799](https://github.com/billlza/q-periapt/actions/runs/42554253799/job/128956333414)
failed after three HTTP 504 responses while fetching the pinned opam 2.5.2
binary. The Tamarin setup in [run 42551831861](https://github.com/billlza/q-periapt/actions/runs/42551831861/job/128948894530)
exhausted the same policy for Tamarin 1.12.0. The existing two backoffs covered
45 seconds. `observed-failures.json` preserves exact diagnostic lines, source
job links and full downloaded-log hashes. The contemporaneous ARM Python
setup also received HTTP 504 responses through `actions/setup-python`; its
separate downloader is outside this change.

## Transport policy

`artifact/formal_tool_asset.py` permits at most six transfer attempts, separated
by 15, 30, 60, 120 and 180 seconds. A shared 900-second monotonic budget covers
the transfers and these waits. Every child receives at most the remaining whole
seconds, capped at the existing 300-second process limit. Curl's own maximum is
clipped to that allowance and capped at the existing 270 seconds. Insufficient
time for the next wait plus a transfer fails immediately; scheduler oversleep
cannot start another transfer after the deadline. The existing bounded process
cleanup still runs on failure.

Only curl statuses 5, 6, 7, 16, 18, 22, 28, 35, 52, 55, 56 and 92, plus the
supervisor's transfer timeout, receive this policy. They identify resolution,
connection, partial-transfer, HTTP, timeout, TLS connection and transport
failures in the [curl exit-code documentation](https://curl.se/docs/manpage.html#exit-codes).
Curl status 22 covers HTTP errors generally; this stdout-only download interface
does not separately classify their HTTP response codes. All other curl exits,
including certificate verification and local I/O failures, stop immediately.

Each attempt starts with an absent target. Failed-process output is discarded
by the existing descriptor-relative atomic writer. A successful transfer must
still have the fixed byte count, SHA-256, private metadata and directory
identity. Integrity, metadata and structural process failures stop immediately.
The three production URLs and their byte/digest pins are unchanged. No alternate
source or previously downloaded output is selected.

## Verification

The 29 tests in `test_formal_tool_asset` pass through the repository's hardened
Python entrypoint. The new controls exercise shared-budget exhaustion, clipped
final allowances, insufficient time for another retry, scheduler oversleep,
sixth-attempt recovery, non-retryable exits and integrity rejection after a
transport failure. Existing cleanup, symlink, output-bound, interruption and
publication-failure controls remain active.

The distinguishing control launches actual child processes through
`write_stdout_at`: three emit partial bytes and exit 22; the fourth emits the
complete pinned fixture. The original downloader stops after the third child;
the revised downloader admits the fourth child's bytes with no partial-file
residue. `base-control.log`, `candidate-control.log` and `validation.json`
record that before/after result and its source identities.

Reproduce the revised controls:

```sh
sh artifact/python-run.sh -m unittest -v test_formal_tool_asset
```

The transport controls establish the bounded retry and cleanup behavior. They
leave the hosted ProVerif and Tamarin execution result to their own jobs.
