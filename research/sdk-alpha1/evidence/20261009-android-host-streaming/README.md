# Linux host-streaming experiment for the Android APK truncation

This bounded experiment tests one candidate explanation for the `b1006eb3`
Android 16 KiB failure: the host output reader might stop when a subprocess
exits, or lose part of a large stream during fragmented writes. It does not
replace the retained failing emulator run or reproduce its ADB transport.

The exact `artifact/bounded_process.py` bytes from the failed CI source were
copied unchanged to the retained native Linux aarch64 VM. Python 3.14.7 runs
as UID 1000 in the original Debian 12 container, without host bind mounts.
The input is the successful parallel job's actual minimal APK, **13,702,871
bytes**, rehashed against its runtime proof. Its run/signing identity differs
from the failed job's APK; this experiment holds stream length constant.

All **13 real subprocess/file-output cases** satisfy their explicit assertions:

* Eight complete copies: two each for bulk output, 4,093-byte fragments,
  65,536-byte chunks, and a parent process that exits before its child finishes
  writing the inherited stdout pipe. Each retained output has the exact APK hash.
* Two zero-exit early-EOF controls retain exactly 1,119,744 and 6,271,488 bytes,
  the two lengths observed in the failed job. Their whole-APK size/hash predicate
  is false. A process exit of zero alone cannot establish complete APK delivery.
* Nonzero exit, output overflow and timeout each retain their failure status
  and publish no partial output; no temporary output file remains.

Source inspection agrees with these observations: `_stream_stdout` waits for
reader EOF before accepting the child result, and `_write_stdout_impl` loops
on short `os.write` results. The higher-level Android observer additionally
checks exact size/hash; that policy is not changed or replaced by this probe.

These cases do not reproduce host reader loss, including the simple premature-
exit hypothesis. Finite tests do not rule out every load-dependent race, and
this aarch64 Linux VM is not the hosted x86_64 runner. No ADB, emulator, ART or
SDK workload executes in this experiment. The real disconnect root cause and
stable 16 KiB acceptance remain open; no retry, timeout or acceptance rule was
changed. The VM/container were restored to their original stopped state.

`CAPTURES.zip` retains the unchanged reader, isolated `emit.py`/`probe.py`, exact
command/interpreter/container/input identities, every result and teardown checks.
The APK and observed binary copies are retained locally, not duplicated into
repository history. To replay, obtain the hash-bound APK member named in
`INPUTS.json`, place it beside the scripts as `payload.apk`, and run `probe.py`
with Python 3.14 on Linux in a fresh private directory.
