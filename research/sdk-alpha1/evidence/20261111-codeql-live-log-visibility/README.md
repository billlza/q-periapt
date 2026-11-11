# Live CodeQL command-log visibility

The two long-running command entry points now open retained stdout and stderr files with exclusive, unbuffered binary handles. This makes small flushed child output visible while the process is still running. The bounded capture arguments, output limits, timeout handling, failure propagation and context-manager lifetime are unchanged.

The defect was observed when the controller log still showed 27 of 39 query completions while the official evaluator log and results directory already showed 38. The parent file sink used Python's default buffering, so a flushed child pipe did not imply a visible tail in the retained log file.

## Fixed source and completed validation

| Item | Identity or observed outcome |
| --- | --- |
| Base commit | `faabcff16fc49e1a99388c68f0991a2bfd64d509` |
| Fix commit | `ac02d3032655da78f6ac39642369cb023ebad71d` |
| Fixed tree | `da36191741a59c084c5890eb95174d15fd9f8238` |
| Production entry points | `codeql_summary_control.run_queries` and `codeql_rust_profile.ProfileRun.command` |
| Before-fix control | Both new live-visibility tests reproduced the defect; exit 1, one failure and one error, 10.079 seconds |
| After-fix control | The same 2 tests passed; exit 0, 0.077 seconds |
| Related-module compatibility | 134 tests passed; exit 0, 5.729 seconds |

Each regression starts an actual Python child that writes 12 bytes to stdout and 12 bytes to stderr, flushes both streams, and checks the parent log files before exiting. It records success only after both strings are visible and the final command receipt is still absent. The five-second child poll and ten-second supervisor bound also keep a failing control bounded.

The original commands, per-file source hashes, unchanged capture-call checks and raw outcomes are recorded in `RECEIPT.json`. The focused and compatibility logs are retained unchanged. This evidence belongs to the identified four-file fix; it is not a rerun of the earlier 207-test integration suite or a new large-database query execution. A process that had already imported the old Python code retained that version for its original run.

## Source archive and replay

`reproduction-sources.zip` contains the complete pre-fix production modules, the four fixed source/test files and the unchanged Python runner. `SOURCE_IDENTITY.json` binds every member to its bytes and SHA-256. Restore remaining repository dependencies and fixed assets from the identified fix commit in a separate checkout, then use the exact commands in `RECEIPT.json`. The before/after control keeps the new test files constant and switches only the two production modules.

This packet was assembled from existing validation records and immutable Git objects. Packaging started no additional tests, CodeQL process or JVM and changed no running probe.
