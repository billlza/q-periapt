# Independent macOS composition deadline: failed CI and isolated diagnostic

The original source lane remains failed. This capture preserves its public
composition evidence and a separate local diagnostic; it does not supply a
repair, a replacement four-profile qualification, or release acceptance.

GitHub run `42008994078`, job `127182900343` (`bootstrap (macos-15, arm64,
source)`) used source `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. Its
`policy_composition_checks.py` run completed the 3-member local, 3-member
witnessed, and 32-member local reports. The 32-member witnessed profile failed
in `native-original-R-under-P`, opcode 40, while reading the response prefix:
`TimeoutError: native output deadline`. The existing 30-second native exchange
budget covers request writing and response reading. This was not the later
capacity command; that command had not started.

All four profiles retained the same 16-byte target request,
`00000000000000040000000000000140`. The three completed profiles retained
73-byte responses. The failed profile retained an empty response file and an
empty native stderr. The original job log, all 4,615 files from the remote
`policy-composition/` subtree, relevant tool/build metadata, and original ZIP
inventory are retained. Original artifact `13415808519` has SHA-256
`a2c93354514e151c8f4a3e8b853b7e3faaee39c493ca84b939ee6d554d4d6a44`.

The separate local diagnostic executed the exact downloaded Release arm64
counterpart (SHA-256
`faa384a23d5cc82412a46aac5ed28c577780b603dfb091616c85abdaab821023`),
with all 225 source inputs byte-identical to CI. Both used cryptography 48.0.1
and OpenSSL 4.0.1. The diagnostic host used Python 3.14.10; the CI log records
Python 3.14.7. It used a fresh private fixture and only the 32-member witnessed
profile, preserving the original transport and worker deadlines. Its in-process
900-second alarm unwinds the fixture owner's existing cleanup; no intermediate
supervisor was externally killed.

That isolated profile completed in 280.232 seconds, including 91 worker
operations and 15 actual process cuts. The target native exchange took 12.032
seconds and returned 73 bytes. The 749 timing observations retain request and
response hashes and lengths without changing their contents or return values.
Source and binary hashes were checked again after execution, and the recorded
native process had exited. `qualification_passed` is explicitly false: the
original workload runs four profiles with two workers, and the hosted timeout
has not been reproduced or causally explained by this isolated observation.
It rules out an unconditional hang in this execution, not contention, input
variation, or a slower hosted execution. No timeout, profile count, concurrency
limit, security check, or remote workflow was changed.

`CAPTURE.zip` contains 6,961 members (35,852,341 bytes), with SHA-256
`75c7383e88add0ab34b6250ac4bee0243987ad884572ca8b41c030fb432d5f38`.
It includes the exact executable, source inventory and source files, local
driver and public observations, and original failure evidence.
`CAPTURE.json` records each member's size and SHA-256. CRC and complete byte
readback succeeded. Private state and keys are outside the selected output
trees; retained private-path identifiers were not followed. The first sealer's
incorrect assumption that native path identifiers end with a newline is
retained with its failed outcome; the corrected reader accepts the actual
single-path formats without traversing those paths.
