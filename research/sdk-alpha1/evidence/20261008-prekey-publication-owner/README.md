# Native prekey publication checkpoint

Source `2a03b795b5e6569ebc2e6febad17e8d7ce9a938e` passed all 814 native library
tests, 22 related tests in both Debug and Release, strict all-feature Clippy and
Rust 1.90 compilation. `QUALIFICATION.json` records input hashes and the measured
50 sync-failure cases, 15 cancellation boundaries, 15 killed-process boundaries
and 14 real witness request/reply-loss cases. `CAPTURES.zip` retains their logs.

The subsequently completed clean standalone preflight passed the source gate,
44 CodeQL quality-gate tests and all 2,663 artifact tests, with warnings treated
as errors. These are recorded in `PREFLIGHT.json` and `PREFLIGHT.zip`.

This checkpoint implements the native local operation, not remote directory
publication. The Swift/Kotlin checks cover retired-report framing, and the C
adapter check is compilation only. Later registered-owner methods, QPPUBA01
encoding and C publication entry points require their own evidence. Cross-OS,
physical/minimum-device, independent implementation and overall release gates
remain separate. No release or registry publication was performed.
