# New platform failures in the active CI wave

The 12:11 UTC snapshot still contains queued and running jobs. This capture
records three new failures; it does not declare the wave terminal.

* Android 16 KiB jobs `127187316739` (117 push, run `42008993544`) and
  `127186189837` (118 push, run `42008993679`) installed the APK successfully.
  Their actual instrumentation records decode to three passing device tests.
  Both jobs subsequently failed because run-owned package cleanup remained
  unresolved. The first uninstall log reports `service package: Broken pipe`;
  the second also records transport and diagnostic-capture failures. The jobs
  remain failed. The matching emulator serial hash does not identify one shared
  emulator across these independent runners.
* macOS reference-account job `127182939597`, run `42009001650`, executed actual
  PR merge source `b08a90d840e1a6f8763cc60b7dabb0a04b6f578b`. Its Release library
  suite passed 134 tests. The binary suite passed 12 and failed one:
  `http_account_and_policy_issuers_recover_original_approval_and_adopt_without_reenrollment`.
  The failure occurred while writing the oversized policy-approval request:
  connection reset by peer, OS error 54. An expected HTTP refusal was not
  verified. The network/fixture cause remains to be traced.

Complete job logs, all 12 job snapshots, and the three verified diagnostic
artifacts are retained. The separate approximately 21 MiB Android runtime
artifacts were not downloaded; the diagnostic archives are 233,105 and 188,605
bytes, and the macOS archive is 22,581 bytes. Original artifact sizes and hashes
are available in the captured job logs. No remote rerun, cancellation or new
push was performed.

`CAPTURE.zip`: 587,845 bytes, 19 members, SHA-256
`8dcf1ec65c8b171d14b92d9dc17b263a3676dc9d2e3b427005f4617a9dc10b53`.
Every member was CRC checked and read back against `CAPTURE.json`.
These remote failures are separate from the local host JNI parent timeout and
the bounded-process composition reproduction.
