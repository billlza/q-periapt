# Android 16 KiB runtime observation — 2026-10-17

[PR job 117415938800](https://github.com/billlza/q-periapt/actions/runs/39038905682/job/117415938800)
at source `fca7a0bcc6f9054dde175afbd0d99864fa281694` fails during the installed
Android consumer gate. The runtime reports a 16384-byte page size on the API 35
`sdk_gphone16k_x86_64` image. Installation succeeds; run-bound instrumentation
returns `pass`, count 3 and terminal code -1 for:

- `sdkOwnersAndPurposeKeys`
- `sdkExpertCancellationAndInputSnapshot`
- `sdkSignedPolicyRevocationAndRecovery`

The job subsequently cannot confirm application cleanup. Its first cleanup
query sees the installed package; the following APK copy returns only 15872 of
13821904 expected bytes, and later queries report the device unavailable. The
bounded cleanup deadline expires, followed by failed exit-info/state/crash-log
capture over the absent ADB transport. The job correctly remains failed and
does not publish a successful two-consumer runtime closure.

Guest diagnostics show repeated low-memory kills and two Binder allocation
failures for 1056768-byte buffers. These are observed infrastructure symptoms,
not proof of the final transport-loss cause. No retry, guest privilege change,
weakened cleanup assertion or product patch is justified solely by the partial
instrumentation success. The separately accepted Android physical-device
cohort remains accepted; this hosted emulator failure does not replace it.

[OBSERVATION.json](OBSERVATION.json) records the decoded instrumentation result,
source identity, failed job and bounded diagnostic scope. The original
[diagnostic artifact 12103776254](https://github.com/billlza/q-periapt/actions/runs/39038905682/artifacts/12103776254)
is retained locally with its full 182853 bytes independently checked against
the GitHub API SHA-256:
`b5d26b9670e906b11b1e9d66aed809d13ce129b9b3ec140f410d98e9de9bbb7f`.
The complete hosted gate and overall CI are not reported as passed.
