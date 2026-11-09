# Fixed RAM for the hosted API 35 / 16 KiB runtime

Main commit `c74b1c7ad2173353a297f965ad735639dbd3958b` installed the hash-bound APK successfully, then failed to start its activity because Android reported `cmd: Can't find service: activity`. The emulator log records a 2560 MiB guest. The extracted artifact verifies API 35, x86_64 and a 16384-byte page size. This artifact does not include guest logcat, so it does not establish the underlying service-loss cause.

The fixed hosted AVD now receives `-memory 4096` at the original receipt-bound emulator exec boundary. The same resource setting already passed both the integration branch runtime and replay checks. The main backport is qualified separately by its hosted runtime job.

The focused regression checks the complete exec argument vector, isolation checkpoint, receipt transition, environment and propagated exec failure. With the new regression and old source, the Linux case fails solely on the missing memory arguments while the macOS case passes. Both cases pass after the source change. The full hosted job remains the validation of the resulting Android runtime.

Run the focused checks with:

```sh
sh artifact/python-run.sh -m unittest -v test_android_bounded_command.AndroidBoundedCommandTests.test_emulator_exec_advances_receipt_before_fixed_exec_and_preserves_failure test_android_bounded_command.AndroidBoundedCommandTests.test_hosted_16k_emulator_has_explicit_ram_at_the_original_exec_boundary
```

The exact base, failed run, artifact digest, reference jobs and source hashes are recorded in `evidence.json`. The full recovered log and artifact are preserved in the research evidence package.
