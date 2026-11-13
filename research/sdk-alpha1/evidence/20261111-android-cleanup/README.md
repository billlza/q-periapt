# Android cleanup budget repair

The failed API 35, 16 KiB page-size job installed the APK and reached the normal cleanup path after its run-bound PASS text, result JSON read, and app-log failure-marker check. Its 45-second shared cleanup window left only one second for the second authorized uninstall attempt; that command timed out. Full result-field verification and the final runtime proof occur after cleanup and had not yet executed.

The repair gives owned cleanup a 120-second shared window, caps each uninstall at 60 seconds, and reserves the final 20 seconds for three bounded absence observations. Exact ownership and signer checks, repeated absence, timeout and signal failures, and the original failing exit status remain enforced. Timing receipts identify the actual command budget and exit. Integration retains its existing emulator-failure capture.

`android-cleanup-timing-control.json` records the old and repaired shell paths under the same deterministic external-command clock. The old path timed out at 45 seconds; the repaired path reached three consecutive absence observations at 57 seconds, with two signer checks and two uninstall requests in each case. `android-cleanup-regression.log` records the focused canonical regression run. `validation.json` identifies the integration port and its separate 41-test result.

`paper-android-failure.zip` is the original hosted failure artifact, bound by SHA-256 in the receipt. Hosted validation of the repaired source is tracked by the new workflow run, not inferred from these local controls.
