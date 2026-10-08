# Android 16 KiB cleanup failure at 33ca8c5c

PR run `37778711512`, job `113320746533`, failed. This checkpoint preserves that
failure and does not qualify Android runtime/replay.

The full installed consumer completed three tests and verified uninstall with
three absent-package observations. The subsequent minimal consumer also returned
a correctly run-bound `runtimeVersionOnly` pass through Instrumentation. The
retained raw instrumentation was decoded again with the existing parser. Its
application log contains the pass marker and no reported application failure.

The failure occurred during cleanup before uninstall. Two exact postinstall APK
reads and the first cleanup ownership sample passed. The second cleanup sample
returned only 5,291,520 bytes of the expected 13,702,871-byte signed APK despite
exec-out success. Its recorded hash differs. The host ADB server then reported
transport read failures; later ownership observations report device-unavailable.
The guard correctly refused to assume ownership or silently treat cleanup as
successful. The failed receipt was retired while preserving exit status 1.

Guest diagnostics show adbd write failure and cached-system-app LMKD activity.
The available evidence does not establish why the transport broke, an SDK crash,
or memory pressure as the cause. No RAM/image/deadline change, relaxed hash check,
or success-shaped retry is introduced. Both original failure and unresolved
cleanup remain required evidence in any subsequent comparison.

CAPTURES.zip retains the already-public CI diagnostics, complete job log and the
separately decoded minimal workload result. A closed member hash inventory binds
them. Private APK signing material and device-private runtime receipts are absent.
