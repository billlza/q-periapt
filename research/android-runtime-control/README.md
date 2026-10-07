# Android 16 KiB no-SDK-workload control

This bounded diagnostic job addresses the API 35 ps16k failures observed at
`8b8d6320e780610cacc8ceb3dd2a10083c5aa5ee`. It does not replace or relax the Android
package/runtime gates in `ci.yml`, and its output never qualifies a release.

The controller runs only on a disposable GitHub-hosted Linux x86_64 runner. It
checks the exact failed-run system-image, kernel and ramdisk hashes, revision 5
source properties, emulator version 37.2.12, running build fingerprint and 16384
runtime page size. It creates one fresh Pixel 6 AVD, preserving the default memory
and system policy settings and the original headless/SwiftShader launch flags.
No APK is installed and no Q-Periapt consumer executes.

A private adb server disables USB discovery, emulator scanning and mDNS. The
controller registers only its newly spawned emulator. Twelve samples at 30-second
intervals copy the read-only guest ART library and compare the complete length and
SHA-256 with guest hashes taken before and after. Memory counters, zone watermarks,
uptime, system_server PID and bounded filtered logcat are retained. Command errors,
timeouts, successful-but-truncated transfers and system_server restarts fail the
control; they are never retried into a clean result. Boot/registration probes have
explicit separate deadlines. The observation has a 15-minute overall bound.

Every command has a recorded exit result and stdout/stderr hashes, including
partial output. Shutdown signals only the controller's original Popen children;
it never searches for and kills unrelated emulator/adb processes. Private adb keys
and writable AVD data live in a separate temporary directory and are excluded from
the uploaded observations. A missing/incomplete result is an incomplete experiment.

This control uses a smaller transport harness than the release proof collector.
A failure can demonstrate a no-SDK environment problem; a clean result cannot
exclude effects of the SDK workload, the production collector's transport/lifetime
sequence, host scheduling or a rare failure. It is not a native-arm64 or physical
16 KiB device result. Do not infer a shared root cause for the prior system_server
SIGSEGV and adb transfer truncation solely because both occurred on this image.

The workflow runs on the authorized CI branch when its own script/workflow changes.
The ordinary Android runtime jobs continue independently with their existing gates.
