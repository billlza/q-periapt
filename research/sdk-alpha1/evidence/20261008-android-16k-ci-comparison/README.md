# Android 16 KiB: matched CI success/failure comparison

Two original CI runs for the same Git tree differ at cleanup. PR run
`37778711512` failed in the minimal consumer's APK readback/ADB transport; its
failure is retained in the adjacent cleanup-failure checkpoint. Existing push
run `37778700773` passed both complete workloads, ownership-checked uninstall,
public export and independent Linux evidence replay. This was not a new retry.

The downloaded push runtime artifact `11552595745` and replay artifact
`11552186425` match their API SHA-256 digests. Local comparison verifies equality
of the AAR bytes, all eight native FFI/JNI library hashes, ADB binary, emulator
backend, system image/kernel/ramdisk/source-properties hashes, extracted image
metadata, device fingerprint and build tools. Both use the same full Git tree.
AAR manifest differences are limited to the actual branch/PR merge commit and
their time fields. Consumer APKs have separate run IDs/signing material and are
not claimed byte-identical.

Both successful consumer traces contain two exact cleanup ownership samples,
an admitted uninstall and three consecutive absent observations. The separate
hosted verifier's retained report binds both public proof closures and the
three/full and one/minimal test identities. This local work compares retained
CI evidence; it does not rerun the Android emulator or SDK workload.

The observations establish intermittency under these recorded identities.
They do not identify the cause, control hosted scheduler/load, prove stability,
or supersede the original PR failure. No product, memory limit, image, timeout,
cleanup guard or acceptance criterion was changed to obtain this comparison.
