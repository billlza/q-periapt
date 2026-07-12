# Q-Periapt Android AAR/JNI

This binding is the Android product surface for `q-periapt-ffi`. It is deliberately
separate from `bindings/kotlin`, which is a JVM/Panama FFM binding for JDK 22+ and
does not run on Android ART.

The AAR and runtime smoke expose the ABI2 signed-policy/OS-random KEM surface, not an identity,
prekey, ratchet, multi-device, or recovery protocol. Emulator/physical runtime proof
must not be described as PQ3/Signal session parity. Future Continuity evidence needs
a physical two-endpoint stateful workload and its own source-bound performance and
fault-recovery gates; see
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).

The Android binding keeps the Rust C ABI as the only cryptographic implementation:

- every AAR slice carries `libq_periapt_ffi_abi2.so` plus the narrow
  `libqperiapt_jni_abi2.so` adapter; legacy unversioned names are rejected;

- `QPeriaptAndroid.java` is a small Java facade for Android apps.
- `qperiapt_jni.c` registers native methods from `JNI_OnLoad` and marshals Java
  arrays into the existing `q_periapt_*` C ABI.
- `artifact/android-aar.sh` cross-builds the Rust Android `.so` slices, builds the
  JNI shim, creates a deterministic AAR, audits the archive, and compiles an
  isolated consumer against the AAR's `classes.jar`.

Run from the repository root:

```sh
sh artifact/android-aar.sh
```

Local in-progress diagnostics can set `QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1`; that is
not release provenance. This gate is package-only: it proves AAR shape, Android ELF
ABI slices, `JNI_OnLoad`/`RegisterNatives` export shape, Java facade compilation,
dex conversion, and an isolated consumer compile. Runtime proof is tracked by the
separate device/emulator smoke below, not by this package-only gate.

For runtime proof, run:

```sh
sh artifact/android-device-smoke.sh
```

With no attached Android device, the script can boot a named local AVD:

```sh
QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_AVD=<avd-name> \
sh artifact/android-device-smoke.sh
```

The runtime smoke builds a temporary APK that consumes the generated AAR, installs it
through adb, runs the Java facade on ART, and accepts only a run-bound
`QPERIAPT_ANDROID_DEVICE_PASS run-id=<32 hex chars>` marker copied from the
app-private files directory. It covers runtime metadata, signed-policy exact-digest
resolution, OS-random key generation and encapsulation,
context binding, ABI1 legacy-state/rollback/tamper rejection, secret wipe, and
boundary fail-closed checks. Raw hybrid, deterministic seeds/coins, CompatXWing and
combine are forbidden from the AAR's product export surface. Reverify the proof with:

```sh
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 sh artifact/proof-to-byte.sh
```

Clean-tree runtime proof is the release contract. `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1`
and `QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF=1` are only for local diagnostics.
