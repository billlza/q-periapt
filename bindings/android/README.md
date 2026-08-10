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
QPERIAPT_ANDROID_SERIAL=<adb-serial> \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical \
sh artifact/android-device-smoke.sh
```

With no attached Android device, the script can boot a named local AVD:

```sh
QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_AVD=<avd-name> \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator \
sh artifact/android-device-smoke.sh
```

The script-owned emulator uses `-no-snapshot -read-only`; runtime writes are discarded
instead of mutating the named AVD's persistent userdata.

The runtime smoke builds a temporary APK that consumes the generated AAR, installs it
through adb, runs the Java facade on ART, and accepts only a run-bound
`QPERIAPT_ANDROID_DEVICE_PASS run-id=<32 hex chars>` marker copied from the
app-private files directory. It covers runtime metadata, signed-policy exact-digest
resolution, OS-random key generation and encapsulation,
context binding, ABI1 legacy-state/rollback/tamper rejection, secret wipe, and
boundary fail-closed checks. Raw hybrid, deterministic seeds/coins, CompatXWing and
combine are forbidden from the AAR's product export surface.
External devices are never selected implicitly. Before installation the smoke
requires the exact package to be absent, and before cleanup it verifies that the
installed base APK matches both this run's exact bytes and signer. Unknown install or
uninstall outcomes are reconciled through bounded repeated observations. Log evidence is bounded to the current
run and tag without clearing any global Android log buffer.
The lane requires `$HOME` to match the current account's non-symlink home directory that is
not writable by group or other users, an owner-controlled non-symlink `~/.android` directory that is not
writable by group or other users, owner-protected `adbkey`/`adbkey.pub` files, and an
already authorized target; do not accept a new authorization prompt during proof.
On macOS, deny-only ACLs may further restrict these nodes, while any allow ACL is
rejected even when the POSIX mode appears private.
Caller-provided adb routing, discovery, and kill-policy environment variables are rejected.
The default IPv4/IPv6 adb endpoints must be absent; the script never stops or reuses them.
It owns a mode-0700, allow-ACL-free `/tmp/qperiapt-adb.<8 chars>/adb.sock` and explicitly routes
every client to that `localfilesystem:` endpoint. mDNS/auto-connect are disabled. Physical
proof is USB-only and serial-bound; the owned AVD server disables USB and enables only emulator
discovery. Parent clients disable both scanners immediately after server spawn so an auto-started
replacement is inert. The server PID/start identity, executable, key, endpoint, transport env,
and mDNS-disabled status are checked before selection and after the final device query. App/AVD/server
cleanup and socket removal complete before atomic final proof publication; failure emits neither an
accepted proof nor the PASS marker. A repository-scoped open-file lock is held before any output reset,
and capability creation defers HUP/INT/TERM until its private state is armed or removed. The script
never signals a cached PID directly. AVD transport
still requires an exclusive trusted evidence host. `SIGKILL`, host loss, and device loss cannot run
traps; use the reported private socket/PID to establish ownership before manual cleanup, and remove an
orphaned `dev.qperiapt.androidsmoke` only after comparing it with the private run APK.
The lane selects every adb/lsof call from a finite operation table backed by a private run capability;
the shared bounded-process module is import-only and has no arbitrary command or output-path CLI.
Capability creation streams the fixed-profile SDK adb from one opened descriptor into a fixed,
run-owned mode-0500 executable under the private work directory while computing its recorded digest.
Every later client/server execution and process-identity check uses that snapshot, so replacing the
SDK path after capability creation cannot redirect an ordinary run. Use
`QPERIAPT_ANDROID_ADB_PROFILE` only with `auto`, `macos-account`, `linux-account`, `linux-system`, or
`linux-opt`; arbitrary `QPERIAPT_ADB` paths are rejected. This is trusted-local reliability hardening;
a hostile same-UID threat model requires a separate account or isolated runner with a read-only
checkout.

Reverify the proof with:

```sh
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 sh artifact/proof-to-byte.sh
```

Clean-tree runtime proof is the release contract. `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1`
and `QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF=1` are only for local diagnostics.

## Published AAR prerelease

A prebuilt research-prerelease AAR is published in the immutable
`abi2-platforms-v0.1.0-alpha.2-r2` GitHub release: one AAR containing `arm64-v8a`,
`armeabi-v7a`, `x86`, and `x86_64` JNI libraries built with stable NDK r29 and
Rust 1.96.1. Every ELF has 16 KiB load alignment, the exact nine-symbol ABI 2
export surface, RELRO/NOW/NX, no text relocations, and no RPATH/RUNPATH. The
release also binds a runtime-evidence bundle that executed the exact public AAR on
the official Android 15 / API 35 `google_apis_ps16k` `arm64-v8a` emulator with
16 KiB pages. Verify the AAR and its manifest with `gh release verify-asset`
against `PLATFORM_DISTRIBUTION.json` and `SHA256SUMS`; see
[`../../artifact/abi2-platform-release-notes.md`](../../artifact/abi2-platform-release-notes.md).
Maven Central publication and physical-device coverage are explicitly not claimed,
and the published emulator evidence does not replace the clean-tree runtime proof
required for a source tree that has advanced past the release tag.
