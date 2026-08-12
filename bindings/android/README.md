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
QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a \
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
proof is USB-only and serial-bound; the owned AVD server disables USB and automatic emulator
discovery. Parent clients keep both scanners disabled. The emulator's external adb is fixed by
`-adb-path` to the run-owned snapshot; its exact ADB-routing projection is fixed to the private
Unix-socket client settings, while launcher-added non-routing variables are outside that commitment;
the emulator-native host notifier is redirected from 5037 to closed loopback port 5586, above the
automatic transport range ending at 5585. After the exact child PID owns its fixed
console/adb listeners, the lane explicitly registers that port pair through the private socket and
rechecks it before selection and shutdown. The server PID/start identity, executable, key, endpoint,
transport environment, and mDNS-disabled status are checked before selection and after the final
device query. Four no-replace receipts record IPv4/IPv6 `ECONNREFUSED` for 5037 and 5586 at emulator
pre-exec, post-registration, runtime pre-cleanup, and post-cleanup. Current proof schema v5 and bundle
schema v2 record those exact checkpoint bytes plus a raw-value-omitting, source-bound control-plane
receipt for the external-adb routing, native-notifier policy, backend, fixed ports, listener, exact
registration response, and private-adb identities. They exclude raw HOME/key/socket, UID, PID, and
serial values and are not independent hostile-builder attestation. App/AVD/server
cleanup and socket removal complete before proof publication in the append-only
`target/qperiapt-android-device-smoke-runs/<32-hex-run-id>/` tree; failure emits neither an accepted
proof nor the PASS marker and leaves any earlier selected proof untouched. A stable,
account-private host/account-scoped open-file lock is held before the unique run root is created.
A durable whole-runtime receipt is committed before the private server releases that lock and binds
the originating run, adb snapshot, endpoint, server, and optional emulator. Long-lived children retain
the registered lock descriptor with close-on-exec set through receipt registration; the kernel closes
it only when the fixed exec succeeds, allowing the next lane to validate and recover an interrupted
runtime. Capability creation defers HUP/INT/TERM until its private state is armed or removed, and the
script never signals a cached PID directly. On the same boot, recovery requires the exact recorded
process/listener identities and uses the authenticated emulator console independently of private adb,
then protocol-stops any still-live private server; after a confirmed reboot it performs offline
cleanup only. The socket directory is reconciled from mode 0700 through the schema-v4 runtime phases
to `ADB_SEALED` plus actual mode 0500 before any adb client. Schema-v3 runtime receipts are rejected
instead of implicitly migrated. Normal proof publication requires accepted protocol shutdowns and
zero child exit statuses; exact already-absent resources can be finalized only by recovery and cannot
make the interrupted run pass. Only the console-token file identity and digest enter the private
receipt, never its bytes. Unsafe receipt/filesystem/listener/path mismatches are preserved and rejected
for operator review; a PID/start-token mismatch is treated as the exact owned process being absent and
is never signalled. AVD transport
still requires an exclusive trusted evidence host, and device loss can still leave app removal
unresolved. Remove an orphaned `dev.qperiapt.androidsmoke` only after comparing it with the private run
APK. The receipt does not continuously reserve 5037 or 5586 between checkpoints; each checkpoint
proves only that its exact IPv4/IPv6 connect attempts were refused, so the exclusive trusted-host
requirement remains. The fixed emulator argv does not enable gRPC; listener evidence binds the
required console/adb pair rather than proving that no other TCP listener exists.
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
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<run-id>/proof/qperiapt-android-device-proof.json \
sh artifact/proof-to-byte.sh
```

The proof path is an explicit selector; consumers never search for the newest run or fall back to the
historical canonical output. Clean-tree runtime proof is the release contract. `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1`
and `QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF=1` are only for local diagnostics.

## Published AAR prerelease

A prebuilt research-prerelease AAR is published in the immutable
`abi2-platforms-v0.1.0-alpha.2-r2` GitHub release: one AAR containing `arm64-v8a`,
`armeabi-v7a`, `x86`, and `x86_64` JNI libraries built with stable NDK r29 and
Rust 1.96.1. Every ELF has 16 KiB load alignment, the exact nine-symbol ABI 2
export surface, RELRO/NOW/NX, no text relocations, and no RPATH/RUNPATH. The
release also binds a runtime-evidence bundle that executed the exact public AAR on
the official Android 15 / API 35 `google_apis_ps16k` `arm64-v8a` emulator with
16 KiB pages. That historical published receipt remains schema v3; current source-tree runs require
schema v5 and do not retroactively change the immutable release. Verify the AAR and its manifest with `gh release verify-asset`
against `PLATFORM_DISTRIBUTION.json` and `SHA256SUMS`; see
[`../../artifact/abi2-platform-release-notes.md`](../../artifact/abi2-platform-release-notes.md).
Maven Central publication and physical-device coverage are explicitly not claimed,
and the published emulator evidence does not replace the clean-tree runtime proof
required for a source tree that has advanced past the release tag.
