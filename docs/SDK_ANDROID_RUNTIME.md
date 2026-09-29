# Android SDK runtime qualification

The SDK retains **ABI major 2**, `libq_periapt_ffi_abi2.so` and
`libqperiapt_jni_abi2.so`. Its package version is `0.2.0`. The original
nine C functions retain their signatures; the SDK package has a separate closed
allowlist of 43 C exports and 26 JNI methods.

This document describes the maintainer runtime gate. Normal application setup
is in [the Android package guide](../bindings/android/PackageREADME.md).

## Explicit profiles and evidence scope

The shared `android-device-smoke.sh` collector accepts two SDK profiles:

| Profile | Actual minified application workload |
| --- | --- |
| `agp_sdk_full_release` | Public owners and all purpose keys; expert transfer, cancellation and input snapshot; signed revocation, recovery and re-enabling |
| `agp_sdk_minimal_release` | Only the public `runtimeVersion()` call; all 26 native registrations and the exception callback must survive R8 without application keep rules |

The full workload uses in-memory policy state. It does not qualify an Android
durable state store. Both profiles consume the exact selected four-ABI AAR,
compile Java 11 bytecode with JDK 21 / AGP 9.4.1 / Gradle 9.8.0, run as
non-debuggable release APKs, and return results through the manifest-declared
Instrumentation component. The runtime target for these profiles is an owned
API 35 emulator with 16-KiB pages, explicitly selected as `arm64-v8a` or `x86_64`.
Those two architectures are separate evidence scopes. Neither covers API 23,
a current physical device, nor an unexecuted ABI slice.

SDK build receipts use `qperiapt.android_sdk_agp_consumer_build`; runtime
receipts use `qperiapt.android_sdk_agp_consumer_proof`. The old 0.1.5 profiles,
receipt kinds and arm64 projection contract remain separate. Verification does
not choose the expected package or architecture from the submitted proof.

## Collection

Start from a clean standalone Git checkout of the selected source commit. The
linked-worktree and dirty-source guards remain active. Build the AAR with
`sh artifact/android-aar.sh --profile sdk-020`, then retain its AAR and
manifest digests. Select the registered SDK/NDK tools and JDK 21. Gradle and its
AGP dependencies must already be cached; the formal collector builds offline.
The installed Maven qualification helper can populate that cache while
checking the independent package consumer; its build report is not ART evidence.

The collector retains the existing private-ADB lane, account lock, owned AVD,
source/AAR pins, APK signer ownership and cleanup checks. An occupied global
ADB port is an admission failure; the collector does not acquire ownership of
an unrelated server by killing it.

For example, after selecting the hash-bound AAR, manifest and a prepared x86_64
CI AVD, run each profile with these explicit selectors:

```sh
for sdk_profile in agp_sdk_full_release agp_sdk_minimal_release; do
  QPERIAPT_ANDROID_CONSUMER_PROFILE="$sdk_profile" \
  QPERIAPT_ANDROID_ADB_PROFILE=linux-system \
  QPERIAPT_ANDROID_RELEASE_MODE=1 \
  QPERIAPT_ANDROID_BOOT_AVD=1 \
  QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator \
  QPERIAPT_ANDROID_EXPECT_ABI=x86_64 \
  QPERIAPT_ANDROID_EXPECT_SDK=35 \
  QPERIAPT_ANDROID_EXPECT_PAGE_SIZE=16384 \
  QPERIAPT_ANDROID_EXISTING_AAR="$SELECTED_AAR" \
  QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST="$SELECTED_MANIFEST" \
  QPERIAPT_ANDROID_EXPECTED_AAR_SHA256="$SELECTED_AAR_SHA256" \
  QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256="$SELECTED_MANIFEST_SHA256" \
    sh artifact/android-device-smoke.sh || exit
done
```

On the canonical macOS lane, select `macos-account` and `arm64-v8a` instead.
Use the SDK's registered AVD profile for that architecture. Missing or unsupported architecture selectors are rejected before acquiring
the runtime lane.

Boot admission waits for `sys.boot_completed=1` and completion of any legacy
full-disk-encryption framework transition. Android can finish a temporary
encryption framework before replacing `/data` and starting its full framework;
the boot-completed property alone is insufficient. The native, read-only query
accepts an empty `vold.decrypt` for boot flows without that transition, or
`trigger_restart_framework` for the completed FDE handoff. Other states remain
pending within the existing 120-second boot deadline. Guest command failures
and incomplete responses cannot become readiness on old ADB transports.
This follows the [AOSP encryption startup flow](https://source.android.com/docs/security/features/encryption/full-disk)
and [Android 6 init service transitions](https://android.googlesource.com/platform/system/core/+/android-6.0.1_r81/rootdir/init.rc).
The emulator state snapshots retain mount and encryption properties alongside
process identities, so qualification can check the admitted runtime.

## Portable replay and CI

After runtime cleanup, the SDK collector verifies and exports the complete
profile closure to the run's `proof/agp-evidence/` directory. This contains the
original proof, selected AAR and manifest, signed APK, Instrumentation response,
results, emulator control evidence, AGP source/JVM/R8 receipts, and binary dumps.
The exporter re-verifies that copy, including actual SDK-tool replay of the APK.
The source checkout must still match the receipt; the original run and AAR
paths need not remain available for exported replay.
Use a compatible host with the recorded Build Tools executables: replay checks
the hashes of `dexdump`, `aapt2`, `apksigner` and `zipalign` before executing APK
inspection. Host-specific binaries can differ even at the same Build Tools
version. For example, a Linux receipt can reject a macOS `dexdump` before any
DEX replay; that refusal does not complete local replay.

```sh
sh artifact/python-run.sh artifact/android_agp_consumer.py verify-export \
  --root "$PWD" --directory "$EXPORTED_PROFILE_DIRECTORY" \
  --profile agp_sdk_full_release --expected-device-abi x86_64 \
  --expected-source-commit "$SELECTED_COMMIT" \
  --expected-aar-sha256 "$SELECTED_AAR_SHA256" \
  --expected-aar-manifest-sha256 "$SELECTED_MANIFEST_SHA256" \
  --sdk "$ANDROID_HOME"
```

These expected values come from the independently selected build, not from
untrusted fields in the proof being checked. `runtime_target` in the validated
projection binds device kind, architecture, API level and page size.

CI uses the distinct `android-sdk-020-aar` raw-artifact intake contract,
checks the downloaded artifact digest and source identity, qualifies the Maven
consumer, and runs both SDK profiles against the same AAR on x86_64. It uploads
both complete runtime closures on success and retains available package/closure
diagnostics if a later step fails. Partial evidence does not satisfy the paired
runtime gate. There is no SDK-to-legacy fallback or package
rebuild in the runtime lane. The arm64 and physical-device gates remain separate.

The diagnostic clock is captured and validated before installation. An install
reply failure, post-install ownership failure or launch failure stays a failure;
the runner collects the bounded, run-filtered smoke log without retrying the
install. Only a currently owned emulator can additionally supply the fixed
system/installer error tags, under the existing 30-second and 16 MiB limits.
Diagnostic failure cannot replace the primary error. App cleanup still needs
its fresh exact APK observations and signer check, including when an install
may have committed before its reply failed.

Owned emulator runs also record `emulator-state-before.txt` before installation
and attempt `emulator-state-failure.txt` when a later operation fails. These
15-second, 64 KiB captures use native commands for boot identity, uptime, memory,
data-partition space, zygote properties and the process table. They do not launch
ART. Each probe keeps its exit status, and a run-bound completion record restores
the guest status on legacy ADB. A failed or incomplete baseline stops before
installation; a failed error-path capture preserves the original error. The two
files remain distinct, and physical runs cannot invoke either operation.
Read these snapshots together with the runtime result and system log when
distinguishing kernel reboot, framework restart and resource pressure. CI keeps
the baseline on successful runs as well as the available failure diagnostics.

When the existing one-shot transport recovery observes the same owned emulator
back in `device` state, it now immediately attempts `emulator-state-recovery.txt`
and `emulator-recovery-logcat.txt` before another APK ownership read. Each capture
has a five-second cap and shares the original post-install/cleanup deadline; no
new grace period or additional transport retry is granted. The captures reuse the
same owner checks, 64 KiB state bound and 16 MiB log bound. Their command statuses
and errors are retained even if the guest disappears again. A capture failure is
explicitly recorded as unavailable, and signals terminate the caller. Diagnostic
data grants no cleanup authority: uninstall still requires both fresh matching
APK observations and the signer check. Recovery files are distinct from baseline
and final-failure files and remain forbidden for physical-device runs.

The current [readiness ledger](SDK_0_2_RELEASE_READINESS.md) records which of
these gates have actually executed. Synthetic verifier tests, an APK build,
workflow syntax checks and historical device receipts do not establish a
current SDK ART pass.
