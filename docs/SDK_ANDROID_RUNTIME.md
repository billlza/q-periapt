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
compile Java 11 bytecode with JDK 21 / AGP 9.4.1 / Gradle 9.7.1, run as
non-debuggable release APKs, and return results through the manifest-declared
Instrumentation component. Runtime targets are selected independently of the
submitted proof:

| Runtime profile | Target | Accepted ABI |
| --- | --- | --- |
| `api35-16k` (default) | Owned API 35 emulator, 16-KiB pages | `arm64-v8a`, `x86_64` |
| `api23-4k` | Owned API 23 emulator, 4-KiB pages | `x86_64` |
| `physical-api36-4k` | Explicit USB physical device, API 36, 4-KiB pages | `arm64-v8a` |

Each target and architecture is a separate evidence scope. A profile's availability
does not establish that it has executed. Physical-device results cannot replace
the canonical 16-KiB or minimum-API emulator gates, or qualify an unexecuted ABI.

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

The collector retains the existing private-ADB lane, account lock, owned AVD for emulator runs,
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

For a physical run, select `physical-api36-4k`, set `QPERIAPT_ANDROID_BOOT_AVD=0`,
`QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical`, `QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a`,
`QPERIAPT_ANDROID_EXPECT_SDK=36` and `QPERIAPT_ANDROID_EXPECT_PAGE_SIZE=4096`.
Set `QPERIAPT_ANDROID_SERIAL` to the independently selected USB device and retain
the same clean release mode, AAR/manifest hashes and both SDK consumer profiles.
The collector rejects emulator boot selection and mismatched device properties
before installation; it neither launches nor recovers an AVD for this target.
The public proof records hashed device identifiers and `emulator_control: null`.
This target is intentionally limited to that device shape; additional devices
need explicit profiles and their own runtime evidence.

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
results, emulator control evidence when applicable, AGP source/JVM/R8 receipts, and binary dumps.
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
For a physical export, pass `--expected-device-abi arm64-v8a` and
`--expected-runtime-profile physical-api36-4k`. Omitting the physical selector
retains the default emulator expectation and rejects the physical proof.

CI uses the distinct `android-sdk-020-aar` raw-artifact intake contract,
checks the downloaded artifact digest and source identity, qualifies the Maven
consumer, and runs both SDK profiles against the same AAR on x86_64. It uploads
both complete runtime closures on success and retains available package/closure
diagnostics if a later step fails. Partial evidence does not satisfy the paired
runtime gate. There is no SDK-to-legacy fallback or package
rebuild in the runtime lane. The arm64 and physical-device gates remain separate.

Each emulator target also stages a separate, fixed 56-file transport containing
both complete public closures. Staging verifies the transported copies before
upload. The `bindings-android-runtime-replay` matrix then uses fresh Linux jobs
to strictly extract that same-run artifact, restore the closures, and replay
both APKs with the recorded Build Tools binaries. The expected AAR and manifest
hashes come directly from the AAR producer job outputs. The source commit and
runtime target are selected by the workflow, independently of the proof.

`android_sdk_runtime_replay.py verify` refuses any original runtime-run or AAR
directory in the checkout. It invokes neither Gradle nor an Android runtime;
it verifies source, package, receipts, results and actual SDK inspection of the
exported APKs. Extra or missing files, additional producer attempts, mismatched
tools, and failed APK inspection fail the gate. Its report remains incomplete
on failure. This independent replay complements the recorded ART execution;
it does not execute a new device workload or establish long-run stability.

The diagnostic clock is captured and validated before installation. An install
reply failure, post-install ownership failure or launch failure stays a failure;
the runner collects the bounded, run-filtered smoke log without retrying the
install. Only a currently owned emulator can additionally supply the fixed
system/installer error tags, under the existing 30-second and 16 MiB limits.
Diagnostic failure cannot replace the primary error. App cleanup still needs
its fresh exact APK observations and signer check, including when an install
may have committed before its reply failed.

Runtime receipt reads and lifecycle writes coordinate on the stable account-state
directory inode: reads hold a shared lock across opening, validating and consuming
the full snapshot; creation, replacement and retirement hold an exclusive lock.
Each lock acquisition has a one-second deadline. Contention waits only for the
lock and never replays a lifecycle mutation. Writers still compare the original
inode and prior digest under the lock; readers open the current name after any
wait. Strict ownership, permissions, JSON and mutation-sensitive snapshot checks
remain mandatory, including for writes that do not honor the lock. Failed staging
creation cannot delete a pre-existing staging file.

This addresses a separate launch-time failure observed on the `18b46afd` PR
matrix. At that phase, the controller polls the owned receipt while the emulator
child advances it by atomic replacement. Unlinking the old inode changes its metadata, which
the strict snapshot correctly rejects when reads are not coordinated. A native
file/lock regression reproduces that exact failure and covers both read/write
orderings. This fix does not resolve the separately retained Android framework,
transport-loss or cleanup failures; actual hosted/device runs remain necessary.

Owned-emulator failure/recovery log capture also selects the events buffer's
fixed `killinfo` tag. LMKD emits its memory counters with each kill there; the
main/system log's reason and nearby memory snapshots alone do not provide the
event-time values needed to investigate watermark-unit discrepancies. The
existing run-start filter, owner rechecks, time limits and 16-MiB bound still
apply. No matching event is not evidence of sufficient memory or a resolved
failure, and the event schema must be tied to the selected system image before
interpreting its numeric positions. Physical-device collection is unchanged.
See [logcat buffer selection](https://developer.android.com/tools/logcat#view-alternative-log-buffers).

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

State format version 2 additionally retains the original `/proc/vmstat` counters
and `/proc/zoneinfo` per-zone free/reserve/watermark data. This fills a gap exposed
by retained 16-KiB failures: `MemAvailable` snapshots alone cannot explain the
reported lowmemorykiller watermark decisions or distinguish them from transport
loss. Keep kernel counter units and the independently checked runtime page size
separate. The [AOSP 16-KiB configuration](https://source.android.com/docs/core/architecture/16kb-page-size/16kb)
distinguishes x86_64 userspace simulation from an arm64 16-KiB kernel. Do not
multiply vmstat/zoneinfo counters by the application page size without validating
their units, or label these point samples as peak memory.
The fixed native reads also run on the API 23 emulator lane. All 13 probe statuses
remain explicit, and the first failed read remains the guest completion status.
The same 15-second baseline/failure, five-second recovery and 64-KiB output bounds
apply. There is no additional retry, RAM change, routing change, or relaxed
package/cleanup acceptance. These fields support diagnosis; they do not themselves
prove a memory or ADB defect was repaired.

At `c3c217e1`, [native Linux job 110586234113](https://github.com/billlza/q-periapt/actions/runs/36926187676/job/110586234113)
builds and installs the selected full-consumer APK but stops before instrumentation.
Postinstall observations 1 and 3 identify the exact APK; intervening package and
transport unavailability prevent three consecutive exact observations. Attempt 17
exhausts the existing absolute deadline while validating the owned ADB server.
App cleanup remains unresolved; the owned ADB stop is finalized, and the failed
run receipt is retired. No runtime proof or paired export is admitted.
Diagnostics artifact `11194721015` matches SHA-256
`a8207b27ab11f638c2a4fb6d1297283b6d74da819259ff680b87246421222971`.
Independent readback matches 54 lowmemorykiller text/killinfo pairs on PID, UID,
adjustment score and RSS, alongside two ADB transport read failures. This does
not establish a page-unit defect or a causal relationship to transport loss.
The failure, original logs and exact source are sealed separately; no timeout,
RAM, permission, retry or cleanup rule was relaxed.

At `41da8962`, [PR run 36706338677](https://github.com/billlza/q-periapt/actions/runs/36706338677/job/109864412248)
fails during APK installation with Package Manager `Broken pipe (32)`, before SDK
instrumentation. Its log records lowmemorykiller activity, a networkstack SIGSEGV
and termination/restart of system_server. Both v2 captures complete all 13 probes
within 64 KiB and retain the same kernel boot ID. `MemTotal = 2,532,416 KiB` and
the sum of managed zone counters `633,104` imply 4,096-byte counter units, while
the separately observed application page size is 16,384 bytes. This does not
establish which conversion the running lmkd used. `oom_kill` remains zero; this
does not rule out userspace low-memory kills. Cleanup verifies the owned APK,
uninstalls it and confirms absence, but the runtime result remains failed.
The matching push run passes; the intermittent failure remains unresolved.

Failure diagnostics also attempt `emulator-app-exit-info.txt` for the fixed
`dev.qperiapt.androidsmoke` package, before cleanup after an instrumentation
failure. The read-only `dumpsys activity exit-info` query uses Android's recorded
process exit history ([AOSP dispatch](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android15-release/services/core/java/com/android/server/am/ActivityManagerService.java)).
It can distinguish an application crash from a system termination when Android
has retained that record. Match its timestamp and PID against the original
run's system log; an empty history, an unsupported command or an unknown reason
does not establish a cause. The query is limited to the same live owned emulator,
15 seconds and 1 MiB, with pre/post ownership checks and a run-bound guest exit
status. Its error is retained separately; it neither restarts the application
nor changes the primary failure or cleanup rules. Physical-device runs cannot
invoke this operation. CI retains both output and diagnostics.

The `8067cd97` 16 KiB PR run recorded `LOW_MEMORY` with status 9 for the exact
failed SDK process, while the preceding full workload passed. This identifies
the recorded termination class, not its cause within the memory system: before
and after snapshots still report about 1.5 GB available and do not capture a
transient peak. The collector now retains the `lowmemorykiller` tag used by
[Android 15 lmkd](https://android.googlesource.com/platform/system/memory/lmkd/+/refs/heads/android15-release/lmkd.cpp)
as well as `lmkd`. Its kill records include process, adjustment score, released
RSS/swap and the pressure reason when available. This corrects a missing diagnostic
tag without changing guest RAM, workload, retry budgets or acceptance. A passing
rerun alone does not resolve the retained low-memory failure.

Before installation on the owned `api35-16k` target, version 2 of the separate
fixed native capture records the kernel release, runtime page size, build
fingerprint and system build fingerprint. The actual version-1 target run at
`2acbbda8` retained `Permission denied` for `/proc/cmdline` and `/system/bin/lmkd`,
while kernel release and page size succeeded. Those protected reads are now
replaced by accessible identity queries; no root or guest permission change is
used. The historical failed capture remains a failure.
The capture has a 15-second / 4-MiB bound, retains every guest command status and
requires a run-bound completion record, with the same live emulator ownership
checks before and after reading. Failure stops before SDK installation. Physical
and API 23 collection remain outside this probe. The existing state-v2 snapshots
and their bounds are unchanged. Capturing these inputs is diagnostic evidence;
it does not itself establish the cause of a low-memory event or a repaired image.
Both success and failure artifact lists retain this capture and its stderr.

The CI 16-KiB lane separately runs `artifact/android_system_image_runtime.py`
before boot. A digest-pinned, task-local 7-Zip 26.03 reads the SDK image as data,
without mounting it or executing guest files. It selects the AVD's exact SDK
package, rejects image overrides, hashes the system image, kernel and ramdisk,
and checks GPT/super/system extent relationships before extracting only
`system/bin/lmkd` and `system/build.prop`. A scanned filesystem at another offset,
fragmented system extent, linked component, oversized output or changed input
fails explicitly. Tool commands have a 30-second deadline with separate 4-MiB
stdout and 64-KiB stderr bounds; system images have an 8-GiB bound and kernel/
ramdisk files a 256-MiB bound. The nested-container offset/tail warnings are retained
with the verified extent metadata, not hidden. CI retains the report, raw
listings, component bytes, pinned tool and its license even after an inspection
failure. The helper's local source-image mode omits AVD selection and does not
start a VM. Installed-image identity and matching fingerprints are diagnostic
inputs, not attestation of the running lmkd process or proof of a memory-unit bug.

Completed native diagnostic commands also retain output when modern ADB returns
the guest's nonzero status. The bounded writer previously removed that output,
including merged stderr, which left the first memory-runtime failure with exit 1
and an empty error file. Diagnostic callers now explicitly retain completed
nonzero output while returning the same failure code. Ordinary artifact writes
remain success-only; deadlines, byte limits, interruption and ownership checks
are unchanged. No failed diagnostic permits SDK installation or proof publication.

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
