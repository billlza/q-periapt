# Android SDK runtime qualification

The alpha SDK retains **ABI major 2**, `libq_periapt_ffi_abi2.so` and
`libqperiapt_jni_abi2.so`. Its package version is `0.2.0-alpha.1`. The original
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
compile Java 11 bytecode with JDK 21 / AGP 9.4.0 / Gradle 9.7.1, run as
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
`sh artifact/android-aar.sh --profile sdk-alpha1`, then retain its AAR and
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

## Portable replay and CI

After runtime cleanup, the SDK collector verifies and exports the complete
profile closure to the run's `proof/agp-evidence/` directory. This contains the
original proof, selected AAR and manifest, signed APK, Instrumentation response,
results, emulator control evidence, AGP source/JVM/R8 receipts, and binary dumps.
The exporter re-verifies that copy, including actual SDK-tool replay of the APK.
The source checkout must still match the receipt; the original run and AAR
paths need not remain available for exported replay.

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

CI uses the distinct `android-sdk-alpha1-aar` raw-artifact intake contract,
checks the downloaded artifact digest and source identity, qualifies the Maven
consumer, and runs both SDK profiles against the same AAR on x86_64. It uploads
both complete runtime closures on success and retains available package/closure
diagnostics if a later step fails. Partial evidence does not satisfy the paired
runtime gate. There is no SDK-to-legacy fallback or package
rebuild in the runtime lane. The arm64 and physical-device gates remain separate.

The current [readiness ledger](SDK_0_2_RELEASE_READINESS.md) records which of
these gates have actually executed. Synthetic verifier tests, an APK build,
workflow syntax checks and historical device receipts do not establish a
current SDK ART pass.
