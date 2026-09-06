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
  JNI shim, assembles the built payload with canonical AAR archive structure,
  independently audits that structure, compiles an isolated consumer against
  the AAR's `classes.jar`, and checks a minimal R8 consumer's DEX. Canonical
  archive structure does not claim cross-host bit reproducibility of the compiled
  payload.

Run from the repository root:

```sh
sh artifact/android-aar.sh
```

Local in-progress diagnostics can set `QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1`; that is
not release provenance. This gate is package-only: it proves AAR shape, Android ELF
ABI slices, `JNI_OnLoad`/`RegisterNatives` export shape, Java facade compilation,
dex conversion, an isolated consumer compile, and minimal R8 native/callback
retention. Runtime proof is tracked by the separate device/emulator smoke below,
not by this package-only gate.

The development producer declares `package="dev.qperiapt.android"` in the AAR
manifest so AGP can derive the library's resource namespace. Its `proguard.txt`
retains every native method registered by `JNI_OnLoad`, including methods unused
by a particular consumer, and the exact
`QPeriaptAndroid$QPeriaptException(String, int, String)` constructor invoked by JNI.
The independent archive audit requires this package, callback class and exact
consumer-rule contract; the producer also checks the compiled constructor with
`javap`. Unused non-native Java methods and unrelated classes remain eligible for
shrinking. A names-only keep rule is insufficient because `RegisterNatives`
registers the whole method table even when the app calls only `runtimeVersion()`.
The published **0.1.5 AAR lacks these manifest and keep-rule corrections**. Ordinary
AGP and minified consumers need an explicit consumer-side correction: identify any
manifest-corrected AAR as a derived artifact, retain the original release checksum,
and apply both exact JNI keep rules emitted by
[`android-aar.sh`](../../artifact/android-aar.sh). Do not relabel the derived bytes
as the published release. The official AAR, its checksums, receipts and tags remain
immutable. These Android archive-consumer defects do not alter the previously
verified Rust, C or Apple artifact bytes or expand what their receipts prove.

The package gate now runs SDK R8 using `classes.jar` and `proguard.txt` read from
the actual AAR. Its only application root calls `runtimeVersion()`; the full-API
compile-only consumer is excluded from R8 inputs. The existing SDK `dexdump`
checks all nine native names/descriptors and the public exception constructor.
This does not execute JNI or AGP's AAR transforms. The r2 consumer gate must
build a minified Release app from the exact AAR through AGP, without supplying
extra Q-Periapt keep rules in the app, then execute the existing
`QPeriaptSmokeActivity` workload from
`artifact/android-device-smoke.sh` and the same `signed-policy-vectors.json`.
That workload already asserts native policy errors as `QPeriaptException`, policy
rollback/signature rejection, KEM round trips, context binding and secret wiping.
AGP/ART acceptance is a separate required consumer result; archive, `javap` or
standalone R8 success does not establish it. A separate minimal-entry variant
that calls only `runtimeVersion()` must also initialize JNI successfully and retain every native
name/descriptor plus the exception callback in its shrunk DEX. The complete
workload alone cannot detect removal of unused native methods. The r2 source and
gate are candidates until the independent `abi2-platforms-v0.1.5-r2-verified` tag
and maintenance receipt confirm the exact public assets. Once verified, select
`abi2-platforms-v0.1.5-r2` for Android and Linux while retaining library SemVer
`0.1.5`; the corrected AAR needs neither manifest conversion nor application-side
Q-Periapt keep rules.

The canonical Android release proof runs the exact package-gate AAR on a script-owned,
cold-boot arm64-v8a Android 15 / API 35 `google_apis_ps16k` AVD with 16 KiB pages,
build-tools 36.0.0, and release mode:

```sh
(
set -eu
sh artifact/android-aar.sh

aar="$PWD/target/qperiapt-android-aar/q-periapt-android-0.1.5/q-periapt-android-0.1.5.aar"
aar_manifest="$PWD/target/qperiapt-android-aar/q-periapt-android-0.1.5/MANIFEST.json"
avd_home=$(sh artifact/python-run.sh artifact/android_bounded_command.py avd-home-path)
avd_name=$(sh artifact/python-run.sh artifact/android_bounded_command.py runtime-avd-name \
  --adb-profile macos-account --device-abi arm64-v8a)
test "$avd_name" = QPeriapt_Release_16K_API_35_V1
umask 077
if [ ! -e "$avd_home" ] && [ ! -L "$avd_home" ]; then
  mkdir "$avd_home"
  chmod 700 "$avd_home"
  ANDROID_AVD_HOME="$avd_home" avdmanager create avd \
    --name "$avd_name" \
    --package "system-images;android-35;google_apis_ps16k;arm64-v8a" \
    --device pixel_6 <<'AVD_INPUT'
no
AVD_INPUT
fi
sh artifact/python-run.sh artifact/android_device_proof.py verify-avd-home \
  --avd-home "$avd_home" \
  --adb-profile macos-account \
  --device-abi arm64-v8a

QPERIAPT_ANDROID_ADB_PROFILE=macos-account \
QPERIAPT_ANDROID_RELEASE_MODE=1 \
QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator \
QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a \
QPERIAPT_ANDROID_EXPECT_PAGE_SIZE=16384 \
QPERIAPT_ANDROID_EXPECT_SDK=35 \
QPERIAPT_ANDROID_EXISTING_AAR="$aar" \
QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST="$aar_manifest" \
QPERIAPT_ANDROID_EXPECTED_AAR_SHA256="$(shasum -a 256 "$aar" | awk '{print $1}')" \
QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256="$(shasum -a 256 "$aar_manifest" | awk '{print $1}')" \
sh artifact/android-device-smoke.sh
)
```

If the fixed fallback root `~/.android/avd` exists, it must be current-user-owned, non-symlink, and
not writable by group or other users; its existing parent chain must meet the same ownership and
writeability boundary, and macOS allow ACLs are also rejected. In all cases the derived
private name must be absent there. The script never chmods or deletes it. Existing old AVDs with
other names may remain. Admission depends on
the descriptor-validated private tree and the observed, proof-bound ABI, SDK, page size, release
mode, and build-tools values. A physical device run is a separate production add-on. It
requires an exact serial and must reuse the same clean-source AAR and manifest; it cannot replace the
canonical AVD in `artifact/results.json`, the release index, or manifest-bound `proof-to-byte`:

```sh
aar="$PWD/target/qperiapt-android-aar/q-periapt-android-0.1.5/q-periapt-android-0.1.5.aar"
aar_manifest="$PWD/target/qperiapt-android-aar/q-periapt-android-0.1.5/MANIFEST.json"
QPERIAPT_ANDROID_SERIAL=<adb-serial> \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical \
QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a \
QPERIAPT_ANDROID_EXPECT_PAGE_SIZE=4096 \
QPERIAPT_ANDROID_EXPECT_SDK=36 \
QPERIAPT_ANDROID_EXISTING_AAR="$aar" \
QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST="$aar_manifest" \
QPERIAPT_ANDROID_EXPECTED_AAR_SHA256="$(shasum -a 256 "$aar" | awk '{print $1}')" \
QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256="$(shasum -a 256 "$aar_manifest" | awk '{print $1}')" \
sh artifact/android-device-smoke.sh
```

The page-size and SDK values in that physical example are the observed Samsung API-36/4-KiB
profile and must be changed to the explicitly intended device's real values. The physical add-on
does not inherit the canonical AVD's SDK-35/16-KiB/release-mode constraints; its invariant is a
clean source snapshot, the exact same AAR and manifest bytes, one explicit physical serial, and
truthful device expectations. A separately reviewed product-readiness evidence transition may
select it independently under `android_physical_runtime` with
`current_clean_tree_physical_pass`; the stable package-publication assembler does not. It can never occupy the canonical
`android_device_runtime` section.

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
device query. Before any adb client runs, the unique bootstrap listener descriptor is committed to
the private recovery receipt. Later Darwin snapshots must retain that descriptor; Linux snapshots
must report it as the sole `LISTEN` record and may contain only exact-socket `CONNECTED` records.
The public projection records only the fixed adb profile and a descriptor digest. Four no-replace
receipts record IPv4/IPv6 `ECONNREFUSED` for 5037 and 5586 at emulator
pre-exec, post-registration, runtime pre-cleanup, and post-cleanup. Current proof schema v6 and bundle
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
cleanup only. The socket directory is reconciled from mode 0700 through the schema-v5 runtime phases
to `ADB_SEALED` plus actual mode 0500 before any adb client. Schema-v4 runtime receipts are rejected
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

Manifest-bound release verification accepts only the canonical AVD proof and also rechecks the
results-selected current AAR:

```sh
QPERIAPT_REQUIRE_ANDROID_AAR=1 \
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<run-id>/proof/qperiapt-android-device-proof.json \
sh artifact/proof-to-byte.sh
```

The proof path is an explicit selector; consumers never search for the newest run or fall back to the
historical canonical output. A complete local release transaction has one fixed order: AAR, canonical
AVD run, first release index including the exact run id, extracted dynamic+static C consumer receipt,
one evidence-only `artifact/results.json` successor, then the bound verifier. Produce the index and
receipt before the successor:

```sh
QPERIAPT_RELEASE_INDEX_CHANNEL=release \
QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=0 \
QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX=0 \
QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id> \
sh artifact/local-release-index.sh
sh artifact/local-release-consumer-smoke.sh
```

The consumer script appends a receipt only after both consumer modes pass. Final verification uses
`QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER=1` together with
`QPERIAPT_REQUIRE_ANDROID_RUNTIME=1`; it validates the selected index and existing receipt and never
generates one. `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1` is limited to producing direct local
diagnostics. A dirty proof may be inspected only with the direct verifier's explicit dirty option;
it cannot be selected in `artifact/results.json` or passed to manifest-bound `proof-to-byte`.

Complete the real physical run against the same source and AAR, then use a separately reviewed
product-readiness evidence transition to select its exact path/hash under
`android_physical_runtime`. Stable package publication leaves this selector absent. Only after that
separate transition may the complete Android local production transaction enable both
non-interchangeable runtime gates:

```sh
QPERIAPT_REQUIRE_ANDROID_AAR=1 \
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<canonical-run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME=1 \
QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<physical-run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER=1 \
sh artifact/proof-to-byte.sh
```

The physical gate fixes freshness to 86,400 seconds and emits
`PROOF_TO_BYTE_ANDROID_PHYSICAL_RUNTIME_PASS`. The finalizer emits
`PROOF_TO_BYTE_ANDROID_LOCAL_PRODUCTION_GATE_PASS` only when the AAR, canonical AVD, physical
runtime, and local-consumer states are all 1 on a clean snapshot. This is a local product-evidence
gate, not a Maven/public-provenance claim. The independent selection mechanism does not itself make
a source physical-ready: a fresh real-device run must be selected, and only the bound marker records
that current state.

CI job `bindings-android-runtime-16k` consumes the exact AAR artifact produced by
`bindings-android-aar` and executes it on real x86_64 API-35 `google_apis_ps16k` ART for every push
and pull request. This is an independent package-face gate. It is neither the canonical arm64-v8a
release proof nor physical-device production evidence.

## Exact-AAR minified AGP Release consumers

The optional `agp_full_release` and `agp_minimal_release` profiles use the pinned
AGP 9.4.0 / Gradle 9.7.1 application template with `minifyEnabled=true` and
`debuggable=false`. The default `legacy_full` profile retains its original
three-test runtime proof and bundle contract. These new profiles produce a separate
`qperiapt.android_agp_consumer_proof` schema-1 proof and never stand in for that
legacy evidence or claim Maven/publication status.

Select a clean source checkout and its exact prebuilt AAR/manifest, then run each
profile in sequence through the existing owned, bounded AVD/ADB lane:

```sh
# Set JAVA_HOME to the approved JDK's canonical home and the four exact-AAR selectors first:
# QPERIAPT_ANDROID_EXISTING_AAR, QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST,
# QPERIAPT_ANDROID_EXPECTED_AAR_SHA256, QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256.
QPERIAPT_ANDROID_CONSUMER_PROFILE=agp_full_release \
QPERIAPT_ANDROID_RELEASE_MODE=1 QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator \
sh artifact/android-device-smoke.sh

QPERIAPT_ANDROID_CONSUMER_PROFILE=agp_minimal_release \
QPERIAPT_ANDROID_RELEASE_MODE=1 QPERIAPT_ANDROID_BOOT_AVD=1 \
QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator \
sh artifact/android-device-smoke.sh
```

These internal release collector CLIs require `--root` to identify the checkout
that executes the collector. To select another source checkout, run that checkout's
own script. CLI SDK paths are assertions against the existing registered Android
SDK profiles (`macos-account`, `linux-account`, `linux-system`, `linux-opt`);
the commands use the registered paths. Read-only SDK verification does not require
ADB to be installed or a device to be available. The Python read-only verification
APIs retain explicit `root` and `sdk` inputs for independently selected source and
evidence directories.
Formal CLI proof paths must use the existing immutable run layout under that
checkout's `target/qperiapt-android-device-smoke-runs`; the run ID and fixed proof
filename are admitted before any proof is read. An external path, traversal or
different filename is rejected before it is resolved or opened.

The internal collector uses the current account's `.gradle` cache, determined
from the account database. If `GRADLE_USER_HOME` is set, it must name that exact
directory; another cache root is rejected before collection. Global Gradle init
scripts remain forbidden. This is a release collector configuration constraint,
not a restriction on applications that use Gradle. `JAVA_HOME` must already name
the canonical home reported by the selected Gradle JVM. A mismatch preserves the
raw Gradle version output and stops before `assemble`; JDK path aliases are not
resolved by the collector.

The full profile compiles the same checked-in three workload groups as the legacy
producer, including the original signed-policy vectors and cryptographic/wipe
assertions. The minimal profile's only facade call is `runtimeVersion()`; full
workload sources and fixtures are absent from its build inputs. Neither application
adds Q keep rules. Both use the AAR's consumer rules, and actual JavaCompile inputs,
merged R8 rule sources, shrunk DEX native declarations, callback constructor, and
Instrumentation entrypoints are checked before runtime acceptance. The SDK default
optimized rules are pinned separately so an additional app keep rule cannot be
hidden in a substituted default file.

The nondebuggable APK contains its own narrow framework Instrumentation. It starts
the Activity by a fixed string and returns the run-bound result bytes through a
Bundle; it has no Q references and introduces no test APK that could preserve
otherwise unused JNI members. Results commit complete JSON first, then atomically
rename the closed text marker. A completed malformed result fails immediately.
Actual ART execution, exact installed APK ownership, and cleanup must all pass;
Java compilation, a standalone R8 dump, or an APK build alone is insufficient.

Each run retains `agp-build/receipt.json`, the unsigned/signed APKs, the
Instrumentation response, and existing device/control evidence. Public diagnostic
files use the explicit `known-path-roots-v1` normalization policy: only recorded
local path roots are replaced, while rule bodies and every warning/error line are
preserved. Original diagnostic bytes remain private under `agp-build-raw/`; their
digests are labeled `raw_private_sha256`, distinct from the hashed
`normalized_public` closure. An unrecognized private path is rejected.
`gradle-version.txt` records the real Gradle Launcher/Daemon JVM selection.
`build-jvm.json` is written once by the actual JavaCompile task and records its
JVM properties, selected compiler home and disabled compiler forking. The verifier
matches the task JVM and compiler selection to Gradle's reported JVM and requires
successful JavaCompile/R8 execution. Runtime vendor/version and VM vendor/version
remain distinct fields. This is actual build JVM evidence, not a separate
`java -version` probe. The original r1 proof and archive schemas are unchanged.
`profile_evidence_files` supplies the fixed export map and `verify_exported_profile`
rechecks that same closure after safe extraction, with `proof.json` at its root.
The validator also independently replays apksigner, 16 KiB zipalign, and SDK DEX/manifest
inspection against each selected signed APK. Supply `sdk` to the Python validation APIs
as an explicit SDK root containing `build-tools/36.0.0`, or select a registered
root with the CLI's `--sdk` assertion;
all four tools must belong to that directory and match their recorded hashes.
No verifier starts Gradle or a device; SDK and Git replay is read-only.

## Stable AAR publication transaction

The original `abi2-platforms-v0.1.5` release is public and immutable. Its
verified three-domain record is preserved at `v0.1.5-verified-cohort`; this
open development tree does not replace that frozen record. The published AAR
has the manifest and consumer keep-rule defects described above.

The alpha.2 historical published receipt remains schema v3, while current
canonical source-tree runs require proof schema v6. Neither is migrated in place.
The r2 ZIP envelope uses bundle schema 3 at a different layer and contains the
unchanged canonical bundle schema 2 plus the two separately typed AGP proofs.

The separate `abi2-platforms-v0.1.5-r2` maintenance distribution is a **source
candidate, not a published or verified replacement**. It keeps product version
`0.1.5` and ABI 2, rebuilds the four-ABI AAR and both Linux packages from one new
source identity, and requires its own exact assets and public verification.
It must include the canonical API-35 arm64-v8a / 16 KiB runtime evidence and
both full and minimal AGP Release consumer evidence for the exact corrected AAR.
The independent completed record, once produced, is named
`abi2-platforms-v0.1.5-r2-verified`; it is not a new three-domain crate cohort.
The original release, Q and all ten published crate bytes remain unchanged.

Until the r2 distribution has a verified public receipt, a consumer correction
is a derived artifact and must retain that distinction. Do not label an APK,
a local rebuild, or the r2 source candidate as the corrected public AAR.
See [`platform-maintenance-release-notes.md`](../../artifact/platform-maintenance-release-notes.md)
for the explicit candidate and publication contract. Verify the selected public
AAR and its manifest against that exact tag's `PLATFORM_DISTRIBUTION.json`,
`SHA256SUMS` and immutable release attestation. An old r1 receipt cannot verify
new r2 bytes.

Maven Central publication and a current same-source physical-device production proof are explicitly
not claimed, and published emulator evidence does not replace the clean-tree runtime proof
required for a source tree that has advanced past the release tag.
