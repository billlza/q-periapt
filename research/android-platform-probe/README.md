# Android system-service reproduction

This isolated diagnostic investigates the API 35 / 16 KiB `system_server`
crash captured at SDK source `a07789f`. It installs no app and loads no
Q-Periapt code. After one cold boot of the same r5 image, it calls the read-only
`file_integrity` feature query sixty times and observes the kernel boot ID and
`system_server` PID. A changed process, failed query or malformed response
fails the run and captures bounded system diagnostics. Completion only describes
this finite experiment; it supplies no SDK acceptance or release evidence.

The [Android 15 AIDL](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/core/java/android/security/IFileIntegrityService.aidl)
places `isApkVeritySupported()` first. Its
[service implementation](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/core/java/com/android/server/security/FileIntegrityService.java)
returns a support query without changing filesystem state. The captured r5
binary's precise ART source revision is not established by these references.

Run only through the dedicated GitHub-hosted workflow. The Python supervisor
rejects local hosts, pins the checked-out commit, limits execution to 360 seconds
and combined output to 2 MiB, and uses the existing bounded-process owner for
cleanup. A fresh private AVD and private ADB socket exclude USB and global ADB.
The emulator transport uses the SDK lane's `emu:5584,5585` registration. Its
internal ADB subprocesses inherit the same private socket and emulator serial.
The hosted shell requires `BASHPID` and admits cleanup only in its original
session leader. An inherited child EXIT handler cannot signal the parent's group
or wait on its child table; the outer supervisor retains the same hard deadline.
Cleanup confirms child exit through the owning shell's job table. TERM has one
startup retry while owned children remain; subsequent observations do not resend
it. The emulator advertises a 20-second graceful-exit window, so cleanup waits at
most 25 seconds and 500 polls before escalation. The ordinary-child regression
retains its five-second deadline; the uncooperative-child regression exercises the
real 25-second escalation bound for both successful and failed drivers.
An unconfirmed shutdown emits its original driver status and kills the entire
owned group; successful queries cannot turn that cleanup failure into success.
Only the observation JSON and bounded log are uploaded; keys and emulator state
remain in the disposable runner. No existing package gate is changed.

## APK copy and transport comparison

The separate `Android APK transport reproduction` workflow investigates the
`after-copy` offline observation from run `37219990138`, job `111489291014`.
That observation proves `exec-out cat` returned zero without a bounded-writer
error. Its size/hash check would have followed the failed `pm path`, so complete
APK transfer has not been established for the failed attempt.

The initial three arms used fresh private instances of the same API35/16KiB image: package
path queries alone, the existing bounded PIPE writer, and the same copy command
with stdout connected directly to a file. Each arm runs 24 samples in each of
two hosted trials. Copy commands have the same 15-second maximum and APK size
bound. Both copy arms record byte length and SHA-256 before the subsequent path
query; incomplete zero-exit copies remain failures. The direct-file comparison
uses an OS file-size limit and an owned child timeout. It does not replace the
production writer or change package admission/recovery budgets.

Those arms installed the same signed public APK, SHA-256
`e2548ac0343802f35bc880804805d60448bf131e436dd0e7e0fb859d0f900724`,
from artifact `11309464232` of successful PR run `37219996163`. The entire ZIP
and selected APK are pinned before use. This is the corresponding PR producer's
APK (checkout `9830732a8bfdafe98b70fce7efce085d7085b1f1`); byte identity with the
failed push's non-exported APK is not proven. No fresh signing key or rebuilt
APK is substituted between comparison arms.

The probe retains transport logs, tool/image hashes, per-command times and guest
boot/adbd/system_server identities, and one bounded syscall trace of the probe's
clients. The syscall selection excludes payload reads/writes and environment
values. It includes process ownership, signals, close and shutdown to distinguish
client cleanup from an independently failing transport. No automatic reconnect
or retry occurs after a failed sample. The outer owner allows 600 seconds for
boot, installation, observations and bounded cleanup. Completion describes only
these finite samples; absence of a reproduced failure does not establish a root
cause or qualify Android cleanup stability. Physical devices and installed SDK
instrumentation remain separate from this transport experiment.

Run `37228953002` reproduced a zero-exit short transfer in the direct-file arm:
sample17 returned 12,570,112 bytes of the expected 13,608,912, followed by offline.
The only traced kill was a later logcat timeout, after the disconnect. The bounded
PIPE collector is therefore not necessary for that observed failure; the underlying
transport cause is still unproven. Another arm stopped because `pidof system_server`
returned both the original PID and a second same-name process. Its process table
still contained the original service, so that observation does not prove restart.

Subsequent probes retain the complete name census but verify the original service
PID, process name, parent, start ticks and boot ID through `/proc/PID/stat`. An
ambiguous initial identity, missing original PID, reused PID, changed parent or
dead process refuses. Extra same-name PIDs cannot replace the tracked service.
Kernel output is captured outside the ADB channel, and the crash log buffer is
read separately so ordinary framework traffic cannot displace its final records.
These observations strengthen diagnosis without changing SDK admission or retry
policy; the earlier failed trials remain part of the evidence.

## Copying without package installation

The preceding matrix compared `uninstalled-pipe-copy`, `uninstalled-file-copy`
and the installed `apk-file-copy` reference, with two fresh boots per arm and
24 samples per boot. The uninstalled arms push the exact same pinned bytes to
`/data/local/tmp/qperiapt-transport-probe.bin`, verify the guest file hash, and
never invoke package installation, an activity or instrumentation. Copy commands
still use `adb exec-out cat`; size limits, hashes, deadlines and both host output
strategies are unchanged. Before/after queries check the fixed regular file's
size instead of asking PackageManager for an installed path. Package absence
requires a successful empty query before and after the run; missing diagnostics
remain failures. The supervisor records staging and installation separately and
refuses an installation marker in an uninstalled experiment.

This comparison tests whether an installed package is necessary for the observed
bulk-transfer failure. It does not identify a failing host/guest transport layer
or establish that finite successful samples are stable. The earlier installed
trials remain evidence: run `37230756014` includes both an exit-zero short PIPE
copy followed by offline and a separate full, exact copy with a captured fatal
PackageManager exception and original `system_server` observed as a zombie.
Guest logcat and host timestamps were not calibrated, so those records do not
establish copy/crash ordering or a shared cause. Run `37231009374` retained three
further short or empty exit-zero copies followed by offline, including both
host output strategies. No SDK gate, automatic recovery or retry budget changes.


## Raw stream versus shell-v2 completion

Run `37233100970` reproduced the failure without installing or executing SDK
code: uninstalled PIPE trial2 sample16 returned 6,295,040 of 13,608,912 bytes,
exit zero and empty stderr, then went offline. Package absence was confirmed
before copying; after-failure absence could not be read. This rejects package
installation/execution as a necessary condition for this particular observation,
without identifying the disconnect cause or equating all earlier failures.

The current matrix uses `uninstalled-pipe-copy` (`exec-out cat`) and
`uninstalled-shell-copy` (`shell -T -n cat`), with the same pinned ordinary blob,
PIPE receiver, exact size/hash checks, per-command and total time limits, two
fresh private boots per arm, and 24 samples per boot. Neither arm installs an
APK, starts an activity, runs instrumentation, reconnects or retries a failure.
Both first require the actual client/device `shell_v2` feature, trace tiny
`true` commands to establish `exec:` and `shell,v2,raw:` routing, then require a
real shell control to return exactly separated stdout/stderr and exit7. Missing
protocol support or mismatched controls fails before copying, with no fallback.
Copy observations include the actual argv and still refuse short exit-zero
output or full exact bytes with a nonzero exit.

AOSP ADB commit `1cf2f017d312f73b3dc53bda85ef2610e35a80e9`
[`client/commandline.cpp`](https://android.googlesource.com/platform/packages/modules/adb/+/1cf2f017d312f73b3dc53bda85ef2610e35a80e9/client/commandline.cpp#297)
returns zero after raw `exec-out` copying; its shell-v2 reader defaults to255
until receiving an exit packet. This motivates the comparison. The observed
installed binary `37.0.1-15733141` has not been mapped to this source revision;
its behavior is measured, not inferred from that reference. A nonzero shell-v2
exit after a short copy would improve diagnosis, not repair the disconnection.
Finite passing samples cannot establish stability or justify changing SDK gates.

The two arms also enable filtered emulator `-logcat` output alongside kernel
output. A fixed guest log marker must appear as an actual logcat record in the
outer supervisor's file before protocol controls or copying; merely echoing the
ADB command does not satisfy it. This avoids depending only on an `adb logcat`
query after transport failure. It does not guarantee all buffers or crash tails
were captured. The protocol arms have an explicit16MiB combined log bound
(previous arms retain2MiB); the600-second owner and15-second copy limits stay
unchanged. Output saturation is a supervisor failure, never natural-disconnect
or successful-transport evidence. No emulator file-size limit is added. Captured
chunks are flushed so the live marker check can observe them. Guest and host
clocks remain uncalibrated and cannot alone establish causal ordering.


Run `37237344003` at `1fb2df29` produced no copy observations: all four arms
failed before boot because combining kernel output and logcat attempted to bind
two QEMU character devices to stdio. The retained original logs report
`cannot use stdio by multiple character devices`; no blob was staged or package
installed. This was an instrumentation defect, not another bulk-copy failure.
The corrected launch keeps kernel serial on stdio and directs logcat through
`-logcat-output /proc/self/fd/2`. Its file backend opens the owned inherited stderr
pipe, which is already captured by the bounded supervisor; no unbounded regular
log file or emulator file-size signal is introduced. Help support is checked
before launch, and the guest marker must still be observed before any copying.
Actual backend startup and stream capture remain hosted validation obligations.
