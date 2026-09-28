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
Cleanup confirms child exit through the owning shell's job table. TERM may be
reissued only while owned children remain, for at most two seconds and 40 signals.
An unconfirmed shutdown emits its original driver status and kills the entire
owned group; successful queries cannot turn that cleanup failure into success.
Only the observation JSON and bounded log are uploaded; keys and emulator state
remain in the disposable runner. No existing package gate is changed.
