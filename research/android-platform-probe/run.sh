#!/bin/bash
# Invoked only by the hosted Python supervisor, inside its owned process group.
set -euo pipefail
umask 077

root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
experiment=${1:-file-integrity}
case "$experiment" in
    file-integrity) output=$root/target/android-platform-probe ;;
    apk-path-only|apk-pipe-copy|apk-file-copy) output=$root/target/android-apk-transport-probe ;;
    *) exit 2 ;;
esac
test -f "$output/commands.log"
test "$(uname -s)" = Linux
# The hosted driver requires Bash's actual process ID, which differs from $$ in
# a forked child. Reject an unsupported shell before creating background state.
test "${BASHPID-unavailable}" = "$$"
sdk=/usr/local/lib/android/sdk
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
test -x "$adb"
test -x "$emulator"
avdmanager=$(command -v avdmanager)
case "$avdmanager" in "$sdk"/cmdline-tools/*/bin/avdmanager) ;; *) exit 2 ;; esac

# No global ADB server or attached USB device participates. All state is new.
work=$output/work
mkdir "$work"
export ANDROID_USER_HOME=$work/user
export ANDROID_EMULATOR_HOME=$work/emulator
export ANDROID_AVD_HOME=$work/avds
export ANDROID_HOME=$sdk
export ANDROID_SDK_ROOT=$sdk
mkdir "$ANDROID_USER_HOME" "$ANDROID_EMULATOR_HOME" "$ANDROID_AVD_HOME"
export ADB_VENDOR_KEYS=$ANDROID_USER_HOME/adbkey
export ADB_MDNS=0 ADB_MDNS_AUTO_CONNECT=0 ADB_USB=0 ADB_EMU=0
export ADB_LOCAL_TRANSPORT_MAX_PORT=5585
socket=localfilesystem:$work/adb.sock
export ADB_SERVER_SOCKET="$socket"
serial='emulator-5584'
for port in 5584 5585 5586; do
    listeners=$(ss -H -ltn "sport = :$port")
    test -z "$listeners"
done
"$adb" keygen "$ADB_VENDOR_KEYS"
"$avdmanager" create avd --name PlatformProbe35 \
    --package 'system-images;android-35;google_apis_ps16k;x86_64' \
    --device pixel_6 <<< 'no'

adb_pid=
emulator_pid=
cleanup() {
    local primary=$?
    # A pre-exec child can receive TERM while the inherited EXIT trap is still
    # installed. $$ continues to name the parent in that child. Only this actual
    # session leader may signal the group or wait on the parent's child table.
    # BASH_SUBSHELL also guards explicit helper subshells on Bash 3 test hosts;
    # the hosted entry point above always requires a real BASHPID.
    if [ "$BASH_SUBSHELL" -ne 0 ] || [ "${BASHPID-$$}" != "$$" ]; then
        printf 'PLATFORM_CLEANUP_NONOWNER subshell=%s\n' "$BASH_SUBSHELL"
        return "$primary"
    fi
    trap - EXIT
    trap '' TERM
    set +e
    # The supervisor retains this group leader unreaped until every child is
    # terminated. No process-name search, global kill-server or borrowed PID.
    # A successful group signal is not an exit acknowledgement: a Bash 5.1
    # pre-exec child can survive the first TERM. Check this shell's job table
    # and allow one startup retry while its children remain running/stopped.
    # The emulator itself permits 20 seconds for graceful shutdown. Observe
    # without further signals, with a 25-second/500-poll bound, before escalation.
    # An unconfirmed cleanup fails even if the diagnostic itself passed.
    local running stopped attempt complete=0 deadline=$((SECONDS + 25))
    for attempt in {0..500}; do
        if ! running=$(jobs -pr) || ! stopped=$(jobs -ps); then break; fi
        if [ -z "$running" ] && [ -z "$stopped" ]; then
            complete=1
            break
        fi
        if [ "$attempt" -eq 500 ] || [ "$SECONDS" -ge "$deadline" ]; then break; fi
        if [ "$attempt" -lt 2 ]; then
            if ! kill -TERM -- "-$$"; then break; fi
        fi
        if ! /bin/sleep 0.05; then break; fi
    done
    if [ "$complete" -ne 1 ]; then
        printf 'PLATFORM_CLEANUP_ESCALATED primary=%s\n' "$primary"
        kill -KILL -- "-$$"
        exit 125
    fi
    if [ -n "$emulator_pid" ]; then wait "$emulator_pid"; fi
    if [ -n "$adb_pid" ]; then wait "$adb_pid"; fi
    exit "$primary"
}
trap cleanup EXIT
if [ "$experiment" = file-integrity ]; then
    "$adb" -L "$socket" nodaemon server &
else
    ADB_TRACE=transport "$adb" -L "$socket" nodaemon server &
fi
adb_pid=$!
for attempt in {1..50}; do
    if [ -S "$work/adb.sock" ]; then
        printf 'PLATFORM_ADB_SOCKET_READY attempt=%s\n' "$attempt"
        break
    fi
    sleep 0.1
done
test -S "$work/adb.sock"

# Match the SDK lane's emulator flags. The native notifier is kept away from
# the default ADB port; connect only this freshly launched loopback transport.
ANDROID_ADB_SERVER_PORT=5586 "$emulator" -avd PlatformProbe35 -port 5584 \
    -no-snapshot -read-only -no-window -no-audio -no-boot-anim \
    -no-direct-adb -adb-path "$adb" -gpu swiftshader &
emulator_pid=$!
adb_call() {
    timeout --foreground 5 "$adb" -L "$socket" "$@"
}
guest() {
    adb_call -s "$serial" shell "$@"
}
confirm_no_sdk_package() {
    local packages
    if packages=$(guest pm list packages dev.qperiapt); then
        if [ -z "$packages" ]; then return 0; fi
    fi
    printf 'PLATFORM_PACKAGE_ABSENCE_UNCONFIRMED\n'
    return 1
}
ready=0
deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
    if adb_call connect emu:5584,5585 &&
       boot=$(guest getprop sys.boot_completed) &&
       decrypt=$(guest getprop vold.decrypt); then
        if [[ "$boot" = 1 && ( -z "$decrypt" || "$decrypt" = trigger_restart_framework ) ]]; then
            ready=1
            break
        fi
    fi
    sleep 1
done
test "$ready" -eq 1
observed_api=$(guest getprop ro.build.version.sdk)
observed_page_size=$(guest getconf PAGE_SIZE)
test "$observed_api" = 35
test "$observed_page_size" = 16384
fingerprint=$(guest getprop ro.build.fingerprint)
test "$fingerprint" = 'google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys'
confirm_no_sdk_package
boot_id=$(guest cat /proc/sys/kernel/random/boot_id)
server=$(guest pidof system_server)
[[ "$boot_id" =~ ^[0-9a-f-]{36}$ && "$server" =~ ^[1-9][0-9]*$ ]]
printf 'PLATFORM_BASELINE boot=%s system_server=%s fingerprint=%s\n' "$boot_id" "$server" "$fingerprint"
guest cat /proc/uptime
guest cat /proc/meminfo
guest sha256sum /apex/com.android.art/lib64/libart.so

capture_failure() {
    if adb_call -s "$serial" logcat -d -b main -b system -b crash -v threadtime \
        -t 1000 -s 'DEBUG:*' 'AndroidRuntime:E' 'ActivityManager:I' 'Zygote:E' 'libc:F' '*:S'; then
        printf 'PLATFORM_FAILURE_LOG_CAPTURED\n'
    else
        printf 'PLATFORM_FAILURE_LOG_UNAVAILABLE\n'
    fi
}
if [ "$experiment" != file-integrity ]; then
    test -f "$output/probe.apk"
    test -x /usr/bin/strace
    test -x /usr/bin/prlimit
    printf 'APK_TRANSPORT_TOOLS time=%s\n' "$(date -u +%s.%N)"
    sha256sum "$adb" "$emulator" "$sdk/emulator/qemu/linux-x86_64/qemu-system-x86_64-headless"
    "$adb" version
    "$emulator" -version
    cat "$sdk/platform-tools/source.properties" "$sdk/emulator/source.properties" \
        "$sdk/system-images/android-35/google_apis_ps16k/x86_64/source.properties"
    sha256sum "$sdk/system-images/android-35/google_apis_ps16k/x86_64/kernel-ranchu" \
        "$sdk/system-images/android-35/google_apis_ps16k/x86_64/system.img"
    ps -o pid,ppid,pgid,etimes,args -p "$adb_pid,$emulator_pid"
    printf 'APK_TRANSPORT_INSTALL_ATTEMPT\n'
    timeout --foreground 120 "$adb" -L "$socket" -s "$serial" install --no-incremental "$output/probe.apk"
    # One bounded syscall log, no reads/writes or payload contents. The private
    # server remains outside this trace; only the owned experiment's children
    # are traced. The file limit also bounds direct-copy comparison output.
    /usr/bin/prlimit --fsize=67108864 -- /usr/bin/strace -f -qq -ttt \
        -e trace=process,signal,close,shutdown -o "$output/syscalls.log" \
        /bin/sh "$root/artifact/python-run.sh" "$root/artifact/android_apk_transport_probe.py" \
        "$experiment" "$work" "$socket" "$serial"
    printf 'APK_TRANSPORT_OBSERVATIONS_COMPLETED mode=%s samples=24\n' "$experiment"
    exit 0
fi
for sample in {1..60}; do
    # IFileIntegrityService's first AIDL method is isApkVeritySupported().
    # No APK is installed and no Q-Periapt classes/native libraries are loaded.
    if reply=$(guest service call file_integrity 1) &&
       observed_boot=$(guest cat /proc/sys/kernel/random/boot_id) &&
       observed_server=$(guest pidof system_server); then
        printf 'PLATFORM_SAMPLE sample=%s system_server=%s reply=%s\n' "$sample" "$observed_server" "$reply"
        if [[ "$observed_boot" != "$boot_id" || "$observed_server" != "$server" ]]; then
            printf 'PLATFORM_PROCESS_IDENTITY_CHANGED sample=%s\n' "$sample"
            capture_failure
            exit 1
        fi
        if ! [[ "$reply" =~ ^Result:\ Parcel && "$reply" =~ 00000000[[:space:]]+0000000[01] ]]; then
            printf 'PLATFORM_QUERY_REPLY_UNEXPECTED sample=%s\n' "$sample"
            capture_failure
            exit 1
        fi
    else
        printf 'PLATFORM_QUERY_FAILED sample=%s\n' "$sample"
        capture_failure
        exit 1
    fi
    sleep 1
done
confirm_no_sdk_package
printf 'PLATFORM_OBSERVATIONS_COMPLETED samples=60 sdk_installed=false\n'
