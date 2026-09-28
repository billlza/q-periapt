#!/bin/bash
# Invoked only by the hosted Python supervisor, inside its owned process group.
set -euo pipefail
umask 077

root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
output=$root/target/android-platform-probe
test -f "$output/commands.log"
test "$(uname -s)" = Linux
sdk=/usr/local/lib/android/sdk
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
test -x "$adb" && test -x "$emulator"
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
serial=127.0.0.1:5585
for port in 5584 5585 5586; do
    test -z "$(ss -H -ltn "sport = :$port")"
done
"$adb" keygen "$ADB_VENDOR_KEYS"
"$avdmanager" create avd --name PlatformProbe35 \
    --package 'system-images;android-35;google_apis_ps16k;x86_64' \
    --device pixel_6 <<< 'no'

adb_pid=
emulator_pid=
cleanup() {
    local primary=$?
    trap - EXIT
    trap '' TERM
    set +e
    # The supervisor retains this group leader unreaped until every child is
    # terminated. No process-name search, global kill-server or borrowed PID.
    kill -TERM -- "-$$"
    if [ -n "$emulator_pid" ]; then wait "$emulator_pid"; fi
    if [ -n "$adb_pid" ]; then wait "$adb_pid"; fi
    exit "$primary"
}
trap cleanup EXIT
"$adb" -L "$socket" nodaemon server &
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
ready=0
deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
    if adb_call connect "$serial" &&
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
test "$(guest getprop ro.build.version.sdk)" = 35
test "$(guest getconf PAGE_SIZE)" = 16384
fingerprint=$(guest getprop ro.build.fingerprint)
test "$fingerprint" = 'google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys'
test -z "$(guest pm list packages dev.qperiapt)"
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
test -z "$(guest pm list packages dev.qperiapt)"
printf 'PLATFORM_OBSERVATIONS_COMPLETED samples=60 sdk_installed=false\n'
