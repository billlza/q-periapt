#!/bin/sh
# =============================================================================
# Q-Periapt camera-ready bare-metal experiments — one fail-closed command.
#
#   mkdir -p target/camera-ready
#   bash -o pipefail -c \
#     'sudo env QPERIAPT_BARE_METAL_CONFIRMED=1 sh camera-ready-bare-metal.sh 2>&1 | \
#        /usr/bin/tee target/camera-ready/transcript.txt'
#
# Run on a quiesced, bare-metal x86_64 Linux host. The root process is only a
# host-state/build supervisor. Cargo, build.rs, measured binaries, and Valgrind
# run as a dedicated locked account with supplementary groups/capabilities
# cleared, no_new_privs, and a per-command cgroup v2, from a root-owned snapshot.
# Root-owned, non-writable Rust and validation tools are mandatory.
# =============================================================================
set -eu
umask 077

# A root shell must not continue interpreting the user-writable live script once
# any build.rs code can run. Freeze the launcher first, re-exec it from /run, and
# later require its bytes to match the clean Git archive that is measured.
if [ "${QPERIAPT_FROZEN_LAUNCHER:-0}" != 1 ]; then
  if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    printf 'error: run through sudo; the root process is the narrow host-state supervisor\n' >&2
    exit 2
  fi
  live_root=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P) || exit 2
  launcher_dir=$(/usr/bin/mktemp -d /run/qperiapt-camera-ready-launcher.XXXXXX) || exit 2
  launcher="$launcher_dir/camera-ready-bare-metal.sh"
  if ! /usr/bin/cp -- "$0" "$launcher" || \
      ! /usr/bin/chown root:root "$launcher_dir" "$launcher" || \
      ! /usr/bin/chmod 0700 "$launcher_dir" || \
      ! /usr/bin/chmod 0500 "$launcher"; then
    /usr/bin/rm -rf -- "$launcher_dir"
    printf 'error: cannot freeze the root-owned camera-ready launcher\n' >&2
    exit 2
  fi
  /usr/bin/env -i \
    PATH=/usr/bin:/bin LC_ALL=C LANG=C \
    QPERIAPT_FROZEN_LAUNCHER=1 \
    QPERIAPT_LIVE_ROOT="$live_root" \
    QPERIAPT_LAUNCHER_DIR="$launcher_dir" \
    QPERIAPT_BARE_METAL_CONFIRMED="${QPERIAPT_BARE_METAL_CONFIRMED:-0}" \
    QPERIAPT_CARGO="${QPERIAPT_CARGO:-}" \
    QPERIAPT_RUSTC="${QPERIAPT_RUSTC:-}" \
    QPERIAPT_CARGO_SEED_HOME="${QPERIAPT_CARGO_SEED_HOME:-}" \
    QPERIAPT_RUN_USER="${QPERIAPT_RUN_USER:-}" \
    QPERIAPT_CAMERA_READY_OUTPUT_DIR="${QPERIAPT_CAMERA_READY_OUTPUT_DIR:-}" \
    QPERIAPT_CAMERA_READY_WORK_DIR="${QPERIAPT_CAMERA_READY_WORK_DIR:-}" \
    PIN="${PIN:-}" REPS="${REPS:-}" \
    /bin/sh "$launcher" || launcher_status=$?
  launcher_status=${launcher_status:-0}
  /usr/bin/rm -rf -- "$launcher_dir"
  exit "$launcher_status"
fi

WORK=""
CGROUP_PARENT=""
BUNDLE_STAGE=""
PUBLISHED_BUNDLE=""
OUTPUT_ROOT=""
WORK_ROOT=""
HOST_RESTORED=0
TUNING_ACTIVE_RECORDS=""
TUNING_AFTER_RECORDS=""
NETEM_AFTER_JSON=""
NETNS_PID=""
RUN_PID=""
RUNNER_FS_MOUNTED=0
RUNNER_ROOT=""

cgroup_has_processes() {
  [ -n "$(/usr/bin/cat -- "$1/cgroup.procs" 2>/dev/null)" ]
}

cleanup_runner_pid() {
  [ -n "$RUN_PID" ] || return 0
  kill -KILL "$RUN_PID" 2>/dev/null || :
  wait "$RUN_PID" 2>/dev/null || :
  RUN_PID=""
}

cleanup_cgroups() {
  [ -n "$CGROUP_PARENT" ] || return 0
  if [ -f "$CGROUP_PARENT/cgroup.kill" ]; then
    printf '1\n' >"$CGROUP_PARENT/cgroup.kill" 2>/dev/null || return 1
  fi
  for cleanup_group in "$CGROUP_PARENT"/run.*; do
    [ -d "$cleanup_group" ] || continue
    cleanup_attempt=0
    while cgroup_has_processes "$cleanup_group" && [ "$cleanup_attempt" -lt 100 ]; do
      /usr/bin/sleep 0.01
      cleanup_attempt=$((cleanup_attempt + 1))
    done
    /usr/bin/rmdir -- "$cleanup_group" 2>/dev/null || return 1
  done
  /usr/bin/rmdir -- "$CGROUP_PARENT" 2>/dev/null || return 1
  CGROUP_PARENT=""
}

cleanup_netns() {
  [ -n "$NETNS_PID" ] || return 0
  kill -TERM "$NETNS_PID" 2>/dev/null || :
  wait "$NETNS_PID" 2>/dev/null || :
  NETNS_PID=""
}

cleanup_runner_fs() {
  [ -n "$RUNNER_ROOT" ] || return 0
  if /usr/bin/mountpoint -q "$RUNNER_ROOT" 2>/dev/null; then
    /usr/bin/umount -- "$RUNNER_ROOT" || return 1
  elif [ "$RUNNER_FS_MOUNTED" -eq 1 ]; then
    return 1
  fi
  RUNNER_FS_MOUNTED=0
}

cleanup_ephemeral() {
  cleanup_status=0
  cleanup_runner_pid || cleanup_status=1
  cleanup_cgroups || cleanup_status=1
  cleanup_netns || cleanup_status=1
  cleanup_runner_fs || cleanup_status=1
  case "$BUNDLE_STAGE" in
    "") ;;
    "$OUTPUT_ROOT"/.bundle.*.tmp)
      /usr/bin/rm -rf -- "$BUNDLE_STAGE" || cleanup_status=1
      ;;
    *) cleanup_status=1 ;;
  esac
  case "$PUBLISHED_BUNDLE" in
    "") ;;
    "$OUTPUT_ROOT"/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
      /usr/bin/rm -rf -- "$PUBLISHED_BUNDLE" || cleanup_status=1
      ;;
    *) cleanup_status=1 ;;
  esac
  case "$WORK" in
    "") ;;
    "$WORK_ROOT"/qperiapt-camera-ready.*) /usr/bin/rm -rf -- "$WORK" || cleanup_status=1 ;;
    *) cleanup_status=1 ;;
  esac
  case "${QPERIAPT_LAUNCHER_DIR:-}" in
    /run/qperiapt-camera-ready-launcher.*)
      /usr/bin/rm -rf -- "$QPERIAPT_LAUNCHER_DIR" || cleanup_status=1
      ;;
    *) cleanup_status=1 ;;
  esac
  return "$cleanup_status"
}

early_exit() {
  early_status=$?
  trap - EXIT
  trap '' HUP INT TERM
  cleanup_ephemeral || [ "$early_status" -ne 0 ] || early_status=1
  exit "$early_status"
}
trap early_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT TERM

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

# Fixed system tools. Camera-ready evidence deliberately rejects hosts whose
# trusted tools are elsewhere instead of consulting a mutable user PATH.
AR=/usr/bin/ar
AS=/usr/bin/as
AWK=/usr/bin/awk
CAT=/usr/bin/cat
CC=/usr/bin/cc
CHMOD=/usr/bin/chmod
CHOWN=/usr/bin/chown
CP=/usr/bin/cp
DATE=/usr/bin/date
DIRNAME=/usr/bin/dirname
ENV_BIN=/usr/bin/env
FIND=/usr/bin/find
FLOCK=/usr/bin/flock
GETENT=/usr/bin/getent
GIT=/usr/bin/git
GREP=/usr/bin/grep
ID=/usr/bin/id
IP=/usr/sbin/ip
LD=/usr/bin/ld
MKDIR=/usr/bin/mkdir
MKTEMP=/usr/bin/mktemp
MOUNT=/usr/bin/mount
MOUNTPOINT=/usr/bin/mountpoint
MV=/usr/bin/mv
NSENTER=/usr/bin/nsenter
PASSWD=/usr/bin/passwd
PYTHON=/usr/bin/python3
RANLIB=/usr/bin/ranlib
READLINK=/usr/bin/readlink
RM=/usr/bin/rm
RMDIR=/usr/bin/rmdir
SED=/usr/bin/sed
SETPRIV=/usr/bin/setpriv
SHA256SUM=/usr/bin/sha256sum
SH=/bin/sh
SLEEP=/usr/bin/sleep
STAT=/usr/bin/stat
SYSTEMD_DETECT_VIRT=/usr/bin/systemd-detect-virt
TAIL=/usr/bin/tail
TAR=/usr/bin/tar
TASKSET=/usr/bin/taskset
TIMEOUT=/usr/bin/timeout
UNSHARE=/usr/bin/unshare
UMOUNT=/usr/bin/umount
UNAME=/usr/bin/uname
VALGRIND=/usr/bin/valgrind
SYSCTL=/usr/sbin/sysctl
TC=/usr/sbin/tc

"$PYTHON" -I -S -c \
  'import sys; raise SystemExit(0 if sys.implementation.name == "cpython" and sys.version_info >= (3, 11) else 1)' || {
  printf 'error: camera-ready proof tooling requires /usr/bin/python3 to be CPython >= 3.11\n' >&2
  exit 2
}

REQUESTED_CARGO=${QPERIAPT_CARGO:-}
REQUESTED_RUSTC=${QPERIAPT_RUSTC:-}
REQUESTED_CARGO_SEED_HOME=${QPERIAPT_CARGO_SEED_HOME:-}
PIN=${PIN:-4-5}
REPS=${REPS:-20}
unset BASH_ENV CDPATH ENV HOME PATH RUSTC_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_HOME CARGO_TARGET_DIR CFLAGS CPPFLAGS CXX \
  CXXFLAGS LDFLAGS LD_LIBRARY_PATH LD_PRELOAD TMPDIR DOCKER_HOST DOCKER_CONTEXT \
  DOCKER_DEFAULT_PLATFORM GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM \
  GIT_CONFIG_COUNT
PATH=/usr/bin:/bin
LC_ALL=C
LANG=C
export PATH LC_ALL LANG

[ -x "$UNAME" ] || fail "trusted uname is missing: $UNAME"
[ "$("$UNAME" -s)" = Linux ] || fail "camera-ready lane requires Linux"
[ "$("$UNAME" -m)" = x86_64 ] || fail "camera-ready lane requires native x86_64"

for required in "$AR" "$AS" "$AWK" "$CAT" "$CC" "$CHMOD" "$CHOWN" "$CP" \
  "$DATE" "$DIRNAME" "$ENV_BIN" "$FIND" "$FLOCK" "$GETENT" "$GIT" "$GREP" "$ID" "$IP" \
  "$LD" "$MKDIR" "$MKTEMP" "$MOUNT" "$MOUNTPOINT" "$MV" "$NSENTER" "$PASSWD" \
  "$PYTHON" "$RANLIB" "$READLINK" "$RM" \
  "$RMDIR" "$SED" "$SETPRIV" "$SHA256SUM" "$SH" "$SLEEP" "$STAT" \
  "$SYSTEMD_DETECT_VIRT" "$TAIL" "$TAR" "$TASKSET" "$TIMEOUT" "$UMOUNT" \
  "$UNSHARE" "$UNAME" "$VALGRIND" "$SYSCTL" "$TC"; do
  [ -x "$required" ] || fail "trusted system tool is missing: $required"
done

ROOT=$(CDPATH='' cd -- "${QPERIAPT_LIVE_ROOT:?}" && pwd -P) || exit 2
cd "$ROOT" || exit 2
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_SYSTEM=/dev/null
GIT_CONFIG_COUNT=6
GIT_CONFIG_KEY_0=safe.directory
GIT_CONFIG_VALUE_0=$ROOT
GIT_CONFIG_KEY_1=core.fsmonitor
GIT_CONFIG_VALUE_1=false
GIT_CONFIG_KEY_2=core.hooksPath
GIT_CONFIG_VALUE_2=/dev/null
GIT_CONFIG_KEY_3=core.attributesFile
GIT_CONFIG_VALUE_3=/dev/null
GIT_CONFIG_KEY_4=core.pager
GIT_CONFIG_VALUE_4='cat'
GIT_CONFIG_KEY_5=tar.umask
GIT_CONFIG_VALUE_5=0022
GIT_NO_REPLACE_OBJECTS=1
GIT_OPTIONAL_LOCKS=0
export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT \
  GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_NO_REPLACE_OBJECTS GIT_OPTIONAL_LOCKS
export GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1 GIT_CONFIG_KEY_2 GIT_CONFIG_VALUE_2 \
  GIT_CONFIG_KEY_3 GIT_CONFIG_VALUE_3 GIT_CONFIG_KEY_4 GIT_CONFIG_VALUE_4 \
  GIT_CONFIG_KEY_5 GIT_CONFIG_VALUE_5

[ "$("$ID" -u)" -eq 0 ] || \
  fail "run through sudo; the root process is the narrow host-state supervisor"
[ "${QPERIAPT_BARE_METAL_CONFIRMED:-0}" = 1 ] || \
  fail "set QPERIAPT_BARE_METAL_CONFIRMED=1 only after confirming this is not a VM"
if "$SYSTEMD_DETECT_VIRT" --quiet; then
  fail "virtualization detected; bare-metal evidence is required"
fi

LOCK_DIR=/run/qperiapt-camera-ready-lock
if [ ! -e "$LOCK_DIR" ]; then
  "$MKDIR" -- "$LOCK_DIR" || fail "cannot create the global camera-ready lock directory"
fi
[ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ] || \
  fail "global camera-ready lock directory must not be a symlink"
"$CHOWN" root:root "$LOCK_DIR" || fail "cannot protect the global lock directory ownership"
"$CHMOD" 0700 "$LOCK_DIR" || fail "cannot protect the global lock directory permissions"
[ "$("$STAT" -c %u "$LOCK_DIR")" -eq 0 ] && [ "$("$STAT" -c %a "$LOCK_DIR")" = 700 ] || \
  fail "global camera-ready lock directory metadata is unsafe"
LOCK_FILE="$LOCK_DIR/capture.lock"
[ ! -L "$LOCK_FILE" ] || fail "global camera-ready lock file must not be a symlink"
exec 9>"$LOCK_FILE" || fail "cannot open the global camera-ready capture lock"
"$CHOWN" root:root "$LOCK_FILE" || fail "cannot protect the global capture lock ownership"
"$CHMOD" 0600 "$LOCK_FILE" || fail "cannot protect the global capture lock permissions"
[ -f "$LOCK_FILE" ] && [ "$("$STAT" -c %u "$LOCK_FILE")" -eq 0 ] && \
  [ "$("$STAT" -c %h "$LOCK_FILE")" -eq 1 ] || fail "global capture lock file is unsafe"
"$FLOCK" -n 9 || fail "another camera-ready capture is already active"

case "$REPS" in
  '' | *[!0-9]*) fail "REPS must be the paper-registered value 20" ;;
esac
[ "$REPS" -eq 20 ] || fail "REPS must equal the paper-registered value 20"
case "$PIN" in
  '' | *[!0-9,-]*) fail "PIN must be a taskset CPU list such as 4-5 or 4,5" ;;
esac
"$TASKSET" -c "$PIN" "$SH" -c ':' >/dev/null 2>&1 || \
  fail "PIN is not a usable CPU affinity list: $PIN"

RUN_USER=${QPERIAPT_RUN_USER:-qperiapt-camera}
case "$RUN_USER" in
  '' | root | *[!A-Za-z0-9._-]*) fail "QPERIAPT_RUN_USER must name a dedicated locked account" ;;
esac
PASSWD_RECORD=$("$GETENT" passwd "$RUN_USER") || fail "dedicated runner account is missing: $RUN_USER"
[ "$(printf '%s\n' "$PASSWD_RECORD" | "$GREP" -c '^')" -eq 1 ] || \
  fail "runner account lookup is ambiguous"
RUN_UID=$("$ID" -u "$RUN_USER") || fail "cannot resolve runner uid"
RUN_GID=$("$ID" -g "$RUN_USER") || fail "cannot resolve runner gid"
[ "$RUN_UID" -ne 0 ] || fail "measurement runner must not be root"
RUN_SHELL=$(printf '%s\n' "$PASSWD_RECORD" | "$AWK" -F: "NR == 1 {print \$7}")
case "$RUN_SHELL" in
  /usr/sbin/nologin | /sbin/nologin | /bin/false | /usr/bin/false) ;;
  *) fail "dedicated runner account must have a nologin/false shell" ;;
esac
RUN_PASSWORD_STATUS=$("$PASSWD" -S "$RUN_USER" | "$AWK" "NR == 1 {print \$2}") || \
  fail "cannot inspect dedicated runner password status"
[ "$RUN_PASSWORD_STATUS" = L ] || fail "dedicated runner account password must be locked"
RUN_HOME=$(printf '%s\n' "$PASSWD_RECORD" | "$AWK" -F: "NR == 1 {print \$6}")
case "$RUN_HOME" in
  /*) ;;
  *) fail "dedicated runner home must be absolute" ;;
esac
if [ -e "$RUN_HOME" ]; then
  [ ! -L "$RUN_HOME" ] || fail "dedicated runner home must not be a symlink"
  unsafe_runner_home=$("$FIND" -P "$RUN_HOME" -maxdepth 0 \
    \( ! -user root -o -perm /022 \) -print -quit) || \
    fail "cannot inspect dedicated runner home"
  [ -z "$unsafe_runner_home" ] || \
    fail "dedicated runner home must be root-owned and non-writable"
fi
PRIMARY_GID_USERS=$("$GETENT" passwd | "$AWK" -F: -v gid="$RUN_GID" \
  "\$4 == gid {print \$1}") || \
  fail "cannot inspect runner primary group"
[ "$PRIMARY_GID_USERS" = "$RUN_USER" ] || \
  fail "dedicated runner primary group is shared: $PRIMARY_GID_USERS"
GROUP_RECORD=$("$GETENT" group "$RUN_GID") || fail "cannot inspect runner group membership"
GROUP_MEMBERS=$(printf '%s\n' "$GROUP_RECORD" | "$AWK" -F: "NR == 1 {print \$4}")
case "$GROUP_MEMBERS" in
  "" | "$RUN_USER") ;;
  *) fail "dedicated runner group has supplementary members: $GROUP_MEMBERS" ;;
esac
if "$PYTHON" -I -S - "$RUN_UID" <<'PY'
import pathlib
import sys

uid = sys.argv[1]
for status in pathlib.Path("/proc").glob("[0-9]*/status"):
    try:
        for line in status.read_text().splitlines():
            if line.startswith("Uid:") and line.split()[1] == uid:
                raise SystemExit(1)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
PY
then
  :
else
  fail "dedicated runner account already owns a live process"
fi

select_root_tool() {
  requested=$1
  shift
  if [ -n "$requested" ]; then
    printf '%s\n' "$requested"
    return
  fi
  for candidate in "$@"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  return 1
}

CARGO=$(select_root_tool "$REQUESTED_CARGO" \
  /opt/qperiapt-rust/bin/cargo /usr/local/bin/cargo /usr/bin/cargo) || \
  fail "root-owned cargo not found; set QPERIAPT_CARGO to a trusted absolute path"
RUSTC=$(select_root_tool "$REQUESTED_RUSTC" \
  /opt/qperiapt-rust/bin/rustc /usr/local/bin/rustc /usr/bin/rustc) || \
  fail "root-owned rustc not found; set QPERIAPT_RUSTC to a trusted absolute path"

trusted_file() {
  trusted_candidate=$1
  case "$trusted_candidate" in
    /*) ;;
    *) return 1 ;;
  esac
  trusted_resolved=$("$READLINK" -f -- "$trusted_candidate") || return 1
  [ -f "$trusted_resolved" ] && [ -x "$trusted_resolved" ] || return 1
  trusted_cursor=$trusted_resolved
  while :; do
    unsafe_path=$("$FIND" -P "$trusted_cursor" -maxdepth 0 \
      \( ! -user root -o -perm /022 \) -print -quit) || return 1
    [ -z "$unsafe_path" ] || return 1
    [ "$trusted_cursor" = / ] && break
    trusted_cursor=$("$DIRNAME" -- "$trusted_cursor") || return 1
  done
  printf '%s\n' "$trusted_resolved"
}

trusted_directory() {
  trusted_candidate=$1
  case "$trusted_candidate" in
    /*) ;;
    *) return 1 ;;
  esac
  trusted_resolved=$("$READLINK" -f -- "$trusted_candidate") || return 1
  [ -d "$trusted_resolved" ] || return 1
  trusted_cursor=$trusted_resolved
  while :; do
    unsafe_path=$("$FIND" -P "$trusted_cursor" -maxdepth 0 \
      \( ! -user root -o -perm /022 \) -print -quit) || return 1
    [ -z "$unsafe_path" ] || return 1
    [ "$trusted_cursor" = / ] && break
    trusted_cursor=$("$DIRNAME" -- "$trusted_cursor") || return 1
  done
  printf '%s\n' "$trusted_resolved"
}

reject_sandbox_masked_path() {
  case "$1" in
    /run | /run/* | /tmp | /tmp/* | /var/tmp | /var/tmp/* | /dev/shm | /dev/shm/* | \
      /home | /home/* | /root | /root/*)
      return 1
      ;;
    *) return 0 ;;
  esac
}

CARGO=$(trusted_file "$CARGO") || fail "cargo must be root-owned and not group/world writable"
RUSTC=$(trusted_file "$RUSTC") || fail "rustc must be root-owned and not group/world writable"
if ! reject_sandbox_masked_path "$CARGO" || ! reject_sandbox_masked_path "$RUSTC"; then
  fail "cargo/rustc paths must remain visible inside the private runner sandbox"
fi

OUTPUT_ROOT=${QPERIAPT_CAMERA_READY_OUTPUT_DIR:-/var/lib/qperiapt-camera-ready}
if [ "$OUTPUT_ROOT" = /var/lib/qperiapt-camera-ready ] && [ ! -e "$OUTPUT_ROOT" ]; then
  "$MKDIR" -- "$OUTPUT_ROOT" || fail "cannot create root-owned camera-ready output root"
  "$CHOWN" root:root "$OUTPUT_ROOT" || fail "cannot assign camera-ready output ownership"
  "$CHMOD" 0755 "$OUTPUT_ROOT" || fail "cannot protect camera-ready output root"
fi
[ ! -L "$OUTPUT_ROOT" ] || fail "camera-ready output root must not be a symlink"
OUTPUT_ROOT=$(trusted_directory "$OUTPUT_ROOT") || \
  fail "camera-ready output root and every ancestor must be root-owned and non-writable"

CARGO_SEED_HOME=${REQUESTED_CARGO_SEED_HOME:-/opt/qperiapt-cargo-home}
case "$CARGO_SEED_HOME" in
  /*) ;;
  *) fail "QPERIAPT_CARGO_SEED_HOME must be absolute" ;;
esac
[ ! -L "$CARGO_SEED_HOME" ] || fail "Cargo seed home must not be a symlink"
CARGO_SEED_HOME=$(trusted_directory "$CARGO_SEED_HOME") || \
  fail "Cargo seed home and every ancestor must be root-owned and non-writable"
unsafe_cargo_seed=$("$FIND" -P "$CARGO_SEED_HOME" \
  \( ! -user root -o -perm /022 -o -type l -o \
     \( ! -type d -a ! -type f \) -o \( -type f -a -perm /7111 \) \) \
  -print -quit) || \
  fail "cannot inspect root-owned Cargo seed home"
[ -z "$unsafe_cargo_seed" ] || \
  fail "Cargo seed home must contain only safe root-owned, non-writable files/directories: $unsafe_cargo_seed"
for forbidden_config in "$CARGO_SEED_HOME/config" "$CARGO_SEED_HOME/config.toml"; do
  [ ! -e "$forbidden_config" ] || fail "Cargo seed home must not inject config: $forbidden_config"
done

WORK_ROOT=${QPERIAPT_CAMERA_READY_WORK_DIR:-/var/lib/qperiapt-camera-ready-work}
if [ "$WORK_ROOT" = /var/lib/qperiapt-camera-ready-work ] && [ ! -e "$WORK_ROOT" ]; then
  "$MKDIR" -- "$WORK_ROOT" || fail "cannot create root-owned camera-ready work root"
  "$CHOWN" "root:$RUN_GID" "$WORK_ROOT" || fail "cannot assign camera-ready work group"
  "$CHMOD" 0710 "$WORK_ROOT" || fail "cannot protect camera-ready work root"
fi
[ ! -L "$WORK_ROOT" ] || fail "camera-ready work root must not be a symlink"
WORK_ROOT=$(trusted_directory "$WORK_ROOT") || \
  fail "camera-ready work root and every ancestor must be root-owned and non-writable"
reject_sandbox_masked_path "$WORK_ROOT" || \
  fail "camera-ready work root must remain visible inside the private runner sandbox"
WORK=$("$MKTEMP" -d "$WORK_ROOT/qperiapt-camera-ready.XXXXXX") || \
  fail "cannot create root-owned work directory"
"$CHOWN" "root:$RUN_GID" "$WORK" || fail "cannot assign protected work group"
"$CHMOD" 0710 "$WORK" || fail "cannot protect work directory"
[ "$("$STAT" -c %u "$WORK")" -eq 0 ] || fail "work directory must be root-owned"
[ "$("$STAT" -c %a "$WORK")" = 710 ] || fail "work directory must have mode 0710"
RUNNER_ROOT="$WORK/runner"
RUNNER_CARGO_HOME="$RUNNER_ROOT/validation-cargo-home"
CARGO_TARGET_DIR="$RUNNER_ROOT/validation-target"
SOURCE_ROOT="$WORK/source"
SOURCE_ARCHIVE="$WORK/source.tar"
MEASURE_ROOT="$WORK/measure"
VALIDATION_HOME="$WORK/validation-home"
VALIDATION_CWD="$WORK/validation-cwd"
"$MKDIR" -- "$RUNNER_ROOT" || fail "cannot create bounded runner mountpoint"
"$CHOWN" "root:$RUN_GID" "$RUNNER_ROOT" || fail "cannot assign runner mountpoint group"
"$CHMOD" 0710 "$RUNNER_ROOT" || fail "cannot protect runner mountpoint"
"$MOUNT" -t tmpfs -o \
  "size=8589934592,nr_inodes=524288,nodev,nosuid,mode=0710,uid=0,gid=$RUN_GID" \
  qperiapt-camera-runner "$RUNNER_ROOT" || fail "cannot mount bounded runner tmpfs"
RUNNER_FS_MOUNTED=1
"$MOUNTPOINT" -q "$RUNNER_ROOT" || fail "runner workspace is not a mountpoint"
[ "$("$STAT" -f -c %T "$RUNNER_ROOT")" = tmpfs ] || \
  fail "runner workspace must be a bounded tmpfs"
for runner_dir in "$RUNNER_CARGO_HOME" "$CARGO_TARGET_DIR"; do
  "$MKDIR" -p -- "$runner_dir" || fail "cannot create runner directory"
  "$CHOWN" "$RUN_UID:$RUN_GID" "$runner_dir" || fail "cannot assign runner directory"
  "$CHMOD" 0700 "$runner_dir" || fail "cannot protect runner directory"
done
for root_only_dir in "$MEASURE_ROOT" "$VALIDATION_HOME" "$VALIDATION_CWD"; do
  "$MKDIR" -p -- "$root_only_dir" || fail "cannot create protected measurement directory"
  "$CHOWN" "root:$RUN_GID" "$root_only_dir" || fail "cannot assign protected measurement group"
  "$CHMOD" 0550 "$root_only_dir" || fail "cannot protect measurement directory"
done
TRUSTED_TOOL_RECORDS=""
SYSCTL_RECORDS=""
SYSFS_RECORDS=""
NETEM_HANDLE=51ab:
NETEM_STATE=none
NETEM_FROZEN_JSON=""
BASELINE_QDISC_JSON=""
TUNING_ACTIVE=0
TUNING_DRIFT=0

CGROUP_REL=$("$AWK" -F: "\$1 == \"0\" && \$2 == \"\" {print \$3}" \
  /proc/self/cgroup) || \
  fail "cannot resolve current cgroup v2 path"
case "$CGROUP_REL" in
  /*) ;;
  *) fail "unified cgroup v2 is required" ;;
esac
case "$CGROUP_REL" in
  .. | ../* | */.. | */../*) fail "unsafe cgroup v2 path" ;;
esac
CGROUP_BASE="/sys/fs/cgroup$CGROUP_REL"
CGROUP_PARENT="$CGROUP_BASE/qperiapt-camera-ready-$$"
"$MKDIR" -- "$CGROUP_PARENT" || fail "cannot create camera-ready cgroup v2 parent"
[ -f "$CGROUP_PARENT/cgroup.kill" ] && [ -f "$CGROUP_PARENT/cgroup.procs" ] || \
  fail "cgroup v2 with cgroup.kill is required"
for required_controller in memory pids; do
  "$GREP" -qw "$required_controller" "$CGROUP_PARENT/cgroup.controllers" || \
    fail "cgroup v2 controller is unavailable: $required_controller"
done
printf '+memory +pids\n' >"$CGROUP_PARENT/cgroup.subtree_control" || \
  fail "cannot enable cgroup v2 memory/pids controllers"
CGROUP_PIDS_MAX=1024
CGROUP_MEMORY_MAX=8589934592
CGROUP_MEMORY_SWAP_MAX=0

run_as_runner_mode() {
  runner_network_mode=$1
  shift
  case "$runner_network_mode" in
    host | none | measurement) ;;
    *) return 125 ;;
  esac
  run_group=$("$MKTEMP" -d "$CGROUP_PARENT/run.XXXXXX") || return 125
  [ -f "$run_group/pids.max" ] && [ -f "$run_group/memory.max" ] && \
    [ -f "$run_group/memory.swap.max" ] && [ -f "$run_group/memory.oom.group" ] || \
    return 125
  printf '%s\n' "$CGROUP_PIDS_MAX" >"$run_group/pids.max" || return 125
  printf '%s\n' "$CGROUP_MEMORY_MAX" >"$run_group/memory.max" || return 125
  printf '%s\n' "$CGROUP_MEMORY_SWAP_MAX" >"$run_group/memory.swap.max" || return 125
  printf '1\n' >"$run_group/memory.oom.group" || return 125
  RUN_PENDING_SIGNAL=0
  trap 'RUN_PENDING_SIGNAL=129' HUP
  trap 'RUN_PENDING_SIGNAL=130' INT TERM
  if [ "$runner_network_mode" = none ]; then
    "$UNSHARE" --mount --ipc --net -- "$SETPRIV" --pdeathsig KILL -- "$SH" \
      "$SOURCE_ROOT/artifact/camera-ready-sandbox.sh" "$MOUNT" "$WORK" "$RUNNER_ROOT" \
      "$SETPRIV" --pdeathsig KILL --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        "$ENV_BIN" -i \
          HOME="$RUNNER_ROOT" USER="$RUN_USER" LOGNAME="$RUN_USER" \
          PATH=/usr/bin:/bin LC_ALL=C LANG=C \
          CARGO_HOME="$RUNNER_CARGO_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
          CARGO_TERM_COLOR=never CARGO_NET_OFFLINE=true \
          RUSTC="$RUSTC" RUSTFLAGS=-Dwarnings \
          CC="$CC" AR="$AR" RANLIB="$RANLIB" AS="$AS" LD="$LD" \
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC" \
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR" \
          "$SH" -c "set -e; ulimit -c 0; ulimit -f 262144; ulimit -n 4096; kill -STOP \"\$\$\"; exec \"\$@\"" \
          qperiapt-runner "$@" 9>&- &
  elif [ "$runner_network_mode" = measurement ]; then
    verify_netns_keeper || return 125
    "$UNSHARE" --mount --ipc -- "$SETPRIV" --pdeathsig KILL -- "$SH" \
      "$SOURCE_ROOT/artifact/camera-ready-sandbox.sh" "$MOUNT" "$WORK" "$RUNNER_ROOT" \
      "$NSENTER" --net="/proc/$NETNS_PID/ns/net" -- \
      "$SETPRIV" --pdeathsig KILL --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        "$ENV_BIN" -i \
          HOME="$RUNNER_ROOT" USER="$RUN_USER" LOGNAME="$RUN_USER" \
          PATH=/usr/bin:/bin LC_ALL=C LANG=C \
          CARGO_HOME="$RUNNER_CARGO_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
          CARGO_TERM_COLOR=never CARGO_NET_OFFLINE=true \
          RUSTC="$RUSTC" RUSTFLAGS=-Dwarnings \
          CC="$CC" AR="$AR" RANLIB="$RANLIB" AS="$AS" LD="$LD" \
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC" \
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR" \
          "$SH" -c "set -e; ulimit -c 0; ulimit -f 262144; ulimit -n 4096; kill -STOP \"\$\$\"; exec \"\$@\"" \
          qperiapt-runner "$@" 9>&- &
  else
    "$SETPRIV" --pdeathsig KILL --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups \
      --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
      "$ENV_BIN" -i \
        HOME="$RUNNER_ROOT" USER="$RUN_USER" LOGNAME="$RUN_USER" \
        PATH=/usr/bin:/bin LC_ALL=C LANG=C \
        CARGO_HOME="$RUNNER_CARGO_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        CARGO_TERM_COLOR=never CARGO_NET_OFFLINE=true \
        RUSTC="$RUSTC" RUSTFLAGS=-Dwarnings \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" AS="$AS" LD="$LD" \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC" \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR" \
        "$SH" -c "set -e; ulimit -c 0; ulimit -f 262144; ulimit -n 4096; kill -STOP \"\$\$\"; exec \"\$@\"" \
        qperiapt-runner "$@" 9>&- &
  fi
  run_pid=$!
  RUN_PID=$run_pid
  trap 'exit 129' HUP
  trap 'exit 130' INT TERM
  if [ "$RUN_PENDING_SIGNAL" -ne 0 ]; then
    cleanup_runner_pid
    "$RMDIR" -- "$run_group" 2>/dev/null || :
    exit "$RUN_PENDING_SIGNAL"
  fi
  run_stopped=0
  run_attempt=0
  while [ "$run_attempt" -lt 500 ]; do
    if [ ! -r "/proc/$run_pid/status" ]; then
      break
    fi
    run_state=$("$AWK" "\$1 == \"State:\" {print \$2}" "/proc/$run_pid/status") || break
    if [ "$run_state" = T ]; then
      run_stopped=1
      break
    fi
    "$SLEEP" 0.01
    run_attempt=$((run_attempt + 1))
  done
  if [ "$run_stopped" -ne 1 ]; then
    kill "$run_pid" 2>/dev/null || :
    wait "$run_pid" 2>/dev/null || :
    RUN_PID=""
    "$RMDIR" -- "$run_group" 2>/dev/null || :
    return 125
  fi
  if ! printf '%s\n' "$run_pid" >"$run_group/cgroup.procs"; then
    kill "$run_pid" 2>/dev/null || :
    wait "$run_pid" 2>/dev/null || :
    RUN_PID=""
    "$RMDIR" -- "$run_group" 2>/dev/null || :
    return 125
  fi
  kill -CONT "$run_pid" || return 125
  if wait "$run_pid"; then
    run_status=0
  else
    run_status=$?
  fi
  RUN_PID=""
  if cgroup_has_processes "$run_group"; then
    printf '1\n' >"$run_group/cgroup.kill" || return 125
    run_attempt=0
    while cgroup_has_processes "$run_group" && [ "$run_attempt" -lt 500 ]; do
      "$SLEEP" 0.01
      run_attempt=$((run_attempt + 1))
    done
    if cgroup_has_processes "$run_group"; then
      return 125
    fi
    run_status=125
  fi
  "$RMDIR" -- "$run_group" || return 125
  return "$run_status"
}

run_as_runner() {
  run_as_runner_mode host "$@"
}

run_as_builder() {
  run_as_runner_mode none "$@"
}

run_as_measurement() {
  run_as_runner_mode measurement "$@"
}

run_archived_python() {
  archived_script=$1
  shift
  run_as_runner "$ENV_BIN" HOME="$VALIDATION_HOME" PYTHONNOUSERSITE=1 \
    "$PYTHON" -I -S - "$archived_script" "$@" <<'PY'
import pathlib
import runpy
import sys

script = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script.parent))
sys.argv = [str(script), *sys.argv[2:]]
runpy.run_path(str(script), run_name="__main__")
PY
}

sha256_file() {
  digest_line=$("$SHA256SUM" -- "$1") || return 1
  digest=${digest_line%% *}
  printf '%s\n' "$digest" | "$GREP" -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$digest"
}

record_tool() {
  tool_name=$1
  tool_path=$(trusted_file "$2") || fail "untrusted tool path for $tool_name: $2"
  tool_hash=$(sha256_file "$tool_path") || fail "cannot hash trusted tool: $tool_name"
  if [ -n "$TRUSTED_TOOL_RECORDS" ]; then
    TRUSTED_TOOL_RECORDS="$TRUSTED_TOOL_RECORDS
$tool_name|$tool_path|$tool_hash"
  else
    TRUSTED_TOOL_RECORDS="$tool_name|$tool_path|$tool_hash"
  fi
}

verify_trusted_tools() {
  while IFS='|' read -r tool_name tool_path tool_hash; do
    [ -n "$tool_name" ] || continue
    current_tool=$(trusted_file "$tool_path") || return 1
    [ "$current_tool" = "$tool_path" ] || return 1
    [ "$(sha256_file "$tool_path")" = "$tool_hash" ] || return 1
  done <<EOF
$TRUSTED_TOOL_RECORDS
EOF
}

for tool_spec in \
  "ar|$AR" "as|$AS" "awk|$AWK" "cargo|$CARGO" "cat|$CAT" "cc|$CC" \
  "chmod|$CHMOD" "chown|$CHOWN" "cp|$CP" "date|$DATE" "dirname|$DIRNAME" \
  "env|$ENV_BIN" "find|$FIND" "flock|$FLOCK" "getent|$GETENT" "git|$GIT" "grep|$GREP" \
  "id|$ID" "ip|$IP" "ld|$LD" "mkdir|$MKDIR" "mktemp|$MKTEMP" \
  "mount|$MOUNT" "mountpoint|$MOUNTPOINT" "mv|$MV" \
  "nsenter|$NSENTER" "passwd|$PASSWD" "python3|$PYTHON" "ranlib|$RANLIB" \
  "readlink|$READLINK" "rm|$RM" \
  "rmdir|$RMDIR" "rustc|$RUSTC" "sed|$SED" "setpriv|$SETPRIV" \
  "sha256sum|$SHA256SUM" "sh|$SH" "sleep|$SLEEP" "stat|$STAT" \
  "systemd-detect-virt|$SYSTEMD_DETECT_VIRT" "sysctl|$SYSCTL" "tail|$TAIL" \
  "tar|$TAR" "taskset|$TASKSET" "tc|$TC" "timeout|$TIMEOUT" \
  "umount|$UMOUNT" "unshare|$UNSHARE" "uname|$UNAME" "valgrind|$VALGRIND"; do
  tool_name=${tool_spec%%|*}
  tool_path=${tool_spec#*|}
  record_tool "$tool_name" "$tool_path"
done

repository_dirty() {
  dirty_output=$("$GIT" status --porcelain=v1 --untracked-files=all) || return 1
  if [ -n "$dirty_output" ]; then
    printf 'true\n'
  else
    printf 'false\n'
  fi
}

FROZEN_GIT_COMMIT=$("$GIT" rev-parse --verify HEAD) || fail "cannot freeze git commit"
printf '%s\n' "$FROZEN_GIT_COMMIT" | "$GREP" -Eq '^[0-9a-f]{40}$' || \
  fail "git commit is not a 40-character SHA-1"
FROZEN_SOURCE_DIRTY=$(repository_dirty) || fail "cannot inspect repository dirty state"
[ "$FROZEN_SOURCE_DIRTY" = false ] || fail "camera-ready primary evidence requires a clean source tree"
"$GIT" archive --format=tar --output="$SOURCE_ARCHIVE" "$FROZEN_GIT_COMMIT" || \
  fail "cannot freeze clean commit archive"
SOURCE_ARCHIVE_SHA256=$(sha256_file "$SOURCE_ARCHIVE") || fail "cannot hash source archive"
"$CHMOD" 0600 "$SOURCE_ARCHIVE" || fail "cannot protect frozen source archive"
"$MKDIR" -p -- "$SOURCE_ROOT" || fail "cannot create source snapshot"
"$TAR" -xf "$SOURCE_ARCHIVE" -C "$SOURCE_ROOT" || fail "cannot extract frozen source archive"
"$CHOWN" -R --no-dereference "root:$RUN_GID" "$SOURCE_ROOT" || \
  fail "cannot freeze source ownership"
"$CHMOD" -R a-w,go-rwx,u+rX,g+rX "$SOURCE_ROOT" || fail "cannot freeze source permissions"
unsafe_snapshot=$("$FIND" -P "$SOURCE_ROOT" \
  \( ! -user root -o ! -group "$RUN_GID" -o -perm /222 -o -perm /007 -o -type l \) \
  -print -quit) || \
  fail "cannot inspect frozen source snapshot"
[ -z "$unsafe_snapshot" ] || fail "source snapshot is not root-owned read-only: $unsafe_snapshot"
FROZEN_LAUNCHER_SHA256=$(sha256_file "$0") || fail "cannot hash frozen launcher"
ARCHIVED_LAUNCHER_SHA256=$(sha256_file "$SOURCE_ROOT/camera-ready-bare-metal.sh") || \
  fail "cannot hash archived launcher"
[ "$FROZEN_LAUNCHER_SHA256" = "$ARCHIVED_LAUNCHER_SHA256" ] || \
  fail "executed root-owned launcher does not match the clean Git archive"

canonical_source_digest() {
  run_as_runner "$ENV_BIN" HOME="$VALIDATION_HOME" PYTHONNOUSERSITE=1 \
    "$PYTHON" -I -S - "$SOURCE_ROOT" "$SOURCE_ROOT/artifact" <<'PY'
import pathlib
import stat
import sys

sys.path.insert(0, sys.argv[2])
from claim_ledger import canonical_file_map_digest

root = pathlib.Path(sys.argv[1]).resolve()
files = {}
for path in sorted(root.rglob("*")):
    metadata = path.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        continue
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"non-regular archive member: {path.relative_to(root)}")
    files[path.relative_to(root).as_posix()] = path.read_bytes()
print(canonical_file_map_digest(files))
PY
}

FROZEN_SOURCE_TREE_SHA256=$(canonical_source_digest) || \
  fail "cannot freeze canonical source-tree digest"
printf '%s\n' "$FROZEN_SOURCE_TREE_SHA256" | "$GREP" -Eq '^[0-9a-f]{64}$' || \
  fail "canonical source-tree digest is invalid"

run_root_archived_python() {
  archived_script=$1
  shift
  "$PYTHON" -I -S - "$archived_script" "$@" <<'PY'
import pathlib
import runpy
import sys

script = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script.parent))
sys.argv = [str(script), *sys.argv[2:]]
runpy.run_path(str(script), run_name="__main__")
PY
}

CARGO_SEED_MANIFEST="$WORK/cargo-seed-manifest.tsv"
CARGO_SEED_RESULT=$(run_root_archived_python \
  "$SOURCE_ROOT/artifact/camera_ready_proof.py" validate-cargo-seed \
  --seed-home "$CARGO_SEED_HOME" --lockfile "$SOURCE_ROOT/Cargo.lock" \
  --output "$CARGO_SEED_MANIFEST") || fail "Cargo seed does not match Cargo.lock"
printf '%s\n' "$CARGO_SEED_RESULT" | "$GREP" -Eq \
  '^CAMERA_READY_CARGO_SEED_PASS packages=[1-9][0-9]* files=[1-9][0-9]* manifest_sha256=[0-9a-f]{64}$' || \
  fail "Cargo seed validator emitted an invalid result"
CARGO_SEED_PACKAGES=$(printf '%s\n' "$CARGO_SEED_RESULT" | \
  "$SED" -n 's/^.*packages=\([0-9][0-9]*\).*$/\1/p')
CARGO_SEED_FILES=$(printf '%s\n' "$CARGO_SEED_RESULT" | \
  "$SED" -n 's/^.*files=\([0-9][0-9]*\).*$/\1/p')
CARGO_SEED_MANIFEST_SHA256=$(printf '%s\n' "$CARGO_SEED_RESULT" | \
  "$SED" -n 's/^.*manifest_sha256=\([0-9a-f][0-9a-f]*\)$/\1/p')
[ "$(sha256_file "$CARGO_SEED_MANIFEST")" = "$CARGO_SEED_MANIFEST_SHA256" ] || \
  fail "Cargo seed manifest hash is inconsistent"

validate_cargo_seed_unchanged() {
  current_manifest="$WORK/cargo-seed-current.tsv"
  "$RM" -f -- "$current_manifest" || return 1
  run_root_archived_python "$SOURCE_ROOT/artifact/camera_ready_proof.py" \
    validate-cargo-seed --seed-home "$CARGO_SEED_HOME" \
    --lockfile "$SOURCE_ROOT/Cargo.lock" --output "$current_manifest" >/dev/null || return 1
  current_hash=$(sha256_file "$current_manifest") || return 1
  "$RM" -f -- "$current_manifest" || return 1
  [ "$current_hash" = "$CARGO_SEED_MANIFEST_SHA256" ]
}

reset_runner_build_state() {
  build_lane=$1
  case "$build_lane" in
    netem | ct) ;;
    *) return 1 ;;
  esac
  validate_cargo_seed_unchanged || return 1
  case "$RUNNER_CARGO_HOME" in
    "$RUNNER_ROOT"/*) "$RM" -rf -- "$RUNNER_CARGO_HOME" || return 1 ;;
    *) return 1 ;;
  esac
  case "$CARGO_TARGET_DIR" in
    "$RUNNER_ROOT"/*) "$RM" -rf -- "$CARGO_TARGET_DIR" || return 1 ;;
    *) return 1 ;;
  esac
  RUNNER_CARGO_HOME="$RUNNER_ROOT/cargo-home-$build_lane"
  CARGO_TARGET_DIR="$RUNNER_ROOT/target-$build_lane"
  for build_dir in "$RUNNER_CARGO_HOME" "$CARGO_TARGET_DIR"; do
    "$MKDIR" -- "$build_dir" || return 1
    "$CHOWN" "$RUN_UID:$RUN_GID" "$build_dir" || return 1
    "$CHMOD" 0700 "$build_dir" || return 1
  done
  "$CP" -a -- "$CARGO_SEED_HOME/." "$RUNNER_CARGO_HOME/" || return 1
  "$CHOWN" -R --no-dereference "$RUN_UID:$RUN_GID" "$RUNNER_CARGO_HOME" || return 1
}

freeze_runner_binary() {
  binary_source=$1
  binary_target=$2
  freeze_result=$(run_root_archived_python "$SOURCE_ROOT/artifact/camera_ready_proof.py" \
    freeze-binary --source "$binary_source" --output "$binary_target" \
    --expected-uid "$RUN_UID") || return 1
  printf '%s\n' "$freeze_result" | "$GREP" -Eq \
    '^CAMERA_READY_BINARY_FROZEN sha256=[0-9a-f]{64}$' || return 1
  FROZEN_BINARY_SHA256=${freeze_result##*=}
  "$CHOWN" "root:$RUN_GID" "$binary_target" || return 1
  "$CHMOD" 0550 "$binary_target" || return 1
  [ -f "$binary_target" ] && [ ! -L "$binary_target" ] || return 1
  [ "$("$STAT" -c %u "$binary_target")" -eq 0 ] || return 1
  [ "$("$STAT" -c %g "$binary_target")" -eq "$RUN_GID" ] || return 1
  [ "$("$STAT" -c %h "$binary_target")" -eq 1 ] || return 1
  [ "$(sha256_file "$binary_target")" = "$FROZEN_BINARY_SHA256" ]
}

validate_root_capture_file() {
  capture_path=$1
  capture_max=$2
  [ -f "$capture_path" ] && [ ! -L "$capture_path" ] || return 1
  [ "$("$STAT" -c %u "$capture_path")" -eq 0 ] || return 1
  [ "$("$STAT" -c %h "$capture_path")" -eq 1 ] || return 1
  capture_size=$("$STAT" -c %s "$capture_path") || return 1
  [ "$capture_size" -ge 0 ] && [ "$capture_size" -le "$capture_max" ]
}

RUST_SYSROOT=$(run_as_runner "$RUSTC" --print sysroot < /dev/null) || fail "cannot resolve Rust sysroot"
case "$RUST_SYSROOT" in
  /*) ;;
  *) fail "Rust sysroot must be absolute" ;;
esac
unsafe_sysroot=$("$FIND" -P "$RUST_SYSROOT" \( ! -user root -o -perm /022 \) -print -quit) || \
  fail "cannot inspect Rust sysroot"
[ -z "$unsafe_sysroot" ] || fail "Rust sysroot is not root-owned read-only: $unsafe_sysroot"
RUSTC_VERSION=$(run_as_runner "$RUSTC" -Vv < /dev/null) || fail "cannot record rustc version"
CARGO_VERSION=$(run_as_runner "$CARGO" -V < /dev/null) || fail "cannot record cargo version"
VALGRIND_VERSION=$(run_as_runner "$VALGRIND" --version < /dev/null) || fail "cannot record Valgrind version"
CC_VERSION_FULL=$(run_as_runner "$CC" --version < /dev/null) || \
  fail "cannot record C compiler version"
CC_VERSION=$(printf '%s\n' "$CC_VERSION_FULL" | "$SED" -n '1p')
[ -n "$CC_VERSION" ] || fail "C compiler version is empty"

validate_sysctl_record() {
  record_key=$1
  record_old=$2
  record_expected=$3
  case "$record_key|$record_expected" in
    "net.ipv4.tcp_tw_reuse|1" | "net.ipv4.tcp_fin_timeout|3")
      printf '%s\n' "$record_old" | "$GREP" -Eq '^[0-9]+$'
      ;;
    "net.ipv4.ip_local_port_range|1024 65535")
      printf '%s\n' "$record_old" | "$GREP" -Eq '^[0-9]+ [0-9]+$'
      ;;
    *) return 1 ;;
  esac
}

validate_sysfs_record() {
  record_path=$1
  record_old=$2
  record_expected=$3
  if printf '%s\n' "$record_path" | \
      "$GREP" -Eq '^/sys/devices/system/cpu/cpufreq/policy[0-9]+/scaling_governor$'; then
    [ "$record_expected" = performance ] && \
      printf '%s\n' "$record_old" | "$GREP" -Eq '^[A-Za-z0-9_-]+$'
    return
  fi
  case "$record_path" in
    /sys/devices/system/cpu/cpufreq/boost)
      [ "$record_expected" = 0 ] && printf '%s\n' "$record_old" | "$GREP" -Eq '^[01]$'
      ;;
    /sys/devices/system/cpu/intel_pstate/no_turbo)
      [ "$record_expected" = 1 ] && printf '%s\n' "$record_old" | "$GREP" -Eq '^[01]$'
      ;;
    *) return 1 ;;
  esac
}

verify_netns_keeper() {
  [ -n "$NETNS_PID" ] && kill -0 "$NETNS_PID" 2>/dev/null || return 1
  [ -e "/proc/$NETNS_PID/ns/net" ] || return 1
  keeper_ns=$("$STAT" -Lc %i "/proc/$NETNS_PID/ns/net") || return 1
  supervisor_ns=$("$STAT" -Lc %i /proc/self/ns/net) || return 1
  [ "$keeper_ns" != "$supervisor_ns" ]
}

measurement_netns_exec() {
  verify_netns_keeper || return 1
  "$NSENTER" --net="/proc/$NETNS_PID/ns/net" -- "$@"
}

start_measurement_netns() {
  [ -z "$NETNS_PID" ] || return 1
  PENDING_SIGNAL=0
  trap 'PENDING_SIGNAL=129' HUP
  trap 'PENDING_SIGNAL=130' INT TERM
  "$UNSHARE" --net -- "$SETPRIV" --pdeathsig KILL -- "$SLEEP" 86400 9>&- &
  NETNS_PID=$!
  trap 'exit 129' HUP
  trap 'exit 130' INT TERM
  [ "$PENDING_SIGNAL" -eq 0 ] || exit "$PENDING_SIGNAL"
  netns_attempt=0
  while ! verify_netns_keeper && [ "$netns_attempt" -lt 500 ]; do
    "$SLEEP" 0.01
    netns_attempt=$((netns_attempt + 1))
  done
  verify_netns_keeper || return 1
  measurement_netns_exec "$IP" link set dev lo up || return 1
}

netem_json() {
  measurement_netns_exec "$TC" -j qdisc show dev lo
}

netem_tc() {
  measurement_netns_exec "$TC" "$@"
}

netns_sysctl() {
  measurement_netns_exec "$SYSCTL" "$@"
}

verify_netem() {
  current_netem=$(netem_json) || return 1
  if [ "$NETEM_STATE" = verified ]; then
    [ "$current_netem" = "$NETEM_FROZEN_JSON" ] || return 1
  else
    [ -n "$BASELINE_QDISC_JSON" ] || return 1
    [ "$current_netem" = "$BASELINE_QDISC_JSON" ] || return 1
  fi
}

verify_tuning() {
  while IFS='|' read -r key old expected; do
    [ -n "$key" ] || continue
    restored=""
    validate_sysctl_record "$key" "$old" "$expected" || return 1
    current=$(netns_sysctl -n "$key" | "$AWK" "{\$1=\$1; print}") || return 1
    [ "$current" = "$expected" ] || return 1
  done <<EOF
$SYSCTL_RECORDS
EOF
  while IFS='|' read -r path old expected; do
    [ -n "$path" ] || continue
    restored=""
    validate_sysfs_record "$path" "$old" "$expected" || return 1
    [ "$("$CAT" "$path")" = "$expected" ] || return 1
  done <<EOF
$SYSFS_RECORDS
EOF
  verify_netem
}

require_stable_tuning() {
  if ! verify_tuning; then
    TUNING_DRIFT=1
    fail "host tuning or netem state drifted during measurement"
  fi
}

netem_restore() {
  [ "$NETEM_STATE" != none ] || return 0
  if [ "$NETEM_STATE" = verified ]; then
    current_netem=$(netem_json) || return 1
    if [ "$current_netem" != "$NETEM_FROZEN_JSON" ]; then
      printf 'error: owned netem qdisc changed; refusing to delete non-identical state\n' >&2
      return 1
    fi
  elif [ "$NETEM_STATE" != armed ]; then
    printf 'error: invalid in-memory netem ownership state\n' >&2
    return 1
  fi
  if ! netem_tc qdisc del dev lo root handle "$NETEM_HANDLE"; then
    printf 'error: failed to remove owned netem qdisc during cleanup\n' >&2
    return 1
  fi
  NETEM_STATE=none
  NETEM_FROZEN_JSON=""
  if [ "$(netem_json)" != "$BASELINE_QDISC_JSON" ]; then
    printf 'error: loopback qdisc did not return to its frozen baseline\n' >&2
    return 1
  fi
}

restore() {
  [ "$HOST_RESTORED" -eq 0 ] || return 0
  cd / || return 1
  restore_failed=$TUNING_DRIFT
  if ! cleanup_cgroups; then
    printf 'error: failed to kill and remove runner cgroups during cleanup\n' >&2
    restore_failed=1
  fi
  if ! netem_restore; then
    restore_failed=1
  fi
  if [ -n "$TUNING_ACTIVE_RECORDS" ]; then
    TUNING_AFTER_RECORDS="$WORK/tuning-after-records.tsv"
    printf 'kind\tname\tbefore\tactive\tafter\n' >"$TUNING_AFTER_RECORDS" || \
      restore_failed=1
  fi
  while IFS='|' read -r key old expected; do
    [ -n "$key" ] || continue
    if ! validate_sysctl_record "$key" "$old" "$expected"; then
      printf 'error: invalid in-memory sysctl restore record for %s\n' "$key" >&2
      restore_failed=1
      continue
    fi
    current=$(netns_sysctl -n "$key" | "$AWK" "{\$1=\$1; print}") || {
      printf 'error: failed to read sysctl %s during cleanup\n' "$key" >&2
      restore_failed=1
      continue
    }
    if [ "$current" = "$expected" ]; then
      netns_sysctl -w "$key=$old" >/dev/null || restore_failed=1
    elif [ "$current" = "$old" ]; then
      if [ "$TUNING_ACTIVE" -eq 1 ] && [ "$old" != "$expected" ]; then
        printf 'error: sysctl %s reverted during measurement\n' "$key" >&2
        restore_failed=1
      fi
    else
      printf 'error: sysctl %s changed concurrently; refusing to overwrite it\n' "$key" >&2
      restore_failed=1
    fi
    restored=$(netns_sysctl -n "$key" | "$AWK" "{\$1=\$1; print}") || restore_failed=1
    [ "${restored:-}" = "$old" ] || restore_failed=1
    if [ -n "$TUNING_AFTER_RECORDS" ]; then
      printf 'sysctl\t%s\t%s\t%s\t%s\n' "$key" "$old" "$expected" "${restored:-}" \
        >>"$TUNING_AFTER_RECORDS" || restore_failed=1
    fi
  done <<EOF
$SYSCTL_RECORDS
EOF
  while IFS='|' read -r path old expected; do
    [ -n "$path" ] || continue
    if ! validate_sysfs_record "$path" "$old" "$expected"; then
      printf 'error: invalid in-memory sysfs restore record for %s\n' "$path" >&2
      restore_failed=1
      continue
    fi
    current=$("$CAT" "$path") || {
      printf 'error: failed to read sysfs control %s during cleanup\n' "$path" >&2
      restore_failed=1
      continue
    }
    if [ "$current" = "$expected" ]; then
      printf '%s\n' "$old" >"$path" || restore_failed=1
    elif [ "$current" = "$old" ]; then
      if [ "$TUNING_ACTIVE" -eq 1 ] && [ "$old" != "$expected" ]; then
        printf 'error: sysfs control %s reverted during measurement\n' "$path" >&2
        restore_failed=1
      fi
    else
      printf 'error: sysfs control %s changed concurrently; refusing to overwrite it\n' "$path" >&2
      restore_failed=1
    fi
    restored=$("$CAT" "$path") || restore_failed=1
    [ "${restored:-}" = "$old" ] || restore_failed=1
    if [ -n "$TUNING_AFTER_RECORDS" ]; then
      printf 'sysfs\t%s\t%s\t%s\t%s\n' "$path" "$old" "$expected" "${restored:-}" \
        >>"$TUNING_AFTER_RECORDS" || restore_failed=1
    fi
  done <<EOF
$SYSFS_RECORDS
EOF
  TUNING_ACTIVE=0
  if [ -n "$TUNING_ACTIVE_RECORDS" ]; then
    NETEM_AFTER_JSON="$WORK/netem-after.json"
    final_netem=""
    final_netem=$(netem_json) || restore_failed=1
    printf '%s\n' "${final_netem:-}" >"$NETEM_AFTER_JSON" || restore_failed=1
    if [ -f "$NETEM_AFTER_JSON" ] && \
        [ "$("$CAT" "$NETEM_AFTER_JSON")" != "$BASELINE_QDISC_JSON" ]; then
      printf 'error: final loopback qdisc snapshot differs from baseline\n' >&2
      restore_failed=1
    fi
  fi
  if ! cleanup_netns; then
    printf 'error: failed to stop isolated measurement network namespace\n' >&2
    restore_failed=1
  fi
  if ! cleanup_runner_fs; then
    printf 'error: failed to unmount bounded runner workspace\n' >&2
    restore_failed=1
  fi
  if [ "$restore_failed" -eq 0 ]; then
    HOST_RESTORED=1
    return 0
  fi
  return 1
}

on_exit() {
  exit_status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if ! restore; then
    [ "$exit_status" -ne 0 ] || exit_status=1
  fi
  cleanup_ephemeral || [ "$exit_status" -ne 0 ] || exit_status=1
  exit "$exit_status"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT TERM

set_sysctl() {
  key=$1
  wanted=$2
  old=$(netns_sysctl -n "$key" | "$AWK" "{\$1=\$1; print}") || fail "cannot read sysctl $key"
  expected=$(printf '%s\n' "$wanted" | "$AWK" "{\$1=\$1; print}")
  validate_sysctl_record "$key" "$old" "$expected" || fail "unsafe sysctl state for $key"
  if [ -n "$SYSCTL_RECORDS" ]; then
    SYSCTL_RECORDS="$SYSCTL_RECORDS
$key|$old|$expected"
  else
    SYSCTL_RECORDS="$key|$old|$expected"
  fi
  netns_sysctl -w "$key=$wanted" >/dev/null || fail "cannot set sysctl $key"
  [ "$(netns_sysctl -n "$key" | "$AWK" "{\$1=\$1; print}")" = "$expected" ] || \
    fail "sysctl $key did not retain requested value"
}

tune() {
  governors=0
  for governor in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do
    [ -f "$governor" ] || continue
    canonical_governor=$("$READLINK" -f "$governor") || fail "cannot canonicalize governor"
    printf '%s\n' "$canonical_governor" | \
      "$GREP" -Eq '^/sys/devices/system/cpu/cpufreq/policy[0-9]+/scaling_governor$' || \
      fail "governor escaped canonical policy tree"
    old=$("$CAT" "$canonical_governor") || fail "cannot read governor"
    validate_sysfs_record "$canonical_governor" "$old" performance || fail "unsafe governor state"
    if [ -n "$SYSFS_RECORDS" ]; then
      SYSFS_RECORDS="$SYSFS_RECORDS
$canonical_governor|$old|performance"
    else
      SYSFS_RECORDS="$canonical_governor|$old|performance"
    fi
    printf '%s\n' performance >"$canonical_governor" || fail "cannot set performance governor"
    [ "$("$CAT" "$canonical_governor")" = performance ] || fail "governor did not persist"
    governors=$((governors + 1))
  done
  [ "$governors" -gt 0 ] || fail "no canonical CPU policy governor controls found"

  if [ -f /sys/devices/system/cpu/cpufreq/boost ]; then
    boost_path=/sys/devices/system/cpu/cpufreq/boost
    boost_expected=0
  elif [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    boost_path=/sys/devices/system/cpu/intel_pstate/no_turbo
    boost_expected=1
  else
    fail "no supported boost/turbo control found"
  fi
  boost_old=$("$CAT" "$boost_path") || fail "cannot read boost/turbo control"
  validate_sysfs_record "$boost_path" "$boost_old" "$boost_expected" || fail "unsafe boost state"
  SYSFS_RECORDS="$SYSFS_RECORDS
$boost_path|$boost_old|$boost_expected"
  printf '%s\n' "$boost_expected" >"$boost_path" || fail "cannot disable boost/turbo"
  [ "$("$CAT" "$boost_path")" = "$boost_expected" ] || fail "boost/turbo state did not persist"

  set_sysctl net.ipv4.tcp_tw_reuse 1
  set_sysctl net.ipv4.ip_local_port_range "1024 65535"
  set_sysctl net.ipv4.tcp_fin_timeout 3
  TUNING_ACTIVE=1
  require_stable_tuning
  TUNING_ACTIVE_RECORDS="$WORK/tuning-active-records.tsv"
  printf 'kind\tname\tbefore\tactive\n' >"$TUNING_ACTIVE_RECORDS"
  while IFS='|' read -r key old expected; do
    [ -n "$key" ] || continue
    printf 'sysctl\t%s\t%s\t%s\n' "$key" "$old" "$expected" >>"$TUNING_ACTIVE_RECORDS"
  done <<EOF
$SYSCTL_RECORDS
EOF
  while IFS='|' read -r path old expected; do
    [ -n "$path" ] || continue
    printf 'sysfs\t%s\t%s\t%s\n' "$path" "$old" "$expected" >>"$TUNING_ACTIVE_RECORDS"
  done <<EOF
$SYSFS_RECORDS
EOF
  printf 'tuning: %s canonical policy governors=performance; boost/turbo disabled\n' "$governors"
  printf 'tuning: tcp_tw_reuse=1, port_range=1024..65535, fin_timeout=3\n'
}

validate_netem_file() {
  snapshot=$1
  delay_ms=$2
  "$CHOWN" "root:$RUN_GID" "$snapshot" || return 1
  "$CHMOD" 0440 "$snapshot" || return 1
  run_archived_python "$SOURCE_ROOT/artifact/camera_ready_proof.py" validate-netem \
    --json "$snapshot" --delay-ms "$delay_ms" >/dev/null
}

reject_external_cargo_config() {
  for config_root in "$RUNNER_CARGO_HOME" "$WORK" /run /; do
    for config_name in config config.toml; do
      [ ! -e "$config_root/.cargo/$config_name" ] || return 1
      [ ! -e "$config_root/$config_name" ] || return 1
    done
  done
}

CPU_NAME=$("$AWK" -F ': ' "/model name/{print \$2; exit}" /proc/cpuinfo) || fail "cannot read CPU model"
[ -n "$CPU_NAME" ] || fail "CPU model is empty"
HOST_UNAME=$("$UNAME" -srm) || fail "cannot record host uname"
RECORDED_AT=$("$DATE" -u +%Y-%m-%dT%H:%MZ) || fail "cannot record capture time"
RUN_ID=$("$CAT" /proc/sys/kernel/random/uuid | "$SED" 's/-//g') || fail "cannot create run id"
printf '%s\n' "$RUN_ID" | "$GREP" -Eq '^[0-9a-f]{32}$' || fail "run id is invalid"
printf '%s\n' "================ Q-Periapt camera-ready bare-metal ================"
printf 'host : %s    date: %s\n' "$HOST_UNAME" "$RECORDED_AT"
printf 'cpu  : %s\n' "$CPU_NAME"
printf 'pin  : cores %s   reps: %s   supervisor: root   runner-user: %s   runner-uid: %s   runner-gid: %s   no-new-privs: yes   cgroup-v2: yes\n' \
  "$PIN" "$REPS" "$RUN_USER" "$RUN_UID" "$RUN_GID"
printf 'commit: %s\n' "$FROZEN_GIT_COMMIT"
printf 'source-tree-sha256: %s   dirty: %s\n' "$FROZEN_SOURCE_TREE_SHA256" "$FROZEN_SOURCE_DIRTY"
printf 'source-archive-sha256: %s\n' "$SOURCE_ARCHIVE_SHA256"
printf 'run-id: %s\n' "$RUN_ID"
printf 'cargo-seed: packages=%s files=%s manifest-sha256=%s\n' \
  "$CARGO_SEED_PACKAGES" "$CARGO_SEED_FILES" "$CARGO_SEED_MANIFEST_SHA256"
printf 'rustc:\n%s\n' "$RUSTC_VERSION"
printf 'cargo: %s\ncc: %s\nvalgrind: %s\n' "$CARGO_VERSION" "$CC_VERSION" "$VALGRIND_VERSION"
TOOL_HASH_FILE="$WORK/tool-hashes.txt"
: >"$TOOL_HASH_FILE"
while IFS='|' read -r tool_name tool_path tool_hash; do
  [ -n "$tool_name" ] || continue
  printf 'tool-sha256: %s %s %s\n' "$tool_name" "$tool_hash" "$tool_path"
  printf 'tool-sha256: %s %s %s\n' "$tool_name" "$tool_hash" "$tool_path" >>"$TOOL_HASH_FILE"
done <<EOF
$TRUSTED_TOOL_RECORDS
EOF
printf '\n'

start_measurement_netns || fail "cannot create isolated loopback-only measurement network namespace"
BASELINE_QDISC_JSON=$(netem_json) || fail "cannot freeze loopback qdisc baseline"
printf '%s\n' "$BASELINE_QDISC_JSON" >"$WORK/netem-baseline.json"
validate_netem_file "$WORK/netem-baseline.json" 0 || \
  fail "loopback qdisc baseline must be exactly one unshaped noqueue qdisc"
tune
printf '\n'

cd "$SOURCE_ROOT" || fail "cannot enter frozen source snapshot"
reset_runner_build_state netem || fail "cannot create a fresh verified Cargo home for netem"
reject_external_cargo_config || fail "external Cargo config injection path is present"
printf 'building netem_bench (release, frozen snapshot)...\n'
if ! run_as_builder "$TIMEOUT" --signal=TERM --kill-after=30s 30m \
  "$CARGO" build --frozen --release -p q-periapt-rustls \
  --example netem_bench --features bench-baseline >"$WORK/netem-build.log" 2>&1 < /dev/null; then
  "$TAIL" -20 "$WORK/netem-build.log" >&2
  fail "netem_bench build failed"
fi
validate_root_capture_file "$WORK/netem-build.log" 67108864 || \
  fail "netem build log is not a bounded root-owned regular file"
if "$GREP" -Eiq '(^|[[:space:]])warning:' "$WORK/netem-build.log"; then
  "$GREP" -Ei '(^|[[:space:]])warning:' "$WORK/netem-build.log" >&2
  fail "netem_bench build emitted warnings"
fi
reject_external_cargo_config || fail "build created an external Cargo config"
BUILT_NETEM_BIN="$CARGO_TARGET_DIR/release/examples/netem_bench"
BIN="$MEASURE_ROOT/netem_bench"
freeze_runner_binary "$BUILT_NETEM_BIN" "$BIN" || \
  fail "cannot safely freeze netem benchmark binary"
NETEM_BIN_SHA256=$FROZEN_BINARY_SHA256
printf 'netem-binary-sha256: %s\n' "$NETEM_BIN_SHA256"

netem_clear() {
  if [ "$NETEM_STATE" != none ]; then
    netem_restore || fail "cannot remove owned loopback netem qdisc"
  fi
  current_qdisc=$(netem_json) || fail "cannot inspect loopback qdisc"
  [ "$current_qdisc" = "$BASELINE_QDISC_JSON" ] || \
    fail "loopback qdisc differs from its frozen baseline"
}

netrun() {
  one_way_ms=$1
  iterations=$2
  repetitions=$3
  netem_clear
  if [ "$one_way_ms" -ne 0 ]; then
    NETEM_STATE=armed
    PENDING_SIGNAL=0
    trap 'PENDING_SIGNAL=129' HUP
    trap 'PENDING_SIGNAL=130' INT TERM
    if ! netem_tc qdisc add dev lo root handle "$NETEM_HANDLE" netem delay "${one_way_ms}ms"; then
      NETEM_STATE=none
      trap 'exit 129' HUP
      trap 'exit 130' INT TERM
      fail "cannot install loopback netem qdisc"
    fi
    if ! NETEM_FROZEN_JSON=$(netem_json); then
      trap 'exit 129' HUP
      trap 'exit 130' INT TERM
      netem_restore || fail "cannot remove owned netem after snapshot failure"
      fail "cannot freeze installed netem state"
    fi
    printf '%s\n' "$NETEM_FROZEN_JSON" >"$WORK/netem-delay-${one_way_ms}.json"
    if ! validate_netem_file "$WORK/netem-delay-${one_way_ms}.json" "$one_way_ms"; then
      trap 'exit 129' HUP
      trap 'exit 130' INT TERM
      netem_restore || fail "cannot remove invalid owned netem state"
      fail "installed netem qdisc has wrong delay or extra shaping options"
    fi
    NETEM_STATE=verified
    trap 'exit 129' HUP
    trap 'exit 130' INT TERM
    [ "$PENDING_SIGNAL" -eq 0 ] || exit "$PENDING_SIGNAL"
  fi
  printf '== one-way=%s ms (RTT=%s ms), reps=%s ==\n' \
    "$one_way_ms" "$((one_way_ms * 2))" "$repetitions"
  rep=1
  while [ "$rep" -le "$repetitions" ]; do
    for group in classical standard bound compat; do
      require_stable_tuning
      benchmark_stdout="$WORK/netem-run.stdout"
      benchmark_stderr="$WORK/netem-run.stderr"
      if ! run_as_measurement "$TIMEOUT" --signal=TERM --kill-after=5s 5m \
        "$TASKSET" -c "$PIN" "$BIN" "$group" "$iterations" 100 \
        >"$benchmark_stdout" 2>"$benchmark_stderr" < /dev/null; then
        "$TAIL" -20 "$benchmark_stderr" >&2
        fail "netem benchmark failed for group=$group rep=$rep delay=$one_way_ms"
      fi
      require_stable_tuning
      [ -f "$benchmark_stdout" ] && [ ! -L "$benchmark_stdout" ] || \
        fail "netem benchmark stdout is not a regular file"
      [ -f "$benchmark_stderr" ] && [ ! -L "$benchmark_stderr" ] || \
        fail "netem benchmark stderr is not a regular file"
      [ "$("$STAT" -c %s "$benchmark_stdout")" -le 65536 ] || \
        fail "netem benchmark stdout exceeded 64 KiB"
      [ "$("$STAT" -c %s "$benchmark_stderr")" -eq 0 ] || \
        fail "netem benchmark emitted unexpected stderr"
      output=$("$CAT" "$benchmark_stdout") || fail "cannot read bounded benchmark output"
      p50=$(printf '%s\n' "$output" | "$GREP" -E \
        '^    p50 = [0-9]+\.[0-9]  p90 = [0-9]+\.[0-9]  p99 = [0-9]+\.[0-9]  p99\.9 = [0-9]+\.[0-9]$') || \
        fail "netem benchmark emitted no valid percentile schema"
      [ "$(printf '%s\n' "$p50" | "$GREP" -c '^')" -eq 1 ] || \
        fail "netem benchmark emitted ambiguous percentile output"
      printf 'rep%-2s %-10s %s\n' "$rep" "$group" "$p50"
      percentile_values=$(printf '%s\n' "$p50" | "$SED" -n \
        's/^    p50 = \([0-9]*\.[0-9]\)  p90 = \([0-9]*\.[0-9]\)  p99 = \([0-9]*\.[0-9]\)  p99\.9 = \([0-9]*\.[0-9]\)$/\1\t\2\t\3\t\4/p')
      [ -n "$percentile_values" ] || fail "cannot normalize percentile output"
      printf '%s\t%s\t%s\t%s\n' "$one_way_ms" "$rep" "$group" "$percentile_values" >> \
        "$MEASUREMENTS_TSV"
      NETEM_RUNS=$((NETEM_RUNS + 1))
    done
    rep=$((rep + 1))
    "$SLEEP" 2
  done
  netem_clear
  require_stable_tuning
}

printf '\n######## (1) netem time-to-session, 4 groups, REPS=%s, pinned to cores %s ########\n' \
  "$REPS" "$PIN"
NETEM_RUNS=0
MEASUREMENTS_TSV="$WORK/measurements.tsv"
printf 'delay_ms\trep\tgroup\tp50_us\tp90_us\tp99_us\tp999_us\n' >"$MEASUREMENTS_TSV"
netrun 0 300 "$REPS"
netrun 10 250 6
netrun 25 150 4
EXPECTED_NETEM_RUNS=$((4 * (REPS + 10)))
[ "$NETEM_RUNS" -eq "$EXPECTED_NETEM_RUNS" ] || \
  fail "incomplete netem matrix: got $NETEM_RUNS, expected $EXPECTED_NETEM_RUNS"
printf 'netem matrix complete: %s/%s group-runs\n' "$NETEM_RUNS" "$EXPECTED_NETEM_RUNS"

printf '\n######## (2) source->binary CT discriminator (NATIVE Memcheck) ########\n'
reset_runner_build_state ct || fail "cannot create a fresh verified Cargo home for CT probes"
reject_external_cargo_config || fail "external Cargo config injection path is present"
if ! run_as_builder "$TIMEOUT" --signal=TERM --kill-after=30s 30m \
  "$CARGO" build --frozen --release -p q-periapt-ctstats \
  --bin ct_decaps_gap --bin ct_leaky_control --features valgrind \
  >"$WORK/ct-build.log" 2>&1 < /dev/null; then
  "$TAIL" -20 "$WORK/ct-build.log" >&2
  fail "combined ML-KEM/synthetic-control CT probe build failed"
fi
validate_root_capture_file "$WORK/ct-build.log" 67108864 || \
  fail "CT build log is not a bounded root-owned regular file"
reject_external_cargo_config || fail "build created an external Cargo config"
if "$GREP" -Eiq '(^|[[:space:]])warning:' "$WORK/ct-build.log"; then
  "$GREP" -Ei '(^|[[:space:]])warning:' "$WORK/ct-build.log" >&2
  fail "CT probe build emitted warnings"
fi
BUILT_CT_ROOT="$CARGO_TARGET_DIR/release"
MLKEM_BIN="$MEASURE_ROOT/ct_decaps_gap"
LEAKY_CONTROL_BIN="$MEASURE_ROOT/ct_leaky_control"
freeze_runner_binary "$BUILT_CT_ROOT/ct_decaps_gap" "$MLKEM_BIN" || \
  fail "cannot safely freeze ML-KEM CT probe"
MLKEM_BIN_SHA256=$FROZEN_BINARY_SHA256
freeze_runner_binary "$BUILT_CT_ROOT/ct_leaky_control" "$LEAKY_CONTROL_BIN" || \
  fail "cannot safely freeze synthetic leaky-control CT probe"
LEAKY_CONTROL_BIN_SHA256=$FROZEN_BINARY_SHA256
printf 'mlkem-ct-binary-sha256: %s\nleaky-control-ct-binary-sha256: %s\n' \
  "$MLKEM_BIN_SHA256" "$LEAKY_CONTROL_BIN_SHA256"

run_memcheck() {
  binary=$1
  mode=$2
  label=$3
  log="$WORK/memcheck-$label.log"
  require_stable_tuning
  if ! run_as_measurement "$ENV_BIN" HOME="$VALIDATION_HOME" \
    "$SH" -c "cd \"\$1\"; shift; exec \"\$@\"" qperiapt-validator "$VALIDATION_CWD" \
    "$TIMEOUT" --signal=TERM --kill-after=10s 10m \
    "$VALGRIND" --leak-check=no --track-origins=yes -- \
    "$binary" "$mode" >"$log" 2>&1 < /dev/null; then
    "$TAIL" -50 "$log" >&2
    fail "Valgrind execution failed for $label"
  fi
  validate_root_capture_file "$log" 67108864 || \
    fail "Valgrind log is not a bounded root-owned regular file for $label"
  require_stable_tuning
  [ "$("$GREP" -c 'ERROR SUMMARY' "$log")" -eq 1 ] || \
    fail "Valgrind emitted an ambiguous ERROR SUMMARY set for $label"
  summary=$("$GREP" 'ERROR SUMMARY' "$log" | "$TAIL" -1) || \
    fail "Valgrind emitted no ERROR SUMMARY for $label"
  LAST_ERRORS=$(printf '%s\n' "$summary" | \
    "$SED" -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p')
  [ -n "$LAST_ERRORS" ] || fail "cannot parse Valgrind error count for $label"
  printf '  %-18s %s\n' "$label:" "$(printf '%s\n' "$summary" | "$SED" 's/^==[0-9]*== //')"
}

run_memcheck "$MLKEM_BIN" control control
CONTROL_ERRORS=$LAST_ERRORS
[ "$CONTROL_ERRORS" -gt 0 ] || fail "negative control did not expose the planted leak"
printf 'negative control OK: %s errors\n' "$CONTROL_ERRORS"
run_memcheck "$MLKEM_BIN" ek ml-kem-ek
MLKEM_EK_ERRORS=$LAST_ERRORS
run_memcheck "$MLKEM_BIN" wholedk ml-kem-wholedk
MLKEM_WHOLEDK_ERRORS=$LAST_ERRORS
run_memcheck "$MLKEM_BIN" probe ml-kem-probe
MLKEM_PROBE_ERRORS=$LAST_ERRORS
run_memcheck "$LEAKY_CONTROL_BIN" planted leaky-control
LEAKY_CONTROL_ERRORS=$LAST_ERRORS
[ "$MLKEM_EK_ERRORS" -gt 0 ] || \
  fail "ML-KEM public-ek positive control reported zero errors"
[ "$MLKEM_WHOLEDK_ERRORS" -gt 0 ] || \
  fail "ML-KEM whole-dk positive control reported zero errors"
[ "$MLKEM_EK_ERRORS" -eq "$MLKEM_WHOLEDK_ERRORS" ] || \
  fail "ML-KEM public-ek and whole-dk controls disagree on this ISA"
[ "$MLKEM_PROBE_ERRORS" -eq 0 ] || \
  fail "ML-KEM probe reported $MLKEM_PROBE_ERRORS errors; expected zero"
[ "$LEAKY_CONTROL_ERRORS" -gt 0 ] || \
  fail "synthetic planted-leak discriminator reported $LEAKY_CONTROL_ERRORS errors; expected >0"
printf 'DISCRIMINATOR HOLDS: ML-KEM probe=0 vs planted secret branch=%s\n\n' \
  "$LEAKY_CONTROL_ERRORS"

require_stable_tuning
[ "$(sha256_file "$BIN")" = "$NETEM_BIN_SHA256" ] || fail "netem binary changed"
[ "$(sha256_file "$MLKEM_BIN")" = "$MLKEM_BIN_SHA256" ] || fail "ML-KEM CT binary changed"
[ "$(sha256_file "$LEAKY_CONTROL_BIN")" = "$LEAKY_CONTROL_BIN_SHA256" ] || \
  fail "synthetic leaky-control CT binary changed"
verify_trusted_tools || fail "trusted tool identity changed during run"
FINAL_GIT_COMMIT=$("$GIT" rev-parse --verify HEAD) || fail "cannot recheck git commit"
[ "$FINAL_GIT_COMMIT" = "$FROZEN_GIT_COMMIT" ] || fail "git commit changed during run"
FINAL_SOURCE_TREE_SHA256=$(canonical_source_digest) || fail "cannot recheck source digest"
[ "$FINAL_SOURCE_TREE_SHA256" = "$FROZEN_SOURCE_TREE_SHA256" ] || fail "source tree changed during run"
[ "$(repository_dirty)" = "$FROZEN_SOURCE_DIRTY" ] || fail "repository dirty state changed"
[ "$(sha256_file "$SOURCE_ARCHIVE")" = "$SOURCE_ARCHIVE_SHA256" ] || \
  fail "source archive changed during run"
validate_cargo_seed_unchanged || fail "Cargo seed changed during run"
printf 'provenance recheck: commit/source/archive/tools/binaries/cargo-seed unchanged\n'

"$CHOWN" "root:$RUN_GID" "$MEASUREMENTS_TSV" || fail "cannot protect measurements TSV"
"$CHMOD" 0440 "$MEASUREMENTS_TSV" || fail "cannot protect measurements TSV"
SUMMARY_SOURCE="$WORK/summary.json"
run_root_archived_python "$SOURCE_ROOT/artifact/camera_ready_proof.py" summarize \
  --measurements "$MEASUREMENTS_TSV" --output "$SUMMARY_SOURCE" >/dev/null || \
  fail "cannot generate canonical measurement summary"
[ -f "$SUMMARY_SOURCE" ] && [ ! -L "$SUMMARY_SOURCE" ] || fail "measurement summary is missing"

BUNDLE_FINAL="$OUTPUT_ROOT/$RUN_ID"
[ ! -e "$BUNDLE_FINAL" ] || fail "refusing to overwrite existing camera-ready bundle"
BUNDLE_STAGE="$OUTPUT_ROOT/.bundle.$RUN_ID.tmp"
"$MKDIR" -- "$BUNDLE_STAGE" || fail "cannot create protected bundle staging directory"
"$CHMOD" 0700 "$BUNDLE_STAGE" || fail "cannot protect bundle staging directory"

stage_bundle_member() {
  bundle_source=$1
  bundle_name=$2
  case "$bundle_name" in
    "" | */* | . | ..) return 1 ;;
  esac
  [ -f "$bundle_source" ] && [ ! -L "$bundle_source" ] || \
    return 1
  [ ! -e "$BUNDLE_STAGE/$bundle_name" ] || return 1
  "$CP" -- "$bundle_source" "$BUNDLE_STAGE/$bundle_name" || \
    return 1
}

stage_bundle_member "$SOURCE_ARCHIVE" source.tar || fail "cannot stage source.tar"
stage_bundle_member "$MEASUREMENTS_TSV" measurements.tsv || fail "cannot stage measurements.tsv"
stage_bundle_member "$SUMMARY_SOURCE" summary.json || fail "cannot stage summary.json"
stage_bundle_member "$TOOL_HASH_FILE" tool-hashes.txt || fail "cannot stage tool-hashes.txt"
stage_bundle_member "$WORK/netem-baseline.json" netem-baseline.json || fail "cannot stage netem baseline"
stage_bundle_member "$WORK/netem-delay-10.json" netem-delay-10.json || fail "cannot stage 10ms netem state"
stage_bundle_member "$WORK/netem-delay-25.json" netem-delay-25.json || fail "cannot stage 25ms netem state"
stage_bundle_member "$WORK/netem-build.log" netem-build.log || fail "cannot stage netem build log"
stage_bundle_member "$WORK/ct-build.log" ct-build.log || fail "cannot stage CT build log"
stage_bundle_member "$WORK/memcheck-control.log" memcheck-control.log || fail "cannot stage control log"
stage_bundle_member "$WORK/memcheck-ml-kem-ek.log" memcheck-ml-kem-ek.log || fail "cannot stage ML-KEM ek log"
stage_bundle_member "$WORK/memcheck-ml-kem-wholedk.log" memcheck-ml-kem-wholedk.log || fail "cannot stage ML-KEM whole-dk log"
stage_bundle_member "$WORK/memcheck-ml-kem-probe.log" memcheck-ml-kem-probe.log || fail "cannot stage ML-KEM probe log"
stage_bundle_member "$WORK/memcheck-leaky-control.log" memcheck-leaky-control.log || \
  fail "cannot stage synthetic leaky-control log"
stage_bundle_member "$BIN" netem_bench || fail "cannot stage netem binary"
stage_bundle_member "$MLKEM_BIN" ct_decaps_gap || fail "cannot stage ML-KEM CT binary"
stage_bundle_member "$LEAKY_CONTROL_BIN" ct_leaky_control || \
  fail "cannot stage synthetic leaky-control CT binary"
stage_bundle_member "$CARGO_SEED_MANIFEST" cargo-seed-manifest.tsv || fail "cannot stage Cargo seed manifest"
stage_bundle_member "$TUNING_ACTIVE_RECORDS" tuning-active-records.tsv || fail "cannot stage active tuning records"

cd / || fail "cannot leave source snapshot"
if ! restore; then
  fail "camera-ready evidence completed but host-state cleanup failed"
fi
[ -n "$TUNING_AFTER_RECORDS" ] && [ -n "$NETEM_AFTER_JSON" ] || \
  fail "host restoration did not produce audit records"
stage_bundle_member "$TUNING_AFTER_RECORDS" tuning-after-records.tsv || \
  fail "cannot stage restored tuning records"
stage_bundle_member "$NETEM_AFTER_JSON" netem-after.json || fail "cannot stage restored qdisc"

verify_trusted_tools || fail "trusted tool identity changed after host restoration"
[ "$(sha256_file "$SOURCE_ARCHIVE")" = "$SOURCE_ARCHIVE_SHA256" ] || \
  fail "source archive changed before publication"
validate_cargo_seed_unchanged || fail "Cargo seed changed before publication"
CAPTURE_METADATA="$WORK/capture-metadata.json"
run_root_archived_python "$SOURCE_ROOT/artifact/camera_ready_proof.py" \
  write-capture-metadata --output "$CAPTURE_METADATA" \
  --host-uname "$HOST_UNAME" --cpu "$CPU_NAME" --recorded-at "$RECORDED_AT" \
  --pin "$PIN" --reps "$REPS" --runner-user "$RUN_USER" \
  --runner-uid "$RUN_UID" --runner-gid "$RUN_GID" \
  --rustc-version "$RUSTC_VERSION" --cargo-version "$CARGO_VERSION" \
  --cc-version "$CC_VERSION" --valgrind-version "$VALGRIND_VERSION" \
  --tuning-active "$TUNING_ACTIVE_RECORDS" --tuning-after "$TUNING_AFTER_RECORDS" \
  --qdisc-baseline "$WORK/netem-baseline.json" --qdisc-after "$NETEM_AFTER_JSON" \
  --cargo-seed-manifest "$CARGO_SEED_MANIFEST" --lockfile "$SOURCE_ROOT/Cargo.lock" \
  >/dev/null || fail "cannot generate canonical capture metadata"
stage_bundle_member "$CAPTURE_METADATA" capture-metadata.json || \
  fail "cannot stage capture metadata"

FINALIZE_RESULT=$(run_root_archived_python "$SOURCE_ROOT/artifact/camera_ready_proof.py" \
  finalize --bundle "$BUNDLE_STAGE" --run-id "$RUN_ID" --recorded-at "$RECORDED_AT" \
  --commit "$FROZEN_GIT_COMMIT" --execution-input-sha256 "$FROZEN_SOURCE_TREE_SHA256" \
  --source-archive-sha256 "$SOURCE_ARCHIVE_SHA256") || \
  fail "cannot finalize canonical camera-ready bundle manifest"
printf '%s\n' "$FINALIZE_RESULT" | "$GREP" -Eq \
  '^CAMERA_READY_BUNDLE_FINALIZED manifest_sha256=[0-9a-f]{64}$' || \
  fail "bundle finalizer emitted an invalid result"
BUNDLE_MANIFEST_SHA256=$(sha256_file "$BUNDLE_STAGE/manifest.json") || \
  fail "cannot hash camera-ready bundle manifest"
[ "$BUNDLE_MANIFEST_SHA256" = "${FINALIZE_RESULT##*=}" ] || \
  fail "bundle finalizer hash is inconsistent"
"$CHOWN" -R --no-dereference root:root "$BUNDLE_STAGE" || fail "cannot freeze bundle ownership"
"$CHMOD" 0444 "$BUNDLE_STAGE"/* || fail "cannot freeze bundle members"
"$CHMOD" 0555 "$BUNDLE_STAGE/netem_bench" "$BUNDLE_STAGE/ct_decaps_gap" \
  "$BUNDLE_STAGE/ct_leaky_control" || fail "cannot freeze bundled binaries"
"$CHMOD" 0555 "$BUNDLE_STAGE" || fail "cannot freeze bundle directory"
PUBLISHED_BUNDLE="$BUNDLE_FINAL"
if ! "$MV" -T -- "$BUNDLE_STAGE" "$BUNDLE_FINAL"; then
  fail "cannot atomically publish camera-ready bundle"
fi
BUNDLE_STAGE=""
if ! "$RM" -rf -- "$WORK"; then
  fail "cannot remove camera-ready work directory after host restoration"
fi
WORK=""
case "${QPERIAPT_LAUNCHER_DIR:-}" in
  /run/qperiapt-camera-ready-launcher.*)
    "$RM" -rf -- "$QPERIAPT_LAUNCHER_DIR" || fail "cannot remove frozen launcher"
    QPERIAPT_LAUNCHER_DIR=""
    ;;
  *) fail "frozen launcher path changed unexpectedly" ;;
esac
printf 'bundle-manifest-sha256: %s\n' "$BUNDLE_MANIFEST_SHA256"
printf 'bundle-location: %s\n' "$BUNDLE_FINAL"
printf 'CAMERA_READY_BARE_METAL_PASS netem_runs=%s ct_mode=native commit=%s source_sha256=%s archive_sha256=%s netem_sha256=%s mlkem_ct_sha256=%s leaky_control_ct_sha256=%s run_id=%s bundle_manifest_sha256=%s\n' \
  "$NETEM_RUNS" "$FROZEN_GIT_COMMIT" "$FROZEN_SOURCE_TREE_SHA256" \
  "$SOURCE_ARCHIVE_SHA256" "$NETEM_BIN_SHA256" "$MLKEM_BIN_SHA256" \
  "$LEAKY_CONTROL_BIN_SHA256" \
  "$RUN_ID" "$BUNDLE_MANIFEST_SHA256"
PUBLISHED_BUNDLE=""
trap - EXIT HUP INT TERM
