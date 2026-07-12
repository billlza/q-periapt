#!/bin/sh
# Root-only pre-drop mount setup for a single camera-ready runner command.
set -eu

if [ "$#" -lt 4 ]; then
  printf 'error: camera-ready sandbox requires mount path, work paths, and command\n' >&2
  exit 2
fi

MOUNT_BIN=$1
WORK_DIR=$2
RUNNER_ROOT=$3
shift 3
[ "$MOUNT_BIN" = /usr/bin/mount ] && [ -x "$MOUNT_BIN" ] || {
  printf 'error: camera-ready sandbox received an untrusted mount path\n' >&2
  exit 2
}
case "$WORK_DIR" in
  /*) ;;
  *)
    printf 'error: camera-ready sandbox work path must be absolute\n' >&2
    exit 2
    ;;
esac
[ "$RUNNER_ROOT" = "$WORK_DIR/runner" ] || {
  printf 'error: camera-ready sandbox received inconsistent work paths\n' >&2
  exit 2
}

"$MOUNT_BIN" --make-rprivate /
"$MOUNT_BIN" -o remount,ro=recursive /
"$MOUNT_BIN" --bind "$WORK_DIR" "$WORK_DIR"
"$MOUNT_BIN" -o remount,bind,rw,nodev,nosuid "$WORK_DIR"
"$MOUNT_BIN" --bind "$RUNNER_ROOT" "$RUNNER_ROOT"
"$MOUNT_BIN" -o remount,bind,rw,nodev,nosuid "$RUNNER_ROOT"
root_probe="/.qperiapt-sandbox-write-probe.$$"
if (set -C; : >"$root_probe") 2>/dev/null; then
  /usr/bin/rm -f -- "$root_probe"
  printf 'error: camera-ready sandbox root filesystem is still writable\n' >&2
  exit 2
fi
"$MOUNT_BIN" -t tmpfs -o \
  size=4194304,nr_inodes=1024,nodev,nosuid,noexec,mode=0755 \
  qperiapt-private-home /home
"$MOUNT_BIN" -t tmpfs -o \
  size=4194304,nr_inodes=1024,nodev,nosuid,noexec,mode=0700 \
  qperiapt-private-root /root
"$MOUNT_BIN" -t tmpfs -o \
  size=536870912,nr_inodes=131072,nodev,nosuid,noexec,mode=1777 \
  qperiapt-private-tmp /tmp
"$MOUNT_BIN" -t tmpfs -o \
  size=268435456,nr_inodes=65536,nodev,nosuid,noexec,mode=1777 \
  qperiapt-private-var-tmp /var/tmp
"$MOUNT_BIN" -t tmpfs -o \
  size=268435456,nr_inodes=65536,nodev,nosuid,noexec,mode=1777 \
  qperiapt-private-shm /dev/shm
"$MOUNT_BIN" -t tmpfs -o \
  size=16777216,nr_inodes=4096,nodev,nosuid,noexec,mode=0755 \
  qperiapt-private-run /run

/usr/bin/awk -v work="$WORK_DIR" '
  $6 ~ /(^|,)rw(,|$)/ {
    target = $5
    if (target == work || index(target, work "/") == 1 ||
        target == "/tmp" || target == "/var/tmp" ||
        target == "/dev/shm" || target == "/run" ||
        target == "/home" || target == "/root") {
      next
    }
    print "error: writable mount escaped camera-ready sandbox: " target > "/dev/stderr"
    bad = 1
  }
  END { exit bad }
' /proc/self/mountinfo

probe="$RUNNER_ROOT/.sandbox-write-probe.$$"
: >"$probe"
/usr/bin/rm -f -- "$probe"

exec "$@"
