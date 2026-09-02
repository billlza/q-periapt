#!/bin/sh
# Boot-time owner of the policy agent's socket directory on macOS.
#
# Install as /opt/qperiapt/libexec/qperiapt-agent-rundir.sh, owned by root:wheel
# and mode 0644, and run it from com.qperiapt.policy-agent-rundir.plist, the
# launchd job shipped beside it. It is the macOS counterpart of
# q-periapt-agent.tmpfiles.conf and does the one thing launchd will not:
# /private/var/run is cleared on every boot, launchd creates the SockPathName
# node itself but never the directory containing it, and that directory's 0710
# mode is the daemon's only enforced admission boundary. The daemon cannot
# verify the socket's own owner, group or mode -- an AF_UNIX descriptor names a
# socket object, not the filesystem node addressing it -- so a directory
# recreated with a default mode is the dangerous outcome: the daemon starts
# normally and cannot tell that the boundary is gone.
#
# So this script creates the directory, verifies it is exactly right, and only
# then bootstraps the agent. Every other outcome is a refusal: a non-zero exit,
# nothing bootstrapped, and the agent left down -- the outcome the daemon itself
# chooses when its listener is missing -- rather than up behind no boundary.
#
# Why the agent plist lives outside /Library/LaunchDaemons: launchd loads every
# plist in that directory at boot, and RunAtLoad jobs have no ordering among
# themselves. Put com.qperiapt.policy-agent.plist there and launchd may load it
# before this job has run: its bind then fails against the missing directory
# and the daemon, handed no listener, exits -- or the bind succeeds inside a
# directory something else created with whatever mode it chose. Keeping the
# agent plist at AGENT_PLIST below, where launchd never scans, means the only
# way the agent gets loaded is through the verification above it.

# --- Parameters -------------------------------------------------------------
#
# Every path is canonical under /private/var: /var is a symlink to private/var,
# and the agent plist names its socket the same way.

# The socket's parent directory: the parent of SockPathName in the agent plist.
RUN_DIR=/private/var/run/qperiapt-agent

# The daemon account (UserName in the agent plist) and the transport group, the
# group whose gid the agent plist carries as SockPathGroup. REPLACE the group
# name with the one created in the provisioning order. chown resolves both
# names, so unlike the plist these are names rather than numbers -- and they
# must name the same uid and gid the plist's numeric fields were templated
# from, or the socket and its directory disagree on who may reach it.
RUN_DIR_OWNER=_qperiaptagent
RUN_DIR_GROUP=_qperiaptclients

# The owner may do anything, the transport group may traverse and nothing more,
# everyone else is refused. This is the admission boundary.
RUN_DIR_MODE=0710

# The agent job and its label. Deliberately NOT under /Library/LaunchDaemons;
# see above.
AGENT_PLIST=/opt/qperiapt/launchd/com.qperiapt.policy-agent.plist
AGENT_LABEL=com.qperiapt.policy-agent

# --- Refusals ---------------------------------------------------------------

set -eu

# The directory is 0700 from the moment it exists until chmod widens it.
umask 077

# Only the system's own tools, whatever PATH launchd or an operator supplied.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

created=0
verified=0

# Say it on stderr (the plist sends that to a log file) and in the unified log.
log() {
    printf 'qperiapt-agent-rundir: %s\n' "$2" >&2
    logger -t qperiapt-agent-rundir -p "daemon.$1" -- "$2" 2>/dev/null || :
}

fail() {
    log err "$1"
    exit 1
}

# Every non-zero exit passes through here, whether from fail or from set -e. A
# directory this run created and could not verify is removed again -- rmdir, so
# only an empty directory of ours can go -- and one that already existed is left
# exactly as found.
cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ "$created" -eq 1 ] && [ "$verified" -eq 0 ]; then
        if rmdir "$RUN_DIR"; then
            log err "removed the directory this run created and could not verify: $RUN_DIR"
        else
            log err "could not remove the directory this run created: $RUN_DIR"
        fi
    fi
}
trap cleanup EXIT

# --- Preconditions: refuse before touching anything -------------------------

if [ "$(uname -s)" != Darwin ]; then
    fail "this is the macOS counterpart of q-periapt-agent.tmpfiles.conf and runs nowhere else"
fi
if [ "$(id -u)" -ne 0 ]; then
    fail "must run as root: chown to $RUN_DIR_OWNER and launchctl bootstrap system both require it"
fi

# The agent plist must not sit where launchd would already have loaded it on
# its own, and it must be a regular file.
case "$AGENT_PLIST" in
    /Library/LaunchDaemons/* | /System/Library/LaunchDaemons/*)
        fail "agent plist must not live where launchd scans at boot: $AGENT_PLIST"
        ;;
esac
if [ -L "$AGENT_PLIST" ] || ! [ -f "$AGENT_PLIST" ]; then
    fail "agent plist is missing or not a regular file: $AGENT_PLIST"
fi

# The parent must already be a real directory. The OS creates /private/var/run
# itself; if it is missing or a symlink, something is wrong with the host and
# nothing here should paper over it.
parent=${RUN_DIR%/*}
if [ -L "$parent" ] || ! [ -d "$parent" ]; then
    fail "parent is not a real directory: $parent"
fi

# --- The directory ----------------------------------------------------------

if [ -L "$RUN_DIR" ]; then
    fail "refusing to touch a symlink at $RUN_DIR"
elif [ -e "$RUN_DIR" ] && ! [ -d "$RUN_DIR" ]; then
    fail "refusing to touch a non-directory at $RUN_DIR"
elif [ -d "$RUN_DIR" ]; then
    # Left by something else: this job re-run by hand, or a host that did not
    # clear /private/var/run. Not ours to remove, but ours to bring to exactly
    # the shipped owner, group and mode -- what tmpfiles.d does on Linux for an
    # entry that already exists.
    log notice "adopting the existing directory $RUN_DIR"
else
    # mkdir without -p: it creates exactly this one directory, fails if the
    # parent is missing, and fails rather than follows if anything -- a symlink
    # included -- has appeared at the path since the checks above.
    if ! mkdir "$RUN_DIR"; then
        fail "could not create $RUN_DIR"
    fi
    created=1
fi

# -h on both: the path itself, never a target it might have become.
if ! chown -h "$RUN_DIR_OWNER:$RUN_DIR_GROUP" "$RUN_DIR"; then
    fail "could not set owner and group $RUN_DIR_OWNER:$RUN_DIR_GROUP on $RUN_DIR"
fi
if ! chmod -h "$RUN_DIR_MODE" "$RUN_DIR"; then
    fail "could not set mode $RUN_DIR_MODE on $RUN_DIR"
fi

# --- Verification: the only thing the bootstrap below trusts -----------------
#
# stat without -L reports the path itself, never a target. %HT is the file
# type, %Su and %Sg the owner and group by name, and %Mp%Lp the setuid, setgid
# and sticky bits followed by the permission bits -- so the comparison is exact:
# a setgid directory reads 2710 and is refused along with everything else that
# is not precisely a directory, owned as configured, at the configured mode.
expected="Directory:$RUN_DIR_OWNER:$RUN_DIR_GROUP:$RUN_DIR_MODE"
if ! actual=$(stat -f '%HT:%Su:%Sg:%Mp%Lp' "$RUN_DIR"); then
    fail "could not stat $RUN_DIR"
fi
if [ "$actual" != "$expected" ]; then
    fail "$RUN_DIR is $actual, not $expected; not bootstrapping $AGENT_LABEL"
fi
verified=1

# --- The agent --------------------------------------------------------------

# Already loaded means either this job ran twice, or the agent plist was loaded
# by something other than this job -- from /Library/LaunchDaemons, say -- and
# may have tried to bind its socket before the directory existed. Neither is a
# state to build on silently. The directory above is correct either way.
if launchctl print "system/$AGENT_LABEL" >/dev/null 2>&1; then
    fail "$AGENT_LABEL is already bootstrapped; this job loads it once per boot, after the directory is verified. If it was loaded from elsewhere: launchctl bootout system/$AGENT_LABEL, then launchctl kickstart system/com.qperiapt.policy-agent-rundir"
fi

if ! launchctl bootstrap system "$AGENT_PLIST"; then
    fail "launchctl bootstrap system $AGENT_PLIST failed; $AGENT_LABEL is not loaded"
fi
log notice "$RUN_DIR is $actual; bootstrapped $AGENT_LABEL from $AGENT_PLIST"
