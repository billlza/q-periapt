#!/bin/sh
# Boot-time owner of the policy agent's socket directory on macOS.
#
# Install as /opt/qperiapt/libexec/qperiapt-agent-rundir.sh, owned by root:wheel
# and mode 0644, and run it from com.qperiapt.policy-agent-rundir.plist, the
# launchd job shipped beside it. It is the macOS counterpart of
# q-periapt-agent.tmpfiles.conf and does the one thing launchd will not:
# launchd creates the SockPathName node itself but never the directory
# containing it, and that directory's 0710 mode is the daemon's only enforced
# admission boundary. The daemon cannot verify the socket's own owner, group or
# mode -- an AF_UNIX descriptor names a socket object, not the filesystem node
# addressing it -- so a directory at a default mode, or a directory something
# other than root put at the path, is the dangerous outcome: the daemon starts
# normally and cannot tell that the boundary is gone.
#
# The directory lives under /opt/qperiapt, not under /private/var/run. On macOS
# /private/var/run is root:daemon 0775 without the sticky bit, and rename(2)
# and rmdir(2) need write permission on the directory holding an entry, not
# ownership of the entry: any process with gid 1 -- accounts with that primary
# group exist by default -- could rename a verified qperiapt-agent directory
# away and put its own directory, or a symlink, at the path, between a
# verification and the bootstrap or at any later time. launchd would then bind
# SockPathName inside a directory that account controls, and the daemon adopts
# the descriptor on the strength of the bound path string alone. Under a
# root-owned /opt/qperiapt nothing but root can do that, and /opt persists
# across boots, so this is a verification job rather than a recreation job: it
# checks every ancestor of the directory from / down, creates the directory
# the first time and adopts it every time after, brings it to exactly the
# shipped owner, group and mode with no ACL, verifies that, and only then
# bootstraps the agent. Every other outcome is a refusal: a non-zero exit, nothing
# bootstrapped, and the agent left down -- the outcome the daemon itself
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

# The socket's parent directory: the parent of SockPathName in the agent plist.
# Under the root-owned installation tree, never under /private/var/run; see
# above. Every component of this path is checked below, from / down, and the
# installer creates everything above the last one.
RUN_DIR=/opt/qperiapt/run/qperiapt-agent

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

# A literal newline for the pattern below.
NL=$(printf '\nx'); NL=${NL%x}

# stat has no ACL format on macOS, chmod 0710 removes no ACL entry, and ls marks
# the mode field '@' rather than '+' whenever the path also has an extended
# attribute, so the mode field cannot be read for one either. ls -e appends one
# line per ACL entry after the listing line; -d lists a directory itself rather
# than its contents, and without -L it reports the path itself. Exactly one
# line is the only thing accepted.
verify_no_acl() {
    if ! listing=$(ls -lde -- "$1"); then
        fail "could not list $1"
    fi
    case "$listing" in
        *"$NL"*)
            fail "$1 carries an ACL, which stat cannot see and which grants what its mode denies; not bootstrapping $AGENT_LABEL: $listing"
            ;;
    esac
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

# --- Ancestors: every directory above RUN_DIR, from / down -------------------
#
# stat without -L reports each path itself, so a symlink anywhere on the way
# reads as "Symbolic Link" and is refused before anything below it is looked
# at. %HT is the file type, %Su the owner by name, and %Mp%Lp the setuid,
# setgid and sticky bits followed by the permission bits. The only thing
# accepted is a real directory, owned by root, that group and other cannot
# write, carrying no ACL entry: those are the directories in which nobody but
# root can rename, remove or replace an entry, which is what keeps the
# directory verified below the same directory launchd binds into. The ACL
# check comes second, after stat has refused a symlink, and is a refusal
# rather than a strip: an entry granting add_file or delete_child on an
# ancestor lets its subject rename or replace the verified directory exactly
# as a group or other write bit would, and this job does not own /, /opt,
# /opt/qperiapt or /opt/qperiapt/run. A missing ancestor is a refusal too: the
# installer creates the tree, and this job never creates anything whose parent
# it has not verified.

verify_ancestor() {
    if ! ancestor_actual=$(stat -f '%HT:%Su:%Mp%Lp' "$1"); then
        fail "could not stat $1, an ancestor of $RUN_DIR"
    fi
    case "$ancestor_actual" in
        Directory:root:[0-7][0-7][0145][0145]) ;;
        *)
            fail "$1 is $ancestor_actual, not a root-owned directory that group and other cannot write; not bootstrapping $AGENT_LABEL"
            ;;
    esac
    verify_no_acl "$1"
}

# Walk /, then each component of the parent in turn: /opt, /opt/qperiapt, and
# so on down to the parent itself.
ancestor=
remainder=${RUN_DIR%/*}
remainder=${remainder#/}
verify_ancestor /
while [ -n "$remainder" ]; do
    ancestor="$ancestor/${remainder%%/*}"
    verify_ancestor "$ancestor"
    case "$remainder" in
        */*) remainder=${remainder#*/} ;;
        *) remainder= ;;
    esac
done

# --- The directory ----------------------------------------------------------

if [ -L "$RUN_DIR" ]; then
    fail "refusing to touch a symlink at $RUN_DIR"
elif [ -e "$RUN_DIR" ] && ! [ -d "$RUN_DIR" ]; then
    fail "refusing to touch a non-directory at $RUN_DIR"
elif [ -d "$RUN_DIR" ]; then
    # /opt persists across boots, so from the second boot on this is the
    # normal case: the directory this job created and verified before. Not
    # ours to remove, but ours to bring to exactly the shipped owner, group
    # and mode -- what tmpfiles.d does on Linux for an entry that already
    # exists -- and to verify again below, because nothing here trusts what
    # the last run left.
    log notice "adopting the existing directory $RUN_DIR"
else
    # mkdir without -p: it creates exactly this one directory, inside the
    # parent verified above, and fails rather than follows if anything -- a
    # symlink included -- has appeared at the path since the checks above.
    if ! mkdir "$RUN_DIR"; then
        fail "could not create $RUN_DIR"
    fi
    created=1
fi

# -h on both: the path itself, never a target it might have become.
if ! chown -h "$RUN_DIR_OWNER:$RUN_DIR_GROUP" "$RUN_DIR"; then
    fail "could not set owner and group $RUN_DIR_OWNER:$RUN_DIR_GROUP on $RUN_DIR"
fi
# The ACL is the job's to remove exactly as the owner, group and mode are its
# to set: an entry here was inherited from an ancestor that has since been
# fixed, or was put there by hand, and either way grants what 0710 denies.
# Say so before removing it; the verification below is what decides.
if listing=$(ls -lde -- "$RUN_DIR"); then
    case "$listing" in
        *"$NL"*) log warning "removing the ACL found on $RUN_DIR: $listing" ;;
    esac
fi
if ! chmod -h -N "$RUN_DIR"; then
    fail "could not remove the ACL from $RUN_DIR"
fi
if ! chmod -h "$RUN_DIR_MODE" "$RUN_DIR"; then
    fail "could not set mode $RUN_DIR_MODE on $RUN_DIR"
fi

# --- Verification: the only thing the bootstrap below trusts -----------------
#
# Both checks read the path itself, never a target. stat proves type, owner,
# group and mode: %HT is the file type, %Su and %Sg the owner and group by
# name, and %Mp%Lp the setuid, setgid and sticky bits followed by the
# permission bits -- so the comparison is exact: a setgid directory reads 2710
# and is refused along with everything else that is not precisely a directory,
# owned as configured, at the configured mode. ls -lde then proves there is no
# ACL entry, which stat cannot: an entry that survived the strip above --
# re-applied between the two commands, or left by a filesystem that refused
# the removal silently -- is refused like any other difference.
expected="Directory:$RUN_DIR_OWNER:$RUN_DIR_GROUP:$RUN_DIR_MODE"
if ! actual=$(stat -f '%HT:%Su:%Sg:%Mp%Lp' "$RUN_DIR"); then
    fail "could not stat $RUN_DIR"
fi
if [ "$actual" != "$expected" ]; then
    fail "$RUN_DIR is $actual, not $expected; not bootstrapping $AGENT_LABEL"
fi
verify_no_acl "$RUN_DIR"
verified=1

# --- The agent --------------------------------------------------------------

# Already loaded means either this job ran twice, or the agent plist was loaded
# by something other than this job -- from /Library/LaunchDaemons, say -- and
# may have tried to bind its socket before the directory was verified. Neither
# is a state to build on silently. The directory above is correct either way.
if launchctl print "system/$AGENT_LABEL" >/dev/null 2>&1; then
    fail "$AGENT_LABEL is already bootstrapped; this job loads it once per boot, after the directory is verified. If it was loaded from elsewhere: launchctl bootout system/$AGENT_LABEL, then launchctl kickstart system/com.qperiapt.policy-agent-rundir"
fi

if ! launchctl bootstrap system "$AGENT_PLIST"; then
    fail "launchctl bootstrap system $AGENT_PLIST failed; $AGENT_LABEL is not loaded"
fi
log notice "$RUN_DIR is $actual; bootstrapped $AGENT_LABEL from $AGENT_PLIST"
