# Policy-agent OS-level isolation contract

This directory holds the deployable OS-enforcement layer for the reference
`serve-agent` daemon. The daemon binary enforces filesystem-capability and
cryptographic boundaries by itself (descriptor-pinned exact-`0700`/`0600`
paths, macOS extended-ACL rejection, pinned ML-DSA-65 peer keys, the
mandatory witness, and the exclusive instance-lease authority). Everything at
the kernel/service-manager level — dedicated uid, syscall filtering,
read-only OS view, private `/tmp`, no core dumps, and the listening socket's
own existence, ownership and mode — is enforced by the templates here, not by
the binary, so a deployment that starts the binary any other way does not get
those guarantees. Since the binary refuses to start without an activated
listener, starting it any other way now fails closed rather than serving a
weaker socket.

## Layers and who enforces them

| Boundary | Enforced by | Where |
| --- | --- | --- |
| Owner-only service/config/state paths (`0700`/`0600`, `O_NOFOLLOW`, descriptor-pinned) | daemon | all platforms |
| IPC socket existence, owner, group and mode (`0660`, daemon owner, client group) | service manager | `q-periapt-policy-agent.socket`, `com.qperiapt.policy-agent.plist` |
| Socket parent directory `0710` — the enforced admission boundary — under ancestors only root can write | tmpfiles.d on Linux; a root `RunAtLoad` job on macOS | `q-periapt-agent.tmpfiles.conf` (Linux; `/run` is a tmpfs); `com.qperiapt.policy-agent-rundir.plist` running `qperiapt-agent-rundir.sh` (macOS; the directory lives under root-owned `/opt/qperiapt/run`, which persists, so the job verifies every ancestor and the directory itself, and is also what loads the agent — see the macOS layout below) |
| Refusal to serve without a matching activated listener; no self-bind fallback | daemon | all platforms |
| macOS extended-ACL rejection on protected paths | daemon | macOS |
| Pinned-key mutual authentication (IPC, witness, authority) + replay windows | daemon | all platforms |
| Exclusive key-use instance lease; fenced instances erase in-process secrets | daemon + authority server | all platforms |
| Dedicated locked non-login account, owner-only umask, no core dumps | service manager | `q-periapt-policy-agent.service`, `com.qperiapt.policy-agent.plist` |
| Read-only OS, private `/tmp`/`/dev`, hidden `/proc`, no home, single writable state tree | systemd | Linux only |
| `NoNewPrivileges`, empty capability bounding set, no SUID/SGID, no new namespaces, W^X memory | systemd | Linux only |
| Seccomp syscall filter (`@system-service` minus `@privileged`/`@resources`) | systemd | Linux only |
| Socket-family restriction, and deny-by-default egress with a deployment-supplied allowance | systemd | Linux only |

## Explicit non-claims

- launchd has no seccomp equivalent, and App Sandbox requires a signed,
  entitled bundle; the macOS template therefore provides uid separation and
  resource hygiene only. Do not represent it as an App Sandbox, hardened
  runtime, or code-signing attestation.
- Neither template defends against a hostile root, a hostile kernel, or
  hostile code already holding the authorized IPC client signing key.
- The daemon cannot verify the socket's owner, group, or mode. An `AF_UNIX`
  descriptor names a socket object rather than the filesystem node addressing
  it, so `fstat` on the inherited descriptor reports a different inode and mode
  than the path does, and `fchmod` on it fails. Those permissions rest entirely
  on the templates here; the daemon's own enforced admission boundary is the
  parent directory's mode. This is why `SocketMode=` is written out explicitly
  rather than left to systemd's default, which is `0666`.
- The socket's lifetime belongs to the service manager, not to the daemon and
  not to an operator. The daemon never unlinks a path it did not create and
  never infers that an existing socket is dead, and nothing here removes one
  with `rm -f` or an `ExecStartPre`: the socket unit owns the node across
  restarts on Linux, as does the launchd `Sockets` entry on macOS.
- **On macOS the socket's parent directory is verified at boot by the shipped
  run-directory job, and that job is also the only thing that loads the
  agent.** launchd has no `tmpfiles.d` equivalent: it creates the
  `SockPathName` node itself and will not create the directory containing it,
  and that directory's `0710` mode is the daemon's only enforced admission
  boundary. The directory is `/opt/qperiapt/run/qperiapt-agent`, not anything
  under `/private/var/run`, and the reason is the parent rather than the
  boot-time clearing. On macOS `/private/var/run` is `root:daemon 0775` with no
  sticky bit, and accounts whose primary group is gid 1 exist by default.
  `rename(2)` and `rmdir(2)` need write permission on the directory that holds
  an entry, not ownership of the entry, so any gid-1 process could rename a
  verified `qperiapt-agent` directory away and put its own directory, or a
  symlink, at the path — between the job's verification and its
  `launchctl bootstrap`, or at any time after. launchd would then bind
  `SockPathName` inside a directory that account controls, and the daemon would
  adopt the descriptor on the strength of the bound path string alone, because
  a descriptor cannot show it the parent's mode. `/opt/qperiapt` already has to
  be root-owned and writable by nobody else (whatever sits at the script path
  runs as root), so under it nothing but root can rename or replace anything
  on the socket's path; and `/opt` persists across boots, so the job verifies
  rather than recreates. `com.qperiapt.policy-agent-rundir.plist` runs
  `qperiapt-agent-rundir.sh` as root at boot: it verifies with `stat`, on each
  path itself and never a target, that every ancestor from `/` down is a real
  directory owned by root that group and other cannot write; creates the
  directory the first time or adopts it every time after; and verifies that it
  is a real directory owned by the daemon account with the transport group at
  exactly `0710`. Only then does it run `launchctl bootstrap system` on the
  agent plist. A directory at a default mode would leave the daemon starting
  normally with no boundary at all, so nothing short of that verification
  reaches the bootstrap: a symlink or file anywhere on the path is refused
  untouched, a directory the run created and could not verify is removed
  again, an agent that is already loaded is reported rather than built on, and
  every refusal leaves the agent unloaded. What is still not claimed: that a
  host installed the job or kept the agent plist out of
  `/Library/LaunchDaemons` (there launchd loads it on its own, unordered
  against the job, which is why the layout below puts it elsewhere); that the
  names in the script and the numeric uid/gid in the agent plist were
  templated from the same account and group; that a failed run is noticed — it
  is written to `/private/var/log/qperiapt-agent-rundir.log` and the unified
  log, and not retried until the next boot or a `launchctl kickstart`; or
  anything against a hostile root, who owns every ancestor the job checks and
  can substitute whatever it likes at any time.
- These are reviewed deployment templates, not measured attestations: no gate
  in this repository verifies that a production host actually loaded them, the
  macOS run-directory job included. The crate's tests check only that the
  shipped files agree with each other and with the daemon's code. Treat host
  provisioning as release evidence to be captured per deployment.

## Provisioning order (both platforms)

1. Create the dedicated locked, non-login service account and its private
   primary group.
2. Create the `0700` service, state, and configuration directories owned by
   that account; install the exact-length owner-only configuration files
   (migration/recovery roots, endpoint identities, signed policy bundles,
   IPC/witness/authority keys, pinned authority wire identity). Each server
   direction needs its own verification key alongside its signing key
   (`ipc-server-vk.bin`, `witness-server-vk.bin`): startup refuses a signing key
   that does not match the one clients were told to pin, so installing a valid
   but wrong key fails at start rather than after the first committed state
   change.
3. Create the transport group and add each authorized client account to it.
   Membership grants the ability to connect, and nothing more: executing a
   protected operation still requires the pinned IPC client signing key.
   Provision the socket's parent directory so that group can traverse but not
   write it — on Linux, `0710` owned by the daemon account with the transport
   group. Install the shipped `q-periapt-agent.tmpfiles.conf` as
   `/etc/tmpfiles.d/q-periapt-agent.conf` rather than creating the directory by
   hand: `/run` is a tmpfs, so it is recreated on every boot, and without that
   entry systemd makes it on demand as `0755 root:root`. That directory mode,
   not the socket's own, is the admission boundary the daemon can actually rely
   on. **On macOS install the shipped run-directory job instead.** launchd
   creates only the `SockPathName` node, never its parent, and
   `/private/var/run` — where a boot-cleared directory would naturally go — is
   `root:daemon 0775` without the sticky bit, so a gid-1 process could rename
   or replace the directory under launchd; the socket therefore lives at
   `/opt/qperiapt/run/qperiapt-agent`, in the root-owned tree that holds the
   binary. Create `/opt/qperiapt/run` as `root:wheel 0755` with the rest of
   that tree. `com.qperiapt.policy-agent-rundir.plist` runs
   `qperiapt-agent-rundir.sh` as root on every boot: it verifies with `stat`
   that every ancestor of that directory from `/` down is a real directory
   owned by root that group and other cannot write, creates or adopts the
   directory as `0710` owned by the daemon account with the transport group,
   verifies that too, and only then bootstraps the agent job — the layout is
   in the macOS section below. Set `RUN_DIR_GROUP` at the top of the script to
   the transport group you created; the directory, mode, daemon account and
   agent plist path already match the agent plist, and the crate's tests hold
   them to it and hold the directory out of `/var/run`. A directory at a
   default mode, or one another account could rename out from under launchd,
   would leave the daemon starting happily with no admission boundary at all,
   which is why the script refuses to load the agent on anything short of an
   exact match all the way down.
4. Provision the repository, witness, and authority stores explicitly
   (`StateRepository::provision_new`, `ReferenceWitnessServer::provision`,
   `ReferenceAuthorityServerV2::provision`); the runtime never bootstraps a
   missing store.
5. Host the witness and the instance-lease authority outside the agent
   host's rollback/restore domain, or their rollback protection is void.
   On Linux this requires the drop-in described in
   `q-periapt-policy-agent.service.d/10-endpoints.conf.example`: the base unit
   denies all egress and ships no allowance, so the endpoints and the matching
   `IPAddressAllow` entries are both deployment-supplied and must agree. The
   unit deliberately does not default to localhost, because that would make the
   only topology satisfying this requirement unreachable while appearing to
   work. Co-locating them behind a protected local relay is a valid choice, but
   it voids this rollback claim and has to be recorded as an accepted risk.
6. Install the templates, adjust paths/endpoints, and enable the socket, not
   just the service: the daemon adopts a listener it is handed and refuses to
   start without one, so a service enabled on its own fails closed rather than
   binding a socket of its own. On Linux enable `q-periapt-policy-agent.socket`;
   on macOS the `Sockets` dictionary in the agent plist covers it, and the plist
   is loaded by the run-directory job rather than by launchd's own scan of
   `/Library/LaunchDaemons`. The agent then
   acquires the exclusive instance lease at startup: it waits for a crashed
   predecessor's lease to lapse (step 7) and fails closed only while a holder
   that is still renewing has it. Before that acquire it settles the
   lease-intent journal in its own store: receipts a previous instance was
   killed before acknowledging are acknowledged then, so the authority's
   bounded receipt table is reclaimed across restarts without any operator
   step. A start that finds all 64 journal rows unanswerable -- the authority
   unreachable after that many unclean stops -- fails closed until the
   authority answers; it is not a store fault and needs no re-provisioning.
7. Stop and restart only through the service manager. A stop delivers
   `SIGTERM`; the daemon observes it within one second, erases its in-process
   secrets, releases the instance lease, and exits 0, so the start that follows
   acquires immediately. Leave `Restart=no` and `KeepAlive=false` as shipped:
   the socket unit and the launchd `Sockets` entry start the daemon on the next
   client connection, and that is also how a crash is recovered -- the new
   process waits for the crashed one's lease to lapse (at most the authority's
   lease TTL, 10 seconds to 5 minutes, plus a five-second margin) and then
   serves, without operator action, subject on Linux to systemd's start rate
   limit. systemd's default `TimeoutStopSec` of 90 seconds is ample: the stop
   is observed within one maintenance interval and the release is one bounded
   authority round trip of at most 5 seconds. The daemon does not log; the exit
   status is the only record of a stop or of a refused start.

## macOS layout

launchd loads every plist in `/Library/LaunchDaemons` at boot with no ordering
among `RunAtLoad` jobs, so the agent plist cannot live there: it would be
loaded whether or not the run directory has been verified yet, and its socket
bound — or not — before the boundary has. The shipped layout keeps exactly one
plist where launchd scans, and that job is the only thing that loads the agent.

| Shipped file | Install as | Owner and mode |
| --- | --- | --- |
| `com.qperiapt.policy-agent-rundir.plist` | `/Library/LaunchDaemons/com.qperiapt.policy-agent-rundir.plist` | `root:wheel`, `0644` |
| `qperiapt-agent-rundir.sh` | `/opt/qperiapt/libexec/qperiapt-agent-rundir.sh` | `root:wheel`, `0644` — it runs through `/bin/sh` and needs no execute bit |
| `com.qperiapt.policy-agent.plist` | `/opt/qperiapt/launchd/com.qperiapt.policy-agent.plist` | `root:wheel`, `0644` |
| — | `/opt/qperiapt/run` | `root:wheel`, `0755` — the socket directory's parent; the job verifies it and refuses to create it |

`/opt/qperiapt` and everything under it must be root-owned and writable by
nobody else: whatever sits at the script path runs as root at every boot, and
the socket directory's whole ancestry is what keeps it the directory launchd
binds into. The socket directory itself is `/opt/qperiapt/run/qperiapt-agent`,
and not under `/private/var/run`, which on macOS is `root:daemon 0775` with no
sticky bit: `rename(2)` in a directory you can write needs no ownership of the
entry, so a gid-1 process there could swap a verified directory for its own, or
for a symlink, at any moment, and neither launchd nor the daemon would notice.
Then `sudo launchctl bootstrap system
/Library/LaunchDaemons/com.qperiapt.policy-agent-rundir.plist`, which also runs
the job once, so the agent comes up without a reboot. On every boot after that
launchd runs the job again — `/opt` persists, so it finds the directory it made
and verifies it rather than recreating it — and it:

1. refuses unless it is root on macOS, and unless the agent plist is a regular
   file outside `/Library/LaunchDaemons`;
2. verifies every ancestor of the socket directory — `/`, `/opt`,
   `/opt/qperiapt` and `/opt/qperiapt/run`, in that order — with `stat` on the
   path itself: each must be a real directory (a symlink is refused before
   anything below it is looked at), owned by root, with no group or other
   write bit; a missing one is a refusal too, because the job creates nothing
   whose parent it has not verified;
3. refuses a symlink or a non-directory at `/opt/qperiapt/run/qperiapt-agent`
   without touching it; creates the directory if absent (`mkdir` without `-p`,
   under `umask 077`, so it is never wider than `0700` before the chmod) or
   adopts an existing real directory, which it never removes;
4. `chown`s and `chmod`s it, then verifies with `stat` — on the path itself,
   not a target — that it is a directory, owned by the daemon account and the
   transport group, with mode exactly `0710`; a setgid or sticky bit fails
   this like any other difference, and a directory this run created and could
   not verify is removed again;
5. refuses if the agent is already bootstrapped, which means something other
   than this job loaded it, possibly before the directory was verified;
6. runs `launchctl bootstrap system` on the agent plist.

A refusal at any step exits non-zero and leaves the agent unloaded, with the
reason in `/private/var/log/qperiapt-agent-rundir.log` and in the unified log
under the `qperiapt-agent-rundir` tag. `KeepAlive` is false, so a failed run
is not retried until the next boot or a
`sudo launchctl kickstart system/com.qperiapt.policy-agent-rundir`. Taking the
agent down by hand is `sudo launchctl bootout system/com.qperiapt.policy-agent`;
bringing it back goes through the same kickstart, so it never comes up without
the verification.
