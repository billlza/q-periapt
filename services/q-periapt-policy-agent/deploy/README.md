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
| Socket parent directory `0710` — the enforced admission boundary | tmpfiles.d | `q-periapt-agent.tmpfiles.conf` (Linux; `/run` is a tmpfs) |
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
- These are reviewed deployment templates, not measured attestations: no gate
  in this repository verifies that a production host actually loaded them.
  Treat host provisioning as release evidence to be captured per deployment.

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
   on.
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
   on macOS the `Sockets` dictionary in the plist covers it. The agent then
   acquires the exclusive instance lease at startup and fails closed while
   another unexpired instance holds it.
