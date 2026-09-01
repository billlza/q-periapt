# Policy-agent OS-level isolation contract

This directory holds the deployable OS-enforcement layer for the reference
`serve-agent` daemon. The daemon binary enforces filesystem-capability and
cryptographic boundaries by itself (descriptor-pinned exact-`0700`/`0600`
paths, macOS extended-ACL rejection, pinned ML-DSA-65 peer keys, the
mandatory witness, and the exclusive instance-lease authority). Everything at
the kernel/service-manager level — dedicated uid, syscall filtering,
read-only OS view, private `/tmp`, no core dumps — is enforced by the
templates here, not by the binary, so a deployment that starts the binary any
other way does not get those guarantees.

## Layers and who enforces them

| Boundary | Enforced by | Where |
| --- | --- | --- |
| Owner-only service/config/socket paths (`0700`/`0600`, `O_NOFOLLOW`, descriptor-pinned) | daemon | all platforms |
| macOS extended-ACL rejection on protected paths | daemon | macOS |
| Pinned-key mutual authentication (IPC, witness, authority) + replay windows | daemon | all platforms |
| Exclusive key-use instance lease; fenced instances erase in-process secrets | daemon + authority server | all platforms |
| Dedicated locked non-login account, owner-only umask, no core dumps | service manager | `q-periapt-policy-agent.service`, `com.qperiapt.policy-agent.plist` |
| Read-only OS, private `/tmp`/`/dev`, hidden `/proc`, no home, single writable state tree | systemd | Linux only |
| `NoNewPrivileges`, empty capability bounding set, no SUID/SGID, no new namespaces, W^X memory | systemd | Linux only |
| Seccomp syscall filter (`@system-service` minus `@privileged`/`@resources`) | systemd | Linux only |
| Socket-family and localhost-only IP restriction | systemd | Linux only |

## Explicit non-claims

- launchd has no seccomp equivalent, and App Sandbox requires a signed,
  entitled bundle; the macOS template therefore provides uid separation and
  resource hygiene only. Do not represent it as an App Sandbox, hardened
  runtime, or code-signing attestation.
- Neither template defends against a hostile root, a hostile kernel, or
  hostile code already holding the authorized IPC client signing key.
- The service manager must guarantee the previous process is gone and remove
  a stale `agent.sock` before restart; neither the daemon nor these templates
  guesses that an existing socket is safe to unlink.
- These are reviewed deployment templates, not measured attestations: no gate
  in this repository verifies that a production host actually loaded them.
  Treat host provisioning as release evidence to be captured per deployment.

## Provisioning order (both platforms)

1. Create the dedicated locked, non-login service account and its private
   primary group.
2. Create the `0700` service, state, and configuration directories owned by
   that account; install the exact-length owner-only configuration files
   (migration/recovery roots, endpoint identities, signed policy bundles,
   IPC/witness/authority keys, pinned authority wire identity).
3. Provision the repository, witness, and authority stores explicitly
   (`StateRepository::provision_new`, `ReferenceWitnessServer::provision`,
   `ReferenceAuthorityServerV3::provision`), then bind the repository with
   `StateRepository::provision_authority_binding` to that authority's actual
   epoch, projected head, endpoint identities, and configuration. The runtime
   never bootstraps a missing store or invents a binding. If the process exits
   after the fresh V3 repository transaction but before binding, the migration
   command below is the only executable finalize path: it requires the actual
   pristine authority and holds both exclusive stores through the binding.
4. For a legacy V1 repository, stop every server and run exactly
   `migrate-agent-repository-v1-to-v3 REPOSITORY AUTHORITY_DATABASE CONFIG_DIRECTORY`.
   The command admits only an actually pristine authority store for V1 or an
   unbound fresh V3 repository; on an already-bound V3 repository it locks and
   validates both current stores. It is not a V2 compatibility decoder.
5. Host the witness and the instance-lease authority outside the agent
   host's rollback/restore domain, or their rollback protection is void.
6. Install the template, adjust paths/endpoints, and start the service. The
   agent acquires the exclusive instance lease at startup and fails closed
   while another unexpired instance holds it.
