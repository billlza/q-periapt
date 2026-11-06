# Cleanup, rekey phases and original pending writes

The [phase/causality note](../../../../docs/continuity/CLEANUP_REKEY_CAUSALITY_V1.md)
distinguishes a retained ordinary freezing intent from a failed attempt to close,
and a selected KEM reservation from later root/traffic state. Its narrower stopping
rule is conditional on original flight origins, one authoritative history and
the ordinary pending-write barrier. It does not complete the private-state
simulation or computational secrecy theorem.

The concrete finding is that closing one peer does not generally prevent the
other peer from sending in the target epoch. This rejects an invalid proof
shortcut; it is not a newly discovered violation of the SDK contract. Runtime
sources are unchanged from parent
`932e6e5d5c84efcb2d42fb194cb748c446cde6db`. One existing native test is extended;
the other three tests retain their previous assertions and behavior.

## Actual executions

Four selected tests each pass under Debug and Release, for eight executions:

- `independent_session_closure_fences_pending_rekey_flights_before_and_after_cutover`
  now checks actual sending behavior. After offer-ready proposer closure, the
  responder remains at sending epoch zero. After response-ready responder
  closure, the live proposer accepts the retained response and sends a 137-byte
  epoch-one ciphertext. After final-ready proposer closure, the live responder
  accepts the retained final and sends a 136-byte epoch-one ciphertext. Each
  closed peer rejects reception with `Suspended`. Original report accounting
  and terminal acknowledgements remain checked. The lengths describe these
  distinct synthetic payloads, not a protocol capacity.
- `public_pending_write_recovery_preserves_staged_joint_authorization` covers
  both original Witness application outcomes. The original proposal is closed
  and renewed without losing the staged target, including lost query responses
  before/after application and exact query retry; report acknowledgement completes.
- `public_pending_write_recovery_preserves_original_operation_through_joint_renewal`
  covers the four combinations of policy expiry and original Witness application.
  The original intent and cleanup report survive the required joint renewal.
- `independent_session_closure_every_observed_sync_fault_reconciles_one_transition`
  injects eight failures around four observed sync barriers for beginning closure,
  and another eight for completing it, per profile. The total across both profiles
  is 32 injected schedules. This run adds no SIGKILL or physical power-loss test.

Each selected invocation reports one passed test with 1,460 filtered out. The
complete library suite was not rerun. Rustfmt and strict all-target Clippy pass
with `anchor-tls,control-tls,connection-tls`, locked/offline dependency resolution
and Rust 1.98.1. The original 900-second component bounds and assertions are
unchanged. These local source executions are not installed-package or device
qualification, and their duration is not a resource-budget measurement.

## Retained identity and readback

[VALIDATION.json](VALIDATION.json) records all 14 commands and observed markers,
from 2026-11-06 06:42:13 through 06:51:57 UTC.
[CHECKS.json](CHECKS.json) records the source identities, the unchanged runtime
comparison, both test executables and the capture identity. All 1,155 tracked
native-input entries selected by the driver match before/after validation and
again at capture. That inventory is `crates`, the native candidate and the root
lockfile; it is not a claim to inventory every file on the machine.

Debug executable SHA-256:
`99b60415a0acc82d87f085a7d74e53832b71b4787d99026cae09cf23d07175c8`.
Release executable SHA-256:
`f3841c9f2c02af751e9d8423068ecbbf5800b118de8bf1e91f3a9b35579d4999`.
The driver checks each executable before and after every selected test; capture
checks them again. The executables remain in the local build directory.

[CAPTURE.zip](CAPTURE.zip) has 68 members, 267,883 bytes, SHA-256
`afaf942343be5d6664f0d9b5d6ab62fef57efc604d18853484f05376b335bc0a`.
It contains command receipts, stdout/stderr, exact markers, native-input hashes,
the test patch, relevant source snapshots and validation/retention drivers.
Every member was reread against [FILES.json](FILES.json). The capsule does not
contain native executables, private toolchains or separately exported public
protocol/report bytes. Archive hash validation is not an independent native
execution or public-wire replay.

The unchanged source model `multi-epoch.spthy` is captured with SHA-256
`78aaca97033b6a5ff470991883d1e36ad881a95e16ef6bd9f7c146e51e83ea0b`.
No Tamarin process ran in this checkpoint. The existing checked MAIN certificate
and its dependencies retain their separate recorded identities and scope.

The private-state bridge, permitted acquisition/failure cases, cleanup MACs,
shared-root/AEAD composition and full computational theorem remain open. Current
package qualification still uses its separately pinned `5678d101` source.
Final contract/ABI admission, platforms, declared resource budgets, external
security review and the authorized release transaction remain separate gates.
