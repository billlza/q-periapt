# Independently implemented exact pending-write recovery

The Python/OpenSSL reference now implements preparation, complete public views
and exact confirmation for the native candidate's privileged pending-write
recovery contract. The [host contract](../../../continuity-openssl-peer/PENDING_WRITE_RECOVERY.md)
describes the independent controller boundary and original-state requirements.
It closes the tested ordering gap where an unapplied ordinary write outlives its
witness credential and prevents a separately valid G/T renewal from starting.
A grant still cannot overwrite that write.

Preparation is read-only: it authenticates the original source and sealed target,
produces the canonical 393-byte proposal and complete bounded public metadata,
and signs purpose 26 without Advance. A separate native fixture controller
retains approval before invoking the genuine witness completion API. Historical
device signatures, ordinary handler requests and a still-live authority cannot
use that exception. Confirmation always uses a fresh signed Query requiring the
exact target and original ordinary Advance command ID, then publishes the
original sealed bytes. It does not reseal or restore expired output permission.

Five profiles pass: unapplied original write, already-applied lost result,
expired original policy, reentrant cancellation during Query, and a second
pending write after renewed traffic/rekey. They use 164 fresh worker operations,
858 native commands, 747 verified signed witness replies and 26 actual SIGKILL
cuts. Five boundaries cover Query, staged head, published head, removed intent
and confirmation completion. The second cycle also loses the committed head
result. Original unknown delivery and Reserved message identity survive into
same-session authenticated consumption, rekey and new traffic when renewal
permits. Policy-expired recovery alone cannot start a new renewal.

The complete first metadata is 25,574 bytes; after renewal/rekey it is 79,986
bytes. Both views have four ordered projected records. Public readback decodes
all fields, verifies the original bootstrap, root-authorized histories, current
authority, retained ciphertext identity and digest, and exact reservation.
Native inspection accepts those same views. A recomputed outer hash cannot hide
an unknown record tag. A plausible locally MAC-bound ordinary intent cannot
relabel a joint-renewal head: the fresh witness last-command identity rejects it.
Already-applied recovery is confirmed without a successful controller approval.

All seventeen final entrypoints and nine public readers pass with an exact
85-file source closure. The 725-file Rust census is unchanged. Strict native
release build, all-target Clippy with `-D warnings`, format check, actionlint,
76 Python AST parses and diff checks pass. Native ARM64 executable SHA-256:
`2806fae5faad22c4412a87167cd0030367fb5a5013508b700c9b8c32e9dd301f`.
The new protocol/recovery/view modules have 85/133/83 lines; fixture and scenario
orchestration are separate. Ordinary session state and crypto domains remain.

Two unsuccessful harness invocations are preserved: one entrypoint imported the
provider too early; another counted a deliberately rejected malformed approval
as successful. The latter had already passed the unapplied profile and stopped
after the already-applied profile's actual operations. Repairs fix import order
and require status 1 when counting approvals. An additional deterministic XOR
replaces a potentially identical byte in the malformed-metadata control.
A public-only reader initially assumed a 32-byte device field; the actual wire
contract uses 16. Both failed readback diagnostics and corrected decoder are
retained. None of these repairs changed the protocol implementation or relaxed
its acceptance rules. Failed private states were kept, without reset/recreation.

`CAPTURE.zip` is 52,167,354 bytes with 15,979 members, SHA-256
`5c0a9fc171db2a99dd2b3c0f63701d03354b7921cc509d44ad396748dcefece7`. It contains the final public transcripts, failed
invocations, earlier prototype summaries, frozen sources, native executable,
readers and verified manifest. Private storage and signing/wrapping keys are
excluded and remain in their original local fixture directories.

Public verification does not decrypt private images or independently rederive
their MACs; exact sealed-target and unchanged-state checks remain runtime
observations. Projected IDs and `QPIRHS01` histories are reference objects, not
native database rows. The structural inspector leaves public histories opaque;
the readback separately checks this reference history against its pinned roots.
Fixture approval is not deployed account authentication. Native traffic uses
time 170 while the independent owner/witness cross signed expiry. Whole-peer
lifecycle, same-account coordination, installed/deployed enrollment and root/
witness/policy/device replacement, power-loss/erasure, resource/energy bounds,
full retained-state PCS/refinement, final ABI/integration and user-owned external
review remain open. This is not full 0.2.0 release admission.

[Hosted Linux qualification](../20261018-hosted-independent-pending-recovery-linux/README.md)
now verifies the exact committed 17-entrypoint/9-reader cohort. Its Apple Silicon
job remains separately pending; no full platform conclusion is implied.
