# Permanent independent session closure

Status: unpublished native candidate. `begin_session_closure`,
`acknowledge_session_closure` and `session_closure_status` close ordinary sessions,
including empty sessions, uncommitted unary input, retained deliveries, committed
fanout members and incomplete rekeys. This is local loss accounting and destruction
of future local authority, not peer revocation, remote deletion, authenticated
remote consumption, device replacement or account-root migration.

## Lifetime and accounting

An established message session starts Open. The caller supplies the original
verified context and session ID. Cleanup checks the journal's owner, exact context,
authority bindings and storage protection without requiring fresh peer permission.
A closed policy or revoked peer does not become permission to send, and does not
prevent local accounting. Required witnesses retain their existing authentication,
availability and rollback assumptions; there is no local-only fallback.

This API requires the original verified context object. The host must retain or
restore that binding across restart; this change does not introduce an archival
context constructor which bypasses current verification time or policy floors.
Restoration when ordinary context verification is no longer admissible remains a
separate product integration requirement. The retained-object cleanup tests do
not establish that missing archival reconstruction capability.

`begin_session_closure` durably changes the whole session to MessagesClosing before
returning metadata. This permanently freezes sends, receive/consume, ACKs and rekey
mutations/releases, including exact old control retransmissions. The existing
source-linked bootstrap fence also blocks cached initial/reply/final release and
reactivation. The caller cannot unfreeze, clear a pending input, invent a dummy
message, refund a budget slot or reset a sequence. Previously returned caller-owned
plaintext/ciphertext and external effects are not recalled by local closure.

The returned `SessionClosure` includes the exact context/session, role and original
peer account/device/generation, rekey progress, every retained epoch's counts,
unknown ciphertext identities, unconsumed inbox IDs/lengths, skipped indices,
prior epoch-accounting state and every reserved ID with plaintext/AD lengths.
There is no plaintext, AD content, plaintext hash, chain key, KEM/signing coin or
control payload. Unseen messages are not invented. Earlier retired epoch history
is not reconstructed. A local observation is not a proof of honest peer behavior.

The application must durably record the **complete** report and reconcile/deduplicate
its external effects by the report ID before acknowledgement. An unknown external
commit stays an application reconciliation problem under that same ID. A report
retry is immutable; it must not repeat the host's external transaction.

`acknowledge_session_closure` atomically replaces private State with a keyless
MessagesClosed record. The same acknowledgement is idempotent; a different report
ID conflicts. Previously acknowledged sends stay Acknowledged. Other committed
sends become DeliveryUnknown; reserved inputs become ReservationAbandoned. A
future or absent ID grants no work. The source/session/one-time tombstones stay;
ordinary `DeviceJournal::close` remains the distinct reversible owner shutdown.

During MessagesClosing, unacknowledged committed sends report ResolutionPending,
except outcomes already covered by earlier acknowledged epoch accounting. Status
queries do not release retained data. Read-only rekey/progress metadata can remain
available while frozen; terminal private-state queries are retired.

## Fanout composition

A session with a pending fanout reservation cannot close independently. Its exact
whole recipient set must use [fanout abandonment](FANOUT_ABANDONMENT.md); individual
closure returns Suspended without changing the aggregate. This prevents breaking
an all-required-recipient reservation into partial completion or loss accounting.

After the aggregate commits, each member session can close independently. The
batch keeps its original committed-message identity. A closed member retains its
actual ACK prefix or unknown outcome; another live member can still reconcile its
already committed unary message. The complete fanout resume cannot release a
partial set when a required session is frozen or terminal. Batch metadata can be
retired only after every member meets the existing accounting/ACK requirement.
Session tombstones remain independently valid after that metadata is removed.

The common terminal codec and epoch-accounting projection serve both closure
paths. No parallel ratchet, KDF, acknowledgement or private-key implementation is
introduced.

## Frozen report and capacity

Every QPMST011 State reserves a fixed 64-byte closure tail at activation. Open and
fanout-frozen states encode canonical zero[64]. An independent frozen state stores
report ID[32] and a fresh private HMAC key[32]. A nonzero key with a zero report is
invalid. The HMAC-SHA-256 domain is the existing messages domain followed by
`session-closure/v1`; its input is journal ID, owner, context, full payload length
as u64, full original private payload prefix and zero[64]. The final tail is
excluded only to avoid including the MAC's own output/key. Every original private
state byte remains authenticated by this report, and all fields are immutable
while frozen. The keyed ID is not a public low-entropy plaintext digest.

Freeze preserves record count and exact encoded payload length. Finalization must
produce a payload no larger than the frozen State. It adds no operation, fanout
slot or outbox item when those storage limits prevent ordinary new work. Revision
or witness-counter exhaustion still fails closed; no counter is reset. This is
an encoded-storage bound, not a promise to recover from process-wide memory
exhaustion. The report key and all private State owners are dropped upon terminal
commit. Historical redb pages, write intents, copied wrapping keys, backups and
caller-owned data are outside this logical-erasure guarantee.

## Storage and protocol identity

Journal v20 uses table `continuity_device_candidate_v20`, outer `QPVLT020` and inner
`QPVIMG20`. Older candidate images fail closed without reset or implicit migration.
MessagesClosing is phase 27; MessagesClosed is phase 28. Existing fanout phases
23–26 keep their meanings. QPMST011 appends the fixed 64-byte tail after Control.

The shared terminal grammar is:

`QPABND02[8] || source[32] || session[32] || batch[32] || report[32] || pending_message[32] || role:u8 || confirmed:u64 || sending:u64 || receiving:u64 || pending_control:option<u64> || count:u8 || epochs`.

Lengths/integers are big-endian. The control option is 0 or 1 followed by u64 only
for 1. Each epoch is `epoch:u64 || sent:u64 || acknowledged:u64 || reserved:u8`,
with reserved exactly 0 or 1. Epochs are consecutive in the existing four-epoch
window, ACK counts cannot exceed sent counts, and progress remains within the
original asymmetric one-epoch bound. Reserved identifies the uncommitted index
`sent` in that epoch; it never turns it into a committed send.

Independent closure encodes canonical zero batch/pending-message fields. Fanout
abandonment requires both nonzero, checks their original binding, and requires its
pending message to match the reserved sending slot. The report is always nonzero.
Trailing bytes, inconsistent origin fields, invalid roles/options/counts and
truncated records are refused. Both paths retain the original bootstrap-linked
session validation after private-state erasure.

QPBNDL01, QPCNET01, QPCCTL01, QPTEPO04, QPCMSG03, v6 rekey controls, cryptographic
KATs and published SDK ABI contracts are unchanged. Device replacement, enrollment,
independent sender-store coordination, installed-language integration, recovery
analysis and current-device/performance qualification remain 0.2.0 work.

## Observed qualification

The final native macOS ARM64 Debug and Release suites each pass 213 tests with no
failures or ignored tests. Seven added tests cover both roles, a real process-killed
message reservation, complete epoch/loss accounting, wrong IDs/contexts, private
frozen-state mutation, retained-context cleanup after revocation/policy close,
incomplete signed controls before and after cutover, committed/partial-ACK fanout
and refusal to split a real reserved fanout. Freeze/finalization retain the same
record count and nonincreasing payload lengths.

Each closure transition has four measured storage barriers: all 16 before/after
faults across both transitions reconcile exactly one state advance. The required
witness has four measured exchanges per transition; all 16 before/after losses
retain original protection and immutable report identity. Two actual process kills
observe committed freeze/terminal markers before API return; a separate competing
process must return Busy within its deadline. Host accounting is fsynced before
terminal acknowledgement, and unrelated member sessions retain their own lifecycle.

The initial full runs each had 210 passes and three failures from stale test-only
end-of-State offsets. Tests now locate and verify the actual serialized Control
range before capture or mutation. Pending-root and epoch mutations still target
those fields rather than the new lifecycle tail. The original decapsulation/KDF
assertions remain; two reservation-disclosure experiments still recover six future
messages each. These finite attacks remain evidence of the earlier recovery limit.

Strict Clippy passes on Rust 1.90/1.98.1, with separate carrier-only checks for the
same library source, no-default compilation, warning-strict docs, fmt and 45 clean
source/isolation checks. Full-suite runner times are 591.800/582.903 seconds under
overlapping load, not a performance comparison. The source, initial failures,
corrected runs and actual test executables are retained. These results do not
qualify installed language bindings, independent hosts/devices, archival context
restoration or the complete protocol/recovery argument.
