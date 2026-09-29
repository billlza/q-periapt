# Explicit resolution of closed epoch outcomes

This is a candidate application contract, not a delivery-success claim. A finite
old-chain disclosure can leave a genuine sender outbox behind a poisoned peer
consumption floor. Fresh epochs isolate new traffic, but the old outbox can never
obtain an admissible acknowledgement. Retaining it forever eventually exhausts
bounded history. Clipping the poisoned ACK or declaring the outbox delivered
would hide the unresolved application outcome.

The v4 rekey profile therefore permits a closed prefix to be *settled*: either
drained by ordinary consumption/ACKs, or explicitly reported to and acknowledged
by the local application through the protocol below. Both first rekey flights
sign this changed contract. Earlier profiles are rejected; no automatic fallback
or timeout performs this operation. The published SDK and ABI 2 are unchanged.

## Two durable application steps

`begin_closed_epoch_resolution(context, session, epoch, now)` is an explicit,
irreversible stop for an already closed old traffic epoch. The sending and
receiving cutovers must both be committed. It is refused during a local pending
rekey, so existing signed assertions cannot change meaning. Current policy,
roster and required-witness authorization apply before commit and release.

The journal freezes the epoch and commits an immutable resolution ID before
returning its report. The report includes exact unconfirmed message IDs and
ciphertext digests, retained unconsumed plaintext, skipped indices, prior consumed
and acknowledged floors, observed counts, and the identity-signed peer close
count. A receive hole is not asserted to contain an honest message. Retained
plaintext was authenticated under the old epoch; resolution does not restore its
authenticity after compromise. Report ownership erases its plaintext on drop.

While the report is pending, old sends, receives, consumption and ACK operations
cannot alter or release that epoch. New-epoch traffic remains available. Reopening
reconciles the exact write intent and retrieves the same report/ID. An unknown
commit returns no report and closes the journal. There is no cancellation that
reactivates the old keys or reinterprets its IDs.

The application durably records its own decisions and deduplication results, then
calls `acknowledge_closed_epoch_resolution` with the exact epoch and report ID.
The journal commits the acknowledgement and erases the old chain/ACK/skipped
keys, retained plaintext and plaintext-derived intent fingerprints, and removes
the ciphertext outboxes. The report body and its temporary plaintext commitments
also use erasing owners. It retains the original
counters and floors, plus the report ID, until that epoch is collected by a later
signed rekey. Previously unacknowledged sends report `DeliveryUnknown`, never
`Acknowledged`. Their IDs cannot be reused or silently re-encrypted. A repeated
application acknowledgement is idempotent; a different ID conflicts. External
application storage is a separate transaction and must be reconciled by the host.

Only an acknowledged resolution can satisfy local prefix-retirement admission.
Each peer independently accounts for its own unresolved outcomes before signing
the v4 assertion. Such a signature does not assert successful peer delivery or
undo previous effects. A missing final ACK can still use ordinary recovery;
explicit resolution is not the default retry path.

## Identity and stored state

Each new report receives an independent platform-random 32-byte HMAC-SHA256 key.
The key and exact ID are sealed with the pending report, never returned through
the public API, and erased when application acknowledgement commits. If no intent
was committed and no output was released, a retry may generate a new private key;
an existing intent/report always restores its saved key and exact ID.

The resolution ID is HMAC-SHA256 over
`Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/closed-epoch-resolution/v1 || body`.
The key is not an old traffic/ACK key. The canonical body, in order, is:

- session[32], direction:u8, then epoch, send floor, send count, receive floor,
  observed receive count and signed receive limit (six big-endian u64 values);
- outgoing count:u16 and ordered `(ID[32], intent[32], ciphertext_digest[32])`;
- incoming count:u16 and ordered `(ID[32], index:u64, intent[32], consumed:u8,
  plaintext_length:u32, plaintext_digest[32])`;
- skipped count:u16 and ordered indices:u64, without skipped secret keys.

The ciphertext/plaintext digests use the existing length-delimited SHA3-256
function under message-domain suffixes `resolution-ciphertext/v1` and
`resolution-plaintext/v1`, respectively. A public correlation ID must not be an
unkeyed commitment to low-entropy plaintext: the reproduced unkeyed draft lets an
observer test guesses using public frame/counter metadata. The private report key
removes that particular verifier; this assumes the key remains secret and does not
claim privacy under current journal compromise. Possession of an ID grants no
authority. Reports still disclose their intended metadata to their authorized host.

An authenticated image admits three distinct traffic states: ordinary, frozen
report, and acknowledged resolution. Ordinary/frozen states retain the original
receipt coverage invariants; a frozen report must match its commitment. The
acknowledged state instead requires no pending input, receipts or skipped keys
and zeroed traffic/ACK keys with no retained report key. Preserving its original
unacknowledged range is essential: setting the floor to the send count would
invent delivery success.

Journal v18 uses `continuity_device_candidate_v18`, `QPVLT018` and `QPVIMG18`;
message state is `QPMST010`, and each traffic entry is `QPTEPO04`. After the
existing epoch/closed/receive-limit fields, traffic records encode the resolution
phase (0=ordinary, 1=frozen, 2=acknowledged), the 32-byte ID for phases 1/2, and a
0/1 key-presence tag followed by 32 secret bytes only for phase 1. The existing
traffic keys, counters and bounded maps follow. Incompatible earlier
candidate images are refused without reset or implicit migration. Whole-image
rollback still requires the independent witness; logical erasure does not erase
old database pages, intents or backups.

## Verification obligations

The 2026-09-29 fixed Rust 1.98.1 local run passes all 151 release tests. Its
closed-epoch grid measures four sync barriers each for freezing and acknowledging
the report, then exercises all 16 before/after fault cases. Two actual process
kills cover the committed freeze and acknowledgement before return. Required
witness reply loss covers both writes and cached report release. Separate tests
cover immutable replay, missing/wrong/duplicate acknowledgements, old-operation
fencing, fresh traffic, malformed checkpoints, expiry, policy close and persisted
device revocation.

The old-chain counterexample reaches epoch 3 and refuses the next response with
`Capacity`: the genuine send remains unacknowledged and its peer's authentic old
ACK is out of range. After the application fsyncs an explicit unknown-outcome
record and its parent directory, resolution preserves the old acknowledgement
floor and permits fresh epochs through 6 with actual traffic and bounded history.
The unkeyed draft's plaintext-guess regression failed before the private report
key change; the keyed implementation passes. This is a specific reproduced
privacy defect and repair, not a general metadata-privacy proof.

Fixed-toolchain format and strict all-target Clippy, Rust 1.90 all-target
compilation and 45 isolated source-contract tests pass. The independent public
oracle verifies the v4 signed profile and 19 envelopes / 95 negative controls;
the witness oracle checks 12 envelopes / 60 controls. These public checks do not
recompute secret MACs or AEAD, which the real journal tests exercise separately.
Finite implementation tests do not prove continuous PQ recovery. Progress
scheduling, the complete compromise argument, multi-device lifecycle and product
integration remain required.
