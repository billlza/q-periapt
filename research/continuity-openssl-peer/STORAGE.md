# Independent local-only storage and session recovery

This is an unpublished single-session implementation for interoperability work.
It is independent of the Rust protocol state machine and redb image format.
It does not yet implement rekey, witnesses, credential/roster/policy renewal,
revocation, account fanout, installed consumers or a complete installation owner.
Its original verified authority snapshot and trusted time remain explicit inputs.
It is not a replacement product package or a completed security proof.

## Assets and authority

The caller retains the original 32-byte wrapping key and `Scope` before creation.
Scope contains a fresh 32-byte journal identity, a public signing-owner binding
and the original bootstrap context digest. The owner binding is the existing
length-delimited SHA3-256 construction over domain
`Q-PERIAPT-INDEPENDENT-OWNER/v1` and the initiator public pair. The wrapping key is
not saved in the session directory. Test workers use a separate private config
file; no key or private journal image enters the public artifacts.

The identity signing owner remains separate. A session snapshot contains no
ML-DSA or P-256 signing private key. Waiting bootstrap snapshots retain the actual
ML-KEM/X25519 reply key seed and first hybrid secret, plus the exact signed initial.
Restoration checks that the seed reproduces the signed public reply key and that
the saved secret verifies the signed initial confirmation. It never generates a
replacement key to reopen an operation. Restored entropy is not fresh recovery.

Completed snapshots retain both exact signed flights, final confirmation, session
identity and the confirmed root. Traffic activation removes that root field and
installs the five derived traffic/rekey/ACK seeds atomically. Public transcript
bytes remain available for exact reconciliation. Restoring private local state
does not grant output permission: bootstrap replay retains advertisement expiry;
established traffic checks the separate credential, roster and policy windows.
Status exposes dispositions without ciphertext or plaintext and can survive expiry.

## Private file boundary

The session directory is independently supplied, owned by the current UID and
mode 0700. Every path component opens without symlink traversal. A nonblocking
lifetime directory lock excludes other owners; in-process locks serialize the
same owner's methods. Reads and writes recheck the selected directory identity.
Formal files must be private mode-0600 regular files with one link, with bounded
reads and descriptor/path identity checks. Hostile code running as the same user
is not isolated by these permissions.

Plain state is capped at 2 MiB, each file at 2 MiB + 4096 bytes, and new writes
respect 128 directory entries and 64 MiB of retained files. Capacity for both
staged publications is checked before admitting a write intent. Failed staging
files remain private and are not chosen as recovery inputs or swept automatically.
An I/O failure can be an unknown commit; it closes the active owner and requires
reopening the same key, identity and context. It never authorizes a new directory.

## Envelopes and transitions

All integers are big endian. The independent image format is:

`QPREFJ01[8] || scope[96] || revision:u64 || AES-SIV ciphertext/tag`.

The complete 112-byte prefix is AEAD associated data. Revision is positive and
below `2^64-1`. AES-SIV uses a 64-byte HKDF-SHA256 key, with salt=journal identity
and info=`Q-PERIAPT-INDEPENDENT-JOURNAL/v1/image-key/ || scope`. The input key is
the external 32-byte wrapping key. The separate intent key is 32 bytes with info
`Q-PERIAPT-INDEPENDENT-JOURNAL/v1/intent-key/ || scope`.

[AES-SIV](https://cryptography.io/en/48.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESSIV)
supports deterministic authenticated encryption. This local format uses that
mode instead of deriving a nonce from a revision that an uncommitted retry might
reuse for different data. It changes no Continuity network cipher or key schedule.
Unsupported provider algorithms fail explicitly.

The intent is `QPREFI01[8] || prior_revision:u64 || SHA256(prior_image)[32] ||
target_length:u32 || complete_target_image || HMAC-SHA256[32]`. The MAC covers
`Q-PERIAPT-INDEPENDENT-JOURNAL/v1/intent/ || scope || all preceding intent bytes`.
Genesis uses prior revision zero and the all-zero prior digest. Every other target
must name the exact current image and have revision exactly prior+1. Both the
target encryption and its protocol payload are verified before any recovery write.

1. Compare the current authenticated image with the caller's expected digest.
2. Seal the complete target and publish its authenticated intent durably.
3. Publish those exact target bytes as `head`.
4. Remove the intent durably, then acknowledge the transition.

Each publication writes a private exclusive staging file, syncs it, renames it
under the held directory lease and syncs the parent. macOS additionally requests
`F_FULLFSYNC`; an unsupported barrier is an error, not a weaker fallback.
These are OS durability requests, not hardware power-loss qualification.

Unlike redb's atomic row update, this file protocol can legitimately retain both
the exact installed target and its intent after interruption. Recovery removes
that intent without a second increment. If the prior remains, recovery publishes
the saved target. Any other prior/target pair is a conflict; no intent is rebased.

Ordinary open refuses a missing active head. The explicit creation reader can
recover only revision-one genesis, and refuses advanced state. A crash before
formal intent publication can leave only a private staging orphan; creation
recovery then reports missing original intent without guessing or recreating.
The caller's original creation/configuration lifecycle is a precondition; this
primitive does not supply a complete installation manager or migration workflow.

## Protocol records and release

`QPREFS01` encodes the original context and exactly one waiting, confirmed or
traffic phase. Unknown tags/phases, extra bytes, malformed transcripts and wrong
KEM ownership fail. Traffic records validate exact outbox coverage, disjoint
inbox/skipped-key coverage, contiguous consumption, counters, send budget and
the bounded record counts. There is no unbounded allocation from a stored count.

A new send first commits its exact ID, plaintext and AD as a reservation. Only
then does it derive a message key and encrypt. The next chain and immutable
ciphertext outbox commit before release. A retry cannot change the reservation;
resume uses its stored input. Completed outboxes retain the original send-intent
digest and frame, not another plaintext copy. Receive and consumption similarly
commit before plaintext or an ACK is returned. Rejected packets leave the previous
chain/skipped keys intact. While a send is reserved, other mutations must wait
for that original operation, preserving its reserved final-image capacity.

These rules provide SDK consumption accounting, not atomic external application
effects. The host must deduplicate and commit its own effects before consumption.
Same-key backups and old filesystem pages can retain prior secrets. Logical
removal is not cryptographic erasure; consistent whole-store rollback is not
detected by this local-only profile. Python bytes/provider temporaries do not
provide a zeroization guarantee. No completed rekey or post-compromise recovery
claim is made.

## Validation entrypoints

`storage_checks.py` kills real worker process groups at eight write boundaries
for both genesis and update, and checks exact-target/idempotent recovery, lost
acknowledgements, wrong keys/scopes, malformed files, leases, CAS races, conflicting
authenticated predecessors and capacity before intent publication.
Workers run directly under the already admitted isolated Python bootstrap and
the parent's private empty cache prefix. Each cut records the actual worker PID,
which must equal the PID being killed and waited for. Waiting only for a launcher
shell does not establish that a child journal owner's lease has been released.

`durability_checks.py` uses fresh processes for operations against a live Rust
journal. It kills the independent peer after final commit, send reservation, send
commit, ACK publication, receive commit and consumption commit. It recovers the
original ciphertext, plaintext and ACK, verifies retired IDs and expiry, and runs
malformed snapshot controls. The identity signing key is not passed to any worker.
The test clock is explicit: bootstrap at 150, advertisement expiry at 160,
established traffic at 170, authority expiry at 200. Rust process restart,
network/TLS carriers, hardware power loss and the broader lifecycle remain separate.
