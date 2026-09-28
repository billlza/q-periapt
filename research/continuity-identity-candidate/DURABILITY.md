# Encrypted responder journal candidate

`ResponderJournal` connects the actual [bootstrap](BOOTSTRAP.md) to redb. It can
recover a pinned response after its original signing/prekey owners have closed.
This remains an unpublished candidate; it does not complete the 0.2.0 session
store, ratchet or recovery contract.

## Ownership and storage identity

`JournalKey::provision` generates a fresh OS-random 256-bit wrapping key and writes
`QPVKEY01[8] || key[32]` to a new private file without replacing an existing path.
`open` requires that exact existing file and never creates a replacement on error.
The owner has no raw-key export and erases its memory on drop. Keep its file outside
database backups. This provider assumes a trusted same-UID host and supplies
neither a hardware keystore nor per-record cryptographic erasure.

After successful provisioning, retain `JournalIdentity` independently of the
database. Opening requires this expected identity and an independently verified
local device. An incoming database cannot choose its expected identity. The owner
binding hashes account, device ID, generation and credential digest using the
bootstrap `storage-owner` domain. Roster updates can retain this owner; a different
credential/generation cannot silently reuse it. One authoritative journal per
device lineage is a host configuration requirement; a new empty journal is not
recovery.

The candidate reuses `q-periapt-host-store::filesystem` private path admission,
exclusive provisioning and lifetime database locking. Path traversal is descriptor
relative with private mode/owner/ACL checks and no symlink traversal. The shared
backend rechecks the inode/extent **after** acquiring the lock and rejects an
unclean redb file lacking the two-phase recovery flag. Its file limit is 64 MiB and
cache is 2 MiB. The policy store uses this same backend and retains its policy and
commit-uncertainty behavior.

## Sealed encoding

Exactly one table, `continuity_responder_candidate_v1`, and one `image` row are
accepted. The image is:

`QPVLT001[8] || store_id[32] || owner[32] || revision:u64 || nonce[24] || ciphertext || tag[16]`

The 104-byte header is associated data for XChaCha20-Poly1305. The wrapping key and
fresh OS-random 192-bit nonce are not network inputs. Revision is in `1..u64::MAX`,
with the upper bound excluded. The encrypted plaintext is:

`QPVIMG01[8] || count:u16 || records`

Each record is `operation_id[32] || context[32] || phase:u8 || key_count:u8 ||
fingerprints[key_count*32] || payload_length:u32 || payload`.
There are at most 128 records, two one-time claims per record and 2 MiB of plaintext.
Records and fingerprint lists are strictly sorted; duplicate claims fail. No
automatic eviction or counter wrap can reactivate an old one-time key.

Operation ID uses the identity candidate's length-prefixed digest function with
domain `Q-PERIAPT-CONTINUITY-VAULT-OP-CANDIDATE/v1` over context plus complete signed
initial wire. Callers cannot supply an unrelated ID. Each API also checks exact
initial bytes, context and derived claims. Claims use authenticated public-key
fingerprints, so a new signed manifest/epoch cannot relabel a consumed public key.

Executing/rejected records retain the initial wire. Other records hold a private
checkpoint: `QPRCHK01[8] || context[32] || initial[5817] || reply[4633] || root[32] ||
state:u8 || tail`. State 1 has a 32-byte initiator-confirmation key; state 2 has the
exact accepted final[136] and no confirmation key. The crate-private restore path
is used only after image authentication and rechecks both signature components,
lengths, context and transcript relationships. Network input cannot mint this
checkpoint. The public journal returns response bytes or a **public session ID**,
never a raw root or application key.

Encrypted extent, stable store/owner headers and revision remain visible; there is
no padding/unlinkability claim. Zeroizing buffers do not erase encrypted old pages,
backups or all compiler/provider temporary copies.

## Durable transitions

`respond` performs bounded public signature/scope admission, then:

1. Commit `Executing`, the exact initial and one-time reservations.
2. Only after acknowledgement, run the real responder computation once.
3. Commit `Prepared` with the exact private result and response.
4. Commit `AwaitingFinal`, consuming the claims together with the immutable outbox.
5. Recheck policy/lifetime before returning response bytes.

Every write uses immediate durability and redb two-phase commit. The expected
encrypted aggregate digest is compared again inside the write transaction.
Invalid signatures fail before reservation; a definitive cryptographic failure
writes `Rejected` and clears reservations. A different initial claiming a reserved
or consumed one-time public key fails. Exact committed input replays saved bytes
without signing, decapsulation or new KEM randomness.

`finish` validates the real final MAC and commits completion before returning its
public session ID. Invalid final input does not advance storage. Exact duplicates
are idempotent; changed final bytes conflict. Returning bytes is local dispatch
permission, not transport delivery or an application-delivery acknowledgement.

Write failure closes the database lease and wrapping-key owner. `CommitUncertain`
is not absence or success. Reopen under the retained identity and query the same
authenticated input:

| Phase | Recovery |
| --- | --- |
| Absent | Reservation did not survive; no crypto crossed its acknowledgement barrier |
| Executing | Computation may have run: remain suspended, never regenerate it |
| Prepared | Commit the pinned result without rerunning crypto |
| AwaitingFinal | Replay the exact response |
| Complete | Exact final replay returns the same session ID |
| Rejected | Retain the failure; do not reinterpret it as a new operation |

Read-only reconciliation remains available after policy close/expiry. Execution,
dispatch and final acceptance retain their policy/time/runtime checks. A missing,
corrupt or wrong-key database is an error, never the `Absent` result.

## Verification and required follow-through

Real-peer tests cover all four modes, private checkpoint preservation, owner close,
database reopen, exact replay, bad signatures/MACs, wrong key/store identity,
header/ciphertext corruption and cross-manifest public-key reuse. A sampled disk
scan detects plaintext root bytes; it is not a general forensic-erasure proof.
The fault matrix covers six synchronization points across three response commits
both before and after sync (12 cases), four final-confirmation sync failures and
a first-write failure that reconciles to exact absence.

Four separate owned subprocesses are killed after reservation, result pin,
response commit and final commit. Their real files reopen under authenticated
contexts reconstructed from public fixtures. Saved results replay without the
original signing/prekey owners; `Executing` remains suspended. Production builds
contain no test-only post-commit parking hook.

The effect is currently **non-repeatable**: entropy is not yet sealed before
execution. A crash before result pin therefore sacrifices liveness rather than
recomputing. Initiator state, prekey **secret** inventory/erasure, cancellation,
supersession, delivery acknowledgements, per-message state, ratchet/rekey and
multi-device transactions remain implementation work. Logical replay retains the
exact cryptographic result, but reseals an outer aggregate on a retried storage
transition; this is not yet G1's persisted byte-identical write/anchor intent.

Store identity does not detect an older snapshot of the same journal. Old encrypted
pages remain decryptable with the wrapping key. The external monotonic checkpoint,
anchor reconciliation, backup/erasure model and complete wire/state/budget lock
remain required in **0.2.0** before product promotion.
