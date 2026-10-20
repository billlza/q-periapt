# Independent exact pending-write recovery

Status: reference implementation of the unpublished candidate contract. This is
not a deployed account-authentication service or final 0.2.0 admission.

`peer.pending_recovery.PendingWriteRecovery` implements the device side of
[exact ordinary write recovery](../continuity-identity-candidate/PENDING_WRITE_RECOVERY.md)
with independent Python/OpenSSL cryptography, journal decoding and recovery
logic. It uses the original scope, wrapping key, historical bootstrap context,
retained local authority and independently pinned witness.

## Host sequence

1. Open `PendingWriteRecovery` on the original journal. `request()` reads the
   authenticated source and ordinary `QPREFI01` target without issuing Advance
   or writing local state. Retain the returned proposal, complete metadata and
   purpose-26 signed request. Request retries preserve the proposal and metadata;
   the randomized device signatures may differ.
2. A controller independently authenticates the account and intended effect,
   inspects both complete views, and durably retains its exact approval. The
   historical device signature is insufficient approval. The native witness
   control API completes only that original write; the ordinary device endpoint
   rejects this format.
3. `confirm(proposal, metadata)` obtains a fresh signed Query. Both the target
   head and original ordinary Advance command must match before the original
   sealed target is published and its intent removed. A privileged controller
   response cannot substitute for this Query. Retry the same retained inputs
   after a lost response or process interruption.
4. Continue the existing credential renewal with independent G/T approval.
   Confirmation alone leaves expired runtime and output access denied.

An already-applied original Advance requires only exact Query confirmation; no
new independent approval is needed. A missing local intent alone proves nothing:
confirmation requires the exact authenticated target, original intent commitment,
full target view and fresh witness history. An intervening renewal or ordinary
write conflicts even if a caller reconstructs a plausible local intent MAC.
If the original source image has already been replaced, `request()` refuses to
invent its metadata. Continue with the previously retained request; do not
recreate the source or reset the journal.

## Representation and bounds

The byte contract is the same 393-byte `QPWRPL01` proposal and bounded 8 MiB
`QPWRMD01` metadata used by the native controller. The reference projects its
single bootstrap, optional session and retained account histories into the
existing public retired-report grammar. Record IDs are deterministic hashes of
the original journal correlation, session or account. These are projections of
authenticated reference objects, not native database row identifiers.

Both views include unknown ciphertext identities and digests, unconsumed lengths,
consumed holes, reserved message identity and lengths, epoch floors, rekey
progress and complete retained public authority histories. They contain no
plaintext or private keys. Account linkage, message IDs and lengths remain
sensitive host metadata. The reference supports reusable bootstrap authority;
it does not advertise unsupported one-time-prekey or fanout records.

Roster history uses the distinct `QPIRHS01` tag with its original/current public
credential identity, public key, validity and complete `IdentityState` encoding.
Separate-account views retain that exact representation. A common account uses
one roster record and one authority reference per object, rather than two roster
records with the same account-derived ID. Its `QPIRHS02` history contains the
original root key, family, policy, both original role bindings and rosters, and
length-prefixed canonical `AccountState` and `AccountRecord` bytes. The complete
grant collection and durable renewal outcome are retained; a role projection or
collection hash alone is insufficient. Original role fields include device,
generation, original checkpoint, credential/key/validity and current
credential/validity. The two fixed roles are encoded local first, peer second.
The common state can also be derived from an unadvanced original version-five
session without mutating it. The public-view record-order, collision and
eight-MiB bounds remain unchanged.
The native structural inspector deliberately preserves those bytes as opaque
public history. Domain verification against independent trust and approval of
the business effect remain controller responsibilities. Structural inspection is
not proof that an untrusted request describes its encrypted storage truthfully.

Only an ordinary authenticated intent is accepted. Typed renewal/cancellation
intents, inactive creation, changed policy/authority and missing storage retain
their separate flows. One owner serializes operations and refuses reentrant
work. Closing it during a Query withholds the result and retains the original
local files for explicit recovery.

## Qualification and control-plane boundary

`pending_recovery_checks.py` uses a genuine native `AnchorStore` and original
native session, with a separate privileged fixture controller. Controller command
36 validates and retains an exact approval; command 37 requires that approval
and invokes the real native completion API. The device endpoint never approves
itself. Only the metadata approval command has an 8 MiB frame allowance; normal
control messages retain the existing 32 KiB bound.

Five profiles cover an unapplied write, an already-applied lost result, expired
policy, cancellation during Query and recovery again after two chained renewals.
They retain unknown delivery and original Reserved work across five process-loss
boundaries, then resume the original ciphertext and complete authenticated
consumption, same-session rekey and fresh traffic when current renewal permits.
The second cycle exercises metadata larger than the ordinary control frame.
Malformed framing, noncanonical fields, an unknown record with a recomputed
commitment, wrong signature purpose, live-authority special completion and a
renewal head relabeled as an ordinary write must all fail explicitly.

`shared_pending_checks.py` adds three- and 32-device common accounts, including
an already-applied lost result and two complete account renewals on the original
installation. It parses both role bindings and the complete signed common
history, and requires the native inspector to see exactly three records per
established-session view. Each profile crosses eight actual process cuts;
confirmation uses five fresh Queries per cycle without issuing a mutation.
A fourth profile starts with all 2,031,616 business bytes and 123 outboxes.
A genuine native-consumption ACK creates its interrupted shrinking write.
After expiry, exact recovery removes that acknowledged row and preserves the
old epoch and surviving ciphertexts. Its second complete metadata is 2,031,260
bytes, within the unchanged eight-MiB bound. The same business-fill helper
serves the local-only capacity regression.

The common-account witness clock advances through 170/210/250/310. The native
responder's enrollment is not renewed in these profiles, so resumed independent
ciphertext is replay-checked locally; these checks do not claim bilateral native
traffic after both original credentials expire. The separate-account scenarios
above retain their existing native traffic/rekey evidence.

The test clock advances the independent owner and witness through expiry; the
native traffic counterpart retains fixture time 170. This isolates recovery and
renewal interoperability. It does not establish both devices' complete lifecycle,
deployed enrollment/controller authentication, actual power-loss durability,
physical erasure, attacker eviction or post-compromise secrecy.
