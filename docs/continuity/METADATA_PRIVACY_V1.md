# Continuity candidate metadata and privacy boundary

Status: **implementation inventory, not a frozen product privacy claim**. Source
baseline: `e00281ec`, with the formats in [WIRE_V1.md](WIRE_V1.md). The target
authenticates accountable bootstrap/control transitions; it does not promise
anonymous participants, deniable control signatures, hidden device membership,
traffic-analysis resistance or a privacy-preserving directory.

This inventory distinguishes access to ciphertext, protocol endpoints, service
metadata and local private state. No observed public digest, signature or
correlation ID becomes an authority capability merely because it is stable.

## Visible surfaces

| Observer / storage boundary | Data available in the implemented path | Relevant limitation |
| --- | --- | --- |
| Holder of a public bootstrap bundle | Signed role-ordered device credentials/rosters, responder manifest, selected prekey proofs and mode | The bundle is not encrypted and does not conceal accounts, device generations, policy bindings, validity, active roster membership or prekey identities from its holder |
| Authenticated remote endpoint | Bootstrap/control wires, context/session/profile commitments, identities, roles, prekey choices, epoch/sequence counters, authenticated payload after receive | TLS authentication does not reduce the peer's protocol visibility; the intended peer receives the application plaintext |
| Ordinary observer of the SDK TLS carrier | Addresses, connection timing/duration, record lengths and traffic pattern | QPCNET01/QPCCTL01 bodies travel inside the standard TLS connection; no traffic padding, anonymity network or cover-traffic mechanism is implemented |
| Witness and observer of the native witness TCP path | Witness binding, journal/owner/policy subject, full heads, command IDs, challenges, signatures, result classes and timing | The current witness carrier authenticates signed messages but does not encrypt them; deployment must not claim TLS confidentiality for this separate path |
| Ordinary observer of the opt-in native `anchor-tls` path | Endpoint addresses, handshake/record sizes and timing; witness request/reply bodies are TLS ciphertext | [Native TLS carrier validation](../../research/continuity-identity-candidate/ANCHOR_TLS.md) does not yet qualify installed C/other-language use or a deployed service; classical TLS identity authentication must not be described as PQ identity authentication |
| Reader of the protected witness database | Enrolled subjects, public device verification keys, enrollment authority/validity, genesis/current head and last command | Witness state is authenticated, not encrypted by that format; private filesystem admission is its local access boundary |
| Reader of the archive index / separately retained cleanup archive | Journal/session identifiers and original cleanup/context/device/protection metadata, plus archive MAC | The index is public metadata in format terms; parsing does not verify the MAC or grant cleanup permission |
| Reader of the journal file without its wrapping key | Clear sealed-image header: journal ID, owner, revision and nonce; ciphertext/tag and file sizes/history available to that reader | Image encryption does not conceal file existence, update frequency, size or stable header correlation |
| Holder of the wrapping key and admitted journal image | Pending private operations, ratchet/traffic/ACK state, retained plaintext/outboxes, claims/rosters, report state and counters | Journal compromise is stronger than observing public wires; the current key also exposes later readable images under that key |
| Authorized host application / accounting system | Delivered plaintext, session/message IDs and retained effects; complete requested loss reports | Host copies and retention are outside the SDK owner's erasure scope; the host must protect and deduplicate its records |

A directory or relay implementation is not qualified merely by this table.
Public material can be copied and linked by its holders. Directory consistency,
query authentication, access logging, lookup privacy and independent checkpoint
distribution require their own deployment/protocol contract. A TLS certificate
does not independently authenticate an account root or a roster checkpoint.

## Linkability and fingerprinting

Account/device IDs, generation, credential digest, signed roster revisions, public
prekey IDs and manifest membership are deliberately stable within their scope.
They bind authority and prevent substitution; hiding or rotating them without a
new authenticated transition would alter that security contract. Rekey preserves
the logical session and original context rather than creating an unlinkable peer.

Message IDs contain epoch and sequence plus a session/role-bound commitment.
Frames expose session, role, epoch, index, message ID and plaintext length to a
holder of the frame. The raw QPCMSG03 frame carries no separate AD field or public
AD digest: the receiver supplies AD as an authenticated input. The QPCNET01 carrier
places the literal AD beside that frame inside TLS, so its authenticated endpoint
can read it. AD must not be treated as message-encrypted private content. Rekey
controls expose their target/predecessor and signed close counts.
These support ordering/reconciliation and reveal activity to protocol participants.
No statement that ordinary payload authentication is a transferable identity
signature follows from identity-signed bootstrap/control.

Signature composition, fixed tags, profile digest, prekey quality, deterministic
field lengths, configured limits and control timing can distinguish this candidate
from other protocols to an observer with access to those bytes. The grammar adds
no padding. Application plaintext length is reflected in message length; the TLS
carrier adds transport overhead rather than a fixed-size privacy envelope. A
product padding/cover-traffic design would need explicit bandwidth, latency,
storage and recovery semantics; it is not an existing default.

Failed authentication, scope, expiry, policy, capacity and lifecycle operations
retain distinct typed local errors where the API specifies them. The network
carrier is not a promise that all error timing or disconnect patterns are
indistinguishable. Do not expose detailed local storage/authority diagnostics to
an untrusted remote caller without a separately reviewed public error contract.
This does not justify swallowing those errors inside the SDK or reporting success.

## Reports and private correlations

Closed-epoch resolution may return original unconsumed plaintext to the authorized
host so that it can account for the exact data before retirement. Session closure
and aggregate abandonment return their metadata-only loss-accounting structures.
They retain unresolved outgoing identities and observed receive/skipped ranges;
their purpose is complete host accounting, not publication to an arbitrary relay.

Report IDs use private, independently generated per-report HMAC keys retained in
the sealed pending report and removed on acknowledgement. They are not unkeyed
public commitments to low-entropy plaintext. The retained
[counterexample](../../research/continuity-identity-candidate/src/durable/messages/tests/epoch_resolution.rs)
shows why a deterministic public plaintext-guess verifier was unacceptable.
This change removes that specific verifier under the private-key assumption; it
does not hide a report's contents from its authorized host or protect against
disclosure of the report key/current journal. Exact pending replay retains the
same ID and report. An ID alone never authorizes accounting or erasure.

Witness command IDs intentionally correlate retries of one immutable mutation.
Fresh challenges prevent admission of a previous attempt's reply; they do not
make those retries unlinkable. Encrypted-image digests identify exact sealed
images and state history, not successful application consumption or public
commitments to a particular plaintext. The witness's full-head contract is needed
for rollback/fork detection within its stated independent-storage assumptions.

## Erasure, compromise and diagnostic handling

Logical retirement removes current secret tokens/keys/data only after the relevant
authenticated consumption or explicit loss-accounting transition. It cannot erase
peer copies, old database pages, snapshots, host application records or secrets an
attacker already copied. [STORAGE_RECOVERY_V1.md](STORAGE_RECOVERY_V1.md) specifies
the boundary. The actual
[reservation-disclosure experiment](../../research/continuity-identity-candidate/RESERVATION_DISCLOSURE.md)
shows that exposed pending coins can reveal traffic computed after restart and
confirmed rekey. Progress counters must not label that traffic as recovered.

Qualification artifacts should contain public vectors, source/binary/package
identities, test outcomes and the minimum correlation metadata needed to verify
the claim. The public installed workload can retain a private runtime directory
containing test keys and journal images; that directory is not a public receipt.
Share only its validated public report and necessary application hashes/logs.
Application hashes of low-entropy or personal content are not automatically safe
to publish merely because they are hashes. The existing random test payloads do
not establish privacy for real application logging.

## Product obligations still open

Before a product privacy claim, specify the actual directory/relay/witness
deployment, encrypted witness transport if claimed, lookup/access-log retention,
any padding policy, public error/timing surface, backup/key-rotation controls and
host accounting retention. Verify the same boundaries through installed language
interfaces, not only Rust types. No current finite wire oracle, signed package,
passing connection or specification file closes these obligations by itself.
