# Durable authenticated hybrid rekey exchanges

This unpublished candidate now executes four identity-authenticated control
flights and installs separate traffic/ACK epochs in the actual encrypted journals.
The permanent logical session, device identities, policy and installed roster
bindings remain unchanged. The complete product profile and its security argument
remain unfrozen. ABI major stays **2**.

The history bound is four retained traffic epochs. The v6 signed profile requires
both peers to attest that the displaced prefix is settled: fully drained or
accounted for through an application-acknowledged
[closed-epoch resolution](EPOCH_RESOLUTION.md). Such resolution reports unknown
delivery rather than success. Pending reports continue to block retirement;
final/receipt commits retire settled history atomically with the new owners. The
[retirement contract](RETENTION.md) preserves lost-ACK recovery and exact control
replay. The [signed application budget](../../docs/continuity/SEND_PROGRESS_V1.md)
now limits new sends across unconfirmed cutovers. Independent control scheduling
and a measured product value remain required for the full 0.2.0 contract.

## Local permission and durable ordering

The original bootstrap initiator proposes odd target epochs; the other role
proposes even ones. Each target is exactly its predecessor plus one. An offer
cannot compete with another retained proposal for the same slot. Both signatures,
complete transcript bindings and current roster/policy authority are checked
before new peer input can reserve private work.
For target `t`, both first flights additionally attest to local retirement
eligibility for all retained epochs below `max(0, t - 3)`. This mandatory
profile-bound assertion is verified by the signing implementation; it is not an
unauthenticated header hint or proof of an arbitrary peer's internal state.

| Flight and local commit | Permitted effect |
| --- | --- |
| Offer: sealed key reservation, exact signing plan, signed outbox | Dispatch the exact offer; traffic remains on the prior epoch |
| Response: exact encapsulation reservation, computed body/root and signing plan, signed outbox | Dispatch the exact response; traffic remains unchanged |
| Final: proposer verifies the response and real decapsulation confirmation; commits a signing plan, then final outbox plus fresh traffic owners | Switch the proposer's sending epoch; dispatch final before new application frames; receiving epoch still waits for receipt |
| Receipt: responder verifies the final; commits a signing plan, then receipt plus both directional switches | Admit the new receiving epoch, use the new sending epoch and release the exact receipt |
| Receipt acceptance: proposer verifies both signature components and MAC; commits receiving cutover and completed transcript | Admit new-epoch incoming traffic and report local completion |

Preparing final/receipt signatures fences only that direction's new sends, fixing
its exact old sending-chain length. Cached sends, receives and consumption remain
available. An existing unresolved send reservation must finish from its retained
input before cutover preparation. A future-epoch packet arriving before control
admission returns `Suspended` without advancing a chain or consuming a key.

Unknown commit/witness outcomes close the journal. Reopening reconciles the exact
saved intent. `rekey_outbox(context, session, target, flight, now)` retrieves only
the named committed flight after fresh authority/release checks; an unsigned stage
suspends. Duplicate response/final/receipt calls return the retained result rather
than incrementing another epoch. The most recent completed four-flight transcript
remains available while the next exchange is pending.

`rekey_progress` separately reports local completed, sending and receiving epochs
and the pending target. After final commit the proposer can report `(0, 1, 0)` for
completed/sending/receiving; this is intentionally distinct from `(1, 1, 1)` after
receipt acceptance. None of these counters asserts that an adversary lacks keys.

## Fixed public grammar and KDF graph

Let `D = ASCII("Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/")` and let `H(label, x)` be
length-delimited SHA3-256 over
`len(D||label):u64 || D || label || len(x):u64 || x`. Integers are big endian.

The closed candidate profile is:

`H("offer-profile", "ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;accountable-epoch-ratchet/v6;messages/v3;retained-epochs=4;settled-prefix-attestation/v1;application-send-budget/v1;control-request/v1")`

A common 153-byte prefix is:

`tag[8] || profile[32] || bootstrap_context[32] || logical_session[32] || prior_epoch:u64 || target_epoch:u64 || signing_role:u8 || predecessor[32]`

The initial predecessor is `H("genesis", session || context)`. After completion it
is `H("completed-epoch", offer_wire || response_wire || final_wire || receipt_wire)`.
Each fixed-size envelope is `body_length:u32 || body || hybrid_signature[3373]`.
Both ML-DSA-65 and canonical P-256 verify under the existing identity context,
separate purpose, length and entire body. No optional signature or downgrade path
is introduced.

| Flight | Tag / purpose | Body after the prefix | Body / envelope bytes |
| --- | --- | --- | --- |
| Offer | `QPRKOF01` / 9 | full hybrid public key[1216] | 1369 / 4746 |
| Response | `QPRKRP01` / 10 | `H("offer-wire", offer)[32] || ciphertext[1120] || MAC[32]` | 1337 / 4714 |
| Final | `QPRKFN01` / 11 | `H("offer-wire", offer)[32] || H("response-wire", response)[32] || old_send_count:u64 || MAC[32]` | 257 / 3634 |
| Receipt | `QPRKRC01` / 12 | the two preceding hashes, `H("final-wire", final)[32] || old_send_count:u64 || MAC[32]` | 289 / 3666 |

The offer's role is the designated proposer; response and receipt use the other
role. Unknown tags/profiles, wrong roles, noncontiguous epochs, altered context,
session, predecessor or exact-wire hashes, bad lengths and trailing bytes fail.
The ciphertext is the 1088-byte ML-KEM component followed by the 32-byte X25519
ephemeral public key. The offer contains the full 1184+32-byte public key.

The graph is acyclic:

1. The SDK's actual two-leg ContextBound encapsulation uses application context
   `H("response-kem", offer_wire)`. Let its combined secret be `S`, and let `C` be
   `H("response-core", response_body_without_MAC)`.
2. HKDF-SHA256 with the old rekey root as salt, `S` as input and info
   `D || "pending-root/HKDF-SHA256/" || C` derives the 32-byte pending root.
3. HKDF-SHA256 with no salt, that root as input and info
   `D || "responder-confirmation"` derives the responder MAC key. HMAC-SHA256
   authenticates `C`; both response signatures then cover core plus MAC.
4. For final/receipt, derive a separate MAC key from the pending root with info
   `D || "final-confirmation"` or `D || "receipt-confirmation"`. Its HMAC input is
   `H("final-core", final_without_MAC)` or `H("receipt-core", receipt_without_MAC)`.
   The final binds the complete signed response; the receipt binds the complete
   signed final. Both cutover counts are independently identity-signed.
5. Epoch traffic HKDF uses salt `session`, input pending root, and info
   `D || "epoch-traffic/HKDF-SHA256/ChaCha20Poly1305/" || context || target:u64 || H("traffic-transcript", offer_wire || response_wire)`.
   Its 128 bytes are initiator-send, responder-send, initiator-message ACK and
   responder-message ACK keys. Each new directional chain begins at index zero
   under its distinct epoch-bound message IDs. The pending root becomes the next
   rekey root; it is not used directly as a traffic or ACK key.

Only owned SDK operations and the journal's internal KDF handle these secrets.
There is no public pending-root import. The 277-byte offer key-generation token
is removed from the current image when final preparation commits; the 245-byte
encapsulation token is removed when response body/root/signing preparation commits.
Stored or disclosed old reservations remain exposed material: later execution of
the same reservation is not new entropy relative to that disclosure.
The [actual reservation disclosure experiment](RESERVATION_DISCLOSURE.md) now
reproduces that boundary at both first durable reservations, including successful
decryption of post-confirmation application frames after restart.

## Stored state and retained authority

The current journal v21 uses `continuity_device_candidate_v21`, `QPVLT021` and
`QPVIMG21`, and rejects earlier images without an implicit migration. `QPMST011` stores common session
identity/rekey state, current send/receive epoch IDs, bounded length-delimited
`QPTEPO04` traffic records and the `QPRKST03` control record. Each traffic record
owns its independent counters, chains, ACK keys, receipts and pending input;
[RETENTION.md](RETENTION.md) specifies their invariants and old-epoch bounds.

Control state contains completed epoch, predecessor, an optional exact last
completed four-flight transcript, one optional [request](CONTROL_PROGRESS.md),
and one pending exchange phase:

- 0: none; 1–3: offer key reserved / signature reserved / outbox committed.
- 4–6: response encapsulation reserved / signature reserved / outbox committed.
- 7: final root/body/signature reserved; 8: final committed, sending epoch switched.
- 9: receipt root/body/signature reserved. Receipt commit moves the four wires
  into completed state and advances both responder directions.

The signer reservations are 64 bytes. Phase 7/9 holds the pending root until the
switch commit; phase 8 uses the installed next rekey root. Image validation checks
MAC/body correspondence, exact local cutover counts, pending-send exclusion,
per-epoch state invariants, directional switch permissions and the completed
transcript digest. Cached release verifies the relevant public identity proof.
Old receiving counts can exceed a new authenticated close count after old-key
forgery; they remain isolated rather than becoming a new-epoch floor.

## Executed validation and remaining requirements

The v4 follow-up adds explicit [closed-epoch outcome resolution](EPOCH_RESOLUTION.md)
and passes 151 release tests on the fixed Rust 1.98.1 toolchain. Sixteen measured
resolution sync faults and two process kills preserve the exact report or
application acknowledgement. The original cutover/retirement grids below also
pass under v4. Format, strict Clippy, Rust 1.90 all-target compilation, 45 isolated
source-contract checks and both independent public-byte oracles pass. This is
local candidate evidence; hosted and installed product qualification are separate.

The retained v3 local runs on Rust 1.94 and the fixed Rust 1.98.1 each pass
**145 release tests**, including eight alternating rekeys with per-epoch traffic
and restart. Fixed-toolchain formatting and strict all-target Clippy pass, and
Rust 1.90 passes locked all-target compilation. The first cutover
grid measures 9/10/5 sync barriers for final, receipt and receipt acceptance;
the history-retirement grid measures 9/9/5. All **94** before/after faults recover
the exact control output and actual traffic. Fourteen process kills cover both
sets of reserved/computed/committed boundaries. Tests separately retain
unconsumed deliveries, recover a lost ACK before signing the peer response, and
recover lost final/receipt output after asymmetric history deletion. The frozen
standalone snapshot passes 45 candidate-isolation and CodeQL-contract tests;
this is not a CodeQL database analysis or a product package qualification.
Required-witness tests lose the final release queries after each switch commit
and on a cached final release; all close without early output.

Tests also exercise old delayed traffic/outbox replay,
future-epoch suspension, cross-epoch ACK forgery, real implicit-rejection/key
confirmation, both identity signature components, revocation, signer-close replay
and restart. The [old-chain counterexample](EPOCH_CUTOVER.md) now includes a real
positive control: epoch-one traffic succeeds while the poisoned old floor and old
outbox remain retained. This does not restore past application authenticity.

`public_vectors --with-rekey` restarts both real journals, completes all four
flights, replays their committed outputs and performs traffic in both directions.
The independent OpenSSL oracle verifies **19 signed envelopes / 95 signature
negative controls**, exact control transcript/cutover fields and both new-epoch
frame/ID encodings. Public parsing does not recompute secret MAC/AEAD operations;
those are checked by the actual journal fixture and Rust tests. The separate
anchor oracle verifies 12 envelopes, 60 negative controls and six transitions.

This is a bounded whole-hybrid candidate, not a completed continuous-PQ security
argument or the finished 0.2.0 SDK. Application resolution records an unknown
historical outcome, not restored authenticity. Authenticated progress limits/control scheduling, complete lifecycle/fanout,
product bindings, construction analysis and current-source platform/performance/
energy qualification remain required. No history is discarded to manufacture
further progress. Logical erasure does not erase old database pages or backups.
