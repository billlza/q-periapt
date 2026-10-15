# Candidate recovery dependencies and asymmetric progress

Status: source-derived disclosure analysis and a finite implementation experiment.
This is not a frozen security claim or a proof of post-compromise secrecy. It
refines [RECOVERY_CONDITIONS_V1.md](RECOVERY_CONDITIONS_V1.md) by identifying which
retained fields can expose later roots. A recovery label must follow these
fields, including both endpoints' pending work, rather than a single epoch counter.

## Scope and concrete dependency equations

For an exchange targeting epoch `e`, let `R[e-1]` be the previous rekey root,
`S[e]` the combined hybrid KEM secret, `C[e]` the public response core, and
`O[e]`/`P[e]` the complete signed public offer/response. With the exact domain
labels in the implementation, the pending root is:

```
R[e] = HKDF-SHA256(salt = R[e-1], IKM = S[e],
                  info = pending-root-domain || H(response-core-domain, C[e]), 32)
T[e] = HKDF-SHA256(salt = session-id, IKM = R[e],
                  info = epoch-traffic-domain || context || e ||
                         H(traffic-transcript-domain, O[e] || P[e]), 128)
```

[`response::derive_root`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs)
and [`State::add_epoch`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs)
implement these equations. `T[e]` creates two directional traffic chains and two
ACK keys. Knowing `R[e]` and the public transcript is sufficient to reproduce
the initial epoch material and subsequent chain steps. This is a constructive
sufficiency claim; absence of a listed derivation is not a secrecy proof.

The replay dependencies include:

| Captured inputs plus public information | Computable descendant |
| --- | --- |
| Matching wrapping key, generation reservation, operation/policy binding | Exact hybrid private/public key |
| That private key and the later response ciphertext/context | `S[e]` |
| Matching wrapping key, encapsulation reservation and retained authenticated offer | Exact ciphertext, `S[e]` and response core, even before response publication |
| `R[e-1]`, `S[e]`, response core | `R[e]` |
| `R[e]` and complete offer/response transcript | `T[e]`, directional message chains and ACK keys |
| Known wrapping key and subsequently obtained protected state | Whatever roots, reservations or retained traffic that later state actually contains |

The last row is ongoing disclosure, distinct from a single captured image.
The first two rows and the encapsulation row use the SDK's actual
[sealed-operation replay owner](../../crates/q-periapt-sdk/src/expert/replay.rs).
Honest SDK policy admission remains enforced, but it is not a cryptographic
barrier to an attacker already holding the token and its wrapping key: the
underlying replay computation can be reproduced outside that admission API.
A wrapper nonce or ciphertext published after capture does not add secrecy to
captured reservation entropy. For encapsulation, the response signature may
still be unpublished, but the predictor can already compute the response core;
it can use the later honest signature bytes when deriving transcript-bound traffic.

## Stored phases and root ownership

Here `n` means that endpoint's local `confirmed_epoch`, and `e = n + 1`.
The phase numbers are private journal encodings, not a stable application API.
This table maps the exchange plan and active root; request records and traffic
records are separate. Independent signer files, retained storage pages, other
sessions and entropy-source state are additional assets.

| Phase | Retained rekey material beyond public wires | Root in `State.rekey` | New send / receive epochs |
| --- | --- | --- | --- |
| 0, no exchange plan | No KEM reservation in this plan; a control request may exist separately | `R[n]` | `n / n` |
| 1, key reserved | Generation token | `R[n]` | `n / n` |
| 2, offer signature reserved | Same generation token; signature reservation | `R[n]` | `n / n` |
| 3, offer ready | Same generation token | `R[n]` | `n / n` |
| 4, response encapsulation reserved | Encapsulation token and authenticated offer | `R[n]` | `n / n` |
| 5, response signature reserved | Pending `R[e]`; signature reservation | `R[n]` | `n / n` |
| 6, response ready | Pending `R[e]` | `R[n]` | `n / n` |
| 7, final signature reserved | Pending `R[e]`; signature reservation | `R[n]` | `n / n` |
| 8, final ready | New traffic installed; final outbox; pending root has moved into the active root field | **`R[e]`** | **`e / n`** |
| 9, receipt signature reserved | Pending `R[e]`; signature reservation | `R[n]` | `n / n` |

The encoding and transition sources are
[`Control::encode/decode`](../../research/continuity-identity-candidate/src/durable/messages/rekey.rs),
[`response::Plan`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs)
and [`completion::Plan`, `validate_epochs`, final/receipt commits](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs).
Receipt commit installs `R[e]`, advances both directions and the local confirmed
counter, and clears the plan. Receipt acceptance at the proposer completes its
receive cutover later. Every row also requires accounting for the separate
retained traffic map: old keys, skipped keys, unconsumed plaintext and outboxes
are not erased merely because the rekey plan changes.

A signature reservation contains a binding and ML-DSA signing randomness. The
[current signer](../../research/continuity-identity-candidate/src/crypto.rs)
passes those coins to ML-DSA, while P-256 uses its own `try_sign` path. Treating
the captured bytes as an exposed P-256 nonce would be incorrect. The effect of
known ML-DSA signing coins remains part of the required auxiliary-information
security analysis; this table does not establish it.

The [persistent signer format](../../research/continuity-identity-candidate/src/crypto/persistence.rs)
encrypts both signing seeds under a key derived from the journal wrapping key.
A threat model granting that key and the corresponding signer file must include
identity compromise. Calling such a disclosure only a traffic-state snapshot
would exclude a real capability. The experiments below explicitly withhold
signer files/owners; they do not model an unrestricted whole-device compromise.

## A delayed receipt can hide a later exposed exchange

The asymmetric experiment holds the first receipt after the responder has
committed it. The initiator reports `(confirmed, send, receive, pending) =
(0, 1, 0, 1)`. The responder reports `(1, 1, 1, 2)` after committing its epoch-two
offer, with phase 3 retaining the generation token. Both observations survive
honest restart before the delayed receipt is delivered.

At that point the predictor receives **one responder snapshot**: its actual
`R[1]`, journal identity, wrapping key and retained generation token. It gets no
initiator snapshot, signer, epoch-two root, future reservation or later private
state. After the honest peers receive the delayed receipt and complete epoch 2,
the predictor reconstructs the epoch-two material from that capture and public
control wires. The experiment checks six actual newly generated application
payloads, three in each direction, after restart. A wrong wrapping key must fail.
See the [executed checkpoint](../../research/sdk-alpha1/evidence/20261015-recovery-ancestry/README.md).

This falsifies a universal exposure bound of `min(peer confirmed epochs) + 1`:
that quantity is one at capture, while epoch-two traffic is reconstructible.
It does not falsify a stated SDK security guarantee; `RekeyProgress` already
describes local progress only. It also does not establish the maximum possible
exposure, a bound relative to the newer peer's counter, or secrecy at epoch 3.
The legitimate asynchronous schedule should not be disabled just to make a
counter-based recovery claim appear true.

## Construction-specific recovery argument still required

For a candidate recovery epoch, the analysis must establish that the selected
hybrid contribution remains pseudorandom given the complete attacker view:
all disclosed ancestors and reservation coins, public transcripts, allowed
chosen inputs and any later state access. For a PQ claim that premise must
survive loss of the classical contribution. Both endpoints' phase/root ownership,
authentication authority and entropy-source recovery must be explicit.

A next proof step can then replace that contribution with an independent secret
in the exact root derivation, justify the root extractor/expander under the
actual previous-root and transcript distribution, and propagate the result to
the exact direction/epoch message keys. The assumptions must cover the
confirmation MACs, signature material, retained traffic and message/ACK cutover;
completing a flight is not that proof step. Further disclosure of the derived
root or traffic state defeats that candidate recovery point.

[RFC 5869 sections 3.1–3.4](https://www.rfc-editor.org/rfc/rfc5869.html#section-3)
explain salt, context and input-independence requirements. They do not supply a
security proof for this composition, whose salt is a previous protocol root and
whose context contains transcript-dependent values. A generic claim that one
unknown input makes every subsequent key secure is therefore not substituted
for the missing construction-specific argument.


A [symbolic research projection](../../research/continuity-recovery-symbolic/README.md)
now checks the original positive recovery formula through a
[20-property dependency group](../../research/sdk-alpha1/evidence/20261015-recovery-positive-symbolic/README.md).
The conditions require both reservations after Cut, no target-session identity
or entropy disclosure anywhere in the trace, and no acquired revision saved after
Cut. Other-session leakage remains allowed. Causal root/traffic/message knowledge
properties join authenticated KEM provenance to the retained-record timing facts.
The main query verifies in nine steps, with every dependency replayed in the same
process. Six observer actions erase to the original rules, and all five original
complete declarations remain unchanged.

The original generated-key provenance (182 steps), honest execution (59), pre-cut
generation-record disclosure (80), and later phase-8 disclosure (45) retain their
separate evidence. Both snapshot witnesses permit exactly one Snapshot and no
extra identity/entropy leakage. A new single-identity-disclosure witness shows
acceptance of an attacker-known root without snapshots or entropy disclosure.
These traces distinguish which sufficient condition has been lost; they do not
establish a maximum exposure bound.

This result assumes perfect primitives and ideal protected storage, with one
exchange per independently initialized pair. It supplies no concrete HKDF/hybrid
argument, shared-device or multi-epoch theorem, explicit-storage equivalence or
Rust refinement. The construction-specific argument above and the full product
release obligations remain open. No runtime flag can infer these attacker-view
conditions merely from protocol progress.
