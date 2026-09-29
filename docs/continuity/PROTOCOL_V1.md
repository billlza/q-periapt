# Continuity v1 protocol candidate

Status: **candidate, not frozen**. This records the implementation decisions and
proof obligations for the [0.2.0 scope](RELEASE_0_2_SCOPE.md). It is not a wire
specification or a completed security argument. Open decisions below must close
before the product session core is admitted. ABI major remains **2**.

## Identity and authority

The v1 target is **accountable bootstrap and control transitions**. Signed
credentials, manifests, enrollment, revocation and fresh bootstrap proofs may be
transferable. Ordinary encrypted application messages do not acquire transferable
sender attribution merely because their session was established with signatures.
Deniable messaging requires a separate protocol identity and analysis.

An account trust root is pinned through an explicit authenticated enrollment
procedure. A directory lookup, TLS server certificate, self-signed device
certificate or caller-supplied digest cannot establish that root. Every device has
its own identity credential, device generation, prekeys and pairwise session state;
devices never share a ratchet root or a restored copy of a live session.

The account-authorized device credential binds the account ID, device ID,
generation, identity verification keys, validity, capabilities and policy
authority/family/floor. A signed roster binds the exact active device generations,
roster version and validity. An accepted roster cannot be replaced by a lower
version or a different digest at the same version. A newer roster is authenticated
before it can authorize enrollment, fanout or revocation. The exact credential and
roster encodings and signature composition remain an open decision.

The isolated [identity candidate](../../research/continuity-identity-candidate)
exercises a concrete ML-DSA-65 AND P-256 composition and canonical credential,
roster and Merkle-manifest encodings. It binds account/device/generation, policy
family and exact roster expectations. Capability/floor semantics, root migration,
directory consistency and durable admission remain open; the candidate format is
not the frozen product contract.

The directory is an adversarial transport. Its view needs authenticated freshness
and consistency against the selected independently retained account checkpoint.
Repeatedly accepting an unverified new directory root is not a recovery procedure.
Unavailable or contradictory checkpoint evidence suspends affected new work.
Trusted genesis, witness/anchor provisioning and root replacement must have
separate, explicit APIs; ordinary message input cannot invoke them.

## Bootstrap and confirmation permissions

The initiator verifies the account/device authority, fresh roster, signed prekey
manifest, selected leaf membership, expiry, policy and directory checkpoint before
creating a pending bootstrap. Its fresh proof binds the role-ordered identities,
device generations, exact policy, prekey quality/IDs and complete bootstrap
transcript. A pre-signed bundle alone is not fresh responder confirmation.

Permissions are derived from verified evidence and committed state:

| Local evidence | Permitted effect |
| --- | --- |
| Authenticated responder prekeys; initiator bootstrap pending | Persist and dispatch the exact initial envelope; no mutually confirmed application privilege |
| Responder verifies the initiator's fresh proof and initial envelope | Atomically consume the selected one-time prekeys and retain a sealed initial inbox; emit a fresh responder confirmation bound to this bootstrap |
| Initiator verifies fresh responder proof and key confirmation | Persist its exact final confirmation and the authenticated peer state; dispatch the final confirmation before messages that require it |
| Responder verifies the final initiator key confirmation | Commit mutually confirmed responder state and release eligible retained application delivery |

The exact transcript graph, KDF outputs, signature inputs and confirmation MACs
must be specified together so no key derivation contains its own output. Local
dispatch, remote cryptographic confirmation and application consumption are
different records. A sent message or elapsed timer cannot advance authentication.
The final initiator transition's precise application permissions must be fixed by
the agreement analysis; the table does not assume common knowledge of delivery.

No application plaintext is delivered before its relevant transaction commits.
The initial envelope can be sent while the responder is offline, but a privileged
control operation waits for the confirmation evidence its policy requires. Failed
KEM confirmation and invalid application authentication produce the same public
authentication failure class; the SDK's implicit-rejection behavior is preserved.

## Prekeys and exact retransmission

The signed manifest resolves every key ID to its role, algorithm, public bytes,
device generation and validity. The two-leg quality representation in
[PrekeySelectionV1](PREKEY_SELECTION_V1.md) is retained as a candidate projection;
it is not accepted as evidence of a manifest signature or service lease.

The receiver commits one-time consumption, session creation, deduplication and the
sealed inbox together. An exact previously committed initial envelope resolves to
that operation's retained result. Different authenticated bytes naming an already
consumed one-time key fail without creating another session. Invalid envelopes
cannot consume the key. A malicious directory can double-lease a key; receiver
at-most-once acceptance and attributable conflicting lease evidence are separate
properties. The latter needs an authenticated lease format and privacy analysis.

Exhaustion can select a last-resort mode only when the closed signed session policy
expressly permits it. The chosen quality is bound into bootstrap. Expiry, quota,
replay and tombstone retention limits must be fixed together; deleting a tombstone
must never make a still-acceptable old prekey usable again.

## Ratchet, policy and revocation

One closed session profile fixes primitives, identity mode, prekey modes, ratchet
construction, wire version, retention limits and PQ progress floor. Product callers
cannot assemble these independently. Policy rollback, a same-version policy fork
or an unapproved weaker profile fails. A suite, identity generation or policy
change requiring migration establishes a new session; it does not reinterpret old
ratchet state in place.

Ordinary sends consume one message key. Receives derive on candidate state and
commit only after authentication. Skipped-key retention and work are bounded.
Classical and PQ updates have distinct domain-separated session KDF operations;
ContextBound is invoked only for an actual two-leg KEM combination with its full
authenticated context. Neither a TLS KeyUpdate nor a symmetric chain step is
reported as fresh-PQ recovery.

The PQ construction is still a selection decision. The comparison must include
whole-KEM rekeys and the pinned ML-KEM Braid/Triple Ratchet component reference
under identical traffic, loss, storage and security assumptions. No candidate
inherits a reference protocol's security result after changing its KDF, ordering
or authentication. Runtime progress reports identify confirmed epochs and pending
work; they never claim to know that an endpoint has recovered from an unknown
compromise. Recovery arguments state which fresh entropy was mixed, what the
attacker learned, which authentication remains trusted and which deliveries occur.

The whole-KEM control now has an [active-fork counterexample](../../research/continuity-whole-kem-reference/ACTIVE_COMPROMISE.md):
one disclosed initial session state permits continuous two-sided impersonation
while both honest endpoints confirm fresh KEM epochs. A session-root MAC cannot
establish recovery from continuing active intervention after that root was
disclosed. Accountable rekey controls must bind independently trusted device
authority to the exact prior/target epoch, role and complete exchange. The proof
obligations must distinguish session-only disclosure, pending KEM keys,
identity-key disclosure and RNG compromise. Revocation/replacement is required
when independent identity authority is lost; a progress counter cannot restore it.

The one-way no-progress traces require the product scheduler to expose control
traffic independently of application sends. A fixed, authenticated PQ-progress
budget must bound new application traffic without a completed fresh contribution;
exhaustion suspends new work while retaining exact control retransmissions.
This is a design obligation, not an implemented governor or chosen numeric floor.
Network loss remains an explicit liveness assumption in the recovery condition.
The [recovery-condition ledger](RECOVERY_CONDITIONS_V1.md) distinguishes pending
entropy reservations, identity/RNG compromise, active intervention and rollback;
its remaining implementation-correspondence checks belong to this release.

An authenticated revocation prevents new affected sends/receives and new dispatch
of retained outgoing work according to its committed fence. Work admitted before
that fence has an explicit completion rule; a transport reconnect cannot revoke
or restore authority. A delayed roster or revoked device cannot silently become an
optional recipient to make fanout succeed.

## Durable service boundary

The service owns secrets and implements the ordering in
[the effect lifecycle](G1_EFFECT_LIFECYCLE.md): durable reservation before provider
execution, exact result pinning, anchor reconciliation, atomic final commit, then
idempotent release. Public model receipts are never production capabilities.

Each persistent operation binds an operation ID, expected state version **and**
digest, writer fence, authenticated context and complete intent. An unknown commit
outcome retains the exact operation for reconciliation; cancellation or retry
cannot generate replacement entropy or different ciphertext under the same key.
After disconnect, dispatch replays the immutable committed outbox. Delivery
acknowledgements are authenticated and bind the exact message and session.

Multi-device sends commit all required recipients under one account transaction.
If external anchors are required, all required anchor progress is reconciled before
any outgoing item becomes dispatchable. Partial anchor progress remains a pending
aggregate. It cannot become a successful partial delivery. Explicit recipient
exclusion is part of the caller-visible signed-policy decision.

The rollback profile must retain an authenticated monotonic account checkpoint
outside the restorable session database. Local redb atomicity protects against
partial commits, not restoration of a complete older database. Restoring ordinary
backups does not reactivate old ratchet state. Device replacement creates a new
generation and authenticates its enrollment and prior-generation retirement.

## Decisions still required for the frozen protocol

1. Exact hybrid credential/root signature composition, authenticated enrollment and
   root replacement, trusted-time source, directory checkpoint and witness format.
2. Exact manifest/leaf/lease grammar, signed prekey modes, consumption and retention
   bounds, and lease-accountability/linkability evidence.
3. The non-circular bootstrap transcript/KDF graph and stage-specific confirmation
   privileges, including loss/replay and key-compromise impersonation analysis.
4. The measured PQ ratchet profile, complete wire grammar, padding and downgrade
   behavior, resource/cadence limits and construction-specific recovery condition.
5. Sealed record/key ownership, external anchor protocol, crash reconciliation,
   revocation fences and atomic account-wide fanout/recovery behavior.
6. Numeric device/workload budgets and the content-locked normative specification
   set. Candidate text does not satisfy this lock.

These are implementation dependencies within 0.2.0, not deferred release features.

The comparison uses the [recorded baseline revisions](reference-baseline.json),
including the [Double/Triple Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
and [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/).
Those component specifications do not define the Continuity identity, persistence
or account-manager composition above.
