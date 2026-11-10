# Authenticated Migration Contract V2

> **Status: non-publishable reference candidate.** V2 is implemented by
> `q-periapt-migration` and is the only migration path that can reach the
> accepted-session typestate. `q-periapt-policy-agent` supplies the durable and
> process-isolated reference boundary. The construction leaves Q-Periapt ABI 2
> byte-for-byte unchanged. Deployment claims remain conditional on a separately
> protected, authenticated external witness and an owner-protected Agent process.

## 1. Frozen lower boundary

V2 does not add a C export or reinterpret an ABI 2 value. The following remain
frozen:

- the exact-nine dynamic exports;
- the 40-byte policy decision and 36-byte trusted policy state;
- `Q-PERIAPT-HYBRID-KEM/v1` and the existing ContextBound field order; and
- the ABI policy wrapper
  `LP8("Q-PERIAPT-POLICY-CONTEXT/v1") || LP8(policy_digest) || LP8(application_context)`.

The Agent passes one V2 body as `application_context`. ABI 2 applies its wrapper
exactly once. A V2 encoder must never pre-wrap the body.

## 2. Accepted construction chain

The accepted path is:

```text
signed state/reset envelope
  -> verified pending transition
  -> durable exact intent
  -> authenticated external-witness CAS/receipt
  -> committed state snapshot
  -> two identity-signed endpoint offers
  -> authenticated role-ordered negotiation
  -> typed pre-KEM transcript and V2 context
  -> frozen ABI 2 KEM inside Policy Agent
  -> typed post-KEM transcript
  -> initiator issues I
  -> responder rechecks exact local/witness head and verifies I
  -> responder accepts, durably releases the reservation, and retains key/cache
  -> responder exposes R
  -> initiator rechecks exact local/witness head and verifies R
  -> initiator accepts, durably releases the reservation, and retains its key
  -> opaque accepted-key handles
```

There is no conversion from `MigrationContextV1`, a raw digest, a raw epoch, or
a caller-created 40-byte decision into this accepted path.

## 3. Migration state

`MigrationStateV1` is an LP8 record signed under the migration authority. Its
fields are:

| Index | Field | Width |
|---:|---|---:|
| S0 | `Q-PERIAPT-MIGRATION-STATE/v1` | 28 |
| S1 | schema `u16_be(1)` | 2 |
| S2 | global generation | 8 |
| S3 | chain ID | 32 |
| S4 | protocol ID | 16 |
| S5 | chain-local epoch | 8 |
| S6 | previous state digest | 32 |
| S7 | authority key ID | 32 |
| S8 | exact execution `TrustedPolicyState` | 36 |
| S9 | minimum PQ category | 1 |
| S10 | component mode | 1 |
| S11 | allowed-suite bit set | 1 |

The state identity is SHA3-256 over the complete canonical body. The signed
certificate uses a separate domain and certificate-kind byte, so a genesis
signature cannot be replayed as an advance.

The transition rules are closed:

- genesis is explicit, signed, generation 1, epoch 1, and has the zero
  predecessor digest;
- an ordinary advance requires the exact predecessor digest, unchanged
  chain/protocol/authority, and exact `generation + 1` and `epoch + 1`;
- neither the PQ floor nor component posture may weaken;
- `PostQuantumOnly` can never transition back to `HybridRequired`;
- reset uses a distinct recovery-authority signature, exact old revision,
  nonzero reset nonce, new chain, epoch 1, and exact `generation + 1`; and
- missing, empty, corrupt, or incomplete storage is never genesis.

The reference Agent pins one migration authority and one recovery authority. A
reset naming an unprovisioned next authority is rejected; authority rotation is
not silently inferred.

Migration-state ownership is independent of immediate executor availability. A
valid committed state may change its execution-policy identity, require
`PostQuantumOnly`, or exclude ML-KEM-768+X25519. The Agent continues to replay,
witness, advance, and recover such a state, but returns an explicit
execution-unavailable error for public-key and session operations. It never
substitutes a weaker executor. Supplying a newly authenticated compatible
execution policy on a later restart can re-enable execution when the committed
posture permits it.

The domain state machine is generic over the certificate verifier and requires
that verifier's NIST level to meet the next state's floor. The reference Agent
currently pins ML-DSA-65, so a level-5 state is rejected before any durable
intent is written because the configured signer is below that floor. Supporting
a level-5 authority is an explicit future provisioning change, not a fallback
to level 3.

## 4. Authenticated negotiation

Each endpoint signs a strict capability offer under its pinned identity key.
The offer binds:

- protocol, chain, session, sender role, sender and receiver identity key IDs;
- a fresh sender nonce;
- the sender's authenticated policy state;
- the exact committed migration-state digest and global generation;
- the complete closed suite bit set, floor, and component mode; and
- a domain-separated commitment to the sender-owned PQ and traditional public
  key bytes.

The joint constructor fixes initiator/responder order, verifies both signatures,
requires reciprocal identities and distinct role inputs, resolves both real
`AuthenticatedPolicy` values against the same execution decision, checks that
both offers include the selected suite, and computes:

```text
initiator_offer_floor = max(
  initiator_authenticated_policy.minimum,
  state.minimum_pq_level
)
responder_offer_floor = max(
  responder_authenticated_policy.minimum,
  state.minimum_pq_level
)
effective_floor = max(
  state.minimum_pq_level,
  initiator_authenticated_policy.minimum,
  responder_authenticated_policy.minimum
)
```

The selected suite must meet that floor. A caller-controlled offer bit set is
not a substitute for policy resolution.

## 5. Typed transcripts and exact V2 context

The pre-KEM transcript is constructed only from one authenticated negotiation,
one committed state, one common execution decision, one KEM direction, and the
exact receiver-owned public keys. The keys must match the commitment in that
receiver's signed offer. The object retains those same key bytes for the KEM;
the caller cannot substitute a second key after hashing.

`encapsulator_role` records KEM direction only. It does not select the Finished
sender: the protocol initiator always sends I first, including when that
initiator decapsulates and the protocol responder encapsulates.

The accepted V2 `application_context` is exactly 324 bytes and thirteen LP8
fields:

| Index | Field | Width |
|---:|---|---:|
| M0 | `Q-PERIAPT-MIGRATION-CONTEXT/v2` | 30 |
| M1 | schema `u16_be(2)` | 2 |
| M2 | protocol ID | 16 |
| M3 | encapsulator role | 1 |
| M4 | committed epoch | 8 |
| M5 | initiator policy digest | 32 |
| M6 | responder policy digest | 32 |
| M7 | authenticated negotiation digest | 32 |
| M8 | selected suite | 1 |
| M9 | effective floor | 1 |
| M10 | committed state digest | 32 |
| M11 | typed pre-KEM transcript digest | 32 |
| M12 | component mode | 1 |

Every field is derived from authenticated types; V2 exposes no raw commitment or
raw epoch constructor. The post-KEM transcript then commits the exact V2 body and
both component ciphertexts. It does not include Finished values, avoiding a
circular transcript.

The current ABI 2 executor contains a traditional X25519 component. Therefore
`PostQuantumOnly` is a valid migration state for blocking legacy execution, but
`Abi2MigrationApplicationContextV2` rejects it. It is never reinterpreted as
hybrid-allowed.

## 6. Mutual confirmation and key release

For the exact post-KEM digest `TH`, each role derives:

```text
Finished(role) = SHA3-256(
  LP8("Q-PERIAPT-MIGRATION-FINISHED/v1") ||
  LP8(ABI2_secret) ||
  LP8(role) ||
  LP8(TH)
)
```

The peer value is compared with `ct_eq`. Reflection fails because the roles use
different one-byte codes. The protocol sequence is fixed:

1. the initiator issues I and retains its pending ABI 2 secret;
2. the responder checks that the incoming flight is I, rejects a pending
   transition, rechecks the exact local and witness head/fence, and verifies I;
3. the responder derives `AcceptedSessionKeyV1` and R, but makes R externally
   visible only after durably releasing the reservation and retaining both the
   accepted key and bounded same-process retry state; and
4. the initiator performs the corresponding state/witness recheck, verifies R,
   derives its accepted key, durably releases its reservation, retains the key,
   and only then returns its opaque handle.

Both accepted keys use the separate derivation:

```text
accepted_key = SHA3-256(
  LP8("Q-PERIAPT-MIGRATION-ACCEPTED-KEY/v1") ||
  LP8(ABI2_secret) ||
  LP8(TH) ||
  LP8(initiator_finished) ||
  LP8(responder_finished)
)
```

Role, transition, capacity, and allocation checks happen before a role-correct
pending typestate is consumed. A wrong flight is an explicit error and does not
replace or consume the valid pending state. A stale state/witness or a Finished
mismatch erases the pending zeroizing secret and cancels its durable reservation;
failure to cancel or release durable state poisons the Agent and exposes neither
R nor a key handle. The process service returns only opaque accepted-key handles.
It does not return a raw decision, KEM private key, pending secret, or
unconfirmed key.

Before release, the Agent rechecks the exact local `(generation, epoch, digest,
fence)` and the authenticated witness head. A concurrent transition may proceed;
its durable commit changes the fence, clears all durable session reservations,
and wipes all in-memory pending secrets. An old handle then fails as stale or
unknown.

The Unix IPC contract is a hard schema-2/domain-`/v2` cut with separate accept-I
and accept-R commands and role-shaped responses; V1 bytes have no compatibility
decoder. IPC nonce replay protection is separate from acceptance-response
recovery: the same nonce is rejected, while an exact same-handle/same-Finished
retry under a new signed nonce returns the same cached handle/R only in the same
process and only while the retained key remains live. Different Finished bytes
fail closed. Destroy, transition, and restart clear this bounded cache. Accepted
keys and R are not durable and are not recovered after a crash; the durable
capability-session tombstone still prevents reuse, so a new session is required.

## 7. Durable state and external witness

The reference repository uses immediate-durability, two-phase `redb`
transactions. It persists the complete canonical signed history, not just a
counter. Opening a store replays and re-verifies genesis through the current
head. The database file is exclusively locked while open.

A transition follows this order:

1. verify the signed envelope and derive an unforgeable pending token;
2. durably persist one exact operation ID, predecessor/successor, fence change,
   and canonical envelope;
3. send that same intent to the mandatory authenticated witness;
4. on an unknown transport outcome, query only that operation ID;
5. accept only an exact applied receipt whose authoritative head is the exact
   successor; and
6. commit the local history/head and invalidate older sessions in one local
   transaction.

Conflict, ahead, equivocation, unauthenticated response, missing history, or a
different receipt suspends progress. There is no local-file witness fallback.

Authenticated capability-session identifiers are durable replay tombstones for the
entire current state. Cancellation, Finished rejection, acceptance, and restart do
not erase them, and capacity exhaustion fails closed instead of evicting history.
A committed state transition changes the state digest/generation before clearing
the old table, so old signed offers fail the new-state checks.

`redb`, SQLite, Keychain, or a normal file cannot independently detect a whole
disk or VM snapshot rollback. For the `MIG-ROLLBACK` profile, the authenticated
witness must run outside the Agent host's rollback domain or use a platform
monotonic facility with equivalent semantics. The reference witness server is
useful for protocol and crash testing; placing both databases on the same
restorable disk does not meet that deployment assumption.

### Key-use authority, instance leases, and Authority Wire V2

Beyond the migration-head witness, the repository implements a separate
key-use authority subsystem that answers the recovery-clone and multi-instance
question: which single process instance may currently consume capabilities and
use accepted keys. The split is a deliberate scope decision: the migration
witness stays minimal and protects exactly the migration head, because
widening that CAS boundary would couple replay, configuration, and key-use
failure domains to the head-transition path; those domains are instead
protected by this dedicated authority, which binds each of them to the exact
head, configuration revision, and lease generation, and fences them on every
advance. It is layered as four modules with explicit stage
boundaries:

- `authority` (Stage 1) is a pure deterministic transition model over one
  monotonic authority version, a nondecreasing trusted-clock floor, the exact
  deployment-configuration revision, the exact migration state head and fence,
  at most one live instance lease, consume-once capability tombstones, and
  registered accepted-key handles. The closed mutation set is acquire/renew/
  release lease, advance state, advance config, consume capability, register
  key, and revoke key. Every mutation names the exact current instance fence
  (lease generation plus a fresh per-process instance identity); acquisition
  names the exact prior lease generation. Advancing state or configuration
  fences the previous holder and invalidates state-scoped runtime records.
  Every applied or rejected intent yields a bounded, queryable receipt keyed
  by operation ID, and reusing an operation ID with a different intent is a
  conflict, so retry after an unknown outcome is decidable.
- `authority_store` (Stage 2A1) persists that state with the same
  immediate-durability, two-phase discipline as the migration store. A commit
  whose durability is uncertain quarantines the whole database path; there is
  no V1 decoder or fallback.
- `authority_protocol` freezes the closed Authority Wire V2 grammar: six
  commands (snapshot, acquire, renew, release, query, acknowledge) under
  dedicated request/response/digest domains, with fixture-pinned encodings.
- `authority_transport` runs that grammar over a mutually authenticated,
  deadline-bounded, one-request-per-connection TCP loop. Both directions sign
  with pinned ML-DSA-65 keys; endpoint construction rejects a signing key that
  matches the peer verification key, so one key cannot serve both roles. The
  client pins the server address, both principals, the authority epoch, and
  the exact expected state head and configuration, and accepts only a response
  that echoes its request digest and nonce. The server keeps a bounded
  time-to-live nonce cache and answers an exhausted cache with an explicit
  rate-limit failure instead of evicting replay history. An unknown transport
  outcome is resolved by querying the exact operation ID, and an acknowledged
  receipt is pruned from the server table only after the client reports it
  durably retained; acknowledgement is idempotent. On open, the server
  re-verifies the exact epoch, head, configuration, and a lease-only history
  before serving, and any fatal store result quarantines the instance.

A restored disk clone or a concurrently started second instance therefore
cannot silently share key-use authority: at most one fence is valid, a stale
fence is rejected as lease-expired or fence-mismatch, and the clock floor
never moves backward. The transport tests exercise the full lease lifecycle,
fencing across instances, replay rejection, lost-response recovery, nonce
exhaustion, role separation, reopen validation, and unresponsive endpoints
over real sockets.

The product Agent consumes this boundary as a mandatory lease client.
Construction acquires the exclusive instance lease and fails closed with
`InstanceFenced` while another unexpired instance holds it; a lost acquire
response is reconciled by exact-operation query or by adopting the lease the
authority already recorded for this exact fresh process identity. Every
key-use operation first renews the lease against the authority's trusted
clock, so a fenced, expired, or superseded instance is rejected before it can
touch a pending or accepted secret; the fenced instance erases every
in-process pending and accepted secret first and permanently refuses
lease-guarded operations. The renew authorizes the start of the
operation; because its receipt carries no expiry, a successful renew is
followed by one snapshot that establishes how long the lease is provably still
held, anchored to an instant taken before that request is sent so it can only
understate. The operation re-checks that coverage immediately before it
reserves a pending session or retains an accepted key, and refuses both if it
has elapsed, releasing any durable reservation it already holds. The guarantee
is therefore that no session secret is retained or returned outside the window
this instance could prove it held the lease.

A renew rejected as expired is not by itself evidence that another instance
took the lease, and the two are not conflated: the agent re-acquires at its own
lease generation, which the authority admits only while that counter is
unchanged, and the counter advances on acquire alone. Success is therefore a
proof that no other instance ever held key-use authority in between, and the
agent recovers with every secret erased rather than retiring permanently. Any
successor — including one that has already released — moves the counter, fails
that re-acquire, and fences the instance exactly as before. It is not that key use has
stopped: the KEM runs before the check, a successor's acquire is gated on
wall-clock expiry alone with no interaction with the incumbent, and the
long-term executor keys are outside this mechanism. The client's fence view is deliberately RAM-only —
a restored clone of this host cannot replay the live fence, and a process
restart always starts a new acquire cycle. Graceful shutdown releases the
lease idempotently so a successor can acquire without waiting out the
time-to-live. Agent-level tests cover second-instance construction fencing,
expired-lease takeover with secret erasure, release handover, lost-response
reconciliation, and a concurrent two-instance acquisition race resolving to
exactly one lease.

Two boundaries remain explicit rather than implied. First, the product Agent
service routes only the lease lifecycle through this authority; capability
consumption and accepted-key registration are not yet routed, and remain
tracked as deployment work, not claimed here. Second, the authority server
inherits the same rollback-domain assumption as the witness: hosting it on
the same restorable disk as the Agent does not defend against whole-host
snapshot rollback.

## 8. Formal and byte-correspondence boundary

- EasyCrypt models one abstract SHA3 operation across the domain-separated
  `K_abi2 -> TH -> I/R Finished -> K_acc` inputs, plus a concrete bounded
  role-specific acceptance predicate that rechecks the exact four-field current
  revision. Equal final accepted secrets under different state identities imply
  accepted-key-input or ContextBound-input collisions; full-state/revision
  divergence adds the state-hash case. Independent post/Finished input-binding
  lemmas and honest/omission controls are checked, but they do not prove
  Finished forgery resistance or temporal ordering.
- Tamarin models active-network identity signatures, restorable local store,
  protected witness/fence, signed transitions/reset, role-separated Finished,
  and the closed floor relation for `MIG-ROLLBACK`, `MIG-AGREE`, and
  `MIG-FLOOR`.
- Independent Python recomputes the state, both offers, negotiation, pre-KEM
  transcript, V2 context, post-KEM transcript, both Finished values, and accepted
  key from structured frozen inputs. The frozen Rust/Python case injects the same
  synthetic 32-byte ABI2-boundary secret; it checks `TH -> I/R -> K_acc`, not an
  independent full ContextBound derivation of `K_abi2`.

These are source-bound translation-validation and symbolic/computational models.
They are not a proof that the Rust implementation, database, operating system,
or machine code refines the models. Transition authenticity additionally relies
on the pinned signature scheme's unforgeability, which is not supplied by the
hash-binding theorem.

The role-specific Rust typestates, service commands, and tests now follow the
same protocol-visible I -> responder accept/R -> initiator accept order as the
Tamarin agreement theory, independently of KEM direction. That reviewed and
tested alignment is still not a formal specification-to-Rust refinement; Tamarin
also does not model the service's durable reservation release, in-process retry
cache, IPC nonce lifecycle, or crash loss of accepted keys/responses.

## 9. Deployment non-claims

The repository does not claim the following without separate evidence:

- rollback resistance when Agent and witness share one rollback domain;
- hostile-local-caller isolation without a separately installed service account,
  protected state directory, pinned roots, and authenticated IPC client;
- resistance to an administrator, kernel, hypervisor, or compromised witness;
- cross-platform service parity beyond the implemented Unix reference IPC;
- formal-to-Rust or source-to-binary refinement; or
- real peer/device interoperability from local unit and loopback tests alone.
