# G1 candidate: effect, journal and release lifecycle

> **Status:** candidate G1 contract, not a frozen protocol and not a security claim.
> The dependency-free executable model uses opaque public commitments plus a candidate
> canonical lifecycle-context projection and lives at
> [`../../models/q-periapt-continuity-model`](../../models/q-periapt-continuity-model).

This document closes several unsafe ambiguities in the earlier two-line
`prepare/resume` sketch. A future production core must preserve the ordering and
failure semantics here, but it may not be created until the remaining G1 artifacts
listed in [`README.md`](README.md) are frozen.

## 1. Required order

```text
prepare
  -> atomically persist ReservedEffect + writer fence
  -> expose one execution/query effect
  -> receive one complete provider completion
  -> service constructs and atomically pins the first complete result
  -> persist the exact finalization and policy-bound anchor plan
  -> reconcile the external anchor, when required
  -> atomically commit next state + prekey/dedup/outbox/delivery effects
  -> replay one exact release/delivery ID until its acknowledgement is durable
```

Provider execution before the reservation commit is an invariant violation. A
reservation outcome that is unknown must be queried by its exact transition ID; it
cannot be treated as failure and recomputed. The same rule applies to result-pin and
anchor-reservation, final-commit, and release-ack writes.

## 2. Structured binding

`OperationId` is a correlation identifier, not an authorization capability. The
candidate [`LIFECYCLE_CONTEXT_V1.md`](LIFECYCLE_CONTEXT_V1.md) encoder now fixes exact
model context bytes and prevents callers from independently selecting stage and
digest. The model still compares the full structured operation binding. It covers:

- protocol namespace, wire version, closed policy digest, and the anchor requirement
  selected by that policy before `prepare`;
- pairwise session and both device identifiers, checked against the model's trusted
  durable session authority before reservation;
- prior and reserved state versions and digests;
- transition ID, command ordinal, and fencing token;
- the complete canonical `LifecycleContextV1`, signed-policy digest and adapter-derived
  context digest, checked against the model's trusted durable current context before
  reservation;
- a closed operation variant, from which purpose, retry behavior, and expected result
  shape are derived;
- provider profile and provider-instance epoch;
- commitment to the complete command intent, including any storage-local stable
  handle or sealed entropy reservation.

Changing any field while retaining the original operation ID is rejected. Repository
intents and receipts also carry this structured binding in the model; the future byte
format must commit it canonically. Provider results echo the complete binding plus the
closed result kind and result commitment; fields from two partial results are never
merged. Storage record/state commitments are constructed by the service after result
validation, not supplied by the provider.

Production APIs will not accept raw caller entropy. An approved service CSPRNG creates
a one-use, purpose/algorithm/transition-bound `EntropyReservation`, seals it before
execution, and consumes it once. Only KAT/test builds may inject deterministic bytes.
Secret or low-entropy plaintext commitments must remain inside sealed local records;
they are not exposed through operation IDs, logs, wire bytes or telemetry.

## 3. Completion and retry taxonomy

A provider completion is one of:

1. one complete successful result;
2. a definitive failure;
3. outcome unknown.

Retry behavior derives from the closed command variant, never a caller boolean:

| Contract | Unknown outcome behavior |
|---|---|
| deterministic from the exact sealed entropy reservation | reissue identical command bytes, operation ID and entropy |
| exact provider stable handle | query the same provider epoch/profile/handle operation |
| non-repeatable | suspend and quarantine; never generate a new operation |

Completion, cancellation and supersession require durable closed records. Exact
duplicates are rejected without a second transition; a conflict while the first result
pin is in flight preserves that exact write intent and queries the repository before
quarantine. A completion is an authoritative terminal adapter report for one operation;
the adapter may not emit a later timeout as a second terminal outcome. Once success is
accepted, a different success or a later definitive-failure/unknown report is a typed
integrity contradiction and durably suspends. The first suspension cause is latched
while a possibly committed write is reconciled, so a later fence/provider event cannot
overwrite the forensic reason. Late results cannot revive a closed operation. Numeric
tombstone retention and orphan-handle cleanup remain unfrozen and therefore are not
yet called bounded.

## 4. Repository unknown outcomes and fencing

Every aggregate write carries one `TransitionId`, an indivisible
`StateAdvance { expected: StateRevision(version,digest), next:
StateRevision(version,digest) }`, exact record commitment, typed stage subject and
current fencing token. Same-version/different-digest is a CAS conflict, not an exact
match. Every authenticated receipt must echo the complete advance.
The subject binds the accepted result kind/commitment, exact anchor reservation, final
anchor intent, release permission, or closure kind as applicable. A receipt for the
right transition but the wrong subject is rejected. The repository must offer a
linearizable exact-operation query with four outcomes:

- exact committed: continue from the already committed state;
- exact absent: replay the identical aggregate write, without rerunning crypto;
- conflict/stale fence: suspend and reconcile from the winner;
- still unknown: keep querying or remain suspended.

Only a CAS loss proven before reservation can create a newly prepared transition.
Fence loss after dispatch never permits reuse of the old entropy, result or handle.
`FenceLoss` evidence must carry a strictly newer authoritative fence; repository
conflict evidence is a separate type because its reported fence need not be newer.

## 5. Anchor profiles

The anchor capability is typed:

| Profile | Current model output |
|---|---|
| `NoAnchor` | commit ordering only; no rollback-detection claim |
| `EpochOnlyAnchor` | commit ordering only until authenticated epoch evidence is explicitly modeled; no epoch assurance is emitted from a policy enum |
| `PerTransitionDigestAnchor` | exact operation/final-record/final-state binding after a durable anchor reservation; still only a candidate for R5 pending canonical derivation and a real adapter |

The requirement is fixed in the operation binding before reservation. The full
profile is an authenticated
`compare_and_advance(anchor_id, exact_prior, exact_next, transition_id, fence)`.
The model first persists an exact anchor plan that also binds the final record and
state digest; only then can it emit an anchor effect. Only an authenticated exact
application may finalize. Authenticated exact-prior may retry the same operation.
Unknown is queried. Ahead, conflict, equivocation or an unauthenticated response
suspends. A plan with `exact_prior == exact_next` fails before any model mutation and
can never yield `PerTransitionAnchored`; idempotence is represented by
`AlreadyAppliedExact` for one non-empty advance. The canonical function deriving
`exact_next` from those fields is not yet
frozen. Multiple independent hardware counters do not magically provide atomic
multi-device fanout; G1 must choose an account-level anchor or explicitly retain that
limitation.

## 6. Durable release and abstract reconstruction

The exact final commit installs a release permission that binds the full operation,
final record commitment, final state digest, and assurance boundary. `Committed` is
not reached when that effect is merely returned. A process reconstructed from the
model's stable `DurableSnapshot` re-emits the same permission until an exact release
acknowledgement record commits. This models idempotent outbox/sealed-inbox control; it
does not choose whether the acknowledgement means local dispatcher acceptance,
remote receipt, or application consumption. G1 must define those as distinct types.

`DurableSnapshot` schema 3 is an abstract desired durable-journal projection with no canonical
encoder, MAC, migration, corruption, fsync, or WAL semantics. It contains stable
states and the exact pending intent for every repository stage. Tests destroy the old
Rust object, reconstruct a new one, query that same intent, and then explore
exact-applied, exact-absent, conflict, and repeated-unknown worlds for reservation,
result pin, anchor reservation, final commit, release acknowledgement, cancellation,
and supersession. `Volatile` and `Pinned` results are distinct model states; every
durable cut scrubs the former, while a pending result-pin subject retains only the
accepted public result kind/commitment needed for exact reconciliation. In-flight
anchor effects are not copied into a snapshot.

A security failure cannot simply set an in-memory flag. If a repository write is
pending, the model first carries its exact intent through `CommitUnknown` until that
write is reconciled. It then appends a separate suspension intent binding the
operation, full binding, first runtime reason, writer fence, typed evidence, and a
pre-bound record-slot commitment. The slot commitment is not yet claimed to be a
canonical commitment to the dynamic reason/evidence; the future codec must derive and
authenticate the complete record unambiguously.
Unknown/absent suspension writes are queried/retried; after the exact tombstone is
known durable, reconstruction can only re-emit the same quarantine. This is the
required abstract contract for a future append-only suspension journal, not evidence
that a real database implements it.

`CryptoCompletion`, repository and anchor outcomes, `CommitReceipt`, and
`SuspensionReceipt` are trusted authenticated-adapter oracles in this model. More
importantly, the model cannot force a host to persist/fsync a
returned snapshot before executing its external effect. Production must enforce
`journal durability acknowledgement -> effect execution` and pass subprocess-kill
tests at every cut. Closing that integration P0 belongs to G4; reconstruction alone
does not close it. Suspension-journal conflict/corrupt-receipt convergence and retry
budgets are also still open rather than silently treated as success.

## 7. Identity stages and zero-RTT

The peer-agreed authentication context distinguishes:

```text
PrekeyAuthenticated -> PeerConfirmed -> MutuallyConfirmed
```

A pre-signed offline bundle proves possession at issuance, not a fresh
sender-specific responder proof. An accountable active-PQ profile may authenticate
and deliver the initiator's first message to the responder after the initiator's
fresh proof verifies, while the initiator remains unconfirmed until the responder's
fresh confirmation arrives. Application privileges that require mutual confirmation
must fail before `MutuallyConfirmed`. A deniable profile uses a different protocol ID
and cannot contain transferable ML-DSA transcript signatures.

The model now treats its initial `SessionIdentity` and `AuthenticatedContext` as a
trusted durable authority. A draft cannot replace the session, local device, peer
device, canonical context, policy digest, or derived digest before reservation, and
snapshot schema 3 retains the same authority across reconstruction. The candidate
context now explicitly commits role-ordered account/device epochs, credential and
suite digests, direction, roster/directory/prekey quality, transcript and root epochs.
Bootstrap quality/manifest/selection fields are derived atomically from the strict
[`PrekeySelectionV1`](PREKEY_SELECTION_V1.md) record after suite, responder scope,
checkpoint, and direction cross-checks; callers cannot provide an unrelated digest.
This is exact trusted-genesis admission, not credential authentication,
stage-transition typestate, manifest authenticity/membership, unique prekey leasing or
consumption, directory consistency, freshness, KCI/UKS or FS/PCS.

The model deliberately has no context-advance API. `ZeroRttSent` is kept out of the
peer-agreed context: a locally committed outbox item is not necessarily sent,
dispatcher-accepted, remotely received, or application-consumed. G1 must still freeze
role- and profile-specific local states, evidence, release/ack meanings, and legal transitions;
until then, a draft cannot self-promote the trusted context and no test is called a
confirmation protocol. Those remain required G1 identity artifacts.

## 8. Model boundary

The executable model currently runs 31 lifecycle integration tests covering
reserve-before-execute, early completion, full binding, closed result shape,
first-result pin reconciliation after restart, provider terminal-outcome contradiction,
first-cause retention, volatile-result scrubbing at every durable cut,
cancellation/supersession, repository unknown outcomes, typed persist subjects,
durable anchor preparation, anchor-profile downgrade, provider restarts, abstract snapshot
reconstruction, trusted session/context admission before reservation, every
repository stage's four outcome classes after reconstruction, durable
suspension/evidence replay, idempotent release/ack, a two-writer shared-
repository fence oracle, same-version/different-digest CAS across every persist stage,
wrong-prior-digest receipt reconciliation, no-op-anchor rejection, post-dispatch fence
loss, and counter overflow. Ten additional context tests cover canonical bytes and
validation. One private regression checks receipt-preflight error atomicity. One of
the lifecycle tests contains a five-mutant trace oracle that rejects execute-before-reserve, release-before-final-commit,
stale-fence commit, non-repeatable re-execution, and split-result merge. This is a
table-driven diagnostic, not an
exhaustive bounded-state explorer or a formal proof. It intentionally cannot establish:

- fsync, WAL or torn-write behavior;
- real multi-process lease/fence correctness or retry fairness/budgets;
- Keychain/Secure Enclave handle idempotence or cleanup;
- secret remnants in allocator memory, old pages, backups, crash reports or OS logs;
- authenticated remote-anchor correctness;
- identity credential authenticity, roles/device epochs, UKS/KCI, FS, PCS, prekey
  one-time behavior, ratchet correctness or interoperability;
- canonical snapshot/record bytes, schema migration, corruption authentication, or
  source-to-model refinement;
- unbounded formal safety or exhaustive phase/event exploration.

Those require real persistence/platform fault harnesses, formal models and physical
device evidence in G3–G5.
