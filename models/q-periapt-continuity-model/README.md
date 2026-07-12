# Q-Periapt Continuity lifecycle model

This crate is a **non-normative, test-only executable model** for the persistence
and external-effect ordering proposed by the future Q-Periapt Continuity research
line. It is `publish = false`, has no dependencies, and is not consumed by any
product, binding, FFI, provider, or protocol crate.

The model deliberately contains no real cryptography, secret key, plaintext,
network wire format, database adapter, identity protocol, prekey protocol, or
ratchet. Command, result, state, journal, and anchor contents remain opaque typed
commitments. The exception is a candidate structured `LifecycleContextV1` metadata
projection plus a strict sixteen-field `PrekeySelectionV1` inner record. Independent
Python encoders/decoders and frozen SHA3 vectors check both byte layers. Their purpose
is to falsify unsafe lifecycle semantics before a production API is frozen:

```text
prepare
  -> persist effect reservation
  -> execute or query the exact provider operation
  -> validate one complete result
  -> service constructs and persists the first result-pin record
  -> persist the exact finalization/anchor plan
  -> reconcile the policy-bound external anchor, when required
  -> atomically commit an exact idempotent release record
  -> replay the same release until its acknowledgement is durable
```

The model fixes the trusted protocol/policy/anchor scope before `prepare`, derives
retry behavior and expected result shape from a closed operation variant, and never
accepts a provider-supplied storage record or state digest. Its abstract
`TransitionModel` and `DurableSnapshot` now also retain one trusted pairwise
`SessionIdentity` and the exact current `AuthenticatedContext`. The latter can only be
constructed from canonical lifecycle bytes, one policy digest, and an explicit
fallible digest adapter; stage and digest cannot be selected independently. Bootstrap
B21-B23 are likewise derived from one canonical selection; callers cannot attach an
opaque digest to a separately chosen quality/manifest tuple. A draft
that changes the protocol, policy, session, either device, context, or incompatible
Bootstrap/RootTransition purpose fails before reservation. This closes structural
grafting in the lifecycle model without pretending that canonical bytes authenticate
their fields.

The abstract `DurableSnapshot` carries stable states plus the exact journaled intent for every
in-flight repository or suspension write. The old process object can be destroyed and
a new model reconstructed to query that same intent. Each repository stage has a
typed `PersistSubject`; every write carries an indivisible
`StateAdvance { expected(version,digest), next(version,digest) }`, so same-version /
different-digest repository state is a conflict. A pending result pin retains only the accepted result kind and
public commitment, not the unpinned provider result object. Provider success cannot
later be contradicted by failure/unknown without durable suspension. A security
failure first latches its initial cause, reconciles any possibly committed write, and
then appends a suspension intent with typed fence/repository evidence when one exists;
recovery only re-emits that quarantine. This catches volatile-result,
forgotten-unknown-write, overwritten-first-cause, volatile-suspension, and
volatile-release mistakes; it is not a database encoding or durability adapter.

A green model run currently means only that 31 lifecycle integration tests (including
one independent five-mutant safety-oracle test), 12 canonical-context tests, eight
strict prekey-selection tests, and one private receipt-atomicity regression satisfy
these model invariants. They include
same-version/different-digest CAS, wrong-prior-digest receipt reconciliation, and
pre-mutation rejection of a no-op per-transition anchor. They do **not**
prove G1 complete, exhaustive state exploration, fsync/WAL/torn-write behavior,
backup cleanliness, provider idempotence, Secure Enclave behavior, PQXDH/Triple
Ratchet interoperability, credential authenticity, UKS/KCI resistance, prekey
single-use, FS/PCS, rollback protection, or proof-to-state-to-byte.
Those remain separate gates in `docs/CONTINUITY_RESEARCH.md`.

The separate `formal/easycrypt/continuity` diagnostics prove LP8 injectivity only for
their modeled Lifecycle and Prekey projections and give explicit policy/direction and
named prekey-field omission collisions. They prove neither SHA3 injectivity nor that
the Rust encoders refine those models, and do not upgrade a green model run into
protocol or release evidence.

The integration precondition is intentionally explicit: before executing any
external `Effect`, a future host must atomically persist and durability-confirm the
corresponding snapshot/journal intent. `CryptoCompletion`, repository and anchor
outcomes, `CommitReceipt`, and `SuspensionReceipt` are trusted authenticated-oracle
inputs in this model. A real adapter must define their canonical bytes and
authentication, enforce journal-ack-before-effect, and survive
process-kill/fsync/WAL/torn-write tests. Until then, an effect emitted just before a
host crash remains an integration P0, not a model-level proof result.

`TransitionModel::new` is also a trusted genesis/migration boundary: this model cannot
prove that its initial account/device credentials, roster, directory checkpoint,
prekey selection, policy or transcript commitments are authentic. It deliberately has
no context-advance API. `PrekeyAuthenticated`, `PeerConfirmed`, and
`MutuallyConfirmed` are peer-agreed candidate stages; local zero-RTT/outbox/delivery
state is not encoded as an authentication stage. Confirmation evidence, privilege
gates, prekey consumption, ratchet behavior, rejection/deduplication, and
session-level availability semantics remain open G1 work.

`ProviderBinding` is caller-selected draft data in this model. Complete echo equality
prevents an in-flight profile/epoch swap, but `prepare` does not prove that policy
authorized the selected provider, that its epoch is current, or that a downgrade was
prevented. Those are host/policy authority obligations until operation-specific
provider profiles are frozen.
