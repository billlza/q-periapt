# Authenticated Migration Contract — research plan

> **Status: staged research plan.** Only the phase-1 canonical context model is
> implemented. The authenticated state machine, transition certificates, policy
> service, acceptance protocol, security games, and ABI 3 handles described below
> are targets, not present guarantees.

## 1. Research question

Q-Periapt ABI 2 is the frozen execution substrate: exact-nine dynamic exports, a
40-byte authenticated-policy decision descriptor, a 36-byte trusted policy state,
and the existing `ContextBound` combiner domains and field order. The research
question above that substrate is:

> Can a session acceptance predicate be made dependent on one authenticated,
> monotonic, mutually agreed cryptographic-migration history, without changing the
> already evidenced ABI 2 byte contract?

The novelty boundary matters. NIST CSWP 39upd1 treats crypto agility as a mature
migration-engineering discipline, including operational mechanisms, trade-offs,
and risk management. RFC 7696 already requires integrity protection for algorithm
selection/negotiation to avoid downgrade. The CFRG hybrid-KEM Internet-Draft's
`UniversalCombiner` already computes over both component secrets, ciphertexts,
encapsulation keys, and a label. Therefore “put more fields in a hash”, crypto
agility itself, or integrity-protected negotiation are not research novelty.

Relevant baselines:

- [NIST CSWP 39upd1, *Considerations for Achieving Crypto Agility: Strategies and Practices*](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final)
- [RFC 7696, *Guidelines for Cryptographic Algorithm Agility and Selecting Mandatory-to-Implement Algorithms*](https://www.rfc-editor.org/rfc/rfc7696.html)
- [draft-irtf-cfrg-hybrid-kems-11, *Hybrid PQ/T Key Encapsulation Mechanisms*](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-11)
- Kim et al., [*Classical Acceptance Is Not Hybrid Authentication: Measuring
  X.509 Verifier Semantics in Post-Quantum Migration*](https://arxiv.org/abs/2607.20800)
  (July 2026 preprint; useful motivation, not a standard or peer-reviewed final
  result)

The candidate contribution is instead the conjunction of authenticated transition
semantics, monotonic state ownership, outcome-bearing acceptance, peer agreement,
and proof-to-byte enforcement.

## 2. Layering and dependency direction

```text
protocol handshake
  identity / capabilities / fresh transcript / key confirmation
        |
        v
q-periapt-migration (publish=false research model)
  canonical context now
  authenticated transition/state/decision later
        |
        | exact application-context body
        v
unchanged Q-Periapt ABI 2
  signed execution policy / ContextBound / ML-KEM-768 + X25519
```

`q-periapt-migration` may depend on `q-periapt-policy` and its closed authenticated
types. Product and publishable crates must not depend on the research model. The
model must not duplicate policy verification, parse raw 40-byte decisions, expose
new C symbols, or move protocol state into `q-periapt-core`.

## 3. Staged implementation

### Phase 1 — canonical commitment (implemented candidate)

- fixed `MigrationContextV1` with role normalization and exact LP8 encoding;
- fields derived from authenticated endpoint and common execution policies where
  existing types permit it;
- a strict ABI 2 adapter that accepts only its fixed suite/profile/key format;
- independent Rust/Python full-byte vectors and ABI 2 round-trip/mismatch tests;
- explicit pre-KEM transcript and key-confirmation boundaries.

Phase 1 does not authenticate the transition-state commitment and does not own
durable state. See [`migration/MIGRATION_CONTEXT_V1.md`](migration/MIGRATION_CONTEXT_V1.md).

### Phase 2 — authenticated transition state and Policy Agent

Freeze typed schemas for:

```text
MigrationStateV1 = {
  chain_id,
  epoch,
  current_policy_digest,
  previous_state_digest,
  security_floor,
  authority_key_id,
  transition_flags
}

TransitionCertificateV1 = Sign_authority(
  domain,
  previous_state_digest,
  next_state_digest,
  transition_rules,
  authority_rotation_evidence
)
```

The certificate verifier must bind exact canonical bytes, an authority lineage,
allowed floor transitions, and any exceptional reset. The state owner must perform
atomic compare-and-swap on `(chain_id, authority_key_id, epoch, state_digest)`;
same-epoch/different-digest is equivocation. Missing or corrupt storage must never
become implicit first enrollment. Reset must be separately authorized and bind the
old state to a new lineage.

An isolated Policy Agent/service owns the pinned authority root, monotonic state,
transition verification, and session snapshot. Transition verification, durable
reservation, and KEM use must operate on one immutable snapshot so concurrent
transition/session operations cannot create time-of-check/time-of-use gaps. A
same-process opaque handle is not a security boundary.

Phase 2 must add crash/failpoint tests for every durability cut, concurrent CAS,
rollback/fork/reset cases, and explicit recovery semantics before making a
monotonicity claim.

### Phase 3 — authenticated agreement and possible ABI 3

Define a protocol-level joint decision derived from:

- role-ordered authenticated identities and fresh session nonces;
- both complete capability offers and endpoint policies;
- the verified transition certificate and exact migration state;
- the common execution policy and selected suite/floor; and
- the complete pre-KEM and post-KEM transcripts.

Both parties must verify role-separated Finished/key-confirmation values before
acceptance or application-key release. Rejection destroys pending key material and
cannot fall back to a weaker or unbound path.

Only after the model, experiments, and security games stabilize should an ABI 3 be
considered. Its likely surface uses process-owned `PolicyHandle`, `KeyHandle`, and
`SessionHandle` capabilities or performs cryptographic operations over IPC. It must
not mutate ABI 2 or pretend that a writable in-process token is unforgeable.

## 4. Target security notions

These are definitions to refine and prove, not current results.

### MIG-BIND-K-STATE

If two accepted executions produce the same non-bottom session key, then, except
with negligible probability, their authenticated migration-state identities are
equal. The likely reduction reuses the existing injective context projection and
collision resistance, but must also link the authenticated state object to the
bytes actually consumed by the KDF.

### MIG-ROLLBACK

After a principal has durably accepted state `i`, an adversary with old policies,
certificates, binaries, messages, and application control cannot cause later
acceptance under a predecessor or unauthorized fork. The game must model trusted
state ownership, authorized reset, crashes, recovery, concurrency, and state loss;
an epoch merely hashed into a key is insufficient.

### MIG-AGREE

If both named peers accept the same session, they agree on roles, identities,
suite, migration epoch/state/certificate, floor, complete capabilities, common
execution decision, and transcript. This requires authenticated negotiation and
mutual key confirmation, not only “different context gives a different key”.

### MIG-FLOOR

No accepted execution falls below the effective authenticated migration floor.
The acceptance predicate—not parsing, metadata, or a post-validation flag—must
depend on all required PQ evidence. The model must define what the floor means for
hybrid, PQ-only, and forbidden-classical states rather than equating it with the
current policy engine's PQ-component NIST category.

## 5. Proof and experiment gates

Before describing the Migration Contract as a stateful cryptographic construction:

1. freeze state, certificate, negotiation, confirmation, and reset schemas;
2. produce independent exact-byte encoders and mutation/fuzz corpora;
3. mechanize context/state projection and omission controls;
4. prove rollback/agreement/floor properties in a model that includes acceptance,
   persistent state, fork/reset, and an active network adversary;
5. link the model's accepted decision to the exact bytes passed to ABI 2;
6. implement the Policy Agent with transaction/crash/concurrency tests; and
7. obtain independent cryptographic, protocol, service-boundary, and ABI review.

Until all relevant gates close, the repository must keep separate claims for:

- canonical-byte commitment;
- transition authenticity;
- durable rollback resistance;
- peer agreement and key confirmation;
- outcome-bearing floor enforcement;
- hostile-local-caller isolation; and
- product/platform interoperability.

Passing one gate is not evidence for the others.
