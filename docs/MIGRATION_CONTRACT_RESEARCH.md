# Authenticated Migration Contract — research status

> **Status: V2 reference candidate implemented.** Phase 1 remains frozen evidence.
> V2 adds authenticated transition state, a process-service reference, role-ordered
> confirmation, independent vectors, and EasyCrypt/Tamarin gates without changing
> ABI 2. This is not production/platform evidence: the rollback result requires a
> separately protected external witness, the Unix service boundary requires real
> deployment permissions and pinned credentials, and no formal-to-Rust refinement
> or device interoperability is claimed.

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
- [draft-irtf-cfrg-hybrid-kems-12, *Hybrid PQ/T Key Encapsulation Mechanisms*](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12)
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
  V1 frozen canonical context
  V2 authenticated transition/state/decision/confirmation
        |
        v
q-periapt-policy-agent (publish=false reference service)
  pinned roots / durable exact CAS / mandatory external witness
  frozen ABI2 KEM / pending secrets / accepted-key handles
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

### Phase 2 — authenticated transition state and Policy Agent (reference implemented)

The implemented typed state is:

```text
MigrationStateV1 = {
  global_generation,
  chain_id,
  protocol_id,
  epoch,
  previous_state_digest,
  authority_key_id,
  execution_policy_state,
  minimum_pq_level,
  component_mode,
  allowed_suite_bits
}

signature_message =
  LP8(certificate_domain) ||
  LP8(certificate_kind) ||
  LP8(canonical_state_body)

SignedMigrationStateV1 =
  LP8(certificate_kind) ||
  LP8(canonical_state_body) ||
  LP8(Sign_authority(signature_message))
```

The certificate verifier must bind exact canonical bytes, an authority lineage,
allowed floor transitions, and any exceptional reset. The state owner must perform
atomic compare-and-swap on the exact
`(global_generation, epoch, state_digest, writer_fence)` head. The digest commits
the chain, authority, execution state, posture, and suite set; same-generation or
same-epoch alternate digests are forks. Missing or corrupt storage must never
become implicit first enrollment. Reset must be separately authorized and bind the
old state to a new lineage.

A separately deployed Policy Agent/service is intended to own the pinned
authority root, monotonic state, transition verification, and session snapshot.
The reference Unix service implements the process boundary, but production OS
account, service-manager, credential, and directory isolation remain deployment
evidence rather than a repository claim. Transition verification, durable
reservation, and KEM use must operate on one immutable snapshot so concurrent
transition/session operations cannot create time-of-check/time-of-use gaps. A
same-process opaque handle is not a security boundary.

The V2 state implementation uses exact signed canonical bodies, explicit genesis,
non-resetting global generation, exact predecessor/epoch checks, non-weakening
posture, and a distinct recovery-authority reset. The reference Agent journals the
complete signed history and pending envelope in immediate-durability transactions,
re-verifies the chain on every open, and reconciles one exact operation with a
mandatory authenticated witness. Missing/corrupt state and witness disagreement
fail closed. A valid state that the frozen ABI 2 executor cannot implement remains
owned and recoverable but exposes no session executor; it is not converted into a
weaker suite or a poisoned repository. The local database is not itself a rollback
anchor.

### Phase 3 — authenticated agreement (reference implemented) and possible ABI 3

Define a protocol-level joint decision derived from:

- role-ordered authenticated identities and fresh session nonces;
- both complete capability offers and endpoint policies;
- the verified transition certificate and exact migration state;
- the common execution policy and selected suite/floor; and
- the complete pre-KEM and post-KEM transcripts.

V2 implements this joint decision using signed endpoint offers, sender-owned key
share commitments, a typed pre-KEM transcript, a fixed 324-byte V2 context, and a
post-KEM transcript. Finished uses role-separated inputs in one domain and a fixed
protocol-role order independent of KEM direction: initiator I; responder exact
state/witness recheck plus I verification/acceptance; responder R; then initiator
recheck plus R verification/acceptance. R is not externally returned until the
responder has durably released its reservation and retained both the accepted key
and bounded same-process retry state. The initiator likewise releases and retains
before returning its handle. Finished verification is constant-time, and failures
never expose a key or Finished response.

The Unix IPC boundary is a hard domain/schema V2 cut with separate accept-I and
accept-R commands; there is no V1 fallback. A lost successful response is
recoverable only by exact same-handle/same-Finished replay under a newly signed IPC
nonce, in the same process and while the accepted key is still live. The original
nonce remains rejected. Restart, destroy, or transition clears the response cache;
accepted keys and R are not crash-durable, while durable replay tombstones prevent
reuse of the old capability session.

Only after the model, experiments, and security games stabilize should an ABI 3 be
considered. Its likely surface uses process-owned `PolicyHandle`, `KeyHandle`, and
`SessionHandle` capabilities or performs cryptographic operations over IPC. It must
not mutate ABI 2 or pretend that a writable in-process token is unforgeable.

## 4. Target security notions

These are implemented reference notions with the proof boundaries stated below.

### MIG-BIND-K-STATE

If two accepted executions produce the same non-bottom session key, then, except
with negligible probability, their authenticated migration-state identities are
equal. `MigrationBindingV2.ec` proves the outer digest-identity reduction and a
full-state bad-event decomposition into ContextBound-hash or state-hash collision.
Signature authenticity remains a separate unforgeability assumption.

### MIG-ROLLBACK

After a principal has durably accepted state `i`, an adversary with old policies,
certificates, binaries, messages, and application control cannot cause later
acceptance under a predecessor or unauthorized fork. The game must model trusted
state ownership, authorized reset, crashes, recovery, concurrency, and state loss;
an epoch merely hashed into a key is insufficient. The Tamarin model includes a
restorable local store and protected witness/fence; the Rust reference implements
the matching exact intent/receipt protocol. The result is conditional on the
witness being outside the host rollback domain.

### MIG-AGREE

If both named peers accept the same session, they agree on roles, identities,
suite, migration epoch/state identity and transition semantics, floor, complete
capabilities, common execution decision, and transcript. Randomized signatures may
produce different certificate-envelope bytes for the same authenticated state, so
exact signature-byte equality is deliberately not claimed. This requires
authenticated negotiation and mutual key confirmation, not only “different context
gives a different key”. The Tamarin gate models both identity signatures and the
two role-separated Finished messages under an active network adversary, in the
fixed I -> responder accept/R -> initiator accept order. The Rust typestates and
reference service now follow that protocol-visible order regardless of KEM
direction, but tests and byte correspondence are not a formal Tamarin-to-Rust
refinement.

### MIG-FLOOR

No accepted execution falls below the effective authenticated migration floor.
The acceptance predicate—not parsing, metadata, or a post-validation flag—must
depend on all required PQ evidence. The model must define what the floor means for
hybrid, PQ-only, and forbidden-classical states rather than equating it with the
current policy engine's PQ-component NIST category. V2 uses a closed component-mode
predicate; the current hybrid ABI2 executor explicitly rejects `PostQuantumOnly`.

## 5. Proof and experiment gates

The reference-candidate gates are:

1. freeze state, certificate, negotiation, confirmation, and reset schemas;
2. produce independent exact-byte encoders and mutation/fuzz corpora;
3. mechanize context/state projection and omission controls;
4. prove rollback/agreement/floor properties in a model that includes acceptance,
   persistent state, fork/reset, and an active network adversary;
5. link the model's accepted decision to the exact bytes passed to ABI 2;
6. implement the Policy Agent with transaction/crash/concurrency tests; and
7. obtain independent cryptographic, protocol, service-boundary, and ABI review.

Gates 1–6 are wired into the repository's V2 reference checks. Gate 7 remains open
as an external review/deployment gate. The machine-checked models are abstract, and
the independent byte verifier is translation validation rather than refinement.

Until all relevant gates close, the repository must keep separate claims for:

- canonical-byte commitment;
- transition authenticity;
- durable rollback resistance;
- peer agreement and key confirmation;
- outcome-bearing floor enforcement;
- hostile-local-caller isolation; and
- product/platform interoperability.

Passing one gate is not evidence for the others. Exact schemas and operational
boundaries are in
[`migration/MIGRATION_CONTRACT_V2.md`](migration/MIGRATION_CONTRACT_V2.md).
