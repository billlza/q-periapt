# Q-Periapt Continuity specification workspace

> **Status on 2026-07-12: G0 complete; G1 partially started.** The only
> executable artifact is a non-normative, public-commitment lifecycle model.
> There is no Continuity wire protocol, identity/prekey protocol, ratchet,
> production state crate, or security claim.

This directory separates candidate specification text from the high-level research
plan in [`../CONTINUITY_RESEARCH.md`](../CONTINUITY_RESEARCH.md). A file appearing
here is not automatically frozen. G1 closes only when all required artifacts are
marked frozen, hashed by a future `SPEC_LOCK.json`, and the open-decision register is
empty.

## Current artifacts

| Artifact | Status | What it establishes |
|---|---|---|
| [`REFERENCE_BASELINE.md`](REFERENCE_BASELINE.md), [`reference-baseline.json`](reference-baseline.json), and the [`reference_baseline.py`](../../artifact/reference_baseline.py) verifier | selected revisions/reproducible content hashes; partial byte lock; integration profile open | Immutable IETF archives and pinned Git commit plus tested versioned raw/normalized drift hashes for mutable publisher pages; not archival completeness or interoperability |
| [`G1_EFFECT_LIFECYCLE.md`](G1_EFFECT_LIFECYCLE.md) | candidate contract, exercised by a test-only model | Reservation/effect/result/anchor-plan/commit/idempotent-release-ack ordering and fail-closed unknown outcomes |
| [`LIFECYCLE_CONTEXT_V1.md`](LIFECYCLE_CONTEXT_V1.md) | candidate canonical model metadata | Exact Bootstrap/RootTransition LP8 bodies, signed-policy K-CTX wrapper and digest preimage; not identity authentication, wire interoperability or ratchet security |
| [`PREKEY_SELECTION_V1.md`](PREKEY_SELECTION_V1.md) | candidate canonical nested selection record | Exact 492-byte strict record and 555-byte digest preimage; lossless classical/PQ quality plus suite/responder/checkpoint cross-binding; not manifest authenticity, single use, directory consistency or rollback protection |
| [`../../formal/easycrypt/continuity`](../../formal/easycrypt/continuity) | non-normative formal diagnostics | Lifecycle and Prekey LP8 injectivity plus explicit policy/direction and named prekey-field omission collisions; not projection completeness, SHA3 injectivity, Rust refinement, authentication or protocol security |
| [`../../models/q-periapt-continuity-model`](../../models/q-periapt-continuity-model) | non-normative executable model | 52 Rust tests: 31 lifecycle integration tests including one five-mutant oracle, 12 canonical-context tests, eight strict prekey-selection tests, and one private receipt-atomicity regression. The model covers schema-3 trusted canonical context admission, atomic B21-B23 derivation, exact version+digest state advances, no-op-anchor rejection, typed persist/evidence subjects, volatile-result scrubbing, exact pending-write/suspension replay, and abstract snapshot reconstruction; operational payloads remain opaque, provider selection remains caller-authoritative, and this is not context advancement, identity authentication, exhaustive exploration, or real durability |

## Required before G1 can close

The following authoritative artifacts do not yet exist and must not be inferred from
the lifecycle model:

1. `PROTOCOL_V1.md`: chosen accountable-versus-deniable profile, identity trust chain,
   trusted genesis/migration rules, zero-RTT and confirmation
   permissions, prekey lifecycle, ratchet selection, policy and migration semantics.
2. `WIRE_V1.md`: protocol ID, exact canonical grammar, field limits, padding and
   unknown/critical-field behavior.
3. `STATE_MACHINE_V1.md`: complete bootstrap, ordinary-message, classical and sparse
   PQ ratchet transitions, including bounded reorder/loss behavior.
4. `STORAGE_RECOVERY_V1.md`: sealed state/journal encoding, repository contract,
   real anchor profile, fanout, retention, backup and restore rules.
5. `METADATA_PRIVACY_V1.md`: complete server-visible surface, linkability goals,
   fingerprinting rules, receipt and lookup behavior.
6. `BUDGETS_V1.json`: numeric per-session/account/global quotas, durable latency,
   cold/cached bootstrap, energy/thermal, recovery, and convergence thresholds.
7. `SPEC_LOCK.json`: content digests and explicit frozen/open status for every
   normative artifact and external specification revision.

Until then, code in the model directory remains test-only and no product crate or
binding may depend on it.
