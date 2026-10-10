# Q-Periapt Continuity specification workspace

The [0.2.0 scope decision](RELEASE_0_2_SCOPE.md) now includes the full persistent
session, ongoing PQ recovery and multi-device work in this release. The component
checkpoint below does not mark the required product protocol complete.

> **Current boundary: G0 complete; G1 remains open.** The isolated candidate now
> executes authenticated bootstrap, persistent messages, hybrid rekey, witness
> reconciliation and cleanup, with scoped installed Rust, C, Swift and Kotlin/JVM
> checkpoints. Candidate wire, state, storage and metadata contracts describe
> that implementation. Product protocol freeze, construction analysis, complete
> authority lifecycle and current-source platform qualification remain required.

New native integrations start with the explicit configuration and registration
entry points: [C](../../bindings/c/ContinuityPackageConsumer/README.md#explicit-first-use-configuration),
[Swift](../../bindings/swift/ContinuityPackageConsumer/README.md), or
[Kotlin/JVM](../../bindings/kotlin/ContinuityPackageConsumer/README.md#first-use-configuration-unpublished-candidate).
These entries generate their own installation wrapping key and device signing
identity after independently supplied inputs are admitted. Account approval,
credential issuance and required-witness enrollment remain host-authorized steps.
The [product admission record](PRODUCT_ADMISSION.md) separates these implemented
paths from the remaining platform, protocol and release requirements.

This directory separates candidate specification text from the high-level research
plan in [`../CONTINUITY_RESEARCH.md`](../CONTINUITY_RESEARCH.md). A file appearing
here is not automatically frozen. G1 closes only when all required artifacts are
marked frozen, hashed by a future `SPEC_LOCK.json`, and the open-decision register is
empty.

## Current artifacts

| Artifact | Status | What it establishes |
|---|---|---|
| [`../../research/continuity-identity-candidate`](../../research/continuity-identity-candidate) | unpublished implementation candidate with its own workspace and lockfile | Required hybrid signatures, independently pinned identity/roster/policy, authenticated selection and three-flight confirmation; encrypted bootstrap journals, prekey inventory, protected signing owners and exact local write intents with real crash recovery. Required-witness release, durable roster revocation, four-flight hybrid rekeys and signed settled-history retirement now run through actual journals. Explicit closed-epoch reports preserve unknown delivery outcomes and require durable application accounting before retirement. Continuous recovery analysis, progress scheduling, directory consistency, device lifecycle and product integration remain required |
| [`PROTOCOL_V1.md`](PROTOCOL_V1.md) | candidate identity/authority and lifecycle decisions; open-decision register retained | Accountable bootstrap/control target, stage-specific delivery boundaries, exact retransmission, revocation and account transaction obligations; not a frozen handshake or ratchet |
| [`WIRE_V1.md`](WIRE_V1.md), [`BUDGETS_V1.json`](BUDGETS_V1.json) | implemented candidate grammar and compiled resource/profile comparison | Canonical public formats, existing signature purposes, epoch-separated ACK grammar, explicit independent trust inputs and unchanged resource bounds; measured product budgets and final freeze remain open |
| [`STATE_MACHINE_V1.md`](STATE_MACHINE_V1.md) | source-grounded candidate operation contract | Owned state, exact bootstrap reservations, commit/consumption distinction, rekey cutovers, send budgets, fanout and terminal accounting; explicit error/cancellation obligations for future adapters |
| [`STORAGE_RECOVERY_V1.md`](STORAGE_RECOVERY_V1.md) | implemented native storage and recovery contract | Original installation/key/path identity, exact pending intents, required-witness reconciliation, archive/application transaction boundaries and backup/migration limits |
| [`METADATA_PRIVACY_V1.md`](METADATA_PRIVACY_V1.md) | current observer and retention inventory | Public bundle, TLS versus plaintext witness path, local headers/indexes, private report correlations and compromise/erasure boundaries; no anonymity or traffic-analysis claim |
| [`RECOVERY_CONDITIONS_V1.md`](RECOVERY_CONDITIONS_V1.md) | candidate recovery obligations grounded in executed passive/active counterexamples | Separates progress from recovery, treats disclosed pending entropy reservations as exposed, and requires control-only traffic plus an authenticated progress budget; no unconditional recovery claim |
| [`SEND_PROGRESS_V1.md`](SEND_PROGRESS_V1.md) | signed budget implemented in isolated v5 candidate; scheduler and product value open | Bounds committed and reserved sends across local rekey confirmation without refund from ACKs, restart or old-epoch resolution; exact pending input and committed output remain recoverable |
| [`../../research/continuity-identity-candidate/CONTROL_PROGRESS.md`](../../research/continuity-identity-candidate/CONTROL_PROGRESS.md) | signed request and explicit-target step driver implemented in isolated v6 candidate | An idle designated proposer responds without dummy application traffic; durable exact output, bounded loss/duplicate/cancellation schedules and process/lock/fault cuts are exercised. Product transport scheduling and installed endpoints remain open |
| [`../../research/continuity-identity-candidate/CONTROL_TLS.md`](../../research/continuity-identity-candidate/CONTROL_TLS.md) | optional native carrier over the SDK standard mutual TLS connection | Separate-process loopback controls, five committed-reply process cuts, cancellation/socket closure, deadline, identity and stale-target failures are exercised. Bootstrap delivery, cross-host and installed language paths remain open |
| [`../../research/continuity-identity-candidate/FANOUT.md`](../../research/continuity-identity-candidate/FANOUT.md) | complete-roster sends under one device journal and its aggregate witness | All required slots and all ciphertexts commit as aggregates; reserved members cannot escape through unary APIs. Mixed roles, partial ACK/accounting, storage faults, process loss and witness reply loss are exercised. Distributed sender-store transactions, complete device lifecycle and installed service integration remain open |
| [`REFERENCE_BASELINE.md`](REFERENCE_BASELINE.md), [`reference-baseline.json`](reference-baseline.json), and the [`reference_baseline.py`](../../artifact/reference_baseline.py) verifier | selected revisions/reproducible content hashes; partial byte lock; integration profile open | Immutable IETF archives and pinned Git commit plus tested versioned raw/normalized drift hashes for mutable publisher pages; not archival completeness or interoperability |
| [`G1_EFFECT_LIFECYCLE.md`](G1_EFFECT_LIFECYCLE.md) | candidate contract, exercised by a test-only model | Reservation/effect/result/anchor-plan/commit/idempotent-release-ack ordering and fail-closed unknown outcomes |
| [`../../research/continuity-identity-candidate/ANCHOR_WITNESS.md`](../../research/continuity-identity-candidate/ANCHOR_WITNESS.md) | actual signed witness/provider candidate | Persistent full-head/fence comparison, fresh reply binding and unknown-outcome recovery; signed required-anchor policy now gates journal admission, application and release. Independent witness deployment and authority renewal remain required |
| [`../../research/continuity-spqr-reference`](../../research/continuity-spqr-reference) | isolated pinned upstream execution reference | Seven deterministic traffic corpora, actual message-key agreement, strict byte/accounting verification and one-way no-progress counterexample. This is neither the full reference manager composition nor a product dependency or complete ratchet-selection comparison |
| [`LIFECYCLE_CONTEXT_V1.md`](LIFECYCLE_CONTEXT_V1.md) | candidate canonical model metadata | Exact Bootstrap/RootTransition LP8 bodies, signed-policy K-CTX wrapper and digest preimage; not identity authentication, wire interoperability or ratchet security |
| [`PREKEY_SELECTION_V1.md`](PREKEY_SELECTION_V1.md) | candidate canonical nested selection record | Exact 492-byte strict record and 555-byte digest preimage; lossless classical/PQ quality plus suite/responder/checkpoint cross-binding; not manifest authenticity, single use, directory consistency or rollback protection |
| [`../../formal/easycrypt/continuity`](../../formal/easycrypt/continuity) | non-normative formal diagnostics | Lifecycle and Prekey LP8 injectivity plus explicit policy/direction and named prekey-field omission collisions; not projection completeness, SHA3 injectivity, Rust refinement, authentication or protocol security |
| [`../../models/q-periapt-continuity-model`](../../models/q-periapt-continuity-model) | non-normative executable model | 52 Rust tests: 31 lifecycle integration tests including one five-mutant oracle, 12 canonical-context tests, eight strict prekey-selection tests, and one private receipt-atomicity regression. The model covers schema-3 trusted canonical context admission, atomic B21-B23 derivation, exact version+digest state advances, no-op-anchor rejection, typed persist/evidence subjects, volatile-result scrubbing, exact pending-write/suspension replay, and abstract snapshot reconstruction; operational payloads remain opaque, provider selection remains caller-authoritative, and this is not context advancement, identity authentication, exhaustive exploration, or real durability |

## Required before G1 can close

The following authoritative artifacts must be complete and frozen; the current
protocol candidate and lifecycle model do not supply missing definitions:

1. `PROTOCOL_V1.md` (candidate exists): chosen accountable-versus-deniable profile, identity trust chain,
   trusted genesis/migration rules, zero-RTT and confirmation
   permissions, prekey lifecycle, ratchet selection, policy and migration semantics.
2. `WIRE_V1.md` (candidate exists): protocol ID, exact canonical grammar, field limits, padding and
   unknown/critical-field behavior.
3. `STATE_MACHINE_V1.md` (candidate exists): bootstrap, ordinary-message and chosen
   hybrid PQ rekey transitions, including bounded reorder/loss behavior and the
   construction's implementation correspondence.
4. `STORAGE_RECOVERY_V1.md` (candidate exists): sealed state/journal encoding, repository contract,
   real anchor profile, fanout, retention, backup and restore rules.
5. `METADATA_PRIVACY_V1.md` (candidate exists): complete server-visible surface, linkability goals,
   fingerprinting rules, receipt and lookup behavior.
6. `BUDGETS_V1.json` (implemented limits exist): product numeric per-session/account/global quotas, durable latency,
   cold/cached bootstrap, energy/thermal, recovery, and convergence thresholds.
7. `SPEC_LOCK.json`: content digests and explicit frozen/open status for every
   normative artifact and external specification revision.

Until then, code in the model directory remains test-only and no product crate or
binding may depend on it.
