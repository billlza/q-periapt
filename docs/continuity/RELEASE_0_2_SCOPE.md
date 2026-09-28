# Continuity in the 0.2.0 release

The release scope changed on 2026-09-28: persistent sessions, fresh-PQ rekeying,
disconnect recovery, revocation, continuous PQ recovery and multi-device lifecycle
are required in **0.2.0**. Earlier scheduling that placed these capabilities in a
later release is superseded. The SDK ownership, ContextBound, native-backend,
standard-TLS, binding, installation, device and performance requirements remain.
ABI major remains **2**.

This is a requirements and implementation-boundary record. It does not promote
the existing public-commitment model into a working cryptographic protocol.

## Current implementation boundary

- `q-periapt-sdk` owns verified policy runtimes and coupled KEM keys, with explicit
  purpose derivation, policy transitions and bounded lifetimes. Its optional
  [sealed operation interface](../SDK_SEALED_OPERATIONS.md) reserves platform KEM
  randomness for exact policy/input-bound recovery. It has no message ratchet or
  session-secret persistence; its sealed operations now back the candidate's staged
  initiator and responder; prekey/signing-owner persistence remains required.
- `q-periapt-rustls::connection` supplies the authenticated reference connection,
  policy confirmation, bounded request/response transport and revocation. A TLS
  connection or symmetric TLS key update does not establish continuous PQ recovery.
- `q-periapt-host-store` persists signed policy through protected files and redb,
  including uncertain commit and activation failure. It does not store encrypted
  ratchet state, inboxes, outboxes or device rosters.
- `q-periapt-continuity-model` is `publish = false` and represents public
  commitments and trusted adapter outcomes. It contains neither cryptographic
  payloads nor a real storage/provider adapter. Its lifecycle counterexamples and
  canonical-context tests are useful design inputs, not product execution.
- `research/continuity-identity-candidate` implements an isolated actual-signature
  root/credential/roster/manifest chain, Merkle membership verification and a
  canonical selection derived from the actual authenticated members. It also
  supplies a signed session policy, three-flight confirmed bootstrap and an
  encrypted device journal with real initiator/responder reservation/result/outbox
  commits and restart from saved private state. Both roles seal KEM/signing commands
  before execution and recover exact results across pre-pin crashes. The responder
  stores its admitted first contribution; earlier recovery still needs its prekeys.
  Its own lockfile and public-byte/OpenSSL verifier remain separate.
  Prekey secret inventory, ratchet, exact anchor-intent replay and
  rollback protection remain required work.

## Required completion evidence

| Capability | Implementation obligation | Evidence required before completion |
| --- | --- | --- |
| Protocol and identity | Separate Continuity identifier, wire version, closed cryptographic profile, authenticated account/device identity and canonical context | Complete protocol/wire/state specifications, strict parsing and independent vectors; authentication, replay, cross-device and downgrade analysis |
| Persistent pairwise sessions | Owned secret state, one-use message keys, bounded skipped keys, atomic state/inbox/outbox transitions and exact-operation reconciliation | Real encrypted storage, crash injection at each durability/release boundary, restart/duplicate/race/cancellation tests and no plaintext release before commit |
| Fresh-PQ rekeying | Fresh post-quantum material introduced and confirmed according to the selected protocol, with a non-negotiable policy floor | Wire/state traces for both roles; update collisions, lost acknowledgements, old-epoch traffic, revoked peers, expiry, overflow and unknown outcomes |
| Disconnect and rollback recovery | Exact committed outbox replay, retained deduplication, suspended uncertain operations and an explicit trusted rollback-anchor contract | Real multi-process restart and restored-snapshot tests; an old snapshot cannot silently reset message-key or nonce state within the claimed anchor profile |
| Continuous PQ recovery | A construction-specific recovery condition under explicit compromise, authentication and delivery assumptions | Protocol analysis and adversarial compromise traces, implementation correspondence and matched reference comparisons; elapsed time or a symmetric key update cannot substitute |
| Multi-device lifecycle | Independent device identities/sessions, enrollment, fresh signed roster, revocation, device replacement and account-wide fanout transactions | Multi-device process tests covering roster races, partial external-anchor progress, duplicate delivery, stale devices, equivocation and required-recipient failures |
| Cross-language and package integration | Shared protocol implementation behind owned Rust/C/Swift/Kotlin/Android/WASM interfaces and actual package consumers | Canonical vectors, the same failure/close/cancel semantics, installed cross-language connections and current/minimum platform execution |
| Performance and final release | Measured session lifecycle, durable latency, recovery, bandwidth, memory, concurrency and energy under the same security contract | Source/binary-bound baselines and results, quality/maintainability review, final exact-source checks, signed distributions where required and the release transaction |

## Dependency and authority boundaries

The cryptographic composition crate remains dependency-free. Account, ratchet,
network and persistence logic belongs above its existing primitive contracts.
The research/reference lane remains separate from the product implementation;
production code cannot acquire authority by depending on a test-model receipt.

One repository transaction must cover each affected session revision, consumed
prekey/deduplication record, inbox release and immutable outbox. Unknown commit
results close the operation to new work until the exact operation is reconciled.
External anchors require their own durable intent and reconciliation; local
database atomicity alone cannot prove that a wholly restored snapshot is fresh.

Ordinary application sends must not release candidate ciphertext before commit.
Receives must not release candidate plaintext or advance an unrelated session on
failure. Multi-device fanout commits all required recipients together before any
item becomes dispatchable. Explicit exclusions must be observable to the caller.

The current ABI 2 functions retain their meanings and ownership contracts.
Continuity must not be smuggled into an existing protocol/group identifier or a
serialized policy-decision blob. Any additive binding surface requires a precise
versioned contract and matching export/registration checks before qualification.

## Implementation sequence within 0.2.0

1. Complete `PROTOCOL_V1.md`, `WIRE_V1.md`, `STATE_MACHINE_V1.md`,
   `STORAGE_RECOVERY_V1.md`, `METADATA_PRIVACY_V1.md`, `BUDGETS_V1.json` and
   `SPEC_LOCK.json`. Resolve authentication semantics, bootstrap/confirmation
   permissions, ratchet selection, rollback-anchor profile and resource bounds
   before presenting the protocol as frozen.
2. Implement and test authenticated pairwise establishment, message protection
   and real transactional persistence with owned secrets and explicit failures.
3. Implement fresh-PQ transitions, continuous recovery, disconnect reconciliation
   and revocation, keeping the protocol and storage models aligned with the code.
4. Add account/device lifecycle and atomic fanout, then integrate the shared
   service into every supported language and installed-package path.
5. Complete the reference comparisons, model-to-implementation checks, current
   device/network matrix, performance measurements and final release audit.

Every step belongs to 0.2.0; completing an intermediate component does not close
the full release goal. Research hypotheses about superiority remain hypotheses
until their specific proof or experiment supports the claim.
