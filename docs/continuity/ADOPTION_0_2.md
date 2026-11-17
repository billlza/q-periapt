# Continuity 0.2.0 normative adoption

This revision adopts the implemented Continuity contract for product version
0.2.0. `SPEC_LOCK_0_2.json` binds the normative documents, actual compiled
descriptor, package graph and separate interface identities. Final source CI,
chosen-package qualification, signing and the journaled publication transaction
remain necessary; specification adoption does not assert that those executions
or public publication have already completed.

The [source-bound internal assessment](RELEASE_0_2_INTERNAL_ASSESSMENT.md)
records the construction and implementation correspondence. The
[current analysis review](../../research/sdk-alpha1/evidence/20261117-release020-internal-review/REVIEW.md)
records the inspected input and critical-operation boundaries. Their original
sources and limits remain explicit. The user manages independent external
review separately.

## Selected contract

| Decision | Adopted meaning |
| --- | --- |
| Identity and bootstrap | Accountable ML-DSA-65 AND P-256 credentials and control signatures, independently enrolled account/device/policy/directory expectations, and the implemented exact three-flight bootstrap. The connection requires its root-bound epoch-zero ACK before reporting established. |
| Trust and time | The embedding host supplies independently authenticated trust, protected checkpoints and trusted time. Directory/TLS responses do not establish those expectations. Lost or contradictory authority suspends the affected operation; normal open/retry never provisions replacement trust. |
| Prekeys and directory | The declared reusable/one-time modes and the implemented accountable lease ledger, signed service identity, original-operation retry, consumption/tombstone retention, cancellation and conflict evidence. Reference-service operation remains subject to its explicit host/operator and freshness contracts. |
| PQ progress | The fixed full-hybrid accountable epoch-ratchet v6, four retained epochs, signed issuer-selected application allowance and independent control requests/steps. Callers schedule the explicit bounded operations; no undocumented background scheduler or default allowance is introduced. |
| Recovery analysis | The completed U1, joint entry/terminal connection, both original-source U2 adapters and U3 correspondence retain their declared observation, record-acquisition, identity, entropy and delivery assumptions. A progress counter alone does not establish recovery from an unknown compromise. |
| Padding and metadata | The exact wire encodings and no additional traffic-padding policy. The metadata contract retains visible identities, membership, timing, lengths, directory/Witness and local-state observations; it promises neither anonymity nor deniable control signatures. |
| Persistence and lifecycle | Original-operation reservation/reconciliation, commit-before-release, current-authority fences, device/account/key/credential/Witness renewal and explicit cleanup/recovery. The supported fanout transaction belongs to one original sender store and complete required roster; it is not atomic remote business delivery or an implicit distributed transaction across independent sender stores. |
| Workloads | All 21 joint implementation limits and the six selected desktop-reference ceilings in `SUPPORTED_WORKLOAD_BUDGETS_0_2.md`. The selected artifact must retain the applicable workload and replacement evidence. |
| Compatibility | The exact image/journal/installation/Witness/archive and maintenance-v2 edges in `COMPATIBILITY_0_2.md`. Unknown previews, missing original state and unsupported migration/downgrade paths retain explicit refusal without reset. |
| Platforms and packages | The already agreed API 37 phone, Apple Silicon macOS and existing Linux/Windows/iOS simulator scope. Twelve SDK registry crates remain separate from the formal Continuity Cargo source archive and its native, Swift, Kotlin, Android, browser and reference-service surfaces. |

The SDK C ABI stays **2**; the Continuity owner interface stays **`qpc-owner/1`**.
The 51 SDK and 158 Continuity exports remain distinct. No cryptographic domain,
signature-purpose byte, profile commitment, wire encoding or persistent tag is
renamed during adoption. In particular, historical `CANDIDATE` strings that are
part of authenticated bytes remain unchanged.

The stable package projection is retained in `PACKAGE_GRAPH_0_2.json`.
Per-build distribution documents live at `release/0.2.0/distributions/` in the
selected release inventory; their source and archive hashes belong to the outer
release manifest. The schema-2 lock keeps those metadata locations and package
identities fixed without placing a future build commit inside the normative
lock. Actual artifacts and completed qualification receipts are still mandatory
in release-mode manifest verification.

Earlier documents and execution packets retain their historical source identities.
Their former candidate-status labels do not change the bytes selected here or
turn an old execution into a new measurement. The current normative status is
this coordinated adoption and its exact lock; the final release evidence must
separately identify the selected source commit/tree and qualified artifacts.
