# Rust snapshots retained by the bootstrap proof packets

The CodeQL source census at paper commit `4fde471641150c68a08b56e728067c72b39ab346` contains 174 tracked Rust files: 106 current sources and the 68 snapshots below. These snapshots preserve the implementation inputs assessed by the proof packets. They are partial source exports with no Cargo manifests, not additional compilation roots.

`codeql_rust_quality.py` pins the exact five `SOURCE_PINS.json` manifests. Each manifest binds every listed file by original path, byte length, SHA-256 and Git blob identity. Inventory admission checks those identities against the current checkout before accepting the database. Every one of the 174 files must be present in the extracted database and remains an input to the unchanged security queries.

The 106 current sources must have successful extraction, zero warnings and zero unresolved source macros. Each of the 68 partial snapshots must have precisely one CodeQL 2.26.2 warning with tag `semantics`, location 1:1 and message `semantic analyzer unavailable (not included in files loaded from manifest)`. The complete message must append `: macro expansion will be skipped.` The gate checks every diagnostic individually and rejects all other diagnostics. Macro details may name only those exact authenticated snapshots; their counts must reconcile with the complete database and per-file inventory. Current-source macro and format-argument sentinels remain nonzero. All extraction errors, unextracted elements and the existing zero consistency and format-argument metrics remain failures. A retained source packet cannot acquire a Cargo manifest above a source file.

`Metrics.ql` retains its global metric formulas and adds tagged rows for the complete extracted path set, per-file macro/format-argument counts, and the path, severity, tag, short and full messages, line and column of all extraction warnings and errors. These rows cross-check the global metrics and unchanged successful-path and unresolved-macro queries. This explicitly records the partial exports' available syntax and original-source provenance while qualifying the current Cargo compilation for semantic analysis. The existing proof-input digest covers the complete query; there is no new unbound query dependency.

For each table, the retained path is `paper/continuity/artifacts/bootstrap/<packet>/source/` followed by the original path in its first column. The source commit is the historical identity from that packet, not the current build commit.

## ack: 19 Rust snapshots

ACK source census and durable message transition inputs.

Assessed source commit: `471900bfe8070d1021a1feb67481437d599d80ba`. [Pinned source manifest](../paper/continuity/artifacts/bootstrap/ack/SOURCE_PINS.json).

| Original source path | Retained role |
| --- | --- |
| `research/continuity-identity-candidate/src/durable/messages.rs` | Durable message dispatch and state integration |
| `research/continuity-identity-candidate/src/durable/messages/acknowledgement.rs` | Acknowledgement creation and processing |
| `research/continuity-identity-candidate/src/durable/messages/closure.rs` | Closure message processing |
| `research/continuity-identity-candidate/src/durable/messages/closure/archive.rs` | Archived closure state |
| `research/continuity-identity-candidate/src/durable/messages/delivery.rs` | Delivery state transitions |
| `research/continuity-identity-candidate/src/durable/messages/fanout.rs` | Fanout message state |
| `research/continuity-identity-candidate/src/durable/messages/fanout/abandonment.rs` | Fanout abandonment transition |
| `research/continuity-identity-candidate/src/durable/messages/fanout/archive.rs` | Archived fanout state |
| `research/continuity-identity-candidate/src/durable/messages/fanout/codec.rs` | Fanout encoding and decoding |
| `research/continuity-identity-candidate/src/durable/messages/progress.rs` | Message progress tracking |
| `research/continuity-identity-candidate/src/durable/messages/rekey.rs` | Rekey message flow |
| `research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs` | Rekey completion transition |
| `research/continuity-identity-candidate/src/durable/messages/rekey/driver.rs` | Rekey driver state |
| `research/continuity-identity-candidate/src/durable/messages/rekey/request.rs` | Rekey request processing |
| `research/continuity-identity-candidate/src/durable/messages/rekey/response.rs` | Rekey response processing |
| `research/continuity-identity-candidate/src/durable/messages/resolution.rs` | Message resolution state |
| `research/continuity-identity-candidate/src/durable/messages/retired.rs` | Retired message state |
| `research/continuity-identity-candidate/src/durable/messages/terminal.rs` | Terminal message transition |
| `research/continuity-identity-candidate/src/durable/messages/traffic.rs` | Traffic-key derivation and message processing |

## entry: 2 Rust snapshots

Joint bootstrap Extract and shared-compression encoding inputs.

Assessed source commit: `b1cff2a045d23aecf75aef12122e5080a8419676`. [Pinned source manifest](../paper/continuity/artifacts/bootstrap/entry/SOURCE_PINS.json).

| Original source path | Retained role |
| --- | --- |
| `crates/q-periapt-sdk/src/purpose.rs` | SDK Extract salt and purpose derivation |
| `research/continuity-identity-candidate/src/bootstrap.rs` | Bootstrap secret combination, transcript and confirmation flow |

## initial: 20 Rust snapshots

Original prekey generation and initial confirmation source adapter inputs.

Assessed source commit: `471900bfe8070d1021a1feb67481437d599d80ba`. [Pinned source manifest](../paper/continuity/artifacts/bootstrap/initial/SOURCE_PINS.json).

| Original source path | Retained role |
| --- | --- |
| `crates/q-periapt-backends/src/contextbound_key.rs` | ContextBound expanded-key binding and restore input |
| `crates/q-periapt-backends/src/lib.rs` | Backend primitive and key serialization definitions |
| `crates/q-periapt-core/src/lib.rs` | Core KEM interface and shared-secret types |
| `crates/q-periapt-sdk/src/expert.rs` | Expert SDK primitive interface |
| `crates/q-periapt-sdk/src/expert/replay.rs` | Replay-tape primitive input handling |
| `crates/q-periapt-sdk/src/lib.rs` | SDK facade and implementation bindings |
| `research/continuity-identity-candidate/src/bootstrap.rs` | Bootstrap secret combination, transcript and confirmation flow |
| `research/continuity-identity-candidate/src/bootstrap/response_staged.rs` | Staged responder bootstrap transition |
| `research/continuity-identity-candidate/src/bootstrap/staged.rs` | Staged initiator bootstrap transition |
| `research/continuity-identity-candidate/src/contract.rs` | Protocol contract and wire-domain constants |
| `research/continuity-identity-candidate/src/crypto.rs` | Continuity primitive adapter |
| `research/continuity-identity-candidate/src/durable.rs` | Durable state and event definitions |
| `research/continuity-identity-candidate/src/durable/initiator.rs` | Durable initiator bootstrap processing |
| `research/continuity-identity-candidate/src/durable/messages.rs` | Durable message dispatch and state integration |
| `research/continuity-identity-candidate/src/durable/messages/traffic.rs` | Traffic-key derivation and message processing |
| `research/continuity-identity-candidate/src/durable/prekeys.rs` | Prekey reservation and publication history |
| `research/continuity-identity-candidate/src/durable/responder.rs` | Durable responder bootstrap processing |
| `research/continuity-identity-candidate/src/durable/write_intent.rs` | Durable write intent and commit ordering |
| `research/continuity-identity-candidate/src/manifest.rs` | Credential manifest and published bootstrap inputs |
| `research/continuity-identity-candidate/src/selection.rs` | Selected bootstrap component attribution |

## reply: 18 Rust snapshots

Original reply generation, response encapsulation and key restore source adapter inputs.

Assessed source commit: `68549dbc3ae4491d8b5edaa708548dc60743eab7`. [Pinned source manifest](../paper/continuity/artifacts/bootstrap/reply/SOURCE_PINS.json).

| Original source path | Retained role |
| --- | --- |
| `crates/q-periapt-backends/src/contextbound_key.rs` | ContextBound expanded-key binding and restore input |
| `crates/q-periapt-backends/src/lib.rs` | Backend primitive and key serialization definitions |
| `crates/q-periapt-core/src/lib.rs` | Core KEM interface and shared-secret types |
| `crates/q-periapt-sdk/src/expert.rs` | Expert SDK primitive interface |
| `crates/q-periapt-sdk/src/expert/replay.rs` | Replay-tape primitive input handling |
| `crates/q-periapt-sdk/src/lib.rs` | SDK facade and implementation bindings |
| `research/continuity-identity-candidate/src/bootstrap.rs` | Bootstrap secret combination, transcript and confirmation flow |
| `research/continuity-identity-candidate/src/bootstrap/response_staged.rs` | Staged responder bootstrap transition |
| `research/continuity-identity-candidate/src/bootstrap/staged.rs` | Staged initiator bootstrap transition |
| `research/continuity-identity-candidate/src/contract.rs` | Protocol contract and wire-domain constants |
| `research/continuity-identity-candidate/src/crypto.rs` | Continuity primitive adapter |
| `research/continuity-identity-candidate/src/durable.rs` | Durable state and event definitions |
| `research/continuity-identity-candidate/src/durable/initiator.rs` | Durable initiator bootstrap processing |
| `research/continuity-identity-candidate/src/durable/messages.rs` | Durable message dispatch and state integration |
| `research/continuity-identity-candidate/src/durable/messages/traffic.rs` | Traffic-key derivation and message processing |
| `research/continuity-identity-candidate/src/durable/prekeys.rs` | Prekey reservation and publication history |
| `research/continuity-identity-candidate/src/durable/responder.rs` | Durable responder bootstrap processing |
| `research/continuity-identity-candidate/src/durable/write_intent.rs` | Durable write intent and commit ordering |

## terminal: 9 Rust snapshots

Bootstrap terminal agreement and sibling schedule source connection inputs.

Assessed source commit: `360aa8107aa7df502108627a4dcf89f30d106594`. [Pinned source manifest](../paper/continuity/artifacts/bootstrap/terminal/SOURCE_PINS.json).

| Original source path | Retained role |
| --- | --- |
| `research/continuity-identity-candidate/src/bootstrap.rs` | Bootstrap secret combination, transcript and confirmation flow |
| `research/continuity-identity-candidate/src/bootstrap/response_staged.rs` | Staged responder bootstrap transition |
| `research/continuity-identity-candidate/src/bootstrap/staged.rs` | Staged initiator bootstrap transition |
| `research/continuity-identity-candidate/src/contract.rs` | Protocol contract and wire-domain constants |
| `research/continuity-identity-candidate/src/crypto.rs` | Continuity primitive adapter |
| `research/continuity-identity-candidate/src/durable/initiator.rs` | Durable initiator bootstrap processing |
| `research/continuity-identity-candidate/src/durable/messages.rs` | Durable message dispatch and state integration |
| `research/continuity-identity-candidate/src/durable/messages/traffic.rs` | Traffic-key derivation and message processing |
| `research/continuity-identity-candidate/src/durable/responder.rs` | Durable responder bootstrap processing |

## Relationship to the current implementation

Each packet records the exact historical implementation assessed by its proof and source controls. The paper branch contains 106 current Rust sources; the partial bootstrap source exports preserve additional assessed research inputs without creating new Cargo compilation roots. The current checkout and the historical input commits keep their separate identities.

Changes to the retained source set require an explicit review of this inventory and its pinned manifests. Missing, substituted, modified or additional snapshot paths fail admission; adding a Cargo manifest above a retained source also fails. Current source additions continue to require the existing exact inventory update and quality checks.
