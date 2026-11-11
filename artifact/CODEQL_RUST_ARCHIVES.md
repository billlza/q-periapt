# Rust snapshots retained by the bootstrap proof packets

The CodeQL source census at integration commit `0e2ca2d79ab0000bed79130cec97b31181e936ea` contains 1241 tracked Rust files: 1173 current sources and the 68 snapshots below. These snapshots preserve the implementation inputs assessed by the proof packets. They are partial source exports with no Cargo manifests, not additional compilation roots.

`codeql_rust_quality.py` pins the exact five `SOURCE_PINS.json` manifests. Each manifest binds every listed file by original path, byte length, SHA-256 and Git blob identity. Inventory admission checks those identities before extraction and again when publication validates current checkout bytes. The complete 1241-file extraction requirement and its zero-diagnostic/integrity checks remain in force.

The raw macro census retains every snapshot entity and its unresolved state. Paired coverage reports their expanded and unresolved counts separately; only current source macros participate in executable target coverage. A snapshot cannot be admitted as a compiler input, cover an active-source failure, or supply the current-source macro sentinel.

For each table, the retained path is `paper/continuity/artifacts/bootstrap/<packet>/source/` followed by the original path in its first column. The source commit is the historical identity from that packet, not the current build commit.

## File loading for the pinned Rust extractor

The Rust 2.27.2 extractor uses rust-analyzer 0.0.352 to load Cargo package file
roots. The producer explicitly includes this reviewed bootstrap archive directory
through `CODEQL_EXTRACTOR_RUST_OPTION_EXTRA_INCLUDES`. The value is a JSON array
containing the original absolute archive path. The existing source-pin check
authenticates all 68 file paths and bytes before the extraction command.

This inclusion loads the snapshot bytes into the file view. Their existing
non-module status remains visible in the extractor diagnostics and raw macro
census. Cargo compilation roots, module declarations and the target coverage
rules retain their existing roles.

The native attempt in
[run 42982431606](https://github.com/billlza/q-periapt/actions/runs/42982431606/job/130412772905)
extracted all 1,241 tracked files, with zero extraction errors and zero
unextracted elements. Its 68 warnings came from exactly the 68 snapshots that
were absent from the loaded Cargo file view; consequently, the successful-file
census contained 1,173 paths. The explicit file-view input addresses that
observed omission. The complete 1,241-path equality and zero-warning checks
continue to govern preparation.

The input follows the fixed upstream
[extractor configuration](https://github.com/github/codeql/blob/a7057b836bf29767461026718b14d20790b9085f/rust/extractor/src/config.rs),
[file-loading diagnostics](https://github.com/github/codeql/blob/a7057b836bf29767461026718b14d20790b9085f/rust/extractor/src/main.rs),
and published
[rust-analyzer package-root loader](https://docs.rs/ra_ap_project_model/0.0.352/src/ra_ap_project_model/workspace.rs.html#833-880).

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

At the stated integration commit, 66 snapshots are byte-identical to their original paths in the current tree. The `initial` and `reply` copies of `crates/q-periapt-backends/src/contextbound_key.rs` retain the earlier key-binding implementation; the current path includes the subsequent staging change. Both historical copies remain pinned and extracted. Their historical role does not stand in for compilation or macro coverage of the current file.

Changes to the retained source set require an explicit review of this inventory and its pinned manifests. Missing, substituted, modified or additional snapshot paths fail admission; adding a Cargo manifest above a retained source also fails. Current source additions continue to require the existing exact inventory update and target coverage.
