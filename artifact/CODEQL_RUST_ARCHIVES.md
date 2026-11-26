# Rust snapshots retained by the manuscript evidence

The CodeQL source census at integration commit `0e2ca2d79ab0000bed79130cec97b31181e936ea` contains 1241 tracked Rust files: 1173 current sources and the 68 snapshots below. These snapshots preserve the implementation inputs assessed by the proof packets. They are partial source exports with no Cargo manifests, not additional compilation roots.

The isolated `services/q-periapt-policy-agent/tests/private_file_umask.rs` integration test adds one current source, bringing that census to 1242 tracked Rust files: 1174 current sources and the same 68 snapshots. Cargo includes the new test in its existing all-targets compilation.

The latency packet at manuscript snapshot `947297e59be9d7fc8febb5d81a4e2b945e328208` adds three retained measurement sources. The current census requires **1245 tracked Rust files: 1174 current sources and 71 archived sources**. The three measurement sources are additions to the measurement setup, not files attributed to the measured protocol commit `358b921ab3469ce49f166633fc9a762ff6ed7e3d`.

`codeql_rust_quality.py` pins the exact five bootstrap `SOURCE_PINS.json` manifests and the three latency paths, byte lengths, SHA-256 values and Git blob identities. Inventory admission checks those identities before extraction and again when publication validates current checkout bytes. The complete 1245-file extraction requirement and its zero-diagnostic/integrity checks remain in force.

The raw macro census retains every snapshot entity and its unresolved state. Paired coverage reports their expanded and unresolved counts separately; only current source macros participate in executable target coverage. A snapshot cannot be admitted as a compiler input, cover an active-source failure, or supply the current-source macro sentinel.

For each bootstrap table, the retained path is `paper/continuity/artifacts/bootstrap/<packet>/source/` followed by the original path in its first column. The source commit is the historical identity from that packet, not the current build commit.

## File loading for the pinned Rust extractor

The producer explicitly includes both reviewed archive directories through
`CODEQL_EXTRACTOR_RUST_OPTION_EXTRA_INCLUDES`: the bootstrap packet root and the
latency packet root, each at its original absolute path. The source-pin check
authenticates all 71 file paths and bytes before the extraction command.

This inclusion loads the snapshot bytes into the file view. Their existing
non-module status remains visible in the extractor diagnostics and raw macro
census. Cargo compilation roots, module declarations and the target coverage
rules retain their existing roles.

The two latency `Cargo.toml` files are exact reproduction recipes: their relative
dependencies resolve only after `prepare_sources.py` installs the archived
protocol tree in a separate work directory. The pinned
[CodeQL 2.27.4 extractor](https://github.com/github/codeql/blob/codeql-cli/v2.27.4/rust/extractor/src/main.rs)
selects a source's nearest discovered manifest. During extraction only,
`retained_latency_manifests` therefore holds each authenticated recipe in an
exclusive adjacent hard link named `Cargo.toml.codeql-retained` and removes its
`Cargo.toml` directory entry. Both original entries are restored and verified,
including inode, mode and SHA-256, on normal and exceptional exits. An existing
backup or substituted restoration path is refused, rather than overwritten.
`archived-manifests.json` records successful restoration in the job's evidence.
This staging step runs in each platform job's dedicated checkout; its manifest
and backup paths require exclusive access throughout extraction and restoration.
The three Rust paths and bytes remain in place throughout extraction. No source,
warning, metric or security query is filtered by this handling.

## Latency: three retained measurement sources

Paths below are relative to `paper/continuity/artifacts/latency/`. The exact
source identities are pinned in `LATENCY_ARCHIVE_SOURCES`; the two recipe
lengths and SHA-256 values are pinned in `LATENCY_ARCHIVE_MANIFESTS`.

| Retained path | Role |
| --- | --- |
| `harness/delivery/src/fixture.rs` | Provision the measured native session before timed delivery |
| `harness/delivery/src/main.rs` | Time established-session delivery and check committed plaintext |
| `harness/primitives/src/main.rs` | Time the six cryptographic backend operations |

Only `harness/delivery/Cargo.toml` (760 bytes, SHA-256 `e7ae8e88d1189e395de35634ddc15fd38525768c21b68261961b4c03ae8d57a2`) and
`harness/primitives/Cargo.toml` (367 bytes, SHA-256 `71b6987ad8cba939d618d8ddbb1f5feb777215c52245d4e9e3e98270673b72a8`)
are admitted reproduction recipes. Any other Cargo manifest above a retained
source fails archive admission. The three sources cannot appear in current
compiler inputs or supply current-source macro coverage.

The corresponding retained locks are authenticated by `ARCHIVE_LOCKFILES` and
are not current Cargo fetch roots. Missing or additional live locks, altered
archive bytes, and an adjacent `Cargo.toml` still fail their existing checks.

| Retained lock path | SHA-256 |
| --- | --- |
| `locks/delivery-358b-Cargo.lock` | `31e3a20d5826f5f5e8503101197ce674d6eadae5f305bba65175fc7a3e4be573` |
| `locks/primitives-358b-Cargo.lock` | `80ee2f22b3dfd7ec76a5824a7b6aa1edd7f27f489a0a9abc3e8b8abd8c95eb5f` |
| `preliminary-9503/Cargo.lock` | `4d00439bc6b0ec7ce060d12ee583fc6e109486fdbb35beb2853a0fefb9ecc573` |

## Historical bootstrap file-loading observation

The native attempt in
[run 42982431606](https://github.com/billlza/q-periapt/actions/runs/42982431606/job/130412772905)
extracted all 1,241 tracked files, with zero extraction errors and zero
unextracted elements. Its 68 warnings came from exactly the 68 snapshots that
were absent from the loaded Cargo file view; consequently, the successful-file
census contained 1,173 paths. The explicit file-view input addresses that
observed omission. Complete current-path equality and zero-warning checks
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

Changes to the retained source set require an explicit review of this inventory and its pins. Missing, substituted, modified or additional snapshot paths fail admission; a Cargo manifest other than the two exact latency reproduction recipes above also fails. Current source additions continue to require the existing exact inventory update and target coverage.
