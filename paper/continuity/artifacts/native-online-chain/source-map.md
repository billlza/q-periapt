# Native constructor and origin correspondence

The snapshots in `sources/` were retrieved from integration commit `a4c089570c787522210d16226219c0cc8aa9b05e`. Every stored Git blob is identical to its entry at the manuscript's original source pin `228c944fc476e3e57d6c08063cacb19bca5b360e`. `source_identity.json` records all byte lengths, SHA-256 digests, Git blob identities and exact commit URLs. The earlier source-attribution and live-profile maps retain the complete surrounding constructor analysis.

| Source | Concrete correspondence used in this result |
| --- | --- |
| `durable/messages.rs` | `step` uses zero-salt HKDF-SHA256, the fixed chain domain, the complete big-endian index and two output blocks. `send_message` assigns a bound pending plan and persists it before calling the private traffic send. Exact Resume returns the retained wire. |
| `durable/messages/traffic.rs` | Role assignment swaps matching send/receive directions. The send path checks any existing pending identifier, plaintext and associated data before stepping or encrypting, then advances the index and retains the outbox. Receive advancement computes skipped steps in transaction-private candidate state before authentication and reuses retained skipped keys. Both message directions use the fixed zero nonce with their separately derived message key. |
| `durable/messages/rekey.rs` | Rekey admission and the original generation plan connect the selected schedule to the retained source handles used by executed-slot attribution. |
| `durable/messages/rekey/response.rs` | Response preparation retains the encapsulation plan and its original operation identity across persistence boundaries. |
| `durable/messages/rekey/completion.rs` | Completion verifies the complete authenticated transcript and installs traffic derived from the original pending target; role and source association are fixed before later application selection. |
| `contract.rs` | The public operation/status interface retains the application intent and plaintext-free resumption boundary used by the existing native game. |

The executable checker authenticates all six files and checks eighteen specific source-order or encoding anchors in the chain/send/receive paths. It records all actual private computations, including failed receive-side candidates, in a monotone proof ledger. That ledger is a representation of deterministic computation and is not a change to native storage behavior. The source-attribution induction, complete signed-body mapping and ML-DSA bridge remain the established manuscript arguments, now applied to the expanded whole-execution controller.
