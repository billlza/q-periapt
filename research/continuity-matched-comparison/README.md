# Directed-opportunity comparison

This research harness executes Continuity budgets 32/64, SPQR chunks 32/64, and
whole-KEM intervals 1/32/64 under a shared 2,048-opportunity transport schedule.
See [CONTRACT.md](CONTRACT.md) for the capture object, arbitration rule, payload
demand, loss/reorder mapping, accounting boundaries, and authentication graph.

The source baseline is commit `358b921ab3469ce49f166633fc9a762ff6ed7e3d`.
SPQR is pinned to `f2589fef855c10f39d72634dab3d14654dd410bf`; the 64-byte case uses
that source and the baseline's two existing variant patches. An isolated archive
contains the Cargo workspace members, three research workspaces, and validation
sources. Only that copy receives the native test module and reference observer
hooks. The live checkout and accepted proof interfaces are unchanged.

## Reproduce

Use Rust 1.98.1, Python 3.14.7, `protoc`, and the existing hash-pinned requirements
in `research/continuity-openssl-peer/requirements.txt`. The dedicated workflow
installs these dependencies and runs the same commands:

```sh
python -m unittest discover -s research/continuity-matched-comparison -p 'test_*.py' -v
python research/continuity-matched-comparison/run.py run \
  --repository "$PWD" --output "$PWD/target/continuity-matched-execution"
```

The output directory must be new. `run.py prepare` with the same arguments only
constructs source derivatives and writes `status: prepared_not_executed`; it
cannot produce a native-execution report. The compiler builds the existing native
workspace's library tests in release mode, and the runner obtains the one target
test's exact name from the compiled executable's `--list` output. It then executes
only that test, followed by new builds and runs of the three reference drivers.
All Cargo invocations use `--locked`; no Rust dependency is added.

`native_driver.rs.txt` is compiled as a child module of the existing private
message test module in the isolated copy. It directly calls real journal APIs,
uses detached captured `State` objects, implements the message-chain HMAC/HKDF
calculation independently, and decrypts actual emitted application ciphertexts
with each derived key. The mutated captured seed must fail actual AEAD. Responses
from receives are queued, and only the next suitable directed opportunity can
transmit them. The test's terminal drain delivers existing packets only.

The reference observer hooks write fresh actual message keys into permission-0600
measurement feeds. The existing capture predictors never read those feeds. A
separate Python audit encrypts the common 32-byte demand payload with
ChaCha20-Poly1305, checks honest decryption and wrong-key rejection, and retains
only public envelopes. This establishes an executed envelope byte count and
binds the reference key-reconstruction result to the honest payload. Its
component-state-return boundary remains explicit; it is not a durable delivery
adapter. Feeds are removed on success or failure and excluded from artifact
upload. Native failure assertions do not print message-key arrays.

## Evidence schema

| File | Meaning |
| --- | --- |
| `preparation.json` | Explicit base commit/tree, selected source paths, before/after file hashes, research input hashes, fixed schedule digest. |
| `variant-preparation.json` | Exact upstream commit/tree/lock, copied and patched 64-byte source inventory. |
| `runtime.json` | Actual rustc, Cargo, protoc, Python and host identities. |
| `executables.json` | Hash and path of every actually executed native/reference binary. |
| `evidence/native/*.jsonl` | 14 native traces: configuration, capture, request opportunity, admission block, first commit, emission, receive, persistence checkpoint, completed receipt. |
| `evidence/spqr-*/`, `evidence/whole-kem/` | 35 new reference traces, existing passive-state predictor reports, raw component CPU samples, public AEAD envelopes. |
| `evidence/reference-validation.json` | Results from the baseline's independent reference wire/predictor validators. |
| `evidence/matched-report.json` | Exactly 49 profile/scenario rows after all execution, inventory, source and trace checks pass. |
| `evidence/manifest.json` | Public evidence file hashes and `status: complete`, emitted only after success. |
| `logs/` | Build/test/command outputs, retained also on failure. |

Each result reports offered, committed, delivered and uncommitted demand by
original sender; emitted/delivered bytes; application/control/ACK/retry categories
where separately framed; all repeated exact-frame logical identities; and the
exact exposed request set at the common before-opportunity-1 cut. Piggybacked
control body repeats are reported separately from exact-frame retransmissions
because their enclosing application key and frame are new.

Native persistence records real committed image revisions and counting-backend
`sync_data` calls after session activation. Reference state-return counts and
serialized bytes describe logical state work. Physical persistence columns are
`null` where no disk adapter executes. These different operation boundaries are
shown in every row, so neither admission loss nor absent physical IO is hidden
inside a favorable denominator.

## Discriminating controls

The finite four-flight model exposes free reply transmission: an erroneous
receive-drain loop completes a four-flight exchange inside one A-only slot,
whereas the charged model leaves B's first output queued. The schedule checker
also rejects wrong-direction output, multiple frames in one slot, unseen-source
delivery, altered duplicate/retry bytes, substituted capture coordinates and
integer aliases. Native trace controls substitute the capture order, FIFO request,
public application epoch, persistence counts, and completion inventory.

These local controls are schedule/parser executions. A compiled native receipt
requires the dedicated workflow or the complete reproduction command above.
