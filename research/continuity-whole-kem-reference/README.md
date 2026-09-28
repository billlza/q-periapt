# Authenticated whole-KEM periodic control

This unpublished workspace is an executable comparison construction,
`experimental_whole_kem_v1`. It is separate from the SDK, the Continuity identity
candidate and the pinned SPQR component. It has no product binding or persistence
adapter and does not establish a protocol security theorem. Its wire version is
`0xd1`; serialized states are not interchangeable with SPQR or Continuity states.

## Fixed construction

The experiment assumes an already established, session-specific shared secret.
The harness uses the same public `[41; 32]` fixture and RNG seed as the Braid
workloads. Those public fixtures do not prove unpredictability. ML-KEM-768
generation, full encapsulation and decapsulation use `libcrux-ml-kem 0.0.8`;
HMAC-SHA-256 uses `libcrux-hmac 0.0.6`; HKDF-SHA-256 uses the same locked HKDF/SHA2
versions and target-specific SHA2 assembly feature as the SPQR baseline. Every
selected registry version and checksum belongs to that baseline's upstream lock.

The two roles alternate as the KEM proposer: A for odd epochs, B for even epochs.
There is one outstanding exchange:

| Action | Evidence and next state |
| --- | --- |
| Proposer sends a complete 1,184-byte public key | A MAC under the previous root binds profile, direction, control kind, target epoch and complete public key. The proposer retains the exact key pair. |
| Peer admits the public key | Authentication and public-key validation precede selection. A different authenticated key at the same pending epoch is rejected. |
| Peer next sends | One full encapsulation creates an immutable 1,088-byte ciphertext and a candidate epoch. Its MAC uses the newly derived root and binds the public-key digest and ciphertext. Ordinary sending remains on the previous epoch pending confirmation. |
| Proposer receives the ciphertext | Decapsulation and the new-root MAC must agree before candidate state is returned. The proposer discards the pending private key, installs its new sending chain and queues an exact confirmation identifier. |
| Peer receives the confirmation | A MAC under the new root confirms possession and binds the exact exchange. The peer then advances its sending epoch and may schedule the next proposal. |

An exact repeated ciphertext elicits the same confirmation; it does not generate
new KEM entropy or replace the root. Retransmitted control **bodies** remain
immutable, while each surrounding application opportunity consumes a different
message key. Delayed acknowledgements cannot replace a newer pending private key.
`known_epoch`, `confirmed_epoch`, `send_epoch` and `receive_epoch` are separate
observations. Confirmation records peer key possession, not application receipt or
common knowledge of delivery.

Closed profiles `1`, `32` and `64` specify a fixed local-send interval. The first
proposal and each freshly prepared response/confirmation use the next send.
Subsequent pending retransmissions use that interval. After confirmation, the next
proposer waits that many local send opportunities before creating another key.
A repeated valid ciphertext can request the retained confirmation immediately;
it cannot lower the fresh-proposal interval. No network-derived adaptive policy or
wall-clock deadline is introduced.

## KDF and wire

All integer inputs inside MAC/KDF domains use big-endian encoding. Initial HKDF
uses the shared secret and `QPWKR1:initial || profile_u32`. It yields 96 bytes:
next root, A-to-B chain seed, B-to-A chain seed. A root update uses the previous
root as HKDF salt and the full KEM shared secret as input, with
`QPWKR1:root || profile_u32 || epoch_u64 || SHA256(pk) || SHA256(ct)` as info.
It yields the same three separately retained outputs. A message-chain step uses
a zero salt and its current chain seed, with `QPWKR1:message || index_u32` as
info, yielding next chain seed and message key. Control MACs use
`QPWKR1:control || profile_u32 || sender_u32 || kind_u8 || epoch_u64 || body`.
The confirmation identifier is
`SHA256(QPWKR1:confirmation || SHA256(pk) || SHA256(ct))`.

The compact wire is `version_u8 || profile_u8 || message_epoch_varint ||
message_index_varint || previous_epoch_send_count_varint || kind_u8`.
Kinds 1–3 append a canonical target-epoch varint and these fixed bodies:

- 0: no control body.
- 1: public key (1,184 bytes), MAC (32 bytes).
- 2: public-key digest (32 bytes), ciphertext (1,088 bytes), MAC (32 bytes).
- 3: confirmation identifier (32 bytes), MAC (32 bytes).

Canonical bounded varints, exact body lengths and a 1,250-byte maximum frame are
required. Unknown profiles, kinds, extra bytes and integer aliases fail. This
parser also requires proposal/ciphertext message keys to belong to the preceding
epoch, and confirmation message keys to belong to the confirmed epoch. This
component returns provisional message keys. Outer application authentication must
cover the complete header and payload **before** candidate receive state is
committed; authenticated control alone does not authenticate ordinary data or its
message index. No ciphertext/plaintext application API is supplied here.

## Secret retention and execution bounds

Actual protocol state is encoded with protobuf on every call, so recorded CPU
time includes its decode/encode work. The input snapshot is borrowed; failed
receive calls return no candidate state. Consumed send-chain seeds are replaced.
On a new receive epoch, the authenticated outer message's previous-send count
allows the old receive chain to derive bounded skipped keys before that chain seed
is erased. There are at most 2,000 retained skipped keys in aggregate and at most
25,000 forward chain steps per admitted packet; exhaustion fails explicitly.
Unused epoch records are removed after both directions have advanced.

This differs from SPQR's per-chain reorder window and old-epoch pruning policy.
The selected traces remain within both configurations' limits. Their serialized
state sizes include different schemas and retention choices; they are not a
controlled memory-efficiency result. These are volatile public-fixture processes:
there is no durable transaction, rollback protection or physical-erasure claim.

## Matched workloads and observations

Each profile executes the existing seven 2,048-send schedules, with actual key
agreement, unique send keys and duplicate rejection: **43,008 sends per execution**.
Six snapshot cuts for each endpoint produce **252 passive disclosure cases**.
The predictor receives one serialized endpoint state and the full public transcript,
including dropped packets. A stolen pending private key derives the next epoch
from the public full ciphertext. It receives no future private state or RNG input.
Every prediction is compared with the actual sender key outside the predictor;
an altered chain-seed control must disagree. `not_derived` is not a security claim.

Alternating traffic observations, excluding outer AEAD/transport/storage/energy:

| Component/profile | Mean bytes/send | Peak frame | Local root/output epochs A/B | Derived keys after A's first-send snapshot |
| --- | ---: | ---: | --- | ---: |
| Pinned Braid 32 B | 32.150 | 37 | 24/23 | 172 |
| Experimental Braid 64 B | 58.971 | 69 | 46/45 | 88 |
| Whole KEM, interval 1 | 819.658 | 1,225 | 683/683 | 4 |
| Whole KEM, interval 32 | 44.047 | 1,223 | 32/32 | 66 |
| Whole KEM, interval 64 | 25.023 | 1,223 | 16/16 | 130 |

The one-way schedule reaches no fresh PQ epoch for any construction and exposes
every post-snapshot key. Different authentication graphs, confirmation cadence and
retention policies prevent interpreting this table as a general security or
performance ranking. Root/output epoch counts are not interchangeable recovery
proofs. The full hybrid composition, active/repeated compromise, durable recovery,
controlled latency/energy and a justified policy floor remain necessary before
product profile selection.

## Verification

`artifact/whole_kem_reference.py` independently parses the public wire and checks
the send/receive schedule, role/epoch transitions, previous-chain counts, immutable
control bodies, public-key/ciphertext/confirmation bindings and all snapshot
accounting. `TRACE_CORPUS.json` locks every public trace, summary and disclosure
report. Repeated executions must match exactly. CPU samples are retained without
a speed threshold. Rust tests cover real confirmation loss, delayed delivery,
conflicting authenticated proposals, modified KEM ciphertext, key-budget failure,
strict parsing and an independent HMAC implementation comparison.

```sh
cargo clippy --manifest-path research/continuity-whole-kem-reference/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path research/continuity-whole-kem-reference/Cargo.toml --locked
cargo run --manifest-path research/continuity-whole-kem-reference/Cargo.toml --locked --release -- target/whole-kem-first
cargo run --manifest-path research/continuity-whole-kem-reference/Cargo.toml --locked --release -- target/whole-kem-repeated
sh artifact/python-run.sh artifact/whole_kem_reference.py target/whole-kem-first --compare target/whole-kem-repeated
```

Use new output directories. `--binary` adds a clean source/tree, compiler and
executable receipt. Optional `--baseline` and `--chunk64` accept the two existing
executed reference directories and generate the full seven-schedule comparison.
Linux and macOS CI execute all three constructions with their locked sources.
