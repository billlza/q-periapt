# Pinned SPQR execution reference

This unpublished, separate workspace runs the public API of Signal's SPQR at
[`f2589fef855c10f39d72634dab3d14654dd410bf`](https://github.com/signalapp/SparsePostQuantumRatchet/tree/f2589fef855c10f39d72634dab3d14654dd410bf).
It is an AGPL-3.0-only reference executable with the accompanying license. No SDK
crate, product binding or identity candidate depends on it. It does not replace
the required Continuity implementation, or establish Signal interoperability.

## Fixed construction and workload

The upstream implementation and its 32-byte polynomial chunks are unchanged.
Every registry dependency selected by this driver has the same version and checksum
as the upstream lock (`e130211d61c7875cf5d94e606487a1da51845446e118633b6099e1f2d0303688`).
The driver calls `initial_state`, `send` and `recv` and reads public epoch counters
from its serialized test state. Both sides require version 1 and use the upstream
25,000-key jump / 2,000-key reorder parameters. The deterministic test seed and
initial test secret are public fixtures, never application input or product keys.

Each scenario sends exactly 2,048 messages:

- Alternating immediate delivery.
- Alternating delivery with messages `sequence mod 10 = 4` dropped before receive.
- Alternating sends delivered in reversed batches of seven.
- Alternating delivery with an immediate duplicate every thirteen messages.
- Nine sends by A followed by one send by B.
- A sends 256 messages while B is offline; retained bytes are then delivered before
  the subsequent alternating exchange.
- Only A sends; B receives but never sends a response.

Every actual receive must produce the sender's exact 32-byte message key. Every
send must use a distinct message key. Immediate duplicates must reject a second
key request. No keys or private state bytes are written to the report. The driver
retains public wire bytes, public counters, serialized-state sizes and raw CPU-call
timings. Serialized-state API calls are not disk crash recovery.

## Observed byte corpus

The two initial macOS arm64 executions produced identical public trace bytes.
`TRACE_CORPUS.json` locks all seven digests and summaries. The independent Python
decoder checks varints, full frame lengths, chunk sizes, message indices, actual
loss/reorder schedules and complete accounting. It checks the driver's reported
agreement outcomes; it does not independently derive the secret keys.

| Traffic | Final emitted epoch A / B | Bytes per send | Peak message bytes | Peak serialized state bytes |
| --- | ---: | ---: | ---: | ---: |
| Alternating | 24 / 23 | 32.150 | 37 | 6,327 |
| Loss | 20 / 21 | 31.957 | 37 | 6,725 |
| Reorder | 18 / 19 | 31.876 | 37 | 6,263 |
| Duplicate | 24 / 23 | 32.150 | 37 | 6,327 |
| 9:1 | 6 / 5 | 23.508 | 39 | 6,728 |
| Offline then exchange | 20 / 21 | 32.957 | 39 | 6,327 |
| One-way | 0 / 0 | 38.875 | 39 | 3,928 |

These are component bytes, not complete application or Continuity traffic. Timings
cover the actual SPQR send/receive call, including its state decoding/encoding;
they exclude application AEAD, transport, durable storage and energy. Raw samples
are retained without a performance pass threshold. A matched whole-KEM comparison,
64-byte construction variant, controlled energy measurements and compromise-schedule
analysis remain required before choosing the product ratchet profile.

## Integration findings

The one-way trace remains at epoch zero despite producing ordinary message keys.
Message count and symmetric key progression cannot serve as a PQ recovery claim.
This matches the delivery-dependent boundary in the
[ML-KEM Braid specification](https://signal.org/docs/specifications/mlkembraid/#the-vulnerable-message-set).
The [Triple Ratchet composition](https://signal.org/docs/specifications/doubleratchet/)
has its own mixing and recovery conditions; these traces do not prove that composition.

The minimum-version control rejects version zero. An unknown future version is
ignored by this upstream component with unchanged state and no message key. The
closed Continuity service must not turn that outcome into successful delivery or
weaker authentication.

With a different initial authentication secret, the first two header fragments
produce provisional, unequal message keys; the completed third fragment fails
the internal MAC. Consequently the outer service must authenticate the application
message before committing the candidate receive state. Calling `recv` alone does
not authorize a persistent state transition. This is a component integration
boundary, not an upstream authentication-bypass claim.

## Reproduction

With Rust 1.96.1 and an existing `protoc` on PATH, from the repository root:

```sh
cargo clippy --manifest-path research/continuity-spqr-reference/Cargo.toml --locked --all-targets -- -D warnings
cargo run --manifest-path research/continuity-spqr-reference/Cargo.toml --locked --release -- target/spqr-first
cargo run --manifest-path research/continuity-spqr-reference/Cargo.toml --locked --release -- target/spqr-repeated
sh artifact/python-run.sh artifact/spqr_reference.py target/spqr-first --compare target/spqr-repeated
```

Output directories must be new. To bind a clean checkout and built executable,
also pass `--binary` with the actual release binary path. That receipt verifies
the upstream Git commit/tree, unchanged tracked sources, both dependency locks,
license bytes, compiler/protobuf identity and executable hash. CI runs the original
upstream tests plus two corpus executions on Linux and macOS, then checks the same
locked public bytes. Hosted results remain evidence for their exact source commit.
