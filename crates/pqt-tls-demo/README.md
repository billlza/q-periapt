# pqt-tls-demo — transport demo + P99

A real **PQ/T hybrid KEM handshake over TCP** using the suite (ML-KEM-768 +
X25519 + SHA3 via `pqt-kem`/`pqt-backends`), plus an end-to-end **P99 latency
harness**. It exists to make the project's actual differentiator *measurable*:

> Handshake tail latency is dominated by **bytes/packets on the wire**, not by
> encap/decap (or combiner) CPU time.

## Run it

```sh
cargo test  -p pqt-tls-demo                                   # loopback handshake, both profiles
cargo run --release -p pqt-tls-demo --bin p99_bench -- bound  3000
cargo run --release -p pqt-tls-demo --bin p99_bench -- compat 3000
```

## What the numbers show

Illustrative loopback run (one dev host; absolute numbers are machine-specific):

| profile        | p50    | p99     | p99.9   | wire / handshake |
|----------------|--------|---------|---------|------------------|
| `ContextBound` | 467 µs | 1321 µs | 1646 µs | **2449 B** (4 flights) |
| `CompatXWing`  | 521 µs | 1667 µs | 2283 µs | **2449 B** (4 flights) |

The two profiles move **identical bytes** and their P99 differs only at noise
level — even though `ContextBound` hashes ~2.5 KB *more* in the combiner. That is
the thesis, measured: the combiner-CPU choice is invisible against TCP/syscall
cost; the ~2.2 KB of ML-KEM material (1184 B `ek` + 1088 B `ct`) is what a tail
budget must account for. On a lossy / high-RTT link those bytes cost extra packets
and interact with TCP slow-start / QUIC Initial flow control — which is where the
P99 engineering actually lives, and why micro encap/decap benchmarks mis-rank
designs.

## What this is — and isn't

- **Is:** an HPKE-base-shaped handshake — server static hybrid key; client
  encapsulates; both derive a session secret bound to the transcript
  (`ContextBound`, context = `SHA3(ClientHello ‖ ServerHello)`); server sends a
  constant-time-checked key-confirmation.
- **Isn't:** the TLS 1.3 wire format. Server identity is trust-on-first-use here;
  real authentication needs signatures (`pqt-sig`: ML-DSA / SLH-DSA) — see
  `docs/ROADMAP.md`.

## Mapping to TLS 1.3 / QUIC / HPKE

| Protocol | Relationship |
|---|---|
| **TLS 1.3** | Standardized hybrid uses the `X25519MLKEM768` named group (codepoint `0x11EC`) with the **TLS key-schedule** combiner — a *different object* from our standalone combiner. Production path: a rustls `CryptoProvider` backed by `pqt-ffi` (the suite supplies the KEM + policy/agility/auditability; TLS supplies the key schedule). |
| **QUIC** | Same key exchange as TLS 1.3; the transport difference amplifies the byte cost — the server's first flight is bound by the anti-amplification limit, so the extra ML-KEM bytes directly shape the initial RTTs. |
| **HPKE** | This demo *is* essentially HPKE base mode (KEM → KDF). HPKE with a PQ/T KEM is the most direct consumer of our standalone combiner. |

## Next (M4 follow-ups, see ROADMAP)

- A literal **rustls `X25519MLKEM768` TLS 1.3 demo** with the same P99 harness, to
  measure standardized PQ-TLS alongside this one (note: that path uses rustls's own
  ML-KEM, not our combiner — it validates the *methodology*, not the suite).
- Emulated-link P99 (added RTT + loss) to exercise the slow-start interaction.
- Server authentication via `pqt-sig`.
