# q-periapt-tls-demo — transport demo + P99

A real **server-authenticated PQ/T hybrid KEM handshake over TCP**, plus an end-to-end
**P99 latency harness**. The handshake is generic over a `HandshakeSuite` and ships in
two suites over one implementation: the **default** (ML-KEM-768 + X25519 + SHA3 for the
KEM, **ML-DSA-65** for server identity — `client_handshake` / `server_handshake`) and
the **enhanced L5** (ML-KEM-1024 + X25519, **ML-DSA-87** —
`client_handshake_enhanced` / `server_handshake_enhanced`, whose 1568-byte KEM
ciphertext and 4627-byte signature make the bytes-on-wire cost concrete). Built on
`q-periapt-kem`/`q-periapt-sig`/`q-periapt-backends`. It exists to make the project's
actual differentiator *measurable*:

> Handshake tail latency is dominated by **bytes/packets on the wire**, not by
> encap/decap (or combiner) CPU time.

## Run it

```sh
cargo test  -p q-periapt-tls-demo                                      # loopback handshake, both suites
cargo run --release -p q-periapt-tls-demo --bin p99_bench -- bound  3000      # profile, iters
cargo run --release -p q-periapt-tls-demo --bin p99_bench -- bound  500 500   # + 500µs/flight emulated RTT
SUITE=enhanced cargo run --release -p q-periapt-tls-demo --bin p99_bench -- bound 3000  # NIST-L5 suite
```

## What the numbers show

Illustrative loopback run (one dev host; absolute numbers are machine-specific):

| suite / profile           | p50     | p99     | wire / handshake |
|---------------------------|---------|---------|------------------|
| L3 `ContextBound`         | 826 µs  | 1879 µs | **5758 B** (4 flights) |
| L3 `CompatXWing`          | 893 µs  | 2099 µs | **5758 B** (4 flights) |
| L5 `ContextBound` (`SUITE=enhanced`) | ~1017 µs | ~1955 µs | **7940 B** (4 flights) |

Three observations, all supporting the thesis:

1. **Combiner CPU is invisible.** The two L3 profiles move *identical* bytes and their
   P99 differs only at noise level — even though `ContextBound` hashes ~2.5 KB more
   in the combiner. The combiner-CPU choice does not move the tail.
2. **Bytes drive the tail.** Of the L3 suite's 5758 B, the server→client flight is
   **4597 B** — dominated by the **~3.3 KB ML-DSA-65 signature** (plus the 1184 B
   `ek`); the client→server flight is 1161 B (1088 B `ct` + 32 B `ct_X`). The PQ
   *signature*, not the KEM math, is the single largest line item. On a lossy /
   high-RTT link these bytes cost extra packets and interact with TCP slow-start /
   QUIC Initial flow control — which is where the P99 engineering actually lives.
3. **The L5 suite makes the byte cost concrete.** ML-KEM-1024 + ML-DSA-87 moves
   **7940 B** (+38%), the server→client flight dominated by the **4627 B ML-DSA-87
   signature** (plus the 1568 B `ek`). Same flight count, more bytes per flight — the
   exact axis the harness is built to surface, now at the NIST level-5 parameter set.

Injecting `DELAY_US=500` per flight pushes p50 from ~0.8 ms to ~3.6 ms: with four
flights, **flight count × RTT** dominates — another reason micro encap/decap
benchmarks mis-rank designs.

## What this is — and isn't

- **Is:** a server-authenticated, HPKE-base-shaped handshake — server static hybrid
  key + ML-DSA-65 identity (its verifying key **pinned** by the client out-of-band);
  client encapsulates; both derive a session secret bound to the transcript
  (`ContextBound`, context = `SHA3(ClientHello ‖ ServerHello)`); the server signs
  the full transcript and sends a constant-time-checked key-confirmation.
- **Isn't:** the TLS 1.3 wire format. Identity here is a pinned key (no X.509 chain);
  the combiner is our standalone one, not the TLS key schedule (see below).
- **Isn't:** PQXDH, Signal's SPQR/Triple Ratchet or Sesame, Apple PQ3, or the
  future Q-Periapt Continuity protocol. It has no offline prekeys, mutual device
  identity, persistent message chains, PQ healing, multi-device state, crash
  recovery, or key transparency. Its four flights and P99 numbers cannot be used as
  session-protocol parity evidence.

## Mapping to TLS 1.3 / QUIC / HPKE

| Protocol | Relationship |
|---|---|
| **TLS 1.3** | Standardized hybrid uses the `X25519MLKEM768` named group (codepoint `0x11EC`) with the **TLS key-schedule** combiner — a *different object* from our standalone combiner. Production-stack demo path: a private-use rustls `CryptoProvider` backed by the shared Q-Periapt implementation; this is an evaluation integration, not a standardized or production-ready group. |
| **QUIC** | Same key exchange as TLS 1.3; the transport difference amplifies the byte cost — the server's first flight is bound by the anti-amplification limit, so the extra ML-KEM bytes directly shape the initial RTTs. |
| **HPKE** | This demo *is* essentially HPKE base mode (KEM → KDF). HPKE with a PQ/T KEM is the most direct consumer of our standalone combiner. |

## Next (follow-ups, see ROADMAP)

- A literal **rustls `X25519MLKEM768` TLS 1.3 demo** with the same P99 harness, to
  measure standardized PQ-TLS alongside this one (note: that path uses rustls's own
  ML-KEM, not our combiner — it validates the *methodology*, not the suite).
- Real netem/tc link emulation (loss + slow-start), beyond the fixed per-flight
  `DELAY_US` knob here.
- Mutual auth / X.509-style identity (currently a pinned ML-DSA key).
- A separate stateful protocol workstream is specified in
  [`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md); this demo
  will remain the small synchronous handshake/performance reference rather than grow
  database, directory, or ratchet responsibilities.
