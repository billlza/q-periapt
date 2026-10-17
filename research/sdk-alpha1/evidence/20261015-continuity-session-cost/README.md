# Native Continuity session cost baseline

Source `1fefe0f7154ac063d8488276442a62a5095f2a6d` was measured on an Apple M1 Max
(10 cores, 32 GiB RAM), macOS 27.0.1 / 26A434, with Rust 1.98.1 Release,
optimization level 3, thin LTO, one codegen unit and overflow checks enabled.
The product implementation is unchanged. This is the source-bound native Rust
candidate path, not installed foreign-package or device performance qualification.

Five blocks alternate local-only and required-witness execution order. Every
profile starts fresh enrolled device identities, original stores and a new
session in its own process. Each block sends 64 application messages: 0, 64,
1024 and 16384 bytes in a fixed cycle, with rekey epoch 1 halfway through. No
sample is discarded. There are 320 ordinary sends per profile, 80 per payload,
and ten independent runtime cohorts. These policy profiles have different
security contracts; the timing comparison is not a reason to remove a required
witness or weaken a signed policy.

Both fixtures use OneTimeBoth prekey selection, a signed application-send budget
of 1024 and a one-hour credential/policy validity window. The workload deliberately
rekeys after 32 ordinary messages; it does not change those policy parameters or
substitute an artificial protocol clock.

The consumer holds the original enrolled owners between calls. Each send includes
fresh mutually authenticated X25519MLKEM768 TLS, the SDK policy/context binding,
original encrypted journal transitions, durable receiver business effects and
authenticated consumption. TLS resumption and early data remain disabled. Real
wall-clock authority checks, write intents and witness reconciliation remain in
the unchanged implementation. No in-memory storage or manufactured ACK is used.

| Payload | Local-only p50 / p95 (ms) | Required witness p50 / p95 (ms) |
| --- | --- | --- |
| 0 bytes | 129.05 / 140.41 | 229.46 / 240.24 |
| 64 bytes | 128.88 / 138.69 | 229.87 / 239.63 |
| 1024 bytes | 129.74 / 138.98 | 229.70 / 242.07 |
| 16384 bytes | 132.77 / 142.90 | 232.44 / 243.87 |

Quantiles use the nearest-rank convention over the stated samples. The p50 range
of the five block-level send medians is
129.03–131.31 ms locally and
229.74–231.14 ms with the required witness.
The largest observed required-witness send is 386.01 ms;
it is retained in the raw record and summary. These finite observed quantiles do
not establish production tails, a non-regression guarantee or a release speedup.

| Phase | Local-only median (ms) | Required witness median (ms) |
| --- | --- | --- |
| Two-device setup | 1664.84 | 1865.72 |
| Initial client open | 59.97 | 79.44 |
| Initial server open | 53.06 | 72.20 |
| Original session bootstrap | 414.78 | 706.86 |
| Rekey epoch 1 | 277.47 | 473.33 |
| Client close and original reopen | 232.03 | 250.83 |
| Original unknown-result replay | 66.08 | 122.35 |

Phase medians above contain five observations per profile and are not tail
estimates. Sender slot lookup and post-send status are timed separately from
`ConnectionEndpoint::send`. The raw observer field `reserve_ns` times
`next_message_id`: it reads the current slot and does **not** durably reserve
input. The real SendPlan reservation is inside `send_message`, and therefore
inside the send interval. Client payload allocation and result JSON serialization
occur outside its API intervals; process launch is also excluded. Observer
bookkeeping in the other threads and scheduling can still affect measured latency.

Every required-witness sample's complete slot-lookup/send/status group contains
20 Query and five Advance requests. Their fixed signed request/reply frames total
183,525 bytes (about 179.2 KiB), excluding TCP overhead and application TLS traffic.
The five block medians of cumulative witness `handle` time range from
71.71 to
73.05 ms per group.
This includes witness authentication and storage work, and is not an isolated
primitive benchmark. Six additional AdmitAuthority/AuthorityCurrent exchanges
per witnessed cohort belong to initial activation and original-owner reopening;
they are not counted as hot-send Query/Advance traffic. The listener waits for
readiness through mio; it does not add a fixed sleep before accepting traffic.

The five whole-process maximum RSS observations range from 13.64–14.56 MiB
for local-only and 17.89–18.38 MiB with the witness. Darwin `getrusage(2)`
reports this counter in bytes. The process includes both SDK peers, the optional
witness, test harness, payload buffers and bounded timing records. This is not
isolated SDK memory, maximum-capacity admission or an allocation count. The raw
`time -l` files retain CPU times and all available process counters. Host load is
recorded, but other applications and power settings were not controlled; energy
was not measured.

Each cohort also commits one actual business effect and intentionally fails the
host callback before consumption can be confirmed. Both original owners close and
reopen; replay uses the same session, message and input, invokes the idempotent
host callback again, and creates no second effect. Durable sender status becomes
Acknowledged. The low-level send API then refuses another send of that retired
ID with the exact Retired error before dispatch. Status remains Acknowledged.
All 650 expected business files are independently compared byte-for-byte with
their original session/message IDs and synthetic payloads. Ten rekeys and ten
unknown-result recoveries complete, followed by explicit owner/server/witness
shutdown. The cohorts are sealed and must not be reopened.

The first eight-send pilot incorrectly expected a successfully acknowledged
sender to reconstruct and resend its retired outbox. It failed with Retired; its
source, executable identity, terminal failure and private cohort remain preserved.
The corrected observer requires the contracted refusal and uses entirely fresh
state. A new small pilot passed both profiles before the five-block schedule was
started. The first public reader also incorrectly restricted the entire witness
transcript to Query/Advance, omitting the existing AdmitAuthority operation. Its
source and correction are retained; no runtime was repeated to repair the reader.
The final reader requires exact request/outcome pairs, hot-send operation scope
and four initial plus two reopened authority admissions.

Nine reader tests pass, including rejection of all 640 individual sample-order
substitutions, false consumption, invalid timing, forged witness aggregates,
misplaced authority checks, missing retired refusal and duplicate recovery effects.
The first build was rejected despite Cargo exiting zero because rust-objcopy
could not load LLVM. A subsequent build invocation had an incorrect cache path
and failed offline. Both are retained. The accepted build probes the tool's
dynamic-library path, uses the original pinned registry and accepts no warnings.

The observations identify substantial fixed per-call cost and a concrete witness
exchange budget; they do not attribute all remaining time to fsync, cryptography
or any single function. The 1,550-line credential-renewal module and 1,315-line
roster module remain maintainability review candidates. Credential-renewal staging
is absent from this ordinary-send workload, so file length cannot explain these
timings. The next profiling boundaries are authenticated image load/validation,
the five durable transitions and current-authority/witness checks. Any
optimization must retain original-operation recovery, current authority and
release-after-commit guarantees; fewer checks are not an acceptance criterion.

| Artifact | SHA-256 |
| --- | --- |
| Accepted native observer | `a1bc03cd181f7b78137eff6d4bfc690c169d5356f38f8674edc459b44dcc82f3` |
| Public capture | `c5586c2ad9bffc231f0989b2310d549a7dbb91c9302e3524141f55d954fc4b0e` |

`CAPTURE.zip` contains 838 public members. Extraction rechecks
every member hash, all ten behavior censuses and 650 actual business effects.
It includes raw timings, process resource receipts, both observer versions,
locked dependencies, source/fixture records and the failed pilot/reader/build
records. Private keys, encrypted SDK stores, browser profiles and compiler outputs
are excluded. Same-host/source observations do not close independent/Linux or
foreign/device performance, sustained concurrency, cold-start tails, complete
bandwidth accounting, physical power-loss behavior, PCS, external review or the
remaining 0.2.0 release gates. No Intel Mac requirement is introduced.
