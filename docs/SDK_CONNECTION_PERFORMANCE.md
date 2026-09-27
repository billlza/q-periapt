# Full connection timing diagnostic

`artifact/sdk_connection_performance.py` measures the public Swift connection
API against the existing Rust reference peer over IPv4 loopback. It builds and
freezes release executables and the ABI 2 library, first runs all twelve existing
acceptance/failure/persistence scenarios, then records five fresh process blocks.
This is a local source-build diagnostic. Native Swift/macOS-to-Rust/Linux and
installed-package performance qualification remain separate requirements. The
installed-package observation below adds a local baseline without changing the
source-build driver's scope or establishing controlled performance qualification.

```sh
RUSTFLAGS='-D warnings' CARGO_NET_OFFLINE=true \
  sh artifact/python-run.sh artifact/sdk_connection_performance.py \
  --output target/sdk-connection-performance-new --reconnects 200
```

The output must be a new directory under `target/`. The reconnect budget is
200..1000 per block; the default is 200. Every block has its own private generated
test credentials and fresh persistent policy files on both peers. The server
prepares its state before `LISTEN`. Both sides retain mutual pinned certificate
authentication, fresh TLS 1.3/X25519MLKEM768, ALPN `qperiapt-sdk/1` and the existing
policy/application-context confirmation. Reconnection does not enable resumption,
0-RTT, automatic retries or classic fallback.

## Recorded intervals

- Setup: client fixture reads, verification/provisioning of durable signed-policy
  state, and endpoint construction. This completes before the first connection.
- Connect: the complete Swift `connect` call, through TCP, TLS authentication and
  application confirmation to a usable connection.
- Request: each complete authenticated echo request, at 0, 1 and 65,536 payload
  bytes, with one request in flight. Payload construction and the separate echo
  comparison are outside the timed interval; every returned payload is checked.
- Shutdown: TLS `close_notify`, transport shutdown and owner disposal.

The monotonic clock is `DispatchTime.now().uptimeNanoseconds`. JSON is written
only after each connection is successfully shut down, outside the timed spans.
An interrupted/failed run retains its raw prefix but cannot satisfy the required
sample matrix and final completion marker. The collector rejects duplicate or
reordered samples, different payloads/phases, malformed schemas/numbers, absent
completion and unexpected server request counts. Exact dyld image identity,
source hashes and frozen executable/library hashes are checked.

Each block contains one first connection followed by the selected number of
fresh reconnections from the same endpoint. Reconnect P50/P95/P99 are nearest-rank
quantiles within each block, with all blocks retained. There are only five
first-connection observations; no first-connect P95/P99 claim is made. “First”
means first in that Swift process after endpoint setup, with a warmed operating
system and previously run acceptance scenarios, not a cold-boot measurement.

The reference server waits for socket readiness with a ten-second absolute
accept deadline. The initial capture below predates that change and includes
the former 5 ms nonblocking-accept polling loop. Transport scheduling remains
included in connect time. These measurements must not be presented as isolated
KEM/cryptographic latency. CPU time, allocation counts,
energy, concurrency/soak behavior, controlled tail non-regression and package
cold start require their own measurements. Host load and power state are
uncontrolled; this script changes neither host settings nor other applications.

All raw stdout/stderr, build commands and failures remain in the run directory.
The manifest stays `completed: false` on error and always records
`release_claim_eligible: false`. Private test keys are excluded from the declared
CI uploads. The added CI step is a declared gate until a hosted run is observed.

## Observed local capture (2026-09-26)

The [connection-timing checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-connection-timing/manifest.json)
records a completed macOS ARM64 capture: twelve actual acceptance scenarios,
then five process blocks with 200 reconnections each. All 1,005 connections and
3,015 requests complete with matching echo bytes, exact server counts, disposal,
source/binary identity checks and the required final markers.

The table shows the median of the five block-level quantiles in milliseconds;
the P99 range includes all blocks and is not a confidence interval.

| Reconnect interval | P50 median (ms) | P95 median (ms) | P99 median [range] (ms) |
| --- | ---: | ---: | --- |
| Connect through confirmation | 8.451 | 8.773 | 8.971 [8.893, 9.422] |
| 0-byte request/response | 0.163 | 0.251 | 0.311 [0.268, 0.569] |
| 1-byte request/response | 0.149 | 0.237 | 0.311 [0.299, 0.358] |
| 65,536-byte request/response | 0.797 | 1.083 | 1.304 [1.120, 1.365] |
| Graceful shutdown/disposal | 0.059 | 0.111 | 0.159 [0.123, 0.177] |

The five first-connect observations are 60.803, 60.589, 58.483, 55.423 and
60.136 ms. Setup is separately observed at 32.572–43.656 ms. These are raw first
observations after per-process setup, not estimates of cold-start tail latency.
The one-minute host load changes from 5.60 to 5.88. This initial descriptive
capture has no competing implementation, randomized baseline or controlled
performance-release threshold; it cannot establish a speedup or non-regression.

Thirteen affected artifact tests, Rust formatting and warning-denied example
Clippy pass. The complete 90-module artifact suite subsequently passes **2,219
tests in 584.438 seconds**, with warnings treated as errors in a standalone
build copy. All 843 selected source files match the primary worktree at execution;
only this guide and the release ledger are updated afterward. The real Rust/C/Swift release builds pass with strict Swift
concurrency and warnings as errors. Five actual Swift/Rust CLI controls reject
out-of-range or fractional budgets before creating policy state. The new Swift
CI job content passes actionlint. Full-workflow actionlint 1.7.12 still reports
the same pre-existing `ubuntu-26.04` catalogue error on both old and changed
workflow files. GitHub's [official runner list](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
includes that label; the error is retained, with no ignore/configuration bypass.
No hosted CI run is claimed.

## First-connection attribution (2026-09-26)

The [CPU and call-path checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-connection-profile/manifest.json)
investigates the first-connect gap using isolated diagnostic copies. The initial
CPU probe reuses the exact compiled Swift SDK object/module and native library
from the wall-time capture. A second probe adds five stage stamps to a copied
Swift SDK module while retaining the same native library. Neither changes the
product sources, public interface, entropy configuration or handshake checks.
The ABI 2 library remains SHA-256
`79f38e363ccc040c575dacd5f6cd4e7b8f75dfe12a3b0b48ade5ace0d63df4b6`.

Each probe completes five fresh-process blocks of 201 connections and 603
authenticated echo requests per block, with exact payloads, server counts,
completion and loaded-library checks. `getrusage(RUSAGE_SELF)` measures the
client process's user plus system CPU, at microsecond resolution. It excludes
the server and system-service CPU. Multiple client threads can accumulate more
CPU than elapsed time in a short span. Instrumentation/logging overhead is
included; these runs are attribution diagnostics, not a paired speed comparison.

The CPU-only probe observes first-connect elapsed time of 51.561–57.276 ms and
client CPU of 26.398–27.801 ms. Its block-level reconnect P50s span
8.341–8.371 ms elapsed and 1.126–1.152 ms client CPU. The stage probe's five
first connections give the following ranges; they are raw observed ranges,
not confidence intervals or first-connect tail estimates.

| First-connect stage | Elapsed range (ms) | Client process CPU range (ms) |
| --- | ---: | ---: |
| Native connection engine creation | 24.270–25.136 | 24.190–24.963 |
| Swift transport object creation | 0.772–0.902 | 0.628–0.765 |
| Transport start through TCP readiness | 1.130–1.418 | 1.157–1.448 |
| TCP ready through TLS/policy confirmation | 28.096–32.083 | 0.782–1.068 |

Two separate owned-process profiles then sample the exact client/native-library
and Rust-server binaries across their first connection. A five-second client
barrier gives the sampler time to attach before the connection starts; those
profiled timings are excluded from the table. The client stack reaches
`ClientConnection::new` → AWS-LC `RAND_bytes` → `get_entropy_source` →
`tree_jitter_initialize` → `CRYPTO_once` → `tree_jitter_initialize_once`, including
`jent_entropy_collector_alloc` and `jent_read_entropy`. The server independently
reaches that initializer while processing the first ClientHello. Each profile
completes 201 connections and 603 requests. An earlier shorter client capture
did not sample the initializer and is retained as insufficient attribution.

Selected sources from the locked `aws-lc-sys` 0.45.0, `aws-lc-rs` 1.18.1 and
rustls 0.23.45 packages are checked against their checksum-matched cached crate
archives and retained with licenses. They show global seed initialization under
`CRYPTO_once` and subsequent per-thread state initialization. Together, the
stage counters and sampled stacks identify provider entropy initialization as
a major first-connection CPU contributor in this native build. Sampling counts
are not CPU durations; the server profile does not assign an exact fraction of
the 28–32 ms confirmation interval. Those retained profiles include scheduling,
transport and the reference server's then-current 5 ms accept polling. No algorithm-only, allocation,
energy or constant-time result follows from these observations.

The provider and its health checks remain unchanged. This diagnostic does not
move initialization outside a reported cold interval or introduce warmup as a
claimed speedup. The remaining performance work must preserve the measured
contract and distinguish first-use costs from steady-state scheduling. Native
Linux, controlled comparisons, installed-package timing and release qualification
remain open.

## Reference listener readiness comparison (2026-09-26)

The [listener checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-listener-readiness/manifest.json)
replaces periodic sleeping in `connection_peer` with the workspace's existing
rustix 1.1.4 readiness API. The listener is explicitly nonblocking, so a reset
between readiness and accept cannot cause an unbounded wait. A single ten-second
deadline is rechecked after wakeups, interruptions and acceptance; it is never
reset by a retry. Listener failures are returned, and a connection accepted
after expiry is closed before delivery. TLS/request deadlines and authentication
remain unchanged. This is a reference-peer change; no cryptographic primitive,
entropy configuration, ABI major or Swift product implementation changes.

The old loop also admitted an already queued connection after its deadline and
reported an idle expiry as `WouldBlock`. A retained copy of that exact loop
fails both new deadline regressions, while the later-arriving-connection control
passes. The replacement passes all three actual socket tests. These tests now
run in the declared native Linux and Swift CI jobs; hosted execution is still
unobserved.

Five paired process blocks compare the frozen old peer with the rebuilt new
peer. Every arm uses the same frozen Swift executable, ABI 2 library and fixture
generator. The two arms within a pair use identical generated test credentials
and separate fresh persistent stores. Before measurement, all twelve existing
TCP/authentication/denial/cancellation/persistence scenarios run with each peer.
The AB/BA order is fixed with a recorded seed before sampling; all ten runs and
all 2,010 connections/6,030 echoed requests are retained and validated.

The table shows medians of the five block-level quantiles in milliseconds.
Bracketed values are the range of block P99s, not confidence intervals.

| Reconnect interval | Polling P50 | Readiness P50 | Polling P99 [range] | Readiness P99 [range] |
| --- | ---: | ---: | --- | --- |
| Connect through confirmation | 8.522 | 1.202 | 12.020 [9.395, 15.462] | 1.880 [1.460, 2.641] |
| 0-byte request/response | 0.178 | 0.138 | 0.509 [0.342, 0.583] | 0.274 [0.231, 0.310] |
| 1-byte request/response | 0.168 | 0.140 | 0.396 [0.347, 0.481] | 0.268 [0.235, 0.315] |
| 65,536-byte request/response | 0.787 | 0.692 | 1.679 [1.270, 2.432] | 0.879 [0.841, 1.153] |
| Graceful shutdown/disposal | 0.051 | 0.045 | 0.102 [0.087, 0.141] | 0.079 [0.075, 0.114] |

Connect P95's block median changes from 10.622 to 1.459 ms. The five first
connections span 53.023–65.025 ms for polling and 53.094–63.098 ms for readiness;
their raw values remain in the comparison manifest, without a first-connect
tail or improvement claim. Provider entropy initialization remains in the first
connection. The one-minute host load changes from 6.81 to 6.19. These observations
support removing an artificial wait from this reference path; they do not
establish faster cryptographic operations, lower CPU/energy, an installed-package
improvement or a controlled release-level tail guarantee.

The comparison deliberately reuses previously frozen, source-matched SDK
executables/library and rebuilds only the changed peer. It is not a fresh full
SDK/package build. At capture, free disk space is below the diagnostic's 2 GiB
build threshold, which remains enforced. Release build, the three socket tests,
strict example/test Clippy, formatting and 57 affected artifact checks pass.
The changed Swift job lints; full old/new workflows retain the existing Ubuntu
26.04 actionlint catalogue error. No diagnostic is suppressed and no hosted CI
result is inferred. Full source freeze, regenerated packages, native platform
and device execution, and controlled performance/CT remain
required for release.

## Fresh source build after space recovery (2026-09-26)

After free disk space recovered above the unchanged build guard, the full
driver ran again from the current source. This [follow-up checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-allocation-and-quality/manifest.json)
includes the real Rust/C/Swift build commands, strict Swift compilation, all
twelve acceptance/failure/persistence cases, and five blocks totaling 1,005
connections and 3,015 requests. It completes with source, binary, loader,
sample-matrix and server-count verification.

The resulting ABI 2 library is
`d709fdc27fcc84baa3054a7e09704c6e2e83f7a9701e67d615e6aa3017e73821`; the reference
server remains
`39078b80fb60625e2745a8d368fae8729aae9106e5a46aa6eb6ca98df15d70b2`.
The native metadata calls return ABI 2 and extension 1, and its project export
set exactly matches the 43-function contract. This is a new local source-build
identity, not qualification of an earlier distribution archive.

Reconnect P50/P95/P99 block medians are 1.092/1.449/2.056 ms; all block P99s span
1.800–2.790 ms. Every first-connect observation and every raw sample is retained.
This fresh capture is descriptive and does not replace the preceding paired
comparison or establish controlled tail non-regression. The accompanying full
artifact suite passes 2,219 tests in 496.991 seconds. Native Linux, installed
final packages, devices, controlled performance/CT and hosted CI
remain separate release requirements.

## Installed-package connection baseline (2026-09-27)

The [installed timing checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-installed-connection-timing/manifest.json)
uses the actual Swift client already built outside the checkout from the complete
alpha ZIP and its exact packaged static native library. The Rust peer is rebuilt
in release mode from the same nine extracted `.crate` archives, with the existing
consumer lock held fixed and warnings denied. Release Clippy passes; Cargo again
resolves all products to the extracted packages and all external versions/sources/
checksums to the workspace lock. No product source, package or host setting changes.

All twelve acceptance/failure/persistence cases run with these release binaries
before measurement. The existing clock, sample parser, quantile calculation and
loader verifier are reused by an isolated captured driver. Five fresh-process
blocks each complete one first connection and 200 reconnections, totaling 1,005
connections and 3,015 checked echo requests. Every block, raw sample and failed
attempt is retained. The same release-built standard TLS peer subsequently
passes eight independent OpenSSL 3.6.3 cases, including the required rejection
reasons. Generated test credentials remain in the private run directory.

Values are the median of five block-level nearest-rank quantiles, in milliseconds.
The bracketed range contains every block's P99 and is not a confidence interval.

| Installed connection interval | P50 median (ms) | P95 median (ms) | P99 median [range] (ms) |
| --- | ---: | ---: | ---: |
| Connect through confirmation | 1.063 | 1.243 | 1.304 [1.281, 1.348] |
| 0-byte request/response | 0.133 | 0.170 | 0.198 [0.185, 0.243] |
| 1-byte request/response | 0.135 | 0.167 | 0.194 [0.178, 0.204] |
| 65,536-byte request/response | 0.617 | 0.726 | 0.773 [0.763, 0.801] |
| Graceful shutdown/disposal | 0.039 | 0.058 | 0.076 [0.065, 0.080] |

The five first connections are 60.001, 54.651, 54.952, 53.831 and 55.777 ms.
Client setup is separately observed at 31.164–36.667 ms. These are first calls
after setup and the acceptance run, not cold-boot or first-connect tail estimates.
The one-minute host load is 4.26 at both recorded endpoints. CPU/power/scheduling
remain uncontrolled; the capture does not estimate energy or CPU cost.

The client's SHA-256 remains
`ff8c373d5321854c33ff4805343776c4f41c4d662bfead73bff9525638c3c3ee`,
and the packaged macOS static library remains
`e220c4110a33acc35e9db1d8fde865710a395fc3134e8d2473d2a0bee625d93a`.
The new release Rust peer is
`4d4dbbbe35457cf7918f45e78470c56beb36fc338204c20dbb9ee9bded340865`.
All binaries, package inputs, selected sources and the primary Git index remain
unchanged through measurement. The archived build commands identify the external
consumer's release profile; this is not a comparison with a different provider,
historical release or earlier source-build table. Controlled tail non-regression,
native Linux/Windows, devices, CT/energy and formal release qualification remain
open. No timing threshold is weakened and no speedup claim is inferred.
