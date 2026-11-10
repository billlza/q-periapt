# Reuse historical roster verification within one journal image

The current change reduces repeated signature work while keeping current
authorization in its existing operation paths. Base source is
`0037d195e2342c0c03ced5653d30b9762a5528be`; implementation commit is `9ed01d70143a6a90ab4ffc6bc1b6d1570c5fd9c6`.
CAPTURE.json binds every integrated file by hash.
The uninstrumented measured variant is byte-identical to the promoted engine
files. No public API, wire encoding, storage schema, dependency or policy changes.

`VerifiedRoster::from_journal` remains the authoritative historical decoder.
Its successful results are memoized by complete encoded bytes, including account,
family, checkpoint, root and signed wire. Changed bytes run the full decoder;
invalid results are never cached. Current time, membership, monotonic/current-head
checks, record identity, journal/policy scope, credential renewal, retirement and
witness state remain outside the memo. Each Image starts with an empty cache and
drops it with that Image. The Active owner and stored journal contain no memo.

The cache bounds retained encoded inputs to 64 KiB and entries to 64. Parsed
public rosters and allocation overhead add memory beyond that input-byte bound.
A capacity miss performs the authoritative decode and preserves valid-input
admission. Signature verification occurs outside the mutex; poisoning returns
an explicit Corrupt error. The private implementation and its tests are separate
modules, and the record parser remains shared with the uncached historical path.

## Paired native observations

Three paired blocks alternate profile order and reverse baseline/variant order.
Every process starts fresh enrolled identities, stores and a session. Each sends
64 messages cycling through 0, 64, 1024 and 16384 bytes, with epoch-1 rekey halfway
through. Each send uses fresh pinned hybrid TLS, encrypted journal transitions,
an actual fsynced receiver business file and authenticated consumption. TLS
resumption and early data stay disabled; no sample is discarded.

The twelve processes execute 768 ordinary sends, twelve rekeys and twelve original
unknown-result recoveries. Each recovery closes/reopens both owners and retries
the exact message without a second business effect. Retired resend is refused.
Public-only readback independently verifies 780 business files and rejects all
768 individual sample substitutions. A preceding four-process pilot and two
fresh diagnostic profiles remain in the capture separately from the paired data.

| Protection | Baseline p50 / p95 (ms) | Cached p50 / p95 (ms) | Observed p50 reduction |
| --- | --- | --- | --- |
| local | 131.42 / 139.91 | 116.13 / 134.12 | 11.6% |
| witness | 231.08 / 243.59 | 215.91 / 231.66 | 6.6% |

Each distribution contains 192 observations and uses nearest-rank quantiles.
The host is Apple M1 Max (10 cores, 32 GiB), macOS 27.0.1 / 26A434, with Rust
1.98.1 Release, opt-level 3, thin LTO, one codegen unit and overflow checks. Host
load is recorded and uncontrolled; no task builds or broad tests overlap the
paired measurement. This two-peer workload does not establish production tails,
general non-regression, energy, independent implementation or foreign/device
performance. Savings may differ or disappear when the bounded cache is full.

| Protection | Baseline process RSS range (MiB) | Cached process RSS range (MiB) |
| --- | --- | --- |
| local | 13.52–13.86 | 13.95–14.38 |
| witness | 17.75–18.66 | 17.67–18.03 |

Each range contains three Darwin maximum-RSS observations. The process includes
both peers, the witness where required and observer buffers. These observations
retain the cache's memory cost and do not establish maximum-capacity SDK memory.

Separate timing-counter builds show roster-verification calls falling from 103
to 28 locally and from 109 to 28 with the witness per slot-lookup/send/status
group. Each such call verifies both signature components.
All measured durability, validation-stage and authority-check call counts remain
unchanged: ten instrumented journal write-intent database commits, five intent
commits and twenty current-state checks. Witness request/reply signatures remain
25 each. Independent network accounting still observes twenty Query and five
Advance exchanges, 183,525 framed bytes per group. The database counter covers
the instrumented write-intent commits; it excludes witness-store commits and the
host business-file fsync. Diagnostic durations are inclusive and do not supply
the speedup estimate; the optimized counter run overlapped native regression.

## Validation and retained failures

All **1025 native library tests** pass with all features, zero failures, ignored
tests or filtered tests. The same source passes 29 focused roster tests, strict
all-target/all-feature Clippy, canonical format, WASM library compilation, six
cache tests under Rust 1.90 and iOS arm64 compilation. The warmed-image policy
graft case still rejects authorization from another journal. The full artifact
suite passes 2879 tests with zero skips, and the
exact implementation-source gate passes.

The new installed WASM archive has SHA-256
`1253152b4714848524099de17c4d3d63131643cefaabe43a5236bf24403cb4d9`. Fresh actual Chrome/IndexedDB flows
execute 81 Worker calls, four Worker terminations and two held-Query cancellations.
Both unapplied and applied R2 recovery paths retain the original pending message
and rekey across real policy expiry. Independent P1 renewals then allow exact
control/ciphertext replay, epoch-1 completion, bidirectional consumption and new
work, with two native business effects per path. Six public-reader controls reject
all 81 call substitutions and altered termination, mutation and delivery outcomes.
The native peer uses the retained baseline executable with fresh identities and
stores; this is cross-version interoperability within the same implementation.
Physical-device qualification of the cache delta remains separate.

The first broad run was deliberately interrupted: its generic 900-second outer
deadline was shorter than a previously recorded 1209.05-second full-library run.
Its 613 passing records remain incomplete evidence. The successful replacement
uses the established 2700-second outer bound with fresh test state and unchanged
assertions and SDK timeouts. The failed manifest relocation and instrumentation
recipe preparation remain, together with their fixes; neither reached a product
runtime. Earlier REPORT_18.md is the explicitly pending experimental checkpoint.

The first new-package browser cohort stopped at establishment with Deadline and
closed its owner. Public receipt times show the unchanged native peer's first
response taking approximately 4.8 seconds, versus 1.3 seconds in the earlier
accepted baseline; native and artifact qualification jobs overlapped that attempt.
After those jobs were terminal, four fresh baseline/optimized/optimized/baseline
bootstrap controls all passed with the original ten-second deadline. Measured
outer call durations were 7.71–7.72 seconds for the baseline and 7.45–7.94 seconds
for the optimized package. These observations support
scheduling contention as a possible contributor, without identifying a unique
root cause or erasing the failed cohort. Its original stores remain sealed.

A second fresh run exposed an observer fence error: Python's fractional clock
passed the integer policy expiry while the Worker's whole-second observation
still equalled it. Both public pending results had runtimeCreated=false; the
first observedAt equalled until and the second was two seconds later. The test
wait now reaches until+1 before issuing recovery, preserving its original strict
observedAt>until assertion and all SDK deadlines. Three controls execute the
actual old/new wait AST, reproduce the old equal-second result and check the
corrected boundary. A subsequent entirely fresh composed run passes both paths
with the same SDK, timeout values and safety assertions. Both failed cohorts
remain sealed and their public records are retained.

The concurrent artifact attempt also hit its 900-second outer bound before a
terminal test report was retained. It contributes no test pass claim. The complete
serial rerun retains live stdout/stderr and a 2700-second outer deadline, with all
assertions unchanged. No SDK timeout, safety check or failure outcome was relaxed.

CAPTURE.zip SHA-256 is `9107c52e80daf08303e97a188f5002dcb023be7bd6b5237c22cd129a3e82f0b2` with 9843
members. Its inventory, public-result parsing and all 780 paired business effects
are read back from the archive. Private journals, keys and runtime directories
are excluded. The two new Rust source paths are added to the exact CodeQL
inventory and missing-source rejection controls; hosted validation remains open.

Current-source native foreign-package/device qualification, controlled tails and energy,
maximum-capacity memory, independent endpoints, full construction/recovery
analysis, maintenance/freeze and external review remain 0.2.0 release gates.
