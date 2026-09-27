# Actual SDK path performance diagnostic

The unpublished alpha now measures calls from a compiled C consumer and the
public Swift bindings through the actual ABI 2 dynamic library. These are local
source builds, not installed release packages. The existing core performance
proofs, budgets and historical Rust diagnostic remain separately scoped.

The separate [full connection diagnostic](SDK_CONNECTION_PERFORMANCE.md) now
records setup, first connection, subsequent fresh TLS connections, request/response
and graceful shutdown through the public Swift adapter and real Rust peer.

## What is measured

The [driver](../artifact/sdk_path_performance.py) builds release-mode Rust/Swift
and `-O3` C, freezes the two executables and library, and requires dyld to report
that frozen library in every process. It checks source hashes before/after
building and running, and binary hashes after running. The manifest records
compiler versions, CPU, source inventory, commands and all raw sample hashes.
Failures retain their output and an incomplete manifest; a previous directory
cannot be reused. This dirty-source diagnostic cannot produce a release proof.

Performance and connection drivers share one loader verifier. It requires
exactly one complete dyld UUID/absolute-path record for the selected library
and rejects another named Q-Periapt dynamic image or transition. Ordinary text,
path suffixes and duplicate records cannot establish the load identity.
SDK names are checked on the basename; an unrelated library does not become
an SDK image merely because a parent directory contains `qperiapt`.

Each consumer compares the retained byte-oriented compatibility API against
the current owner API under the same verified ContextBound policy. Outside the
timed interval it generates one key, explicitly imports that same key into the
owner, compares the public key and policy state, and checks real roundtrips in
both directions before and after every context cell. No deterministic entropy
or alternate cryptographic backend is selected.

There are seven cells: key generation, plus encapsulation and decapsulation at
32, 4096 and 65536 context bytes. Decapsulation reuses one already-generated key
and ciphertext; it does not model fresh connection establishment. Each call
includes normal shape checks, result creation, explicit combined-secret export,
secret erasure and owner disposal. Key generation also returns the public key;
key generation/encapsulation include platform RNG. Swift uses both real public
wrappers, including their allocations and marshalling. Diagnostic ciphertext
split/join operations are outside timing for both APIs.

Five fresh process blocks each collect 1000 paired observations per cell after
64 warmup pairs. Pair order alternates AB/BA; the starting phase and executable
order alternate between blocks. All blocks are retained. Nanoseconds use the
macOS raw uptime clock in C and `DispatchTime` uptime in Swift. P50/P95/P99 use
nearest-rank quantiles; the reported comparison is the median and range of the
five block-level ratios of quantiles. A range is not a confidence interval.

Excluded costs are policy verification, key import/setup, persistence, async
dispatch, network/TLS, and printing. Allocation counts, concurrent/long-running
resource use, energy and cold-start/package size need separate measurements.
These results compare two APIs in the same source/provider build; they do not
compare against historical 0.1.5 binaries or another vendor.

## Observed local results

The [checkpoint](../research/sdk-alpha1/evidence/20260925-sdk-path-performance/manifest.json)
retains every attempt. The final run used an Apple M1 Max with ten logical CPUs,
Rust 1.96.1 and strict Swift concurrency/warnings-as-errors. CPU/power/host load
were uncontrolled; one-minute load changed from 10.37 to 9.36. Nothing changed
the host's power settings or other applications.

P50 values below are medians across five blocks, in microseconds. The last
column is owner/compatibility P99 ratio: median followed by the observed range.

| Consumer | Operation | Context bytes | Compatibility P50 (µs) | Owner P50 (µs) | P99 ratio median [range] |
| --- | --- | ---: | ---: | ---: | --- |
| C | Key generation | 0 | 50.709 | 50.208 | 0.996 [0.873, 1.022] |
| C | Encapsulation | 32 | 96.916 | 97.000 | 0.991 [0.978, 1.057] |
| C | Decapsulation | 32 | 57.542 | 56.834 | 1.057 [0.981, 1.144] |
| C | Encapsulation | 4096 | 106.291 | 103.667 | 0.965 [0.925, 0.975] |
| C | Decapsulation | 4096 | 66.875 | 63.417 | 0.919 [0.844, 1.048] |
| C | Encapsulation | 65536 | 246.583 | 202.875 | 0.742 [0.681, 0.837] |
| C | Decapsulation | 65536 | 207.083 | 162.584 | 0.725 [0.722, 0.741] |
| Swift | Key generation | 0 | 50.333 | 50.833 | 0.894 [0.838, 1.362] |
| Swift | Encapsulation | 32 | 97.459 | 97.917 | 1.014 [0.948, 1.037] |
| Swift | Decapsulation | 32 | 57.792 | 57.458 | 0.929 [0.860, 1.225] |
| Swift | Encapsulation | 4096 | 106.791 | 104.584 | 0.977 [0.970, 1.069] |
| Swift | Decapsulation | 4096 | 67.000 | 64.000 | 1.043 [0.831, 1.087] |
| Swift | Encapsulation | 65536 | 246.792 | 204.292 | 0.786 [0.682, 0.815] |
| Swift | Decapsulation | 65536 | 206.834 | 163.417 | 0.760 [0.710, 0.985] |

The 64-KiB cells show lower observed owner latency in both consumers. Small
context P50 is close, and several P99 comparisons exceed 1.0. **Small-context
tail non-regression remains unestablished.** No block is dropped, threshold
relaxed or security check removed to turn these observations into a pass.
These numbers do not establish a release speedup, sustained throughput, energy
saving or constant-time property.

The first C capture exposed 1000-ns timestamp quantization. A separate
`clock_getres` check reported 1000 ns for `CLOCK_MONOTONIC` and 42 ns for
`CLOCK_UPTIME_RAW`; Swift's samples did not have the microsecond quantization.
The C harness now uses `clock_gettime_nsec_np(CLOCK_UPTIME_RAW)`. An initial
compile attempt hid that Darwin extension behind a POSIX-only feature macro;
using the Darwin feature namespace fixed it without lowering warnings. Both
that failure and the coarse-clock run remain in the checkpoint. The final
table is the first complete run after the timer correction, not a selected
best-performing rerun. No product code changed for this correction.

## Reproduction

```sh
sh artifact/python-run.sh artifact/sdk_path_performance.py \
  --output target/sdk-path-performance-local --samples 1000
```

Use a new path under `target/`. All builds run before sampling. The driver uses
the existing bounded-process cleanup, caps raw output and validates the exact
cell/sample matrix. Tests reject missing/duplicate/reordered cells, bad sample
counts, booleans/floats/nonpositive/oversized times and changed measurement
metadata. A declared macOS CI step uses 200 samples to check wiring only; it
has not been observed running on a hosted runner and has no numeric gate.

## Loader verification follow-up (2026-09-26)

The [loader checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-dynamic-loader/manifest.json)
retains four concrete old/new controls. The former performance guards accepted
ordinary diagnostic text, a duplicate image record and a second SDK image or
transition. The shared connection verifier already required a real image record,
but its dynamic mode still allowed a second SDK library. The performance driver
now calls that shared verifier, whose dynamic mode rejects the mixed identity.
Two regression tests first fail on the previous implementation and then pass;
they also prevent a false rejection based only on a directory name.

A fresh real C/Swift run completes all five blocks with the unchanged 1,000-pair
budget per cell: 140,000 timed calls, plus warmup. Both executables and the
selected library are frozen and hashed; all ten actual dyld logs satisfy the
corrected verifier. The source inventory and binary identities are unchanged
through measurement. The nine affected tests pass, and the Rust/C/Swift builds
emit no compiler warnings or errors. The previous ten performance logs and
twelve installed static-client logs also pass revalidation against their pinned
historical records; this log revalidation is not another connection execution.

The new capture's one-minute host load changes from 5.29 to 5.91. It validates
the corrected runtime evidence check under real execution, with all raw samples
retained. It does not change the selected historical table above or establish
controlled P99 non-regression, installed-package performance, constant time,
concurrency, long-run resource use or energy targets. Product cryptographic code,
ABI major 2 and package versions are unchanged.

## Rust allocator observation (2026-09-26)

The [allocation and quality checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-allocation-and-quality/manifest.json)
adds an isolated Rust executable that compares the statically linked compatibility
C entry points with the public owned Rust SDK. It uses the same authenticated
ContextBound policy and the same hybrid key, transferred through the explicit
expert import API. Before and after every context cell, ciphertexts from each
path are decapsulated by the other and their secrets are compared. This observer
does not change the product allocator, ABI or cryptographic implementation.

The executable registers a `GlobalAlloc` observer that forwards pointers,
layouts, sizes and results unchanged to `System`. Counter bookkeeping uses
atomics without adding allocations, logging, locks or an unwind path. A direct calibration
checks allocation, zero-initialized allocation, reallocation with preserved
contents, deallocation and the associated layout-byte counts. Counter windows
surround one synchronous encapsulation/decapsulation, explicit combined-secret
export and result disposal. Counter overflow fails the capture. No background
Rust worker is started by the probe.

Five fresh processes each run 200 alternating AB/BA pairs per cell after 32
warmup pairs. Both operations cover 32, 4,096 and 65,536 context bytes: **12,000
measured calls** in the final run, or 1,000 observations per operation, context
and API. Every observed row in each cell has the following counts. The byte
column sums requested allocation layouts, not allocator overhead or RSS.

| Context bytes | Compatibility allocations/call | Compatibility requested bytes/call | Owned Rust allocations/call | Owned requested bytes/call |
| --- | ---: | ---: | ---: | ---: |
| 32 | 2 | 2,754 | 0 | 0 |
| 4,096 | 2 | 10,882 | 0 | 0 |
| 65,536 | 2 | 133,762 | 0 | 0 |

Both encapsulation and decapsulation produce the same table. The compatibility
path also records two deallocations with matching requested-layout bytes per
call; neither path records reallocation, zero-initialized allocation or a
failed allocation inside these operation windows. Source inspection identifies
the retained compatibility policy-context vector and staged transcript reserve;
the owned path streams the same fields using prepared key storage. The counters
observe calls in this build and do not measure secret-copy counts or erasure.

Policy verification, key generation/import, preallocated sample storage,
ciphertext split/join, output formatting and cross-checks are outside the
windows. Native C allocation calls, foreign-language wrappers, the SDK's C
owner-handle registry, peak live memory, RSS, concurrency, failures and energy
remain unmeasured. Runtime and key owners already occupy memory before the
windows. These results must not be described as an allocation-free whole SDK
or process. Rust explicitly permits the compiler to eliminate allocations;
the observation is not an all-build API guarantee. See the official
[GlobalAlloc safety contract](https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html#safety).

All 107 resolved diagnostic packages match the workspace lock's identities and
checksums; no dependency version is upgraded. The observer uses the canonical
development toolchain, Rust 1.96.1. The public SDK's minimum compiler contract is
unchanged. Initial strict Clippy rejected a manual parity idiom; the observer
uses the supported integer method and declares its development compiler floor.
The initial capture and lint failure are retained, and the corrected executable
passes Clippy, calibration, five actual invalid-budget controls and a complete
rerun with identical counter distributions. No lint is suppressed.

Disk space initially prevented this build. Its prepared sources and blocked
record remain retained; execution started only after free space recovered,
without deleting the requested incremental cache. The current Rust/C/Swift
connection build subsequently passes all twelve boundary scenarios and five
complete timing blocks. The full artifact suite passes **2,219 tests across
90 modules in 496.991 seconds**, with warnings treated as errors in the owned
standalone copy. All 843 selected source files match the primary checkout during
that run. Only documentation changes afterward; release/platform/controlled
performance qualification remains open.

## Actual C owner allocations and public-key storage (2026-09-27)

The [C owner checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-public-key-view/manifest.json)
measures the actual C owner entry points, including registration, secret export,
wiping and close. The existing `bindings/c/sdk_path_perf.c` consumer is compiled
as a separate, non-LTO C object and linked to an isolated Rust allocator observer.
The C object and counter/controller sources are byte-identical before and after
the product change. Undefined-symbol inspection confirms the object calls the
real compatibility and owner functions; cryptographic operations are not mocked.

Each capture runs five fresh processes, 200 alternating pairs per cell and 64
warmup pairs. Key generation and both KEM operations at 32, 4,096 and 65,536
context bytes yield 14,000 measured calls before and 14,000 after. Both captures
pass allocator calibration, six actual invalid-budget/phase controls, and
cross-decapsulation in both directions before and after each context cell.
All 1,000 observations per API/cell have the counts below. Requested bytes are
the sum of successful Rust allocation layouts, not peak memory or RSS.

| C operation | Context bytes | Legacy allocations / requested bytes | Owner before allocations / requested bytes | Owner after allocations / requested bytes |
| --- | ---: | ---: | ---: | ---: |
| Generate/export public key/close | 0 | 1 / 2,400 | 3 / 4,888 | 3 / 3,704 |
| Encapsulate or decapsulate/export secret/close | 32 | 2 / 2,754 | 1 / 80 | 1 / 80 |
| Encapsulate or decapsulate/export secret/close | 4,096 | 2 / 10,882 | 1 / 80 | 1 / 80 |
| Encapsulate or decapsulate/export secret/close | 65,536 | 2 / 133,762 | 1 / 80 | 1 / 80 |

The owner retains a stable, zeroizing expanded ML-KEM key. That representation
already contains its 1,184-byte paired public key; caching another copy inside
`PreparedMlKem768Key` duplicated public storage. Public access now borrows the
embedded field. A compile-time format-size invariant bounds the view, and
generation still checks it against the provider's returned public key. Expanded
imports retain native encapsulation/decapsulation and constant-time pairwise
consistency checks. Every normal decapsulation still runs the native canonical
encoding and H(ek) checks. No unchecked native entry point is introduced.

Only `crates/q-periapt-backends/src/contextbound_key.rs` differs between the two
measured product source inventories. Regression coverage verifies both generated
and imported public views borrow the paired field, and preserves rejection with
unchanged output for corrupted encoding/hash. All compatibility counters and
all encapsulation/decapsulation counters stay identical; key generation's
requested bytes decrease by exactly 1,184. Owner key generation still allocates
more than the compatibility call. The C owner path's 80-byte allocation also
remains visible: the earlier zero-allocation observation applies to the direct
Rust operation window, not to C handles or the whole SDK.

The before/after observer executables have SHA-256
`4c91615820bceab8af44aa75a49fca9aff83ee0177d10b29943317aeb8466618` and
`181a396cb35a7c5898dfee35c6d24e47652ac14d6e999b68082044d61d191f52`.
Every measured allocation has a matching deallocation and layout-byte total;
neither capture records reallocations or allocation failures. Native C allocator
calls, foreign wrapper allocations, setup/import, peak memory, allocation-failure
injection, concurrency, energy and installed dynamic-library allocation counts
remain outside this observer. The build-specific counters do not establish a
latency, constant-time or release performance claim. ABI major 2, extension 1,
the 43-symbol table and SDK version 0.2.0-alpha.1 are unchanged.

## Eight-thread resource observation (2026-09-27)

The [native resource checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-native-resources/manifest.json)
uses an isolated C11/pthreads consumer of the same frozen ABI 2 dynamic library.
Twenty predeclared 30-second blocks complete 600.010053 seconds of steady work
with eight threads. All threads share one generated key per block, use platform
entropy for each encapsulation, and verify both the combined secret and derived
key. Each thread cycles through 32-, 4,096- and 65,536-byte contexts and all five
purposes. The run completes 12,716,379 KEM/derivation roundtrips; this is an
operation count, not a count of independent security tests or network requests.

After each block, two sets of sixteen close schedules race eight actual C calls
against key or runtime close. Key-close schedules produce 2,520 successful
decapsulations and 40 `ERR_CLOSED` results. Runtime-close schedules produce 1,442
successful encapsulations and 1,118 `ERR_CLOSED` results. Successful key-race
secrets still match the original secret; after runtime close, any previously
published secret handle rejects export and produces zero output. Failed calls
produce zero handles and, for encapsulation, zero ciphertext. These schedules
observe public call spans; the separate controlled Rust tests pin internal
admission/borrow points. No other native status is accepted as a successful run.

Before the workload and after every block, the consumer fills the complete
registry with one runtime and 1,023 keys. The next child must fail with
`ERR_RESOURCE_LIMIT` and a zero handle. Parent close then drains its children,
whose old IDs must reject reuse. All **21 capacity probes** pass. The final
capacity checks occur after workers have joined, consistent with the contract
that an active native borrow can delay disposal.

Each post-drain sample reads this process's `task_vm_info` and `getrusage`:

| Field | First sample | Last sample | Observed range |
| --- | ---: | ---: | ---: |
| Physical footprint, bytes | 6,209,944 | 6,308,248 | 6,209,944–6,308,248 |
| Resident memory, bytes | 7,340,032 | 7,454,720 | 7,340,032–7,454,720 |

Both values remain unchanged from the fourth through twentieth sample. The
initial footprint increase is 98,304 bytes; this diagnostic does not attribute
it to a particular allocator or thread cache. CPU totals are 3,683.093666 user
seconds and 100.417190 system seconds, including setup, races and capacity
probes. Host load changes from 17.70 to 27.90 and is uncontrolled. No memory
acceptance threshold is selected afterward, and these observations do not
establish absence of leaks over arbitrary runtimes, controlled throughput,
tail latency, energy use or release qualification.

Strict C compilation and a one-second preflight with six real invalid-argument
controls precede the full run. Every child must load the exact frozen library;
source/input/binary hashes remain unchanged throughout execution. The consumer
and collector are retained as isolated diagnostic assets. Product code, default
allocator, entropy and cryptographic checks are unchanged. Installed packages,
foreign async queues, network/persistence, allocator-failure injection, other
platforms and longer controlled runs remain separate requirements.
