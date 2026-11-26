# Absolute latency measurements for the persistent-recovery manuscript

This artifact supplements the service/work experiments with two different measurements:

1. Six warmed cryptographic backend operations, with 1,600 calls per operation.
2. Established-session, same-host committed-plaintext delivery between two distinct native file journals, with 256 individually timed messages.

Both manuscript measurements use the service-source commit
`358b921ab3469ce49f166633fc9a762ff6ed7e3d` of `billlza/q-periapt`. They are new
measurements of those source bytes. They are not timings recovered from the
earlier 42 matched-service or 28 retry-readiness traces.

## Recalculate and verify without building Rust

```sh
python3 analyze_latency.py --check
```

The checker verifies every retained file against `MANIFEST.json`, every upstream
source blob in the source archive against both its Git blob ID and SHA-256,
the sample inventory, positive clock intervals, delivery phase sums, and the
execution receipts' raw-file hashes. It recomputes the JSON summaries and both
TeX tables from all raw rows. When placed at `paper/continuity/artifacts/latency`,
it also checks the two corresponding manuscript table files. A table located
elsewhere can be supplied with `--paper-table`.

The JSON/CSV summaries retain more digits than the manuscript's three-decimal
millisecond presentation. `primitive-summary.csv` and `primitive-table.md` are
convenience exports of the same retained primitive samples. `analysis/` contains
the two generated manuscript tables.

## Source and build identity

`sources/upstream-358b.tar.gz` contains a minimal compileable source closure,
required license texts, and copies of the measurement harnesses and build locks.
`inventory-358b.json` separates original upstream blobs from the added
`_measurement/` files. The latter are explicitly experiment additions, not
files claimed to exist at the upstream commit. The same harness files are also
available as plain text under `harness/` for review.

No cryptographic, journal, bootstrap, or message-state source is changed. Source
preparation changes only the root workspace membership list to the included
packages and adds the primitive harness as a member. The delivery harness is a
separate workspace using public APIs. Its setup fixture is adapted from the
same commit's bootstrap fixture: private deterministic root/device/policy-key
constructors are replaced by their public `generate()` APIs. This setup is
outside all timed intervals. The fixture still performs actual signed policy,
credential, manifest, prekey and bootstrap validation.

The measured backend is `mlkem-native-2.0.0/portable-c`, using the default
features; the optional Linux AVX2 feature is not enabled. ML-DSA uses
`fips204 0.4.6`. The C build driver is `cc 1.5.1`. Exact transitive versions and
registry checksums are retained in the two lockfiles. The compiler is Rust/Cargo
1.98.1; release settings are optimization level 3, thin LTO, one code generation
unit, and overflow checks enabled. The actual C compiler version, host
description, compiler environment, binary hash, and source/lock hashes are in
the execution metadata. Native C flags are fixed by the archived
`q-periapt-mlkem-native-sys/build.rs` and its pinned `cc` build driver.

The host reports an Intel Xeon Platinum 8573C, Linux 6.18.57, Debian 13, and
virtualization. Both measurements are pinned to logical CPU 0. The ordinary
process environment provides no demonstrated exclusive hardware, thermal or
frequency control. Full raw host descriptors and before/after load observations
are retained. No sample is excluded for its duration.

## Timing definitions

Primitive inputs comprise 64 distinct deterministic seed/coin/message cases
prepared outside timing. Each operation gets 256 warm-up calls, followed by
200 samples of eight calls each, rotating operation order between samples.
Each case occurs 25 times in each measured operation. Signature input is 1,024
bytes with an empty context. The public backend APIs include their ordinary
input/key parsing and validation. OS random-number acquisition, storage,
protocol state, and networking are outside these microbenchmarks. All 64 KEM
round trips and signature verification checks succeed, and modified-message
negative controls fail as expected, before collection.

Wall time is `CLOCK_MONOTONIC_RAW`. CPU time is
`CLOCK_PROCESS_CPUTIME_ID`. The CPU interval encloses the wall-clock reads, so
the boundaries differ slightly. Raw integer nanoseconds are retained. No
timer-overhead subtraction is performed; a no-op batch control is retained.
Primitive percentiles are percentiles of eight-call **batch averages**, not
single-operation tail latency. The manuscript uses primitive arithmetic means.

Delivery uses 16 independently provisioned pairs, two warm-up messages per
pair, and 16 measured messages per pair. Directions alternate, giving 128
messages in each direction. Each payload is 1,024 bytes and associated data is
32 bytes. The interval starts before `next_message_id`, includes sender
reservation and chain/outbox persistence, carries the resulting ciphertext
directly in memory, and ends when `receive_message` returns authenticated
`CommittedPlaintext` after receiver chain/inbox persistence. The two journals
are distinct actual `DeviceJournal` instances using `LockedFileBackend` and
redb's file backend on the workspace filesystem (reported as `ext2/ext3`).
Original OS-randomness and synchronization calls are retained.

Credential/policy/key provisioning, the initial three-flight bootstrap, chain
activation, correctness comparisons, application consumption, acknowledgement
creation/acceptance, and directory deletion are outside delivery timing.
There is no socket/network delay, loss, reordering, or rekey within these
intervals. This measures established-session local delivery, not connection
startup, a full recovery cycle, mobile storage performance, or a network SLO.
All 256 plaintext/message-ID checks succeed. Delivery quantiles operate on
individual messages and use nearest rank, `ceil(p*n)`.

The retained wall-clock distribution has mean 24.531298 ms, median 17.007100 ms,
p95 37.045552 ms, and maximum 257.105098 ms. The sample standard deviation is
31.969126 ms. Process CPU has mean 18.690721 ms, median 13.590518 ms, p95
27.253009 ms, and maximum 178.035019 ms. The long observations remain in every
summary. This descriptive measurement does not attribute their cause.

## Synchronization boundary and unsuccessful tracing attempt

The archived native source requests redb `Durability::Immediate` and two-phase
commit. Each send persists the reservation and the advanced chain/outbox;
receive persists the chain/inbox before returning plaintext. The commit path
reserves and applies the write intent, and `LockedFileBackend::sync_data`
delegates to redb `FileBackend::sync_data`, which calls the file synchronization
API. These paths were also reviewed independently of the collector.

After the 256-message run completed successfully, a separate one-message
`strace` audit was attempted. The environment denied `PTRACE_TRACEME` and
`PTRACE_SETOPTIONS`. `sync-audit.json`, the original stderr, the empty trace,
and the collector's resulting marker-parse failure are retained. No instrumented
message was pooled with the measurements. **No dynamic sync-call count or
physical power-loss persistence result is claimed.** The reproduction command
below skips this unavailable optional tracing step.

## Run a new measurement

Requirements: Linux x86_64, Rust/Cargo 1.98.1 on `PATH`, a C compiler, Python 3,
and registry access or a populated `CARGO_HOME` for the locked dependencies.
Use a fresh work and output directory:

```sh
python3 run_latency.py --work-dir /tmp/qperiapt-latency-work --output-dir /tmp/qperiapt-latency-results
```

This unpacks and verifies the supplied sources, installs the two harnesses and
locked manifests, builds both release executables, collects the same workload,
and recalculates results in the new directory. It does not overwrite the
retained paper results. Hardware, scheduler and filesystem conditions affect
new absolute times; reproducibility here means an exact defined source,
workload, timer and analysis procedure, not an assertion of identical timings
on different hosts. Compiler override environment variables must be unset to
match the recorded default build.

`preliminary-9503/` retains an earlier capture at the current paper-branch source
(fips204 0.5.0 / cc 1.11.1). It is clearly separated and supplies no manuscript
number. Its raw data, environment, summaries, lock and source inventory are
preserved without duplicating the large source/vector archive.
