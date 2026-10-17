# Native owner outbox capacity — 2026-10-17

Four fresh native processes at source
`3df45b849012334190f764aecc73ac558b3eb712` exercise the 64-outstanding-message
limit for one direction in epoch zero. They use original enrolled owners,
encrypted journals, real wall-clock policy admission and either local-only or
required-witness policy. Product code, the allocator, durability and authority
checks are unchanged. The observer runs Rust 1.98.1 Release with opt-level 3,
thin LTO, one codegen unit and overflow checks on Apple Silicon/macOS.

Each process establishes its session through authenticated hybrid TLS, then
calls the activated owner's public journal `send_message` API to commit 64
outboxes without dispatch. Payload size is either zero or the maximum 16 KiB;
associated data is always the maximum 1 KiB. These are single-session capacity
observations, not the maximum of the separate 2 MiB aggregate journal limit.

The next send must return `Capacity`, leave its ID `Absent`, and preserve the
next ID. Both original owners close and reopen. The sender must still report
the same next ID and reject the same over-capacity operation. Every retained
ciphertext is compared against its original SHA3-256 digest before delivery.
Fresh authenticated TLS carries each original message to a durable application
effect. After the first authenticated acknowledgement frees a slot, the original
rejected next ID succeeds. All 65 messages become acknowledged and all 65
business files match session, message ID and synthetic plaintext byte-for-byte.
No store is reset, no acknowledgement is manufactured and no SDK limit changes.

| Policy | Payload | Whole-process peak RSS | Sender journal at 64 | Journal after all ACKs |
| --- | ---: | ---: | ---: | ---: |
| Local-only | 0 | 13.59 MiB | 0.375 MiB | 0.363 MiB |
| Local-only | 16 KiB | 53.67 MiB | 11.879 MiB | 0.598 MiB |
| Required witness | 0 | 18.22 MiB | 0.375 MiB | 0.363 MiB |
| Required witness | 16 KiB | 59.20 MiB | 11.879 MiB | 0.598 MiB |

RSS is Darwin's process high-water counter. It includes both SDK peers, the
witness where selected, database/allocator overhead and observer bookkeeping;
it is neither current resident memory after drain nor isolated SDK allocation.
Journal file size includes database pages and is not the authenticated encoded
image size. Thus a 2 MiB image limit does not imply a 2 MiB database file or
process-memory limit. Each maximum-payload cohort retains 1 MiB of plaintext's
corresponding ciphertext payload at its full-outbox point. The witness observer
also retains bounded timing/tag rows, whose memory belongs to the process count.

The timed interval is the local durable `send_message` call. Slot lookup,
status checks, payload creation, ciphertext hashing and result serialization
are outside that interval. Filling does not include application TLS delivery;
the later drain uses TLS and authenticated consumption. In these ordered
observations, the first eight versus last eight fill-call medians are
45.76/91.66 ms locally and 108.96/135.38 ms with the required witness for the
maximum payload. The zero-payload pairs are 52.30/51.27 and 70.40/73.92 ms.
These windows describe the traces; they are not independent latency trials or
production-tail estimates and do not isolate encryption, serialization, fsync,
database allocation or witness costs. The host's other applications and power
settings are uncontrolled. No local task build or broad test overlaps a cohort.

An independent public reader checks all 260 durable effects and rejects 272
negative controls: all 260 individual sample-index substitutions, missing
restart outcomes, modified effects and missing effects in each cohort.
[SUMMARY.json](SUMMARY.json) retains exact observations and source/binary IDs.
[CAPTURE.zip](CAPTURE.zip) contains 348 public members; every byte is read back
against [CAPTURE.json](CAPTURE.json), then all four runtime censuses and business
effects are revalidated directly from the archive without reopening a store.
Its SHA-256 is `bea1bf00484631988400b3ea586a848523f76538417485651a4613b07ac62146`.
Private keys, encrypted databases, installation configuration, executables and
compiler caches are excluded. The original private cohorts remain sealed.

The first observer build failed because it named a private backend hash type.
Its exact source, compiler diagnostics and terminal failure remain in the
capture; switching the observer to the existing public `Sha3_256Xof` interface
passes the strict build. No runtime ran from the failed build and no diagnostic
was suppressed. All four subsequent cohorts complete.

This closes one explicit native capacity/reopen/reclamation observation. It
does not establish leak freedom, maximum multi-session/fanout/journal memory,
energy, controlled tails, foreign-package/device performance or full 0.2.0
release qualification. The measured growth motivates profiling the authenticated
image load/encode and database allocation paths; it does not justify weakening
their checks or selecting a speculative storage-format optimization.
