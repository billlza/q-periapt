# Aggregate journal capacity and live memory — 2026-10-17

Source `68e05c56a195bee0a2f964e20738cbfde8446d13` completes two fresh
maximum-payload cohorts, under local-only and required-witness policy. Both retain
64 unconfirmed epoch-zero messages, complete a real authenticated PQ rekey to
epoch one, then retain 60 more messages. The next 16 KiB plaintext with 1 KiB
associated data reaches the 2 MiB aggregate encoded-image limit before epoch
one's separate 64-outstanding-message limit. The send path changes an existing
session record; its operation count does not grow, and the signed send budget
is not exhausted. Together with the source's sealing checks, these observations
identify the aggregate byte boundary rather than a second per-epoch count limit.

At this boundary `persist` returns `Capacity` and closes the active journal.
The first observer incorrectly queried that same closed journal and failed with
`Closed`. This follows the existing [storage contract](../../../../docs/continuity/STORAGE_RECOVERY_V1.md)
and [adapter obligations](../../../../docs/continuity/STATE_MACHINE_V1.md), rather
than requiring a weakened runtime guard. The original failed cohort, its exact
observer and terminal output remain preserved; it supplies no successful
capacity/recovery result.

The corrected observer requires the closed-owner result, reopens the original
paths/identities, and verifies that the rejected message remains `Absent` with
the same next ID. A repeated full-state submission again returns `Capacity` and
closes the journal. A second original reopen verifies the unchanged ID and
absence. Delivery and authenticated acknowledgement of one old-epoch message
then free enough space for that exact rejected ID to succeed. All old/current
ciphertexts match their original SHA3-256 digests before dispatch. All 125
messages in each cohort are delivered over authenticated hybrid TLS, durably
consumed and independently checked byte-for-byte in the host's business files.
No old store is reset, new identity substituted or failure converted into success.

## Whole-process memory observations

The observer calls the installed macOS `task_info(TASK_VM_INFO)` interface to
capture current resident bytes and physical footprint, alongside `getrusage`'s
high-water RSS. Native C field widths and the minimum returned structure revision
are checked, and the shim compiles with warnings as errors. These calls are
outside the timed SDK operation. Neither allocator configuration nor SDK code
changes. Both peers, the witness where selected and observer buffers are counted.

| Cohort | Peak RSS | Physical footprint before refusal | Physical footprint after owner closure |
| --- | ---: | ---: | ---: |
| Local-only | 213.53 MiB | 200.28 MiB | 206.89 MiB |
| Required witness | 213.17 MiB | 193.13 MiB | 210.20 MiB |

These measurements show a practical process-memory cost well beyond the 2 MiB
encoded-image limit. The database file is a third quantity: it is 11.879 MiB
before refusal and shrinks after closure/consumption. Neither file shrinkage nor
owner closure proves physical erasure or post-compromise recovery.

A third, separate local-only diagnostic repeats the same 124-retained/125-effect
flow while sampling `malloc_zone_statistics(NULL)`. After all owners close, it
reports about 1.09 MiB in currently used malloc blocks and 64 MiB in its reserved
allocation counter, while physical footprint remains about 199 MiB. Its peak
RSS is 206.25 MiB. The malloc high-water field reports zero throughout and is
retained raw, not used as a maximum-memory result. These aggregate counters do
not account for all VM footprint and do not establish either an SDK object leak
or a complete allocator-retention explanation. VM-region/allocation attribution
remains the next investigation; no speculative memory fix is promoted here.

The subsequent [VM-tag and pressure-relief diagnostic](../20261017-vm-footprint/README.md)
narrows the retained pages to malloc-related regions, records variable idle
reclamation and a zero-release intervention result. It does not establish a
complete allocator explanation or a product fix.

All three processes run on Apple Silicon/macOS with Rust 1.98.1 Release,
opt-level 3, thin LTO, one codegen unit and overflow checks. Other applications
and power settings are uncontrolled. No local task build or broad test overlaps
the runtimes. The source-bound observer is not an installed foreign-language or
physical-device performance qualification. One cohort per policy and a separate
diagnostic do not establish production tails, leak freedom, energy, sustained
concurrency or maximum multi-session/fanout cost.

## Retained evidence

[SUMMARY.json](SUMMARY.json) records all source-bound measurements. An independent
reader verifies all 375 synthetic business effects and rejects 390 controls:
every individual message/epoch substitution, missing closure/reopen/reclamation
outcomes, replacing the rejected operation ID, and altered durable bytes.
[CAPTURE.zip](CAPTURE.zip) contains 530 public members. Every member is read back
against [CAPTURE.json](CAPTURE.json), then all three successful runtime censuses
and business-file sets are revalidated directly from the archive. Its SHA-256
is `d9f0e2fc24353ae6cb1a13f808293209e04120018755f391803537a58b0b2f58`.
The failed first cohort and all three observer versions remain distinguishable.
Keys, encrypted databases, private installation configuration, executables and
compiler caches are excluded; the original private cohorts remain sealed.

This verifies the stated native capacity/closure/recovery sequence. A resource
capacity or confirmed epoch count is not a bound on attacker knowledge or a PCS
proof. Full protocol/SDK refinement, resource qualification across the support
matrix and the remaining 0.2.0 release gates remain open.
