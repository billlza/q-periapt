# VM footprint attribution — 2026-10-17

Two fresh local-profile processes at source
`fca7a0bcc6f9054dde175afbd0d99864fa281694` repeat the
[aggregate capacity and original-owner recovery workload](../20261017-journal-capacity/README.md).
Each retains 64 epoch-zero and 60 epoch-one maximum-sized messages across a real
PQ rekey. Aggregate refusal closes the journal; two original-owner reopens and
an old-epoch acknowledgement recover capacity for the original rejected message
ID. All 125 ciphertexts replay exactly, cross authenticated TLS, and produce
the expected durable business effects. SDK source and resource limits are unchanged.

The diagnostic adds self-only `mach_vm_region_recurse` observations to the existing
per-task resident/physical footprint and malloc counters. Native structure
revisions, arithmetic overflow, nesting depth and an 8192-call enumeration bound
are checked. Every sample must contain a nonempty resident-page census. Reports
contain tag aggregates, never addresses, object identifiers, memory contents or
mapped paths. The observed page size is 16384 bytes. Installed SDK header hashes
and the malloc tag constants are retained in the archive.

## Results and interpretation

| Process | Peak RSS | Physical footprint at closure | After 15 seconds of idle waits | `MALLOC_LARGE` resident pages at that last sample |
| --- | ---: | ---: | ---: | ---: |
| Unchanged allocator observation | 212.56 MiB | 164.48 MiB | 164.50 MiB | 138.08 MiB |
| Separate pressure-relief probe, before intervention | 217.08 MiB | 210.36 MiB | 159.48 MiB | 127.19 MiB |

Both processes sample after owner closure and after cumulative 1, 5 and 15 seconds
of explicit sleeps; enumeration adds time between those samples. The second
process falls from 210.38 to 159.48 MiB between the 1- and 5-second observations,
before any intervention. The first process does not show that fall. This
variation precludes treating one post-close value as a stable memory floor.

The second process then calls `malloc_zone_pressure_relief(NULL, 0)` once, after
all product owners have closed and the idle observations finish. The installed
header defines this as best-effort relief across all malloc zones, returning
the number of bytes released. It returns **zero**; physical footprint is
159.50 MiB afterwards and `MALLOC_LARGE` resident pages remain 127.19 MiB.
The probe does not support a claim that this call remedies the retained footprint.
It is confined to the diagnostic executable and is not added to the SDK.

The large-region tag narrows the next investigation to malloc-related VM, but
does not identify a particular SDK allocation, prove a live-object leak or
establish that the remainder is harmless cache. Reported malloc in-use bytes
remain about 1.25 MiB at the 15-second samples, substantially below per-task
physical footprint. The malloc high-water field is again zero and is retained
raw without using it as a maximum-memory measurement.

VM region enumeration is non-atomic. Region counts include shared mappings and
use different accounting from per-task physical footprint; summing all tags is
not a process-memory estimate. `internal_pager_resident_pages` classifies the
pager, not exclusive ownership. The shared tag-zero mappings alone exceed the
process resident count, demonstrating why those quantities must not be conflated.

This experiment supplies attribution and a negative intervention result, not a
memory optimization. Allocation-lifetime/call-site profiling remains needed
before changing serialization or allocator behavior. It does not establish
isolated SDK cost, leak freedom, energy, controlled latency tails, witness-mode
performance or the maximum cost of multiple sessions/fanout. Both peers and
observer bookkeeping are in the measured process. Other host applications and
power settings are uncontrolled; no task build or broad test overlaps either run.

The later [persistent encoding correction](../20261017-secret-encoding/README.md)
is based on a separate moving-reallocation counterexample. Its default-allocator
capacity cohorts observe lower process peaks and post-close footprint, without
turning this earlier zero-release probe into a successful intervention or a
complete allocator-retention explanation.

## Reproduction evidence

The observer uses Rust 1.98.1 Release, optimization level 3, thin LTO, one codegen
unit and overflow checks. The C shim compiles with warnings as errors. Build 03
is the observation-only executable; build 05 adds the post-close intervention.
Their exact sources, hashes, commands and terminal outputs are distinct. An
earlier unexecuted prototype remains preserved locally and supplies no runtime
result.

[SUMMARY.json](SUMMARY.json) retains all stages. The independent reader checks
250 business files and rejects 271 controls, including every individual
message/epoch substitution, missing lifecycle outcomes, altered durable bytes,
missing/duplicate VM tags, invalid page units, inconsistent pager partitions
and a falsely ordered intervention. Both original private cohorts remain sealed.

[CAPTURE.zip](CAPTURE.zip) contains 356 public members, all read back against
[CAPTURE.json](CAPTURE.json); both capacity/business/VM censuses are revalidated
from the archive. SHA-256:
`023b3ad7e5ff769be55f8f5a496d2f3eafdc5a8f3144d5195149809def8861ec`.
Keys, encrypted databases, private installation configuration, executables and
compiler caches are excluded. Full protocol security, support-matrix resource
qualification and the remaining 0.2.0 release gates remain open.
