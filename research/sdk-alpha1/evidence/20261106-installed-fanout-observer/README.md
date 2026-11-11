# Installed two-recipient fanout resource observer

This checkpoint adds operation-level observations for the actual installed
account fanout path at source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Four functional cohorts pass:
local-only or required signed-TCP Witness protection, each with recipients in
the sender's own account or a separate account. Every cohort completes 13
aggregate operations, 26 durable business effects and 89 measured spans.
The captured public evidence and reader source reproduce all four readbacks.

This closes the functional validation of this two-recipient observer. It does
not freeze a resource budget or qualify the declared maximum recipient count.
One host-JNI qualification process overlapped every cohort; CPU and memory
include all three device owners, both TLS endpoints, the optional Witness and
the observer. `performance_qualified=false` remains explicit.

## Inputs and execution

The SDK producer report has SHA-256
`1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`.
Nine SDK archives plus candidate archive
`0730aa20794527b3947dc4734bf82d48516294c42018dc8dfd23ebc5f42fc2a6`
are extracted outside the checkout. Every installed file is compared with its
archive before and after each run. The Cargo graph uses 174 external packages
from the original lockfile union; installed product crates are not workspace
members. Rust 1.98.1 Release compilation and strict Clippy both pass with
warnings denied. The observer executable has SHA-256
`b7ec37b3bbab8a9e7600e987461a702442c61ea31e7908e3d10c819a68e93a70`.

The workload uses the unchanged installed `owned_connection` multi-device
fixture and public installation, service, bootstrap, connection, control and
journal APIs. These are three pre-provisioned device owners; this fixture does
not measure account login, registry integration or fresh enrollment. The complete
signed roster determines both recipients. For the own-account layout the
sender's own device is excluded according to the existing contract. Public
account IDs are retained and independently checked against the layout.

Each run:

1. Opens all three owners and establishes two real hybrid-TLS sessions.
2. Sends six complete fanouts in epoch zero, updates both sessions through the
   traffic-independent PQ control endpoints, then sends six more in epoch one.
   Each epoch has two samples for each `(plaintext bytes, associated-data bytes)`
   pair: `(64, 0)`, `(1024, 32)` and `(16384, 1024)`.
3. Alternates which recipient is delivered first. Both calls retain the original
   aggregate ID and complete target set. Both members' confirmed outcomes are
   read again without an application-network exchange, then the aggregate is
   explicitly retired.
4. Commits the first recipient's business effect for a thirteenth aggregate,
   deliberately returns an application error before acknowledgment, and observes
   one exhausted network attempt. The original aggregate remains Committed.
   Both original member IDs and ciphertexts are retained.
5. Closes and reopens all three owners. The sender explicitly reopens both
   original sessions. Native assertions compare the original and recovered
   ciphertexts byte for byte. Retrying recipient zero creates no second effect;
   delivering recipient one creates its first effect. The aggregate is retired.
6. Refuses a pre-cancelled next aggregate without reserving or advancing its ID,
   closes the owners and joins the workers.

Recipient zero records 14 callbacks and 13 effects; recipient one records 13
callbacks and 13 effects. All 26 business files are checked against the actual
session, message ID and synthetic plaintext. The SDK's first consumption attempt
failed at the application boundary, so its retry can invoke the callback again:
the callback's durable application key prevents a duplicate business effect.
The `duplicate` protocol flag is not a substitute for this effect check.

This is orderly owner reopening after application-result loss, not a process
crash or power-loss experiment. It does not measure revocation, replacement,
Witness migration or mobile energy. No product code, security check, protocol
limit, persistence format or retry deadline is changed.

## Exact Witness accounting

Both Witness cohorts contain 1,203 exchanges and 8,831,223 framed bytes.
Their per-operation counts agree in every individual interval. The recorder
uses a mutex across each complete request/reply, so a snapshot is an exact prefix
of the retained operation rows. Each framed exchange is 7,341 bytes, excluding
TCP overhead and the application TLS connection.

| Operation | Calls per cohort | Exchanges per call | Framed bytes per call |
| --- | ---: | ---: | ---: |
| Provision three owners | 1 | 63 | 462,483 |
| Open an owner | 3 | 3 | 22,023 |
| Establish one session | 2 | 58 | 425,778 |
| Obtain next aggregate ID | 14 | 2 | 14,682 |
| Deliver first member | 12 | 31 | 227,571 |
| Deliver second member | 12 | 25 | 183,525 |
| Read retained member outcome | 24 | 3 | 22,023 |
| Retire a confirmed aggregate | 13 | 4 | 29,364 |
| Independent PQ update of one session | 2 | 43 | 315,663 |
| First member effect committed, result lost | 1 | 17 | 124,797 |
| Reopen three original owners | 1 | 17 | 124,797 |
| Retry the uncertain first member | 1 | 23 | 168,843 |
| Deliver the original second member | 1 | 25 | 183,525 |
| Pre-cancelled delivery / sender close | 1 each | 0 | 0 |

The ordinary first-member interval contains 26 Query/Current and five
Advance/Advanced exchanges; the second contains 22 and three respectively.
Retained-outcome reads still issue three Witness queries even though their
application exchange count is zero. Retirement contains three queries and one
advance. These counts include the participating endpoints and their shared
Witness; they are not universal per-client network budgets.

Measured spans account for 1,180 exchanges. The other 23 belong to the observer's
surrounding status, original-wire and cancellation checks and remain explicitly
unassigned. Local-only cohorts contain no Witness exchanges. The recorder retains
operation tags and counters, not complete signed Witness frames; this readback
does not claim to reverify their cryptographic signatures.

## Resource observations and validation boundaries

Every completed span is immediately emitted to stdout and retained in the final
result, with monotonic duration and process user/system CPU deltas. Five stages
record resident size, physical footprint, allocator counters and the actual
sizes of all three journal databases. These observations include the observer
and concurrent endpoint work. Raw zero allocator counters are not interpreted
as zero peak memory.

The host is Apple M4 Max, Mac16,5, 16 CPUs and 48 GiB RAM, running macOS 26.7.2.
All four executions retain their hardware receipt, process census, load,
inherited `MallocNanoZone=0`, wall/CPU observations and `/usr/bin/time -l` output.
No power, thermal or allocator setting was changed. The 22.7–26.6 second whole-run
durations include provisioning, setup, recovery, checks and shutdown. They are
functional-run observations, not a controlled comparison, throughput target or
production tail estimate.

The independent reader checks operation order, aggregate ordinals, per-recipient
message epoch/index, alternating member order, retained outcomes, account layout,
callback/effect counts, raw stdout/result equality, all business bytes, resource
stages and exact Witness prefixes. It rejects 32 altered inputs per local cohort
and 34 per Witness cohort. These controls test evidence validation, separately
from the native protocol assertions.

Native execution checks byte-identical original ciphertext on reopening. The
public reader checks reported ciphertext widths, digest format and actual
business files; ciphertext bytes are not part of this capsule, so archive replay alone
is not a second independent ciphertext comparison.

Controlled performance cohorts, accepted workload/budgets, larger declared
fanout capacity, maintenance/revocation/replacement costs and applicable mobile
resource/energy measurements remain existing release work. This checkpoint does
not close protocol proof, ABI admission, platform qualification, external review
or release acceptance.

## Retained evidence

[CAPTURE.zip](CAPTURE.zip) is 12,120,421 bytes, with SHA-256
`b936211f7125fc067e867381c7c377d7d6baa569b03e2889e2774f788017da64`.
Its 223 members include the ten installed archives, actual executable, observer
source, build/Clippy receipts, four public cohorts, 104 synthetic business files,
and the original source-only Python dispatcher and JSON reader. Private runtime
keys and databases are excluded. [FILES.json](FILES.json) records every member.

The four `*_READBACK.json` files retain the first independent checks and rejected
alterations. [ARCHIVE_READBACK.json](ARCHIVE_READBACK.json) reproduces all results
and controls using only the public capsule.
[STANDALONE_REPLAY.json](STANDALONE_REPLAY.json) binds that run to the five
extracted reader files, with no private-runtime access.
[READER_SOURCE.json](READER_SOURCE.json) records the original Git-matched reader
dependencies. [replay-capsule.py](replay-capsule.py) verifies the capsule, extracts
only those reader files, and runs their isolated dispatcher; invoke it through
the repository's `artifact/python-run.sh`, passing absolute capsule, manifest and
fresh work-directory paths.
