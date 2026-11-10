# Installed operation observer: functional validation and exact Witness accounting

This checkpoint supplies an operation-level resource observer against the actual
installed SDK/candidate archives at
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Local-only and required signed-TCP
Witness configurations both complete the workload, and the public records can
be independently checked without their private installations. These two runs
validate the observer; concurrent qualification processes prevent treating their
timings as a controlled performance comparison or an accepted product budget.

The preceding [capacity baseline](../20261104-installed-resource-baseline/README.md)
and [two-phase accounting](../20261105-resource-phase-accounting/README.md) retain
their original purpose and source. They could not assign an ordinary send's cost
from an aggregate capacity/recovery workload. This observer records explicit
before/after boundaries around the actual public owner/transport operations.
No product code, authority check, allocator setting, protocol limit or persistence
format changes.

## Installed inputs and executed workload

The SDK producer report digest is
`1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`.
Nine SDK archives plus the current candidate are extracted outside the checkout.
All ten installed trees are byte-checked; the Cargo graph has 174 external
packages, constrained by the original lockfile union. Installed dependencies are
excluded from workspace membership. Rust 1.98.1 Release build and strict Clippy
pass with warnings denied. The actual observer binary is retained with SHA-256
`3172ba3ded841405320d907ccce9de68b2d876693ad4651eb8f3f65abbc79186`.

The observer reuses the existing enrolled-owner setup, durable application
consumer, bounded listener and Witness recorder. Its fresh workload is:

1. Provision and open two independently enrolled owners, then establish their
   authenticated hybrid-TLS session.
2. Deliver 24 messages in epoch zero and 24 in epoch one. Each epoch has eight
   samples for each `(plaintext bytes, associated-data bytes)` pair:
   `(64, 0)`, `(1024, 32)` and `(16384, 1024)`, in a fixed rotating order.
3. Between those epochs, complete a real PQ update through the independent
   control endpoint while no business message is being sent.
4. Commit a 49th application effect, deliberately return an application error
   before consumption acknowledgment, and observe one exhausted network attempt.
   Preserve the Committed message, close/reopen both original owners, verify
   byte-identical ciphertext, and retry the original message. The same business
   effect is read again; no second effect is created.
5. Refuse a pre-cancelled next message without reserving its ID, then close the
   owners and join the workers.

Each run has 106 measured spans, 49 unique durable business files and 50
application callback invocations. The last callback is the exact retry after the
first callback's result was lost. Normal sends use an explicit one-exchange
invocation; no global retry or timeout contract is changed. Reopening is orderly
owner reopening, not an injected process crash or physical power-loss test.
Owner close is not relabeled as device revocation.

Each completed span is immediately emitted to stdout and also retained in the
final result, preserving partial observations if a later operation fails.
The reader matches the two representations exactly, checks message epoch/index
and operation order, verifies all synthetic business bytes, and reconciles
resource stages, callback counts and Witness prefixes. Twenty altered inputs
are rejected for the local cohort and twenty-two for the Witness cohort. These
are measurement-reader controls, separate from native security regressions.

## Observed Witness operation counts

The single Witness records both owners' requests. A snapshot takes the same
mutex held across a complete exchange, so each boundary identifies an exact
prefix of the retained rows. A framed request/reply is 7,341 bytes. This count
excludes TCP overhead and the application TLS connection.

| Observed operation | Calls | Witness exchanges | Framed Witness bytes |
| --- | ---: | ---: | ---: |
| Provision and open both owners | 3 spans | 56 | 411,096 |
| Establish session | 1 | 58 | 425,778 |
| Obtain next message ID | 48 | 2 in every call | 14,682 in every call |
| Complete ordinary send and consumption | 48 | 22 in every call | 161,502 in every call |
| Independent PQ update | 1 | 43 | 315,663 |
| Effect committed, result lost | 1 | 11 | 80,751 |
| Reopen both original owners | 1 | 14 | 102,774 |
| Retry original uncertain message | 1 | 16 | 117,456 |
| Pre-cancelled send / initiator close | 1 each | 0 | 0 |
| Checks outside measured spans | — | 60 | 440,460 |

Every one of the 48 ordinary-send spans contains seventeen Query/Current and five
Advance/Advanced exchanges. Each ID lookup contains two Query/Current exchanges.
These per-call statements come from all individual intervals, not division of
the whole workload by its number of effects. The total is 1,410 exchanges and
10,350,810 framed bytes: 1,350 exchanges belong to measured spans and sixty to
the observer's surrounding status/replay checks. The latter remain explicitly
unassigned to an API cost. Local-only records contain no Witness exchanges.

These are observed counts for this exact two-owner workload and protection
profile, including both endpoints. They are not a universal per-client network
budget or proof that any of the admission queries can safely be removed. The
recorder retains operation tags and counters, not full signed wire bytes; this
readback does not claim a second cryptographic verification of those wires.

## Resource and qualification limits

The raw spans retain monotonic wall intervals and `getrusage` user/system CPU
deltas. Five stages retain process resident size, physical footprint, allocator
counters and each journal's actual database size. CPU and memory cover both peers,
the optional Witness and observer together. They are not isolated client costs.
Raw zero allocator counters are not interpreted as zero peak memory.

Both runs record two concurrent qualification processes and inherited
`MallocNanoZone=0`. The task changes neither that setting nor host power/thermal
conditions. `performance_qualified=false` is explicit in each run and readback.
No timing comparison, throughput target or production tail claim is made here;
raw timings remain available for diagnosing and validating the observer.

The original first build failed because the reused server's opening-time field
was not read, with `-D warnings` turning that warning into an error. Its source,
commands and failure remain in the capsule. The observer now records that counter
and emits completed spans immediately. The subsequent build and Clippy pass
without suppression or changes to installed package sources.

Controlled repeat cohorts, the declared acceptable workload/budget, multi-session
and fanout costs, maintenance/revocation/device-replacement costs, and applicable
mobile resource/energy measurements remain existing release work. This observer
does not close those requirements, platform admission, the computational proof,
external review or release qualification.

## Retained and independently replayed evidence

[CAPTURE.zip](CAPTURE.zip) retains 207 members, including the ten actual installed
archives, source reports, observer source and executable, original failed build,
successful build/Clippy receipts, both complete public cohorts and 98 synthetic
business files. Private keys, stores and runtime installations are excluded.
The 12,106,746-byte capsule has SHA-256
`a0ba9b7b19eb1b139a98627442853b2fc54df304277780142668d6e746785738`.
[FILES.json](FILES.json) gives every member's size and digest.

[LOCAL_READBACK.json](LOCAL_READBACK.json) and
[WITNESS_READBACK.json](WITNESS_READBACK.json) preserve the initial independent
rereads and altered-input controls. [ARCHIVE_READBACK.json](ARCHIVE_READBACK.json)
rechecks all 207 captured members and reproduces both results using only the
public capsule, without accessing private runtime directories. The retained
[reader](readback.py) supports an archive-only replay through the repository's
isolated `artifact/python-run.sh` dispatcher; give `--archive`, the capsule,
`FILES.json`, and a fresh output JSON path in that order.
