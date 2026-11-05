# Witness cost accounting at the recorded capacity boundary

This reread separates the two installed-engine Witness observations from the
[resource baseline](../20261104-installed-resource-baseline/README.md) at their
recorded capacity barrier. It adds no runtime experiment and does not qualify
a current-source resource budget. The original candidate is
`21e00e9c3cfd193b9f51491888347f583620dfe0`; the observer was built at
`539845d573ac0af5fe104aabed2f96a86f9eac8b`.

Both observed cohorts have exactly the same operation census:

| Recorded interval | Query / Current | Advance / Advanced | AdmitAuthority / AuthorityCurrent | Exchanges | Framed Witness bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Setup, fill, rekey and first aggregate-capacity refusal | 989 | 283 | 4 | 1,276 | 9,367,116 |
| Original-owner reopens, repeated refusal, reclamation, replay, delivery and close | 2,281 | 377 | 3 | 2,661 | 19,534,401 |
| Whole recorded workload | 3,270 | 660 | 7 | 3,937 | 28,901,517 |

The boundary is the observer's `witness_at_capacity` call, after the first
Capacity failure closes the sender and before the server's Reopen task. The
observer holds the same mutex across a complete exchange and while reading
this snapshot. Its index therefore selects an exact prefix of the retained
rows. Each framed exchange is `4 + 3674 + 4 + 3659 = 7341` bytes, including
both length prefixes; TCP overhead and application TLS traffic are outside
that count.

The integer tag pairs `(1,1)`, `(2,2)` and `(4,5)` are mapped using the pinned
request encoder, outcome enum and store dispatch. The byte offset is
`4 + 8 + 32 + 96 + 32 + 32 = 204`: the signed-envelope length, message tag,
Witness binding, subject and two 32-byte fields precede the command/outcome.
The three relevant implementation files remain byte-identical at this reread.
That does not transfer the historical timings to a new candidate.

There are 3,277 read-only exchanges per whole workload, approximately 83.2%
of its recorded exchanges. This includes status/readback observations, setup
and recovery; it is not an ordinary-send amplification factor. Dividing the
whole workload's bytes by its 125 application effects would not establish a
per-message network budget. Only the two retained phase boundaries are
attributable here; finer per-API costs need observations at those call boundaries.

| Cohort | Witness handler intervals through first refusal | Handler intervals in remaining phase |
| --- | ---: | ---: |
| Witness 1 | 4.020704441 s | 6.572311139 s |
| Witness 2 | 4.029165989 s | 6.624736155 s |

These sums cover measured `AnchorStore::handle` intervals, not CPU-accounting
counters, total wall time or end-to-end latency. The JSON retains per-kind
nearest-rank p50/p95 observations; the ordered, changing journal populations
do not justify stationary production tails. The original M4 Max/macOS setup,
inherited allocator control and uncontrolled power/thermal conditions remain
applicable. No new performance comparison is inferred from unchanged tag code.

The independent reader verifies the original capsule and selected member
digests, every row's exact schema and successful tag pair, all duration sums,
the capacity prefix and conservation across both phases. Twenty-two altered
inputs are rejected, including shifted boundaries, wrong totals, missing rows,
inconsistent tags and an unclosed worker. These checks validate measurements;
they do not cryptographically reverify raw signed wires, which this observer
did not retain.

`CAPTURE.zip` retains both original result objects, observer source, build
receipt, pinned encoder/dispatch files, reader and results. All 12 members were
reread against `FILES.json`. Its 171,537 bytes have SHA-256
`93a627d7ce91e0a45fc82d3b7bb509a22788b3d0d490d20d4f5a2f6b817eb619`.
The original capsule remains pinned by
`60fb59b6d6b55a7f964cdbdc6ac3e28b5f185033fffce6c0be8b17c5aa19832e`.

This closes the two-phase accounting gap for these historical observations.
Declared application workloads, multi-session/fanout and maintenance costs,
current candidate measurements, mobile resources/energy and acceptable product
budgets remain part of the existing release work.
