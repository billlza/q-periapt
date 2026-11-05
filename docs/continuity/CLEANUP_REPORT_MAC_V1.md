# Cleanup reports and one immutable MAC transcript

Session closure and fanout abandonment expose a private-keyed report identifier
over retained message state. This output is separate from the six SHA3 digest
domains in the [original-record argument](MULTI_RECORD_COMMITMENTS_V1.md).
The statement below supplies a conditional replacement for one original report.
It does not yet establish the complete native private-record interface or the
multi-epoch computational theorem. Source and six focused executions are pinned
to `c32362567e748787a64ab767769e811f62cb87d5` in the
[evidence record](../../research/sdk-alpha1/evidence/20261105-cleanup-report-mac/README.md).

## What the native transcript contains

Both paths draw a fresh 32-byte report key with `getrandom::fill`, then compute
HMAC-SHA256. The report identifier must be nonzero. There is no loop that retries
a zero identifier. Entropy, encoding, persistence and release errors propagate
through the existing operation boundaries.

For [independent closure](../../research/continuity-identity-candidate/src/durable/messages/closure.rs),
the MAC input is the complete message domain plus `session-closure/v1`, journal
ID, owner, record context, payload byte length, payload except its final 64 bytes,
and 64 canonical zero bytes. The excluded tail stores the report and report key.
The original state preceding the fresh key draw therefore determines the entire
transcript; the report does not MAC its own output or key.

For [fanout abandonment](../../research/continuity-identity-candidate/src/durable/messages/fanout/abandonment.rs),
the input is the complete message domain plus `fanout-abandonment/v1`, journal
ID, owner, batch metadata and, in member order, each record context, payload
length and complete payload. The batch's own report/key tail is outside
[`Batch::metadata`](../../research/continuity-identity-candidate/src/durable/messages/fanout/codec.rs).
The immutable member payloads can still contain other private keys, reservations
and plaintext. Excluding this report's key does not make that payload public.

On first closure, report construction and its nonzero check precede installing
the pending closure, persistence and report release. On first abandonment they
precede changing the member phases and batch state, persistence and report
release. An existing Closing/Abandoning state retains its original report/key;
the retry path does not draw a replacement. A failure before durable commit
does not by itself establish permanent closure. Unknown commit outcomes must
follow the existing original-write recovery path.

## Conditional one-report replacement

Use the exact compression-QROM experiment and HMAC encodings from the
[shared-root note](SHARED_ROOT_HMAC_V1.md). A hidden 256-bit report key `K` is
uniform and independent of the public compression oracle `h` and initial
auxiliary state. Execute and count the complete oracle-dependent preparation.
There is no raw-key, midstate, protected-record or other `K`-dependent channel
besides the following report interface. This last premise must be established
by the private-state bridge; encrypting a key is not enough to assume it.

The machine chooses one classical transcript `m`, of at most `L` bytes, without
access to `K`. It obtains `t = HMAC_h(K,m)`. All later report computations and
validations under this original key use exactly that same transcript. They may
compare supplied identifiers with `t` and return the real errors. The machine
may otherwise adapt, including quantum queries to `h`. This interface excludes
changed-transcript MAC or verification queries under `K`; such queries need an
extended simulation and cannot be cached as an unchanged report.

Let `T >= 1` bound the actual classical report-row calls, including validation,
and `q` bound all other ordinary compression queries in the reduction. With
`L <= 2^61-65`, set `ell = 1 + ceil((L+9)/64)`. Applying only the row stages of
the shared-root calculation (`C=0`) gives

```text
epsilon_report = min(1,
    DFH(2, q + ell*T) + E_NMAC(T, q, ell)).
```

Here `DFH` and `E_NMAC` retain their exact definitions, padding offset, query
regimes and non-numerical constants from that note. The two private key-pad
calls are replaced first; then the NMAC row is replaced by a private random
function `U`. No column replacement or row/column alias-repair term is used.
The underlying results are [DFH Theorem 2](https://arxiv.org/pdf/2206.08132)
and [Hosoyamada–Iwata Proposition 6](https://eprint.iacr.org/2021/774).
This is our restricted-interface corollary, not a theorem about native cleanup
in either paper.

Only `U(m)` is used. Its first answer is uniform and independent of `h` and the
prepared state: condition on `h` and the classical chosen transcript, then
trace out the otherwise unused independent table. This reasoning retains any
residual quantum prepared state. The exact ideal interface therefore samples
one 256-bit `t`, caches it for this original report, and returns that value on
every exact repeat. The transcript itself is no longer needed to generate the
tag in this ideal interface. It can remain needed elsewhere in the experiment.

All later tests on `t` remain in both games. In particular, `t=0` produces the
source's nonzero-ID error before closure is installed; it is neither silently
resampled nor converted into a successful close. In the ideal game the fresh
tag is zero with probability `2^-256`. Keeping that branch is exact and adds
no error term. Conditional on a successfully returned report the tag is
nonzero, but this is not permission to condition the whole security experiment
on successful cleanup or to delete failed attempts.

A genuinely fresh attempt after a failed, uncommitted operation draws a new
key and constitutes a new invocation. A durable original report, its replay,
validation and exact acknowledgement keep the same invocation. The required
index is not just a session or batch ID. Multiple report keys need an explicit
bounded hybrid with the same public oracle, all other honest computations and
their possible key aliases; this one-report statement does not declare the
actual keys or all report answers jointly independent.

## Where this can enter the KEM adapter

The ordering matters. While the simulator still knows the real reservation
coins, it can supply the actual transcript to the report-row reduction. Only
after that hop, and after the other private-record outputs have been justified,
can the [KEM adapter](KEM_CHALLENGE_ADAPTER_V1.md) retain an opaque reservation
origin and its cached ideal report tag. Starting with unknown challenge coins
and pretending the real MAC transcript is known would be circular.

The remaining obligations include the source equality relation for every
permitted validation, key/state acquisitions under the unchanged Snapshot and
entropy predicates, failed writes, unrelated journal changes, original-record
copies, malformed inputs and all shared SHA-256/SHA3 queries. A raw report-key
and transcript disclosure would allow recomputation with public `h`; comparing
that value with an independently replaced tag distinguishes with probability
difference `1-2^-256`. The protected-record premise is therefore material.

Closing a selected endpoint may prevent a later target message, but calling
`begin_*` is not an automatic zero-output event in `Eligible AND D_output`.
The ordinary error and unknown-commit branches above still exist. Nor does
closing a responder after it emitted its response imply that the live initiator
cannot reach `FinalReady` and send. No requirement that both endpoints confirm
is added to MAIN.

## Executed correspondence checks

Three existing tests each passed under Debug and Release, using Rust 1.98.1,
locked offline dependencies and denied warnings. They check retained metadata
and exact repeated reports, rejection after mutating private state, three rekey
flight/cutover closure schedules, and fanout freeze/terminal process cuts with
Busy exclusion of competing writers. Each invocation runs one named case and
filters 1,458 other library cases. The selected cases include five owned child
terminations per profile; they do not test physical power loss.

These are source-bound finite observations. No product or Rust test source was
changed. They do not sample the negligible zero-MAC event, prove HMAC security,
establish a generic malformed-state simulator or requalify a complete platform.
The conditional corollary, source audit and executions reduce a specific open
output obligation; full accepted-prefix and multi-root composition remain open.
