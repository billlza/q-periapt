# Native fanout latency comparison

This experiment follows the [desktop observations](../../research/sdk-alpha1/evidence/20261018-fanout-latency/README.md):
paired medians had no consistent improvement, and observed p95 increased at 10
of 12 positions. Those results remain part of the evidence. A successful CI job
means that the comparison completed and its records replayed; it does not admit
a performance improvement, a latency SLO or the 0.2.0 release.

The [workflow](../../.github/workflows/fanout-latency.yml) compares the immutable
`b47eb5417d3c25cb7bd05dd91e56ad73777c56fb` runtime source with its current candidate
on Linux x86_64 and macOS arm64. The macOS label is `macos-15`; both the actual
machine and Rust host are checked before building. Intel macOS is outside this
experiment. GitHub documents these [standard runner architectures](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Fresh hosted jobs reduce desktop workload interference; they do not establish
exclusive physical hardware or eliminate all scheduling and I/O variation.

The source preparation accepts only the expected candidate README and fanout
module changes. Every other candidate file, all SDK source/configuration paths,
the two manifests and dependency locks must match. Small source copies use the
same repository SDK dependencies and separate fresh Cargo target directories.
Both uninstrumented Release/all-features binaries are built before sampling;
their hashes must differ and remain unchanged. Rust 1.98.1 and the original
Release settings are retained. No new crypto, persistence, witness or test path
replaces the existing `send_account_message` test.

After two warmup blocks, 200 blocks alternate baseline/candidate and
candidate/baseline order. Each process runs only the original exact test, with
one test thread and all of its ciphertext, associated-data and restart assertions.
Its 12 workload positions cover two recipients, same/cross-account modes and
three payload/AD sizes at two journal positions. Each variant supplies 2,400
timed sends, or 200 samples per position. Timing includes the actual journal
transaction; bootstrap/setup and later receiver checks are outside the interval.

The [collector](../../artifact/fanout_latency.py) retains bounded command streams,
start/completion or interruption receipts, source archives/identities, compiler
and host information, test catalogs, execution order and host load observations.
Its private source/build/cache area and generated runtime state are not uploaded.
A command boundary interruption is an error; no completed experiment is emitted
for a partial run. Stream capture on boundary interruption may be incomplete;
the started/interrupted receipts retain the command and failure classification.

The separate [reader](../../artifact/fanout_latency_review.py) reconstructs both
source archives from the exact Git revisions, checks each command and complete
workload census, and reproduces all 4,800 samples. Independent Linux jobs must
produce byte-identical JSON and CSV reports for each measurement job. Reports
retain per-position medians, maxima and nearest-rank p95/p99 values. They never
pool different positions, exclude samples, or apply a convenient speed threshold.
At this sample size, p99 has only two higher rank positions per variant/workload.
Both favorable and adverse tails require interpretation after execution.

These are native journal-send observations. Installed foreign interfaces,
network/whole-connection latency, physical devices, energy, confidence intervals
and release performance requirements remain separate work.
