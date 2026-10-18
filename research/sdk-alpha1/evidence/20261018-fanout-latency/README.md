# Uninstrumented fanout latency observations

The previous allocation experiment is followed by a fixed 200-block comparison
of the uninstrumented baseline and snapshot-lifetime candidate. Both use the same
original two-recipient test, manifests, dependency lock, Release/all-features
configuration and Rust 1.98.1. Source and distinct binary identities are retained.
Two warmup blocks precede alternating baseline/candidate and candidate/baseline
blocks. All original ciphertext, associated-data and restart assertions pass.
The 4,800 timed sends provide 200 samples per variant at each of 12 workload
positions. Timing includes the real journal transaction; bootstrap/setup and
subsequent receiver checks are outside that send interval.

The paired median changes range from -1.78% to +1.14%, without a consistent
latency improvement. Observed p95 increases at 10 of 12 positions. Those adverse
tails are retained and remain unresolved. Host load averages range from 4.82 to
17.50 on the desktop; this includes the benchmark and outside work. There are no
own concurrent builds or large artifact downloads during sampling. Small source
reads and a documentation-only edit/commit also occurred. These observations do
not isolate a causal regression or establish a latency SLO.

All positions are shown below. Values are milliseconds in median / p95 / p99
order. Quantiles use the observed nearest rank; p99 has only two observations
above it per variant/position. No different journal positions are pooled.

| Account relation | Position | Plaintext bytes | Baseline median / p95 / p99 | Candidate median / p95 / p99 |
| --- | --- | --- | --- | --- |
| cross | 0 | 0 | 42.169 / 58.974 / 88.670 | 42.425 / 74.353 / 120.220 |
| cross | 1 | 1024 | 47.950 / 70.406 / 105.503 | 47.391 / 76.918 / 107.567 |
| cross | 2 | 16384 | 55.217 / 74.682 / 117.559 | 54.649 / 80.927 / 120.574 |
| cross | 3 | 0 | 49.327 / 61.749 / 81.247 | 49.451 / 68.412 / 87.589 |
| cross | 4 | 1024 | 48.696 / 60.632 / 71.447 | 48.570 / 64.484 / 100.368 |
| cross | 5 | 16384 | 50.687 / 65.112 / 79.799 | 50.709 / 70.559 / 103.599 |
| same | 0 | 0 | 41.440 / 54.500 / 72.185 | 40.829 / 50.054 / 63.096 |
| same | 1 | 1024 | 41.921 / 54.526 / 71.645 | 41.422 / 49.603 / 58.345 |
| same | 2 | 16384 | 48.723 / 59.933 / 77.203 | 49.173 / 65.462 / 72.962 |
| same | 3 | 0 | 48.396 / 61.729 / 78.462 | 48.635 / 64.686 / 80.033 |
| same | 4 | 1024 | 48.341 / 62.401 / 80.154 | 48.660 / 66.759 / 76.721 |
| same | 5 | 16384 | 50.206 / 63.172 / 88.185 | 50.526 / 70.630 / 84.022 |

Post hoc order/time strata are descriptive checks of the same complete data,
without dropping samples or changing the original comparison. The direction of
the p95 differences varies across time ranges; cross-account tails remain worse
at several positions under both execution orders. This does not justify blaming
all adverse results on noise. A cleaner-host comparison is needed to resolve the
tail concern before treating the change as performance-qualified. The measured
allocation reduction remains its own result; it is not a speed claim.

`CHECKS.json` binds `CAPTURE.zip`, whose inventory covers every raw command,
sample, source/binary identity and analysis result. The native regression,
WASM compilation and actual installed browser behavior remain separate evidence.
No foreign/network/device/energy or full release qualification is claimed.
