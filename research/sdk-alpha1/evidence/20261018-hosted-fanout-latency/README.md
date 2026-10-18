# Hosted fanout latency observations

[Run 39115501316](https://github.com/billlza/q-periapt/actions/runs/39115501316) completes both native measurement jobs and both independent Linux readback jobs at `aa7ef3b13c2af60849fc9cbfe1d4ea4c47bdf795`. The [fixed protocol](../../../../docs/continuity/FANOUT_LATENCY_V1.md) compares baseline `b47eb541` with the snapshot-lifetime implementation. Each host retains two warmup blocks and 200 alternating paired blocks: 4,800 measured sends, with 200 samples for each variant/workload position. No samples are excluded.

Both complete datasets pass the original correctness assertions and source/command/workload checks. Producer, independent cloud and local JSON/CSV reports are byte-identical for each host. All actual Cargo build events also pass the strict parser added after the first collector commit; both selected executables match the recorded source and command identities. Test-binary hashes remain producer observations, not independently downloaded binaries.

Neither host shows a consistent latency improvement. Observed p95 increases at six of twelve positions on each host. The earlier [desktop observations](../20261018-fanout-latency/README.md), including ten adverse p95 positions, remain evidence. These results do not establish no regression, explain away those observations, or qualify a tail-latency SLO. The separately measured [requested Rust allocation peak reduction](../20261018-fanout-snapshot-lifetime/README.md) remains a memory result.

The fresh hosted jobs do not establish exclusive hardware or controlled scheduling, thermal or power state. Measured load averages below include preceding activity and do not identify a cause. In particular, the macOS runner did not provide a demonstrated low-noise condition. Absolute timings across the two platforms are not a hardware ranking.

## macos-15

Actual target: `aarch64-apple-darwin`; reported CPUs: 3. Paired median changes range from -3.67% to +3.92%; observed load1 ranges from 1.80 to 17.78.

All times below are milliseconds, baseline → candidate. Paired median change is the median of per-block ratios, which can differ from the ratio of the two marginal medians.

| Account mode | Position | Payload / AD bytes | Median | p95 | p99 | Paired median change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cross | 0 | 0 / 0 | 10.006 → 9.901 | 14.685 → 15.661 | 34.352 → 18.773 | -2.23% |
| Cross | 1 | 1024 / 32 | 11.767 → 11.673 | 16.507 → 18.185 | 21.718 → 39.544 | +2.13% |
| Cross | 2 | 16384 / 1024 | 15.586 → 15.767 | 23.246 → 23.193 | 38.676 → 28.261 | +2.65% |
| Cross | 3 | 0 / 0 | 13.369 → 13.995 | 19.937 → 20.676 | 25.339 → 25.749 | +3.92% |
| Cross | 4 | 1024 / 32 | 13.462 → 13.707 | 21.827 → 19.619 | 36.950 → 27.623 | -0.70% |
| Cross | 5 | 16384 / 1024 | 16.278 → 17.131 | 26.187 → 26.378 | 43.502 → 41.484 | +3.77% |
| Same | 0 | 0 / 0 | 8.083 → 8.054 | 13.311 → 12.439 | 17.493 → 18.473 | -1.59% |
| Same | 1 | 1024 / 32 | 8.377 → 8.450 | 13.685 → 13.336 | 24.690 → 18.806 | +1.37% |
| Same | 2 | 16384 / 1024 | 12.514 → 12.277 | 19.722 → 16.841 | 22.683 → 24.029 | -3.67% |
| Same | 3 | 0 / 0 | 12.011 → 12.151 | 18.180 → 19.519 | 25.151 → 33.090 | +0.56% |
| Same | 4 | 1024 / 32 | 12.013 → 12.185 | 18.130 → 18.851 | 20.796 → 31.057 | -2.62% |
| Same | 5 | 16384 / 1024 | 14.795 → 15.114 | 21.707 → 21.438 | 27.003 → 24.810 | +0.78% |

## ubuntu-24.04

Actual target: `x86_64-unknown-linux-gnu`; reported CPUs: 4. Paired median changes range from -0.36% to +0.45%; observed load1 ranges from 1.01 to 1.25.

All times below are milliseconds, baseline → candidate. Paired median change is the median of per-block ratios, which can differ from the ratio of the two marginal medians.

| Account mode | Position | Payload / AD bytes | Median | p95 | p99 | Paired median change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cross | 0 | 0 / 0 | 7.278 → 7.266 | 7.818 → 7.890 | 9.196 → 9.156 | +0.30% |
| Cross | 1 | 1024 / 32 | 8.231 → 8.243 | 9.808 → 9.605 | 11.963 → 11.686 | -0.34% |
| Cross | 2 | 16384 / 1024 | 11.814 → 11.794 | 14.148 → 13.810 | 17.317 → 15.614 | -0.36% |
| Cross | 3 | 0 / 0 | 10.620 → 10.630 | 11.599 → 11.342 | 13.508 → 12.879 | +0.13% |
| Cross | 4 | 1024 / 32 | 10.942 → 10.933 | 11.569 → 11.869 | 13.341 → 13.989 | -0.04% |
| Cross | 5 | 16384 / 1024 | 14.226 → 14.192 | 15.821 → 15.829 | 16.907 → 18.104 | -0.03% |
| Same | 0 | 0 / 0 | 5.219 → 5.244 | 5.785 → 5.967 | 6.209 → 7.468 | -0.10% |
| Same | 1 | 1024 / 32 | 6.299 → 6.307 | 7.142 → 7.616 | 9.358 → 10.185 | +0.43% |
| Same | 2 | 16384 / 1024 | 9.209 → 9.235 | 10.345 → 10.107 | 11.415 → 11.492 | +0.44% |
| Same | 3 | 0 / 0 | 8.499 → 8.529 | 9.599 → 9.950 | 10.249 → 11.402 | +0.45% |
| Same | 4 | 1024 / 32 | 8.895 → 8.914 | 10.588 → 10.428 | 12.234 → 11.948 | +0.12% |
| Same | 5 | 16384 / 1024 | 11.972 → 11.953 | 14.100 → 14.085 | 14.647 → 14.860 | -0.36% |

## Readback and interpretation

The capture retains the four exact GitHub ZIP artifacts, the complete combined readback, the executed local reader and post hoc order/time analysis. `INVENTORY.json` verifies all retained members. To reproduce, place the four ZIP files under `target/fanout-latency-hosted-aa7-01` in a repository containing the baseline and measurement commits, then run `review-hosts.py` there using the repository Python bootstrap. Its existing local Linux review may be retained only when byte-identical to the raw producer and cloud reports; a fresh directory replays both hosts.

The post hoc partitions retain all samples separately by baseline-first/candidate-first order and four consecutive 50-block periods. Their direction varies; n50 p95 observations are sparse and are not new acceptance gates. The primary n200 nearest-rank p99 estimates have only two higher rank positions. No confidence interval, causal conclusion or favorable-subset selection is introduced.

The Windows/native/browser correctness checkpoints remain separate from this timing experiment. Controlled tails, wider workloads, physical-device costs, energy, independent protocol implementations and full 0.2.0 release admission remain open.
