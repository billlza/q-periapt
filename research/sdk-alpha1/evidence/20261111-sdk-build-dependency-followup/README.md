# Additional SDK dependency failures and external status — 2026-11-11

This packet extends evidence commit `8abb26513e75fdd40053184c9630aadd34657919` with eight later completed failures from ordinary CI run `43050342715`, plus an independent fresh read of Canonical's official status feed. It leaves the parent seven-job snapshot intact.

## Repository job facts

| Job | Actual runner image | Dependency that failed |
| --- | --- | --- |
| check — 130625398900 | Ubuntu 22.04, 20261101.347.1 | cmake, pkg-config |
| cross AArch64 — 130625399514 | Ubuntu 24.04, 20261101.360.1 | gcc-aarch64-linux-gnu |
| cross RISC-V — 130625399245 | Ubuntu 24.04, 20261101.360.1 | gcc-riscv64-linux-gnu |
| audit — 130625399456 | Ubuntu 26.04, 20261101.186.1 | cmake, pkg-config |
| Binary CT AArch64 — 130625399323 | Ubuntu 24.04 ARM, 20261101.172.1 | valgrind |
| x86 AVX2 candidate — 130625398966 | Ubuntu 26.04, 20261101.186.1 | valgrind |
| Tamarin proof — 130625399125 | Ubuntu 26.04, 20261101.186.1 | graphviz, unzip |
| Binary CT x86 portable — 130625399165 | Ubuntu 26.04, 20261101.186.1 | valgrind |

Each full log records Ubuntu mirror resolution errors and APT exit code 100. Hostnames differ with the selected image and mirrors; `FAILURE_ANALYSIS.json` records the actual values for each job. All eight logs check out PR merge `b72f7f8e8e6f2526ebab4b825b7d47402ac9835f` for SDK head `75eda8f54a721dbed16a0bed43cdc493c9071485`.

The later package, target Cargo build, Memcheck, native audit, and machine-proof steps were skipped at their recorded dependency failure. Earlier successes remain explicit: **the audit job completed its byte-identical CycloneDX output step, and the AVX2 candidate completed its Clippy, KAT, differential, rejection, and SDK checks**. Tamarin's lemma-name gate also passed before dependency preparation. The APT failure does not overwrite those outcomes.

`logs/` contains each complete decoded GitHub job log with its original UTF-8 BOM and ANSI sequences. `FOLLOWUP_STEPS.json` retains one dedicated step-summary readback per selected job: the first three were recorded by 16:10:44 UTC, and the five added jobs were read between 16:17:20 and 16:17:21 UTC. This selection is not a new census of every workflow job. The endpoint returns step outcomes without timestamps; the complete logs retain actual event timestamps.

## Independent external observations

Canonical's official feed was freshly read from <https://status.canonical.com/rss> between **16:09:18.672416 and 16:09:26.563556 UTC**. The complete 11,040-byte body is `canonical-status.rss`; `CANONICAL_READBACK.json` binds its bytes, response status, source URL, selected response metadata, and this retrieval interval. It contains the status entry **DNS - Major Outage**, published at **14:26 UTC**. This is a new observation, separate from any earlier status check.

That official entry corroborates a concurrent external DNS outage. The repository logs independently establish the precise dependency failure and skipped work. The separate public runner report at <https://github.com/actions/runner-images/issues/15296> describes matching symptoms on Ubuntu 26.04 and is identified as a public report, not an official diagnosis.

`ubuntu2604-runner-image.md` retains the official inventory linked by the four Ubuntu 26 job logs: CMake 4.4.5, pkg-config 2.5.1-4, and libssl-dev 3.5.5-1ubuntu3.7. The audit job's actual Ubuntu 26 image is now observed directly, replacing the earlier uncertainty associated with its rolling `ubuntu-latest` label.

`EXTERNAL_CONTEXT.json` records source URLs and scopes. `MANIFEST.json` binds all packet files. No CI rerun, query execution, or source modification was performed for this evidence collection.
