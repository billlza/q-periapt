# SDK build dependency failure evidence — 2026-11-11

At the single 15:53:52–15:53:53 UTC readback, seven completed jobs across four workflows failed in Ubuntu dependency preparation. Each full log records APT mirror name-resolution errors followed by exit code 100. The six x86 jobs report `azure.archive.ubuntu.com`; the ARM ABI job reports `ports.ubuntu.com`.

## Source and scope

- SDK head: `75eda8f54a721dbed16a0bed43cdc493c9071485`.
- Actual checkout recorded in all seven logs: PR merge `b72f7f8e8e6f2526ebab4b825b7d47402ac9835f`.
- Evidence parent: `239f2684e9baba5915c5a5f5f48b1749ec872683`.
- `JOBS_SNAPSHOT.json` retains the seven original job payloads, including step outcomes and times, plus the four endpoint census counts. Every queried endpoint fit one page.
- `FAILURE_ANALYSIS.json` records derived line references, command text, hostnames, exit status, elapsed dependency-step time, and skipped work.
- `logs/` holds the complete decoded GitHub job logs as returned by the connector. UTF-8 BOM and ANSI sequences are preserved; no line filtering or normalization was applied. `MANIFEST.json` binds every file by byte length, SHA-256, and Git blob SHA.

## Observed failures

| Workflow / target | Job | Dependency step (seconds) | Requested packages |
| --- | --- | ---: | --- |
| CodeQL Rust WASM | 130625389933 | 404 | protobuf-compiler, clang |
| CodeQL Rust native | 130625390075 | 405 | protobuf-compiler, clang |
| Native and reference matched | 130625388353 | 405 | protobuf-compiler, libssl-dev, pkg-config |
| Native retry readiness | 130625388744 | 405 | protobuf-compiler, libssl-dev, pkg-config |
| SPQR reference, Ubuntu 24.04 | 130625398832 | 404 | protobuf-compiler |
| ABI2 Linux x86_64, Ubuntu 22.04 | 130625398754 | 491 | cmake, pkg-config |
| ABI2 Linux aarch64, Ubuntu 22.04 ARM | 130625398884 | 730 | cmake, pkg-config |

Both Rust CodeQL jobs stopped before the rejection-case checks, CodeQL setup, extraction, and query execution. Their two missing-file upload errors followed that early stop. The matched, retry, and SPQR jobs likewise skipped their research execution steps, then failed to upload outputs that had not been produced. ABI package construction and public-consumer verification were skipped.

These logs establish the immediate APT failure and the shared dependency-preparation boundary. They do not identify which upstream DNS component caused name resolution to fail. The earlier qualified full-query wrapper result remains recorded separately in the parent evidence history; this packet contains the failed SDK runs without converting them into query or protocol results.

No tests, queries, JVM processes, CI reruns, or source changes were performed to collect this packet.
