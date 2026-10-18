# Fanout snapshot lifetime

The `send_account_message` path retained its decoded journal image, selected
recipient states and batch while `resume_account_message` loaded another image.
The implementation now releases those temporary objects after successful
reservation persistence and before the existing resume call. The exact-input
retry branch releases its checked batch/image at the same reload boundary.
The original crash marker, persistence ordering and resume authorization checks
stay in place. Database, key, anchor and authority ownership remain in `Active`.

The paired experiment starts from `44528b0ef2edfc5fc933129801c0fc2633f0d8b4`.
All 373 candidate Rust sources also match the installed producer at
`b47eb5417d3c25cb7bd05dd91e56ad73777c56fb`. Both measured variants use the
same test-only allocator observer, source tests, dependency lock and manifest;
the measured implementation delta is the three releases on the new-batch path.
The observer is confined to the experiment. The product patch additionally
releases the retry snapshot; no numerical improvement is claimed for that branch.

On an Apple M1 Max, 32 GiB, macOS 27.0.1 (26A434), Rust 1.98.1, five alternating
blocks execute the unchanged payload/ciphertext/associated-data/restart test.
Each variant yields 60 samples per profile: two recipients, same/cross-account
modes and payload/AD pairs of 0/0, 1024/32 and 16384/1024 bytes, repeated at two
journal positions. Each workload position compares the median of five blocks.

| Profile | Reduction in incremental requested Rust allocation peak |
| --- | --- |
| Debug, default features | 14.00%–17.04% |
| Release, all TLS features | 13.88%–17.31% |

Before/after live requested bytes match within every pair. The old snapshots
release 57,605–232,921 requested bytes earlier. These are allocator observations;
process RSS, foreign allocator allocations, latency, tails, energy and physical
devices were not measured. A shorter source file alone would not explain this gain.

The uninstrumented implementation preserves all 372 other Rust files and every
original test. It passes all 56 original Release fanout regressions, including
process loss, sync failures, exact retries, mixed roles, managed authority,
witness losses, policy continuation, abandonment and archive retirement. Strict
Release/all-features library Clippy, formatting and WASM async-library compilation
also pass. WASM compilation is separate from browser/IndexedDB execution.
Foreign consumers and the Windows cohort have not yet exercised this patch.

`CAPTURE.json` binds every member of `CAPTURE.zip`. The capture contains paired
raw streams/CSV, source and binary identities, instrumentation and implementation
patches, unchanged-test catalogues, commands, environment, lifetime inspection,
dependency verification, original producer reviews and uninstrumented results.
Exact local command paths describe the observed run, not a portable installation
interface. Source reconstruction uses the stated Git base and packaged inputs
identified by the producer reviews; apply `observer.patch` to both measurement
variants and `measured-optimization.patch` only to the candidate. Use separate
Cargo target directories and verify distinct binary hashes before comparing.

The initial missing-workspace build, shared-target baseline-binary reuse and
optimized builds with a missing `libLLVM.dylib` strip dependency remain recorded
and excluded. The optimized comparison uses fresh, warning-clean builds with the
pinned toolchain's library directory supplied through the process environment.
Earlier reviews retain their original pending-work fields; the uninstrumented
receipts record the subsequent regression/async/lint results. This checkpoint
supports this local optimization, not complete 0.2.0 release admission.
