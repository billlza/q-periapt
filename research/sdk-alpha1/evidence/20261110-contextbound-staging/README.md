# Reserved ContextBound staging

## Change and source identity

This increment resumes PR #37 on integration source
`4c8a894cae712c71fe555a08571f21b2fb3127be`. Its historical CI failure was
`clippy::int_plus_one` in the new capacity assertion. The assertion now uses
`capacity() > SHA3_XOF_INLINE_CAP` with warnings still treated as errors.
The original failing jobs and complete current input hashes are recorded in
`source_identity.json`.

The selected implementation uses a nonzero spill capacity to represent heap
staging. A large reservation activates that storage immediately. Existing
inline input moves to the reserved buffer once; a reservation before input
creates no inline transcript copy. The representation adds no field to
`Sha3_256Xof`.

The storage invariant is as follows:

- With zero spill capacity, the initialized inline prefix is the complete
  transcript. Small reservations preserve the allocation-free 134-byte
  CompatXWing route.
- With nonzero capacity, the spill contains the complete transcript, including
  the valid empty transcript after an initial reservation. `reserve` records
  the preceding storage mode before allocating, so repeated reservations do
  not append the inline prefix twice.
- A migrated inline prefix remains initialized until `Drop`. Its original
  `inline_len` and secret-range offsets remain available to erase both live
  secret copies. The existing copy-then-wipe reallocation and synchronous
  wipe-before-abort paths are unchanged.

The digest input, field order, domain separation, output bytes and secret-range
classification are unchanged. The branch and allocation choices depend on
input lengths and reserved capacity. The result is a reduction in staging
copies for pre-reserved transcripts.

## Executed validation

The official Rust 1.98.1 toolchain was installed with `rustfmt` and `clippy`;
the downloaded installer matched its published SHA-256. Every final command
used `--locked`, with `RUSTFLAGS=-D warnings` for compilation. Receipts include
the toolchain version, command, source-file hashes, environment and exit code.

| Execution | Unit tests | Binding tests | Strict-import tests | Compile-fail doctests | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Original integration source | 64 | 2 | 3 | 3 | 72 passed |
| Selected capacity-derived implementation | 68 | 2 | 3 | 3 | 76 passed |

The four new tests cover activation before absorption, one-time migration after
an inline prefix, digest equivalence and allocation behavior at reservation
boundaries, and erasure of both secret copies after a reservation migrates
partially absorbed input. The boundary test includes lengths 0, 1, 134, 200,
201 and 2,500, three reservation schedules, empty absorbs and chunked input.
Existing tests continue to cover range overflow, invalid metadata, legacy
unclassified input and secure geometric spill growth.

`cargo clippy -p q-periapt-backends --all-targets --all-features --locked -- -D warnings`
and `cargo fmt --all -- --check` both pass. The test inventory records executable
hashes and confirms that all four added tests were present in the executed
candidate binary. The selected source hash is
`a91f2ddb28ee793ea253cc3a44470cde46d8c8bf8ee08eeb569c6ac1c4bb01dd`.

## Paired timing observation

The repository's existing `combiner` benchmark is byte-identical in both
builds. The benchmark binaries were compiled in separate Cargo target
directories. The baseline executable SHA-256 is
`457cc516632b525666721212b969307f1cca711b8b2c90e2eb08fc08dcfa12a4`;
the selected executable SHA-256 is
`3a229e4002e8b73b8a2b3a0ee9568f564ec0956e4b292f6cef6decebd584d5f1`.

The final cohort ran on an Intel Xeon Platinum 8573C, Linux x86-64, pinned to
CPU 0. Both source builds had completed; the parallel release build had ended
and archive work was deferred during this cohort. Each invocation used
Criterion with 0.5 seconds of warm-up, 1 second of measurement and 100 samples
per benchmark. The order was baseline A, candidate A, candidate B, baseline B.
All sample arrays, estimates and confidence intervals are retained under
`criterion/`; `paired_benchmark_capacity.json` binds their source and binary
identities and exact commands.

| Run | ContextBound mean, µs | ContextBound median, µs | CompatXWing mean, ns | CompatXWing median, ns |
| --- | ---: | ---: | ---: | ---: |
| Baseline A | 9.082 | 8.506 | 545.659 | 523.759 |
| Candidate A | 8.709 | 8.385 | 534.925 | 531.272 |
| Candidate B | 8.926 | 8.516 | 551.465 | 527.363 |
| Baseline B | 8.773 | 8.646 | 546.966 | 541.877 |

The two ContextBound median comparisons are 1.43% and 1.50% lower for the
candidate. Their mean comparisons have different signs, and the retained
intervals overlap. These local observations accompany the verified copy
reduction; they do not establish a stable latency improvement. The observed
CompatXWing cost remains in the same approximately 0.53–0.55 µs range.

An earlier explicit-boolean representation was also evaluated. Its complete
source delta, validation and ABBA samples are retained in `alternatives/`
and in the corresponding unsuffixed Criterion directories. That cohort ran
while a separate release build was active. The selected representation uses
the allocation itself as the storage-mode indicator and preserves the
original struct layout. No favorable subset of either cohort is removed.

## Reproduction and cache correction

Create baseline and candidate worktrees and use a distinct, initially absent
`CARGO_TARGET_DIR` for each source. Use Rust 1.98.1 and the checked-in lockfile.
In each worktree, run the backend tests, the all-feature Clippy command above,
and the unchanged benchmark build:

```sh
cargo test -p q-periapt-backends --locked
cargo clippy -p q-periapt-backends --all-targets --all-features --locked -- -D warnings
cargo bench -p q-periapt-backends --bench combiner --no-run --locked --message-format=json
```

Take each benchmark executable from its own `compiler-artifact` JSON record,
retain its SHA-256, and execute the two binaries in ABBA order on the same CPU.
The final receipt supplies the exact Criterion arguments. The source hashes
and executed test inventory should be checked before interpreting the result.

The first attempt shared one Cargo target directory between the two worktrees.
Cargo reused the baseline binary: the supposed candidate listed 64 unit tests
and its benchmark executable hash was identical to the baseline. Those test
and benchmark receipts are invalid for the candidate. They remain in
`invalid-shared-target/` with the superseded Clippy receipt, and the finding is
recorded in `cache_contamination.json`. The candidate was then rebuilt in its
own target directory. The final 68-unit-test inventory, distinct executable
hashes and source-matched receipts above supersede the shared-target attempt.

This packet records local source validation. Hosted protected-main admission
continues to use the checks attached to the actual published branch head.
