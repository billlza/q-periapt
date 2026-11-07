# Continuity installation after publication-maintenance changes

This checkpoint qualifies the new shared publication-maintenance implementation
through actual archive-derived native consumers and a newly installed independent
Python wheel on one Apple-Silicon host. It also records separate complete local
Debug and Release regressions. It does not freeze the candidate or authorize publication.

The SDK producer is `f560d803c43a24fff222daa5e5e5bd623bfdf874`. The clean consumer
checkout is `4effa8b2b25e7403ab912b65894a7d1e73695542`; the intervening changes are
documentation and evidence. Source, archive, compiler and provider identities
were checked before and after execution. Earlier installed cohorts do not supply
these new results.

## Observed installed results

- The existing Rust package consumer executes all three original public API
  tests in each of Debug and Release, with zero failed, ignored or filtered
  tests. Strict Clippy passes. Original runtime readback and all ten exported
  enrollment/reopen/roster/replacement/retirement public closures were reread.
- The native counterpart and bootstrap importer are newly built from the same
  candidate archive and installed SDK archives, with strict Clippy. The Rust
  consumer uses nine SDK crates plus the candidate; the independent counterpart
  uses eight SDK crates plus the candidate. Neither resolves product code from
  the source checkout.
- The complete existing wheel path passes all 25 commands and final source,
  installed-file, wheel, native and provider checks. Its unchanged wheel bytes
  were verified against all 105 current source modules before a fresh
  outside-checkout installation. This is not a claim that the wheel was rebuilt.
  The observed provider is cryptography 48.0.1 / OpenSSL 4.0.1.
- The last full policy/credential/roster capacity command takes **891.810 seconds
  within its unchanged 900-second limit**. Both local and required-Witness
  profiles cover 32 members, 2,031,616 original traffic bytes and 123 rows; their
  respective worker/process-kill counts are 36/7 and 39/8. The small time margin
  is retained as observed, without extrapolation to other runners or a product
  performance guarantee. Other local native regressions ran during this sequence;
  these wall times do not attribute a slowdown to that concurrent work.
- Independent readback checks 1,399 Rust-package source inputs, 26 counterpart
  inputs, 240 wheel inputs, the installed 113 wheel files and 120 copied harness
  files, all 25 original/streamed command pairs, and the completed composition
  and capacity records. No test rerun was needed for that readback.

The earlier actual-directory CLI public fixture is reused solely for historical
public-byte verification by the freshly installed reader. No new directory CLI
producer execution, live authorization or consumption claim follows from it.

| Artifact | SHA-256 |
| --- | --- |
| Twelve-archive SDK report | `93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8` |
| Candidate crate, identical across both packaging paths | `9bd308702bbb922122ae9f69c40d0cd691f67da9ef0d7d6c2b5381adf2cce163` |
| Installed native counterpart | `eaf5e7cc305775b7d13292252dfba581bc797bca90be2a2b94d66ba2c2205254` |
| Installed wheel | `596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094` |
| Original complete wheel result | `e88c28765339a10fa71065bf0ee1ac3f65e710f2aacd4783a9585c03379120bd` |

## Separate native Release regression

[NATIVE_RELEASE.json](NATIVE_RELEASE.json) retains the complete result and input
hashes for the unfiltered, all-feature, locked/offline candidate Release command:
1,456 library tests, integration targets of 4/2/4/3 tests and 19 doctests, totaling
1,488. The sealed SDK additionally passes 27 library tests and four doctests.
All report zero failed, ignored and filtered tests. Compiler output has no
warnings, and captured source inputs remain unchanged.

The candidate catalog/build took 206.363 seconds and its complete execution
3,107.694 seconds. The sealed SDK followed within the remaining part of the same
pre-existing 90-minute job budget; that budget was not reset or enlarged. The
workflow is byte-identical to the pre-maintenance version. Earlier 600-second
diagnostic observations remain timed out and retained in their original
[maintenance checkpoint](../20261104-managed-publication-maintenance/README.md).
They are not relabelled as complete regression passes.

[NATIVE_DEBUG.json](NATIVE_DEBUG.json) additionally closes the existing Debug
partition union. The main partition passes 1,455 library tests and all 32
integration/doctests; the separate capacity partition passes the remaining one
library test. Their 1,456-entry library catalogs are identical, and the selected
sets are disjoint and cover the entire catalog. The main partition also passes
the sealed SDK's 27 library tests and four doctests. Total wall times, including
catalog/build work, are 2,614.179 seconds for the main partition and 1,126.422
seconds for capacity, each within its existing 90-minute job budget. Both source
checks pass, with zero failed or ignored tests. The filters are the existing
complementary CI selections; no case is omitted from their union.

These local results do not replace hosted final CI or another platform's run.

[CI_STATUS.json](CI_STATUS.json) retains the observed effective wave at the old
PR heads `475cd239` and `6084f3bf`: 287 successful jobs, 36 queued, seven failed
and two skipped at that snapshot. The unchanged failures remain in their
existing classification/evidence records. Queued or skipped jobs are not passes,
and this older wave does not qualify the new local source. No new wave, push,
retry or cancellation was triggered.

## Capture and provenance

[RESULT.json](RESULT.json) is the installed-qualification index.
[EVIDENCE.zip](EVIDENCE.zip), SHA-256
`4cc57c38a746f0c361e73149fe30f14e41cf3edff03f653f99dd58304e7afbc2`,
contains 850 exact selected files plus its manifest. Its
[FILES.json](FILES.json) records both original and archived hashes. All 534
closed public binary exports retain their exact bytes. The 150 metadata files
whose local paths changed are explicitly derived disclosure copies; their
original receipts and scripts remain private under
`target/continuity-installed-managed-cohort` and the original root named by
`WHEEL-DRIVER.json.output_original`. Path aliases in derived scripts are not a
claim that those edited script bytes were executed.

The archive contains the actual command records, driver/tool/source identities,
public outputs and independent readbacks. It excludes the private runtime trees,
outside temporary consumers and executable files. The original wheel runtime
has 65,890 regular files; it is retained at its original location. The unnecessary
whole-tree copy was explicitly interrupted **after** all 25 commands and final
qualification readback succeeded. Its outer exit is **130**, and its partial
mirror is not authoritative. No symlink or special-file failure was observed.

Preparation/readback diagnostics also remain explicit: launch exit 126 before
Python started, the first internal reader's report-schema `KeyError`, the public
reviewer's own quoted-PEM-marker false positive, and the first sealer's own
temporary-path-marker assertion. Their corrected readback/sealing paths pass;
these are not product assertion failures or hidden product test retries.

This establishes same-host Apple-Silicon installation and both complete native
test profiles. New C/Swift/Kotlin/Android consumers, Windows/Linux execution,
cross-host and physical power-loss qualification, final product/ABI contracts,
the computational proof obligations, external security review and formal release
remain separately tracked.
