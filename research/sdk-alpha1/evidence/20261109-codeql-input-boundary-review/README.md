# CodeQL input-boundary review — Python critical and C qualification findings

## Result

This review covers **52 Python critical SARIF results and all four C/C++ results** from [workflow run 42507570881](https://github.com/billlza/q-periapt/actions/runs/42507570881), attempt 1. Both language jobs checked out merge `f99a1100a74a10cb649a6f2a5fc61430f1174436`; the run's branch head was `358b921ab3469ce49f166633fc9a762ff6ed7e3d`.

The Python flows were reviewed as follows:

| Classification | Results | Meaning |
|---|---:|---|
| Explicit execution interface | 11 | A local invoker deliberately selects an interpreter, compiler, SDK tool or qualification executable. |
| Fixed command with constrained data arguments | 1 | Fixed Git executable/verbs with repository paths and checked commit identities. |
| Fixture/test driver | 10 | Explicit test tool selection and generated fixture commands. |
| Retained experiment driver | 30 | Dated local experiment scripts, inspected individually and by exact template differences. |

These are classifications of the recorded source-to-sink flows, not blanket false-positive labels. For example, historical joint-policy drivers forward a test selector without checking leading-option syntax; that fact is retained in group PY17, whose intended boundary is a trusted local experiment CLI. The review does not describe those arguments as sanitized.

The C findings contain **one confirmed qualification defect**, fixed by [PR #128](https://github.com/billlza/q-periapt/pull/128), commit `96f58b924dfd2e026e73b8adc01cad9ee4476b06`: seven ordinary caller-buffer overwrites could be deleted by an optimizing compiler. Volatile unsigned-char stores now preserve the intended overwrite, and the included actual-client model checks owned and each borrowed region at both `-O0` and `-O3` (30 cases). The independent focused replay and exact source hashes are in `c-fix-review.json`.

The other three C results are explicit harness file capabilities. The parent removes inherited `QPC_TEST_`/loader overrides, then injects its generated target and fresh receipt. The sync target is opened read-only, checked for regular/euid/0600/nlink1 and reduced to device/inode identity; the log is created with `O_EXCL`. The setup phase hook appends fixed records to the harness-selected log. These checks assume the harness and same-user process environment are trusted. The hook can also append to another qualifying file selected by a direct local invoker; leaf `O_NOFOLLOW` is not ancestor-directory or hostile-host authentication. Group C02 records this boundary explicitly.

**The remaining 1,257 Python high results are individually marked `unreviewed` in `unreviewed-high.tsv`.** No conclusion from the critical review is transferred to those items. Their breakdown is 1,202 path flows, 53 permission findings, one cleartext-storage result and one weak-hash result. The final two retain their raw query identity; their security interpretation is still unreviewed.

## Source and scan identity

The review verified **73 source files** against the exact merge tree's Git blobs and SHA-256 values. At integration candidate `93a8ce264624d2c711c894d02c04c582b0d10c63`, **72 files are byte-identical**; the only changed file is the reviewed PR #128 caller-buffer fix. `source-manifest.json` records both identities. A later evidence-only or paper-only commit should preserve these source blob identities for this review to apply unchanged.

Original retained artifacts are Python **13628179075** and C/C++ **13627814136**, produced with CodeQL **2.27.1**. `provenance.json` includes artifact digests, raw SARIF hashes, job URLs, and exact checkout-log excerpts. The raw SARIF and full Git tree are not duplicated here.

## Item and chain accounting

`reviewed-results.jsonl` contains all 56 reviewed result IDs, rules, scores, exact sink regions, source hashes, input origins, canonical full-chain hashes and review-group references. `groups.json` supplies the actual input boundary, controls, conclusions and line-specific source evidence for each of 30 semantic groups.

The 56 raw results have **155 recorded thread flows**, reduced to **140 distinct sink-plus-full-input-chain keys** after exact de-duplication. Every physical sink remains represented. These are scan units, not 140 independently established vulnerabilities. Full chain hashes can be reproduced from the original SARIF using the algorithm recorded in `provenance.json`.

The CodeQL pull-request comparison may show fewer new alerts than the complete SARIF scan. Raw result totals and PR alert-difference totals are distinct measurements.

## Review and gate state

The four C review conversations on PR #121 were resolved by the repository integrator following the actual fix and harness-boundary review. **Resolving a review conversation does not dismiss a code-scanning alert or change a required check.** No queries, scan exclusions, severity thresholds or branch gates were changed by this review; no alert dismissal was attempted.

At the recorded observation for integration `93a8ce2`, all 136 checks were queued and the new aggregate CodeQL check was not yet present. This package is a source review receipt. The final same-head hosted checks and aggregate result retain their normal role in main-branch admission.
