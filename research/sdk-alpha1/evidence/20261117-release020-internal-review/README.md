# Current analysis reconciliation

The [review](REVIEW.md) and `DISPOSITIONS.json` associate all 5,012 raw results
from nine source-matched analyses with their actual input/operation boundaries.
They bind source `8abbf8d2e73a27af7794528fd92d13fe3be2942d` and CodeQL run
[43964930828](https://github.com/billlza/q-periapt/actions/runs/43964930828).
The source index retains 538 exact file pins, 184 Python path origins, 383 Rust
path/command origins and all 28 named zero-initialized-key sinks. The original
archive digests, SARIF member digests and individual result indices remain in
`INVENTORY.json`.

`capture.py` only captures the raw population and deliberately makes no review
claim. `index_review.py` records the later source review and rejects unclassified
rules/origins or a changed population; it is not a general automatic security
classifier. Its source-bound statements and limits are in the companion review.
The index was checked for complete, unique result coverage, exact input/script
digests and the 28-sink population. No native runtime suite was run by this review.

All nine downloaded ZIP digests matched their hosted artifact metadata. The raw
archives are retained under the local task's `target/release020-finalization/`
directory. The older Python execution review was compared against all 70 of
its Python source pins: 64 identical, with the six changed files individually
reconciled. Historical executions retain their original identities.

The current-source result review establishes no new required product fix for
the reported operations. It does not dismiss remote alerts or qualify later
source changes. Final release-source analysis/delta reconciliation, full CI,
chosen artifacts, signing and publication remain separate requirements.
