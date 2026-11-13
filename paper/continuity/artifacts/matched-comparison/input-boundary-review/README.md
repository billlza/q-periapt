# Validated input snapshots for the public-trace auditor

The current `../audit_matched_traces.py` parses each compact result and native trace from the same validated byte snapshot that supplies its reported digest. Canonical relative manifest paths stay within the evidence root and reject symlink components. Each regular-file read checks descriptor identity before and after reading. This fixes the reported path-expression flow and the demonstrated compact parse/hash mismatch.

`validation.json` binds the fixed auditor and `../test_audit_input_boundaries.py` to seven passing controls through the repository's hardened Python launcher. The original script fails the retained counterexample: mutating the compact-results path after parsing causes the old final digest to describe the later contents. The fixed script continues to report the digest of the bytes actually parsed. The before/after stdout and stderr files preserve that result.

`compatibility-review.json` records an independent replay of the complete original 49-case archive. It reproduces all 49 compact rows, 14 native trace analyses, 35 reference trace/envelope analyses and all 126 public manifest hashes. Its fixed output, `audit-fixed.json`, differs from the original retained `../independent-review.json` only in the checker-source hash. The scientific measurements and original historical receipt retain their identities.

These controls validate each checked file read. Manifest verification and later recounts remain separate reads. The receipt's scope is input identity and path admission; the complete corpus replay supplies measurement compatibility.

`independent-review.json` records a separate inspection of the fixed byte-snapshot and path-admission logic and binds the reviewed source and regression evidence.

From the repository root:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/matched-comparison/test_audit_input_boundaries.py
```

`make check` also executes these seven controls. Current file hashes are included in the parent artifact manifest and the manuscript integration record.
