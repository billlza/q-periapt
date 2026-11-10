# Paper-branch CodeQL Rust inventory repair

The exact paper baseline `4fde471641150c68a08b56e728067c72b39ab346` has 174 tracked Rust files, comprising 106 current sources and the same 68 frozen bootstrap proof snapshots as integration. Its original quality suite reproduces one inventory error in 43 tests because the old literal remains 106.

The minimal paper patch adds the exact source-pin manifest and per-file archive validation, retains all 174 files in extraction, and passes 48 tests including five new archive rejection tests. Three existing tests of language coverage, the fail-closed quality gate and the documented publication boundary also pass. The paper branch keeps its existing single-database policy, including zero unresolved source macros across the entire source set. It does not adopt integration's target profiles or alter query/toolchain policy.

The four implementation, test and documentation files are bound by SHA-256 in `RESULT.json`; source identities for all 68 retained snapshots are bound through the same five historical packet manifests. The baseline and candidate test inventories and full logs are retained. This validation used CPython 3.14.7 from a separate ordinary Git clone; additional proof-input trees were materialized before running the publication-boundary checks.

Hosted compilation, extraction, query completion and resulting required checks remain separate CI outcomes for the published paper head.
