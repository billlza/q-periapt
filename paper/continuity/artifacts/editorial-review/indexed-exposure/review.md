# Indexed exposure evaluation: integration review

This revision adds an indexed, cumulative evaluator for the finite guarded-record semantics already defined by the manuscript. Proposition 4.5 proves agreement with the least closure and total `O(N + M + U)` work over a fixed graph and a complete acquisition/disclosure history, with `O(N + M)` storage. The parameter `M` counts stored incidences with multiplicity, and `U` includes repeated input events. Full-state exports incur their output cost; variable-length identity handling and graph updates have their own input costs.

The mathematical argument uses sound worklist steps, eventual processing of every enabled rule, and a one-time bound for each stored incidence. It attributes the classical Horn-closure method to Dowling and Gallier (1984), Section 4. The contribution here is the explicit incremental realization and complexity guarantee for the paper's three-sorted exposure semantics. The existing cryptographic reduction and recovery statements are preserved.

## Evidence

- All 5,360 assignments on the retained finite fixture inventory agree with the original scan in all three sorts and with the original guarded-path oracle on exposed sources.
- All 2,189 checked history prefixes agree, including 360 legal event permutations, ten directed histories and one duplicate-event history. Seventeen explicit expected cases and thirteen invalid-input cases pass.
- A separate oracle enumerates Boolean models of 24 deterministic small typed Horn graphs and intersects the models containing each seed set. All 2,592 seed sets agree in all three sorts, including equal literal names in different sorts.
- The original `Model.forward` is directly instrumented for the reversed-key-chain comparison. At 512 key edges it visits key edges 262,656 times; the indexed evaluator visits those edges 512 times, with 1,028 total counted propagation visits. These are operation counts, not elapsed-time or native cryptographic throughput results.
- The 128-layer record DAG has 257 records and `2^128` root-to-source paths by combinatorial counting. Indexed propagation uses 1,027 counted visits; 2,000 repeated events cause no further propagation. A 4,096-record chain completes without recursion. The indexed module's reference-oracle constructor is disabled during the scale controls.

## Build integration and document review

Both new checkers are part of the existing `make check`/`make source` path. Their results are retained by both the success upload and the always-run diagnostic upload in the manuscript workflow. A discovered import incompatibility with the repository's isolated Python launcher was fixed by loading explicitly named adjacent files with `importlib`; the launcher and its isolation flags remain byte-identical to the integrated baseline.

The final `make source` and independent source-export reconstruction pass. The reading PDF has 123 pages, a 213-word abstract, seven keywords and 35 bibliography entries. The nine-file export rebuild has identical complete plain and layout text; all 48 fonts are embedded, and there are no undefined references/citations or overfull boxes. Pages 17, 18, 91, 92, 93, 104 and 108 were rendered and visually inspected. The 137 underfull-box notices are recorded separately and did not produce clipping or overlap on those pages.

The source-preservation receipt compares the canonical base `1ce86a455b45721393676be15d7f0532d71e7c6a` with this revision. It accounts for all original formal statements, proofs, displayed mathematics and labels using block identity rather than shifted block positions. Historical executable receipts remain attached to their original sources. The new validation does not relabel those runs as executions of the current native code.

## Reproduction and continuation

Use the commands in `paper/continuity/Makefile` and the artifact map. `validation.json` identifies the current local evidence; `build-check.json` and `source-export-check.json` identify the frozen reading PDF and submission-source archive. `ci-integration-review.json` covers the actual isolated entrypoints and workflow artifact paths. The canonical paper branch remains `paper/joc-persistent-recovery` (PR #194); the combined project candidate remains PR #187. Their hosted checks must be read against the published commit identities.
