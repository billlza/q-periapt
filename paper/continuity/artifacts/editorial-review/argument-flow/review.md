# Whole-manuscript argument flow

This revision develops the explanatory prose from the observed restart to the original-source recovery condition, the computational connections and the measured service. Its baseline is manuscript branch commit `03cdd1fb3d3173f885bb39f83108e9b3b36c82fc`.

## Changes

All 40 canonical TeX modules were read. Explanatory prose was revised in 36 modules, including the technical sections and appendices. Existing formal statements and proof environments were retained verbatim.

- The opening execution identifies the saved key-generation randomness, the inputs acquired by the observer and the public response that completes traffic-key reconstruction. That execution motivates the distinction between an original reservation, an immutable session version and its physical images.
- The model and simulation exposition explains why a saved version can become readable after acquisition, why exact retries need immutable handles, and how the acquisition history fixes candidate-local stopping. The formal experiment retains its original observation and selection boundaries.
- The computational connections follow the same candidate through the hybrid contribution, root, confirmation and traffic schedule. Each transition identifies the interface needed by the next comparison, the information still available to the observer and the cost charged for the complete continuation.
- The bootstrap discussion traces the protected ACK to its surviving original source. It explains why the complete source and joint-entry comparisons precede the parent-family partition and why a delayed READY proof authenticates the earlier durable activation.
- The evaluation distinguishes complete-profile comparisons from the paired retry-readiness intervention. It interprets reconstructed keys together with first commitments, logical deliveries, communication and persistence work, preserving the actual schedule-dependent tradeoffs.
- Related work identifies the question and mechanism contributed by each cited line of research. The discussion states the established recovery result and relates its original-source condition to the executed service measurements.

The abstract specifies that the send budget of 32 applies per epoch and per direction. The current-manuscript navigation link in the artifact map now points to PR #200; historical source and evidence pins retain their original targets.

## Preservation and validation

`source-preservation.json` compares the 40 canonical modules with the pinned baseline. It records exact ordered identities for 58 formal statements, 53 proofs, 170 displayed mathematical groups, 15 tables and 187 labels. Citation and cross-reference multiplicities and all inline mathematical expressions are preserved. The sole numeric-token change is the manuscript navigation URL from PR #194 to PR #200; experimental and mathematical values are unchanged.

The 729 original artifact files, author declarations, author metadata, bibliography and publisher style files remain byte-identical. This revision adds no mathematical result and reruns no native protocol or Tamarin experiment. Existing evidence keeps the source revision and execution identity on which its claim rests.

`validation.json` records the actual manuscript checks and visual review. `build-check.json` identifies the compiled reading copy and its source inputs. `source-export-check.json` records the fresh build of the nine-file submission package and its complete text comparison with the reading copy.
