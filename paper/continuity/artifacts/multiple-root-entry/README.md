# Several root entries from one recovered contribution

This artifact contains the complete proof of the finite multiple-root entry comparison and its first-message consequence.

`multiple-root-entry.tex` is the integrated manuscript module. `multiple_root_entry_proof.md` gives the exact controller, complete query accounting, constructive example and counterexamples. The independent review files record the statement-by-statement argument check and exact input identities. `FREEZE.json` binds this artifact to the integrated source and its reviewed inputs.

## Result

The real service derives `P_r = HMAC(r,S)` and `R_(r,I) = HMAC(P_r,I || 01)` from one hidden uniform contribution `S`. Its root-use descriptor is the complete pair `(Gamma(r),I)`, where `Gamma(r)` contains the two public HMAC pad states. Equal descriptors retain one root entry across callers and resumptions.

One shared-column comparison followed by adaptive class-row comparisons gives a private table of independent roots, with bit gap

`Delta_mr = min(1, epsilon_Hjoint(C,0,q_S,32) + sum_i epsilon_Hrow(N_i,q_i,98))`.

An online mark selects a fresh descriptor before its first root evaluation. Its class may already contain other information entries. Every alias of the marked descriptor retrieves one retained schedule handle. This supplies the existing joint first-message continuation, while the other root values remain available to the controller.

The explicit budgets distinguish `D` available salt strings from `C` pad-state classes. For `N = sum_i N_i`, conservative complete-query bounds are `q_S = B + 2D + 5N` and `q_i = B + 2D + 5 sum_(k>i) N_k`. The whole preparation, feedback, continuation and terminal test are included.

## Evidence and dependencies

The result is a mathematical interface composition. It uses the retained operational HMAC bounds in `joint-primitive-bounds.tex` and the retained joint schedule and first-message reduction. The complete-tuple ContextBound comparison provides an optional preceding contribution entry. The source instance in the preceding next-rekey theorem retains its established source induction.

The proof note includes a concrete controller that reveals two roots in a class, marks a fresh third information entry, and uses a disclosed earlier root as a later salt. Counterexamples explain the exact tuple, fresh-allocation and retained-handle conditions. The independent review checks these constructions and the resulting bounds.

The artifact's review is an independent mathematical argument check. Native execution and finite-model receipts retain their respective original identities in the manuscript's evidence map.
