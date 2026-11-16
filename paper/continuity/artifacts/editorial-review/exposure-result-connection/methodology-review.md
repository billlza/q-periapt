# Independent methodology and editorial review

Baseline: `9d49c678565d3d9d8ca7d001a117781917e3782c`. Paper result commit: `f93fb5903a5a39edbbdb9a9340f52dfb2e706a93`.

Theorem 5.28 and its candidate-local eligibility/stopping, online-selected chain and AEAD continuation; Proposition 4.5 and implementation/evidence interface; final introduction/discussion patch. This is a scoped audit, not a universal proof certification.

**Outcome:** No demonstrated defect found in the inspected derivation and cost-accounting path. Final two-module editorial patch approved.

The reviewed formal modules and artifact source files match the baseline byte for byte. Review method: source reading and derivation audit; execution evidence remains with the dedicated artifact/build checks.

## Acquisition eligibility and source readability

The definitions implement distinct, compatible predicates. Guarded closure computes source derivability in the fixed graph. Native eligibility binds the chosen accepted message and cut to original reservation events and acquired-session first-save metadata. The new discussion preserves this distinction instead of deriving eligibility directly from source-set membership.

Source locations: `security-model.tex:422-477 (eq:eligibility)`; `guarded-provenance.tex:123 (prop:guarded-worklist)`; `discussion.tex:12-23`.

## Candidate selection and stopping

The free stopping certificate is candidate-local and anchored to original acquisition/save/reservation metadata. It applies to all eligible continuations of that candidate even when the final cut or other origin has not yet been selected. Localization is performed in the original game, and modified-world selectors are recomputed. No global-stop substitution or conditioning by eligibility probability was found in this inspected proof path.

Source locations: `candidate-local-accounting.tex (Origin-anchored adaptive stopping; signed score accounting)`; `security-model.tex:487-546`; `native-chain-composition.tex:189-277 (thm:native-online-message)`.

## Online mark and chain hybrids

The first-computation ledger includes receiving-side and failed transaction computations. Repeated computation does not open a new marking opportunity. The hybrids retain the continuation and the stated query budgets; their index-wise sum does not insert an unsupported extra guessing claim. The selected-key AEAD continuation explicitly supplies the pre-encryption decryption interface.

Source locations: `native-chain-composition.tex:24-105`; `chain-prefix-continuation.tex`; `joint-continuation.tex (application secrecy and selected-key AEAD continuation)`.

## Signed score and candidate costs

The inspected signed-score comparisons consistently account for two-sided difference costs and the final one-half conversion to conventional advantage. Original attribution and later simulation residuals are localized separately; the derivation does not partition probabilities across unrelated altered worlds.

Source locations: `candidate-local-accounting.tex`; `native-chain-composition.tex:189-277`; `common-virtual-accounting.tex`.

## Incremental closure cost and implementation

The fixed-graph worklist maintains exactly the least closure through cumulative record acquisitions and key/source disclosures. Separate key/record arrival handling covers both orders. The opened latch prevents repeated payload scans. Incidence multiplicity, duplicate input events, and complete-state export cost agree with Proposition 4.5 and the new introductory statement. The lazy reference-path helpers are outside the incremental worklist path.

Source locations: `guarded-provenance.tex:123 (prop:guarded-worklist)`; `artifacts/guarded-provenance/indexed_exposure.py`; `introduction.tex:87-94`.

## Empirical linkage and independent checks

Source inspection confirms that the independent reviewer computes Horn-model intersections over sort-tagged atoms, while directed fixtures cover alias sorts, repeated incidences, both arrival orders, and no-record key cycles. These support implementation/semantics alignment. This review does not introduce new execution counts or claim that those scripts were rerun by this reviewer.

Source locations: `artifacts/guarded-provenance/review_indexed_exposure.py`; `artifacts/guarded-provenance/check_indexed_exposure.py`.

## Two-module editorial patch

Approved. The introduction now presents an already-established algorithmic result with N/M/U definitions and output-size accounting. The discussion connects graph semantics to the separate native proof interface. The conclusion explicitly retains the fixed-graph condition. The condensed extensions paragraph preserves its theorem references and technical claims.

Source locations: `introduction.tex:87-94`; `introduction.tex:133-140`; `discussion.tex:12-23`; `discussion.tex:133-142`.

## Frozen editorial snapshot

| File | SHA-256 |
| --- | --- |
| `paper/continuity/introduction.tex` | `4d79744628d36d87e5eb992dce3edc1808fd9ff5dad727865f389a460783fe19` |
| `paper/continuity/discussion.tex` | `dfaa695269f67083043a1c7da176ff24c7c9343f842352587c8b8da757f1a25c` |

The accompanying JSON records hashes for all reviewed source files.
