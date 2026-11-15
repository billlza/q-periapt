# Exposure, allocation and completed service

This revision connects the manuscript's recovery condition to its measured application service. Its base is manuscript commit `4b8cda65727e91508a4d258d550d9de610a21815`. It revises five section modules while retaining the previous abstract, introduction and adjacent main-theorem substitution table.

## Argument and structure

The evaluation opening now follows the objects used by the proofs: original reservations, acquired versions, reconstructed keys and admitted applications. It identifies component-snapshot outcomes separately from the common-opportunity executions, whose protocol services produce first commitments, logical deliveries, emitted frames and persistence work. The validation map includes the paired retry-readiness intervention explicitly. The section title, “Exposure, communication and admitted service,” matches those outcomes.

The end of the separating-executions section now explains what its positive symbolic execution, delayed-receipt witness, native reconstruction and aggregate-image execution establish together. It then points forward to the corresponding measurements. The discussion condenses the online-controller and bootstrap accounts around their established conclusions, selection timing, original acquisition histories and profile-specific costs.

## A general allocation explanation

For one captured epoch, let `n_d` count first allocations before the cut and `N_d` count first allocations afterwards in direction `d`. The existing per-direction cap gives `0 <= n_d <= b` and `N_d <= b - n_d`. Consequently,

`N_A + N_B <= 2b - n_A - n_B`.

Changing retry readiness or arbitration retains this inequality because an exact retry reuses its original allocation. The retained cut has one preceding allocation, giving `2b - 1`; the one-way continuation has `N_B = 0` and `n_A = 1`, giving `N_A <= b - 1`.

The manuscript then identifies the concrete positive computation: the captured-seed predictor reconstructs each subsequent epoch-zero application, with actual key equality, actual AEAD recovery and an altered-seed control. The occupied allocation capacity determines the corresponding reconstructed set. Security of a selected send under a later traffic chain follows through Theorem 5.28 and its original reservation/acquisition predicate. The commitments, admission denominator and queued demand remain beside the measured set.

## Why the service counts improve

The discussion now accounts for how the retry intervention uses the same 2,048 opportunities. Differences between the retained alternating rows are:

| Budget | Fewer application retries | More first applications | More ACKs | More control frames |
|---|---:|---:|---:|---:|
| 32 | 588 | 283 | 265 | 40 |
| 64 | 571 | 281 | 274 | 16 |

Each row balances exactly. The manuscript uses the budget-32 example to explain the observed rise in completed service together with the additional ACK and control work. It states the increased total communication and persistence work alongside the lower alternating per-delivery costs. The one-way result retains its admission cap, confirmed epoch and queued demand.

[data-accounting.json](data-accounting.json) records the original row values, differences, source digests and predictor source locations. These calculations use the existing retained traces and analysis.

## Three precise wording refinements

The guarded-history corollary now states that copying or rewrapping preserves existing routes and may add routes to the same source identity. Its proof distinguishes the identical object and route reused by an exact ciphertext copy from the record or guard changes possible under source-preserving rewrapping. The counter-separation proposition explicitly identifies the proposed bound as an upper bound on the **index** of an exposed epoch.

These are three natural-language refinements within two formal statement blocks and one proof block. The mathematical expressions, assumptions, conclusions and derivations retain their meaning. Across the 40 canonical source modules, 35 modules remain byte-identical; 55 of 57 statement blocks, 51 of 52 proof blocks and all 169 displayed mathematical groups are byte-identical. All labels retain their identities. [source-preservation.json](source-preservation.json) records the exact differences, and [editorial-semantic-preservation.json](editorial-semantic-preservation.json) supplies an independently generated comparison. The independent [methodology review](methodology-review.md) verifies the allocation argument, source boundary, numerical accounting and final wording.

## Build and review

`make source` passed with the existing retained research checks. A fresh build of the nine-file submission export produced the same complete plain text and layout text as the reading copy. The final reading copy has 121 pages, a 213-word abstract and seven keywords; all 48 fonts are embedded, with zero unresolved references or citations and zero overfull boxes.

Rendered pages 17, 88–90, 94–95 and 97–100 were inspected for the changed formal wording, evaluation map, allocation argument and discussion. The text, tables and equations fit their pages without clipping or overlap. The final document check was rerun after the export build, and both retained receipts identify the frozen reading PDF. [validation.json](validation.json) binds the commands, source records, independent review and build receipts.

Native experiment outputs, generated numerical tables, author declarations, bibliography, class, styles and figure bytes retain their baseline identities. The current pass adds the general counting explanation and existing-data accounting above; the recorded native experiments and formal-prover executions retain their original execution receipts.
