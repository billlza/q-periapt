# Ordinary KEM game connection

The integrated module is [`kem-ordinary-bridge.tex`](../../kem-ordinary-bridge.tex),
with stable labels `sec:kem-ordinary-bridge`, `prop:kem-deferred-challenge` and
`eq:kem-deferred-bridge`. It follows the original-operation adapter and precedes
its live-core instantiation.

The proposition bounds the actual two-stage ML-KEM distinguishing advantage by
an ordinary IND-CCA advantage plus

`zeta_pre(q_pre) = min(1, q_pre / 2^256 + delta_mr)`.

Here `delta_mr` is message-recovery failure of K-PKE on an honestly generated
challenge. The existing KEM shared-key correctness term remains separate.
The ordinary reduction withholds its challenge until the original controller
requests it, forwards genuine prechallenge decapsulations and stops at a query
equal to the withheld challenge. The full real prefix, with the common static
oracles fixed, is independent of the unused encapsulation message. The shared
bad-event probability yields one `zeta_pre` per Boolean advantage; the existing
signed-score conversion supplies its stated factor of two.

This gives an ordinary-game instantiation of the existing operational-game
theorems. Their original-source choices, record-acquisition stops, exact retries
and whole-execution budgets are preserved. The result applies through the
component terms in the established-session, online-message and complementary
bootstrap compositions.

## Review and evidence

- `author-check.md` is the retained draft-stage argument and integration map.
  Its status text describes the draft before integration.
- `independent-review.md` records the separate mathematical review, including
  the static-QROM argument, the common-event coefficient and the distinct
  correctness probabilities.
- `formal-preservation.json` compares all preceding canonical statement, proof
  and displayed-math blocks against manuscript commit `4fde471641150c68a08b56e728067c72b39ab346`.
- `current-labels.json` records the current numbering and pages after insertion.
- `build-check.json`, `source-export-check.json` and `visual-review.json` bind
  the integrated document and independently compiled submission archive.

The mathematical addition introduces no new native experiment or benchmark.
The official FIPS 203 algorithm checks are recorded in the independent review;
historical source and execution packets retain their original identities.
