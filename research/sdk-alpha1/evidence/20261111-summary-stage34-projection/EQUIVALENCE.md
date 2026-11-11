# Stage3 and Stage4 target projection

This candidate enables the already compiled target-projection mechanism for
`Stage3Param` as well as `Stage4Param` in the fixed full Rust `SummaryStats` query.
The sole changed vendor file is the query pack's actually resolved embedded
`codeql/dataflow@2.1.15` `DataFlowImpl.qll`. Its effective SHA-256 is
`6a444d1baf03a1db4cbf1f98e39320ba3a7d68d2b9b6db7feffb2bf9cd315bde`.

## Source identity

Relative to the prior Stage4 candidate, the executable change adds
`predicate projectRecursiveReadTargets() { any() }` to `Stage3Param`. The other
change updates the helper's explanatory comment to name both stages. The
generic default remains false, so the other stage parameters retain their
original read branch.

For a fixed stage parameter, let `R` denote the original eleven-column read
relation, and let `P(R)` project it onto
`(node2, t2, ap2, stored2, cc, summaryCtx)`. The helper existentially quantifies
the five discarded source/content columns. Its join body and every guard are
byte-identical to the original read body, including both type checks, the
`ApNil` branch, stored-type handling and target-node type. Thus the helper
denotes exactly `P(R)`.

`SOURCE_EQUIVALENCE.json` records direct equality of the complete original
`fwdFlowRead`, `readStepFwd` and relevant `PathGraph.localStep` definitions.
These consumers preserve their full source/content witnesses.

## Stage3 fixed-point argument

The independently inspected original Stage3 RA has one forward-recursive
consumer of `R` outside the evaluator's own previous-relation deduplication:
`fwdFlow0`, which consumes exactly the six target columns. The complete
`readStepFwd` relation is evaluated after that recursive layer.

Let `X` collect the remaining relations in the forward recursive layer. Its
original consequence operator has the form

    F(X, R) = (G(X, P(R)), H(X)).

The projected implementation uses

    F'(X, T) = (G(X, T), P(H(X))).

For `Phi(X, R) = (X, P(R))`, direct substitution gives
`Phi(F(X, R)) = F'(Phi(X, R))`. Existential projection preserves the empty
relation and increasing unions, so the Kleene iterations and their least fixed
points agree under `Phi`. In particular, the final `X` is unchanged. Evaluating
the original full read body afterwards yields the same `R = H(X)` that the
original fixed point contained. Later consumers therefore receive the same
complete relation.

This argument concerns relational set semantics. The `#prev` references emitted
by the evaluator implement seminaive duplicate elimination; they do not add a
new source-level predicate dependency or a further consumer of the discarded
columns.

Stage2 is unchanged. The Stage3 argument preserves its exported relations and
therefore the previous-stage inputs used by Stage4. The same argument then
applies to the unchanged Stage4 target helper. This establishes the composition
for the two selected stages.

## Compiled structure

The correctly bound compile returned zero with compiler input key
`6a7530eb694360655ab8331a895c9fcd`. `IR_COMPARISON.json` enumerates every complete
read-reference occurrence and the corresponding recursive-layer boundaries:

| Stage | Forward recursive layer | Recursive Target6 definition | Later full Read11 definition | Later readStepFwd |
| --- | --- | ---: | ---: | ---: |
| 3 | 169800–172287 | 171727 | 172321 | 172356 |
| 4 | 174991–177236 | 175263 | 177270 | 177305 |

Each full Read11 definition occurs in `EVALUATE NONRECURSIVE JOIN AST RELATION`
after its forward layer. Neither forward layer references full Read11. Both
later `readStepFwd` definitions still consume the complete relation. The new
RA SHA-256 is
`b5b6d32f5c56686b685fa30b93c1b00187fd584626c7b603b7decf62c08185b5`.

The performance motivation is the observed Stage3 Read11 work and memory
evictions in the retained-project probe. The source and compiled structure
establish this candidate's mechanism; execution records determine its measured
behavior and result equality.
