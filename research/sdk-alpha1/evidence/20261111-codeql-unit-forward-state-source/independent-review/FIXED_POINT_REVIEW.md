# Independent semantic review of five-column Unit state

## Scope and result

The review compares the existing fused source (143,802 bytes, SHA-256 `99b4abd6d105ae3b1997312bb360bced64303b10bcde306bf0f675ca7602e67b`) with the five-column candidate (144,545 bytes, SHA-256 `b075351f6095254a2284bf644e61e505dc73d4ee12f36670c01b9adf6e6dc5a7`). The source-level transformation preserves the selected stages' least fixed point and the original typed interfaces. The physical compiled representation is reviewed separately after the implementation owner's compilation.

The replacement has three declarations: an inline `additional fwdFlow/6` adapter; `nomagic fwdFlowTyped/6` retaining the original unselected projection; and `nomagic fwdFlowUnit/5` containing the original selected formula with its output `Typ t` bound locally. The source before and after that replacement is byte-identical. The moved formula is token-identical after removing comments/whitespace and restoring the original location of the `t` binder.

## Order-isomorphic state representation

For a selected stage let `x = (node, cc, summaryCtx, ap, stored)`, and let `u` be the sole value of `Typ = Unit`. Define `E(G)(x,t) = G(x) and Unit(t)` and `pi(F)(x) = exists(t | F(x,t))`. On the typed relation domain, `pi(E(G)) = G` and `E(pi(F)) = F`. Both maps preserve inclusion, so this is an order isomorphism, not a lossy projection justified by matching row counts.

Let `R` denote all other mutually recursive relations, including the type-flow feedback relations. Write the original joint immediate-consequence operator as `(B(F,R), A(F,R))`. After expanding the declared inline adapter, the candidate reduced operator is `(pi(B(E(G),R)), A(E(G),R))`; the implementation changes no formula in `A`. The map `H(G,R) = (E(G),R)` commutes with the operators and maps the empty relation vector to the empty vector. Therefore corresponding approximants agree, and their least fixed points agree through `H`. This argument covers the whole positive recursive component, not only post-closure consumers. The corresponding approximants refer to these reduced operators; evaluator iteration numbering and scheduling may differ.

The locally bound `t` in `fwdFlowUnit` and the `t` produced by the public adapter are both `u`. Thus existentially quantifying the core type does not decouple two genuinely distinct types. The selection predicate remains true only for Stage3 and Stage4.

## Node admissibility and guards

`getNodeTyp(node)` remains exactly `PrevStage::revFlow(node) and result = getTyp(node.getType())`. Its `node.getType()` existence/admissibility work remains observable even though the result is Unit. Every call remains at its original branch position. In particular, the source branch retains `t = getNodeTyp(node)`; the transformation neither drops that condition nor applies it as an extra global condition to branches that previously lacked it.

The branch-local access-path approximation, source context, store length bound, read target selection, field-flow condition, source/sink call-context feature, previous-stage reverse reachability, filter, and cast/content checks are unchanged. Stage4's `not clear(node, ap)` is unchanged. `stored` remains `Option<Unit>`: None and Some(Unit) are distinct values and no such projection is attempted. `summaryCtx`, its constructors, and its original type parameters are unchanged.

## Recursive and external interfaces

The selected `fwdFlow1` remains `t0 = t and fwdFlow(...)`; substituting the adapter yields the same two Unit values and the same five-column core state. Its three original consumers remain unchanged. `FwdTypeFlowInput::fwdFlow1Param` and `fwdFlow1Out` stay positive feedback inside the original recursive component; their call-context and previous-stage return-edge guards remain. `Graph::typeStrengthenToPathNode` receives the same original seven-coordinate interface. Full read/store witnesses, path construction, reverse flow, and stage statistics retain their definitions and interfaces.

The new edges from the adapter to `fwdFlowUnit` and from that body through the adapter are positive. `Param::fuseUnitForwardState()` is a static module-selection predicate; its conditional fallback does not depend on the recursive state. No formula under an existing negation or universal condition was changed, and no new negative recursive dependency is introduced.

For Stage3, the previous-stage inputs are unchanged. Its public outputs therefore remain equal, giving Stage4 the same previous-stage inputs. The same argument establishes Stage4 equality. Subsequent stages, including the access-path cost decisions consuming Stage4 counts and reverse reachability, receive equal relations.

For every unselected stage, the adapter calls `fwdFlowTyped/6`, whose body is the exact original `fwdFlow1(..., _, t, ...)` projection. The `nomagic` typed materialization boundary is retained under an internal name change. No five-column Unit assumption is applied to Stage5/6 Type domains.

## Compiled-plan acceptance focus

A successful physical specialization should contain Stage3/4 recursive `fwdFlowUnit/5` entities with no selected `fwdFlow/6`, `fwdFlowTyped/6`, `fwdFlow0/7`, or `fwdFlow1/7` core entity reintroduced by consumers. Interface projections may still bind Unit; that does not by itself reconstruct the complete six-column core. The expected nonselected core remains typed. These are compiled-plan checks, distinct from the semantic proof and from subsequent runtime performance measurements.

No source was edited and no compiler, CodeQL query, CI run or new test framework was started by this reviewer.
