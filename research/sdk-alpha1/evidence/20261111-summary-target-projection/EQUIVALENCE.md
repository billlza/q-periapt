# Stage4 read-target projection: least-fixed-point argument

## Exact source transformation

The candidate changes one file in the authenticated `codeql/dataflow@2.1.15` dependency. A new StageParam predicate defaults to false; only Stage4 enables it. Its forward read branch consumes a new six-column target relation. The original eleven-column `fwdFlowRead` definition is retained verbatim, including both type checks, the ApNil/stored/asSome case, the non-Nil stored/getNodeTyp case, and its existing ct1/ct2 witnesses.

The helper existentially quantifies precisely the five witnesses previously discarded by the Stage4 forward consumer: node1, t1, ap1, stored1, c. Its remaining join/guard suffix is byte-identical to the original definition. `SOURCE_EQUIVALENCE_CHECK.json` records this structural check. No type, call context, summary context, access-path, store or source/sink case is removed.

## Recursive dependency check

In the original exported RA, the forward recursive layer spans lines 174954–177197. The full read relation is declared at 175499; its own previous relation is used at 175578 for the evaluator's delta deduplication. The only other reference inside that forward layer is the target projection consumed by fwdFlow0 at 176875–176880. The later readStepFwd relation is a nonrecursive consumer at 177231–177235 and keeps the source/content/target-edge columns needed for reverse analysis.

The library also contains a full fwdFlowRead reference in PathGraph.localStep. It is preserved unchanged by the patch. That Stage4 PathGraph consumer is not demanded in the original full-summary RA, but it must remain correct for library semantics. The candidate retains the full relation rather than substituting a six-column relation into those later consumers. The candidate RA check separately determines whether the compiler actually moves the wide relation out of the forward recursive layer.

## Algebraic proof

Let X be the tuple of all other relations in the forward recursive component; let R be the eleven-column read relation. Let H(X) be its original full guarded join, and let P project to `(node2,t2,ap2,stored2,cc,summaryCtx)`. The original component has monotone set equations

    X = G(X, P(R))
    R = H(X).

The relevant source consumers and exported RA establish that G uses R only through P. The candidate instead has

    X = G(X, T)
    T = P(H(X)).

Define Phi(X,R)=(X,P(R)). The original and transformed immediate-consequence operators satisfy `Phi(F_original(X,R)) = F_candidate(Phi(X,R))` for every component valuation. Phi maps the bottom valuation to bottom and commutes with unions of increasing chains. Induction over Kleene approximants therefore gives equal least fixed points after projection: the candidate X and T equal the original X and P(R). At the resulting X*, computing the unchanged full R=H(X*) yields exactly the original full read relation for every later consumer, including PathGraph.

The generated seminaive `not previous` operation is duplicate elimination in the evaluator, not an additional source-level negative dependence that changes this set argument. Independent source review checked the two typechecks and both access-path branches explicitly. A shifted iteration schedule is possible and does not invalidate least-fixed-point equality.

## What this establishes

This is a source-level least-fixed-point equivalence argument for the concrete patch, supported by the complete original-RA consumer inventory and a structural body comparison. QL legality and the intended recursive-layer structure are assessed by the correctly bound candidate compiler receipt and RA. No database evaluation, fresh BQRS semantic comparison or performance result is attributed to this prototype.
