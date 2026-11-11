# Five-column Unit specialization: independent review

Source equivalence and the intended compiled core specialization both pass. The candidate source SHA-256 is `b075351f6095254a2284bf644e61e505dc73d4ee12f36670c01b9adf6e6dc5a7`.

`SOURCE_REVIEW.json` records independent byte/token checks. `FIXED_POINT_REVIEW.md` gives the order-isomorphism and interface argument, including the original node-admissibility guards, positive type-flow feedback, stage induction and unchanged typed fallback.

The implementation owner's completed explicit-all compilation produced a 10,613,270-byte RA, SHA-256 `371eae585a6609f5651ad40f034ed9254a7337da71a5d66e3e3c38433f68127c`. Its actual output was independently read, hashed and inspected. Stage3/4 each contain a five-column `fwdFlowUnit` recursive core. Every direct core, previous and delta invocation has five arguments. Selected `fwdFlow/6`, `fwdFlowTyped/6`, `fwdFlow0/7` and `fwdFlow1/7` have zero mentions. The getNodeTyp(node, _) predicate remains in the base case, preserving node admissibility while discarding the singleton output value.

The generated argument projection also becomes three columns `(arg, ap, stored)`, from the prior four `(arg, t, ap, stored)`. Consumers reconstruct `argT` through `Unit::Unit` locally. Param/Out interfaces still use their original typed five-column schemas; the same singleton is reconstructed at those interfaces. Other original typed event/read/store/return auxiliary relations remain, so this result concerns the full recursive core, not every relation in the component. Stage2/5/6 retain typed six-column cores through `fwdFlowTyped`, their original F0/F1 relations, and no five-column Unit core.

`RA_READBACK.json` records exact schemas, calls and remaining named typed auxiliaries. `RA_EXCERPTS.txt` preserves original source lines. The reviewer did not edit source, compile queries, run tests or CI, change modes, update refs, or touch the existing 9c results and ongoing retained benchmark. The verified result is source equivalence plus the actual compiled representation; no new runtime speed or memory number is assigned.
