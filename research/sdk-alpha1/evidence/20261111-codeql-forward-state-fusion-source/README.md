# Unit forward-state fusion candidate

This candidate specializes the Stage3 and Stage4 forward closure in the pinned
CodeQL 2.27.2 / `codeql/dataflow@2.1.15` implementation. It is layered on the
existing Stage3+Stage4 read-target projection. This isolated candidate worktree
pins the new capsule through the existing projection installer and production
admission. It adds no workflow or plan mode. The integration checkout and remote
references are managed separately from this candidate.

## Mechanism

The original closure materializes an unfiltered `fwdFlow0` relation, a filtered
`fwdFlow1` relation, and the six-column `fwdFlow` projection. Stage3 and Stage4
both instantiate `Typ = Unit`. Their two type columns in `fwdFlow1` therefore
contain the same unique value. The candidate places the complete candidate
generation and filtering body directly in `fwdFlow`, and defines `fwdFlow1`
as its exact embedding with `t0 = t`. Its name, signature, and consumers remain
unchanged. Other stages select the original bodies.

The source deliberately keeps the original `fwdFlow0` body for the other
instantiations. The selected body is a literal copy, verified after whitespace
normalization. Future maintenance must preserve that identity when updating the
vendor patch.

## Fixed-point argument

Fix the previous-stage results and all nonrecursive inputs of one selected
stage. Let `X` denote its other recursive relations. Write the original candidate
body as `B(F, X)(n, c, s, t0, a, aa, v)`. Let `G` be the complete original
conjunction of previous-stage reverse reachability, `filter`, and the cast
compatibility guard. The original equations include:

```
C = B(F, X)
U(n,c,s,t0,t,a,v) = exists aa. C(n,c,s,t0,a,aa,v) and G(n,t0,t,a,aa)
F(n,c,s,t,a,v) = exists t0. U(n,c,s,t0,t,a,v)
```

Here `C`, `U`, and `F` are `fwdFlow0`, `fwdFlow1`, and `fwdFlow`. In the two
selected instantiations, the utility library defines `Unit` by one nullary
constructor, so `t0 = t` holds for every typed pair. Define the embedding
`E(F)(n,c,s,t0,t,a,v) := (t0 = t and F(n,c,s,t,a,v))`. At every fixed point of
the original system, `U = E(F)`. The candidate substitutes that equality in
every consumer and substitutes `B` into its sole `C` consumer:

```
F(n,c,s,t,a,v) = exists aa. B(F,X)(n,c,s,t,a,aa,v) and G(n,t,t,a,aa)
U = E(F)
```

All other equations retain their bodies. Mapping an original fixed point to
its `(F, X)` component and reconstructing `U = E(F)` and `C = B(F, X)` are
inverse, order-preserving maps on fixed points of the existing recursive
stratum. They therefore select the same least fixed point on every consumed
relation. This argument uses the singleton type and the exact bodies; equal
observed row counts alone would not justify the rewrite. Fusing predicates can
change the evaluator's iteration schedule, so raw iteration counts are not an
equivalence check.

## Preserved branches and consumers

The copied candidate body retains source contexts; value-preserving and
non-preserving local steps; jump contexts; stores and their access-path bound;
the selected read-target path; both callable-entry cases; the equal-source/sink
context feature guard; return flow; and the field-flow condition when traversing
a callable. Every branch retains its `getApprox` condition.

The outer guard retains `PrevStage::revFlow`, the selected stage's `filter`,
and all alternatives for a casting node: empty access path, compatible
container, or top-type content. Stage4's clear-content conditions remain in its
unchanged `filter` implementation.

The three consumers of the original seven-column predicate are unchanged:
`FwdTypeFlowInput::fwdFlow1Param`, `FwdTypeFlowInput::fwdFlow1Out`, and
`Graph::typeStrengthenToPathNode`. They receive the reconstructed
seven-column relation, including both original type positions. The complete
read and store relations and their reverse/path consumers are also unchanged.
The first two consumers are positive feedback within the forward/type-flow
closure. The Graph consumer uses the resulting state downstream.

## Structural and semantic admission

The final compile uses the official pinned CLI with explicit
`--dynamic-join-order-mode=all`, a separate runtime, empty private caches,
disabled default compilation caches and global QL configuration, a 4,096 MB
compiler budget, two threads, and a 180-second deadline. It succeeded in
75.94 seconds, with a maximum child RSS of 1,993,984 KiB.
`COMPILE_PRIVATE_ALL.json` records the command and result. `SOURCE_BEFORE.json`
and `SOURCE_AFTER.json` bind all 2,282 runtime files outside the query pack,
all 1,175 embedded dependency files, all 39 query roots, and the other 38 QLX.

`RA_STRUCTURE.json` and `RA_EXCERPTS.txt` record the actual optimized plan:
neither selected stage contains a `fwdFlow0/7` or `fwdFlow1/7` reference, and
each retains one recursive `fwdFlow/6`. The six-column read target remains
recursive; the full eleven-column read and its downstream consumers remain
outside that forward closure. Stage2, Stage5, and Stage6 retain their original
two intermediate state relations.

Two earlier structural compiles are also retained: 79.57 seconds with the
default cache and 79.92 seconds with empty private caches. They used the default
compiler join mode and produced identical RA bytes. The final capsule is built
only from the subsequent explicit-`all` compile. The separate records distinguish
cache provenance and compiler mode; none is a database evaluation.

Before selecting any resulting capsule, compare the full decoded 29-row
SummaryStats relation against the existing complete baseline on the same
database, retain the 39-query inventory and the unchanged other 38 compiled
queries, and verify actual loaded source/runtime/pack identities. A subsequent
large-database comparison must use the same database and evaluator allocation;
record wall time, relation/delta sizes, eviction events, process CPU, and I/O.
The present task performs compilation and source/plan review only.

## Evidence motivating the candidate

The sealed Stage4-only run `43009319450` reached its 18,000-second limit in
both heap profiles. Its two logs contain the same completed Stage3 relations:
209,894,367 rows in the eleven-column read relation and 152,892,493 rows in
each of `fwdFlow0`, `fwdFlow1`, and `fwdFlow`. Stage4 continued its forward
closure through iterations 285 and 290 respectively. The largest reported
Stage4 candidate deltas were 129,230,765 and 190,764,231 rows, compared with
at most 30,594,253 rows in a filtered `fwdFlow1` delta. These are logged delta
events, not final relation cardinalities or a completed-result comparison.

The profiles recorded 46,585 and 54,051 array-eviction pauses. Their actual
heap/off-heap settings matched the requested allocations. The ongoing combined
Stage3+Stage4 run has a distinct source and compiled-plan identity; the old
run's relation and phase observations are not attributed to that run.
