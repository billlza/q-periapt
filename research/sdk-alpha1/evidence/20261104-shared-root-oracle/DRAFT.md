# Candidate shared-root oracle argument - internal proof work

This is an unverified proof sketch for one finite obligation in
`docs/continuity/COMPUTATIONAL_RECOVERY_V1.md`. It does not change the security
assumptions of the product, instantiate HMAC-SHA256, establish the combiner or
authentication premises, or close the multi-epoch computational claim. Its
purpose is to test whether a single ideal keyed random oracle could supply the
joint interface that separate forward and swapped PRFs do not directly supply.

## Proposed game boundary

For now take a single fresh `R <- {0,1}^n`, sampled independently of the global
oracle and all other initial classical and quantum state. Let
`F : {0,1}^n x {0,1}^{<=L} -> {0,1}^n`, for a fixed finite `L >= n`, be one
quantum-accessible random function with an unambiguous pair encoding. Honest protocol computations are
classical. Neither `R` nor an independently supplied predicate of `R` is leaked.
This is a deliberately conditional game: whether the existing extraction
hybrid supplies this oracle-relative independence is a separate obligation.

The root-dependent interface permits the exact shared calls
`F(0,R)`, `F(session_id,R)` and `F(R,s_i)`. Repeated pairs have the same output.
`session_id=0` is permitted and aliases the first two calls. Continuations may
derive labeled keys, tags and later roots from the returned values using the
same public `F`, and may reveal allowed later results. Selectors `session_id`
and `s_i` may be adaptive functions of the public transcript; they must have no
additional dependence on the hidden `R`. This last restriction needs a code and
game correspondence argument before applying the sketch to Continuity.

## Coupling to examine

Sample independent `F` and `G` and define the random hidden set

```
B_R = {(k,m): k = R or m = R},
```

where the second equality requires an exactly `n`-bit message. Let `F_R` agree
with `G` on `B_R` and with `F` elsewhere. For fixed `R`, `F_R` is a random
function. In the real game all computations use `F_R`; in the candidate ideal
game the explicit root-dependent interface uses `G` and every other oracle
access uses `F`. All three root-dependent call families lie in `B_R`.

The root interface must use one table indexed by the full pair, not independent
tables for each call family. In particular, `F(0,R)` is shared across three
confirmation expansions and can also be shared with traffic extraction. The
intersection `(R,R)` and any cross-family aliases must also be consistent.

If the state immediately before each public-oracle query in the ideal game were
independent of `R`, its expected query probability on `B_R` would be at most
`2 / 2^n`: one term for the key and one for an exactly `n`-bit message. The norm
change from substituting one oracle query is at most twice the square root of
that probability. An elementary telescoping hybrid would then give a norm
bound at most `2 q sqrt(2 / 2^n)` over `q` such calls, including ordinary honest
queries to the public oracle. This is an implication of the stated independence
premise, not a claimed bound for the present protocol.

## The point requiring independent checking

The private `G` interface itself is indexed by `R`. It is therefore insufficient
to assert independence of the ideal adversary state just because each response
is marginally uniform. The complete transcript includes equality patterns,
adaptive selectors, downstream public-oracle calls and any permitted later
leakage. One must either prove that these give an `R`-independent distribution,
or isolate their exceptional alias events and bound them without conditioning
away a permitted attack.

Examples requiring explicit treatment include a public selector equal to `R`,
a returned value equal to `R` that becomes a later key, and a root-interface
query crossing an ordinary continuation query. No implementation check excludes
these cases. A union bound is not justified until the relevant ideal transcript
and sampling order establish the needed conditional distribution. There is no
claim here of a concrete bound for these events, nor of a completed reduction.

A useful review outcome is either (a) a complete proof for this restricted
single-root game with every independence/alias hypothesis stated, or (b) a
specific counterexample or missing simulation step. Any extension to adaptive
multi-epoch corruption, the original reservation leakage model, ContextBound
ML-KEM combination, message encryption/ACKs, or actual SHA-256 is outside this
single review question.

## More explicit candidate coupling for review

The following refinement may remove the independence gap for the restricted
game. It is still pending independent checking; it is not asserted as a proved
protocol theorem.

Presample independent tables `A : {0,1}^n -> {0,1}^n`,
`B : {0,1}* -> {0,1}^n`, a public random oracle `F`, and the independent root
`R`. In game `I`, the private column interface on public selector `a` returns
`A(a)` and the private row interface on selector `b` returns `B(b)`. All ordinary
queries use `F`. The row/column interfaces are classical and the continuation has
no other access to `R`. Their distinct internal type tags need not be protocol
bytes; they specify the two call roles. The public transcript and public-query
state in `I` are then independent of `R`, even with adaptive selectors and
arbitrary postprocessing of earlier outputs through `F`.

Define a public oracle `P_R` by this precedence order:

```
P_R(k,m) = A(k)  if m is exactly the n-bit value R;
           B(m)  if k = R and m != R;
           F(k,m) otherwise.
```

For every fixed `R`, these are independent uniform outputs at distinct pairs,
so `P_R` is a random oracle. In particular, `(R,R)` uses `A(R)` rather than
`B(R)`. Game `J` uses `P_R` for ordinary queries but keeps the private interfaces
`A(a)` and `B(b)` unchanged. Games `I` and `J` differ only at ordinary oracle
queries on the hidden row/column. If the usual telescoping norm argument applies
to the complete interactive game including its classical private-interface
calls, the preceding bound gives trace-distance at most

```
delta = min(1, 2 q sqrt(2 / 2^n)).
```

The ideal query states used in that argument are `R`-independent because the
private interfaces in `I` use only `A`, `B` and selectors from that ideal
execution. This argument would include a final classical copy of `R` in the
trace-distance comparison; it is not made available during the interaction.

Now game `K` uses `P_R` for ordinary queries and returns `P_R(a,R)` and
`P_R(R,b)` for the two private interfaces. This is the real random-oracle
interface. Column answers in `J` and `K` always coincide. Row answers can differ
only when `b=R`. With at most `t` row calls, game `I` satisfies
`Pr[Bad] <= t/2^n` because its complete selector transcript is independent of
`R`. The strengthened trace-distance comparison would give
`Pr_J[Bad] <= t/2^n + delta`. Coupling `J` and `K` until their first such row
call would then imply the candidate bound

```
distance(I,K) <= min(1, 2 delta + t/2^n).
```

No separate exclusion of a continuation-derived key equal to `R` is used here:
ordinary queries with that key are counted among the `q` oracle queries and
their mass on the hidden row. Repeated selectors preserve table identity,
including `session_id=0`. The intersection is handled by `Bad`, without adding
an implementation restriction. All ordinary honest oracle calls must be
included in `q`; counting only adversarial calls would not justify this hybrid.

Review must check: (1) the telescoping comparison with classical interactive
interfaces and a root register retained to the end; (2) the exact trace/norm
constants; (3) whether the classical-until-Bad coupling survives the quantum
public-oracle interaction; and (4) any omitted direct or auxiliary dependence
on `R`. A successful proof would establish only this single-root ideal-primitive
lemma. The actual HMAC instantiation and prefix-independence premise remain
unproved, as do the other protocol obligations listed above.

## Current literature access boundary

The primary abstract and indexed definition excerpt for Hosoyamada/Iwata,
ePrint 2021/774, describe an ordinary hidden-key qPRF game. Full-PDF retrieval
returned HTTP 403 in this pass. No joint key/message-role theorem has been
verified from that paper. The primary abstract for Hosoyamada, ePrint 2026/128
(June 2026 revision), reports failure of post-quantum public/sequential
indifferentiability for strengthened Merkle-Damgard. It is a limitation on a
generic whole-hash replacement route, not an observed HMAC or Continuity attack.
The full 2026 PDF was also unavailable. These observations do not by themselves
prove or refute the conditional ideal-`F` game above.

Sources: https://eprint.iacr.org/2021/774 and
https://eprint.iacr.org/2026/128. No new release blocker or assumption change is
introduced by this draft; the existing shared-schedule obligation remains open.
