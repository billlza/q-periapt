# Joint bootstrap Extract with one surviving contribution

Source assessment: `b1cff2a045d23aecf75aef12122e5080a8419676`, 9 November
2026. This supplies the two primitive entry comparisons identified in the
[joint-schedule assessment](BOOTSTRAP_JOINT_SCHEDULE_REVIEW_V1.md). The proof
uses the same ideal SHA-256 compression oracle as the existing primitive
appendix and preserves the shared input between initial confirmation and the
64-byte bootstrap Extract.

## Result and exact scope

For a uniform hidden first contribution, the initial-confirmation PRK and the
joint-bootstrap PRK table have a joint comparison to independent private
tables. For a uniform hidden second contribution, the bootstrap PRKs have the
corresponding table comparison while the known first contribution's initial
confirmation is evaluated normally. The result permits adaptive public salts,
adaptive known halves, exact retries and all effective-input aliases.

The proof first produces a fresh bootstrap PRK at each complete descriptor.
It can therefore initialize the completed bootstrap-PRK-to-activation
derivation. The original KEM/disclosure adapter remains the source-specific
input to that composition. This document settles the two compression-level
services; it introduces no new wire, primitive, persisted format or release
condition.

## 1. Source equations and one public oracle

Let `h : {0,1}^512 x {0,1}^256 -> {0,1}^256` be the public random compression
oracle, in message-block/chaining-state order. Public queries may be quantum;
protocol calls and the private interfaces below are classical. All preparation
which depends on `h` occurs inside the counted experiment. The actual source
uses SHA-256 in HMAC; the theorem uses this declared ideal-compression model.

Let `F(a,m) = HMAC_h(a,m)` and, for a 32-byte salt `a`, write

```text
I(a) = (a || 00^32) xor 36^64
O(a) = (a || 00^32) xor 5c^64
alpha(a) = h(I(a), IV)
beta(a)  = h(O(a), IV)
Gamma(a) = (alpha(a), beta(a))

P = 80 || 00^23 || BE64(768)       # 32 bytes
Q = 80 || 00^55 || BE64(1024)      # 64 bytes
B(z) = z || P                     # 64 bytes
```

The exponents count bytes. HMAC has already consumed its 64-byte key pad, so
the encoded lengths are 768 bits for a 32-byte message and 1024 bits for a
64-byte message. The source equations are exactly

```text
F(a,S)      = h(B(h(S || P, alpha(a))), beta(a))
F(a,S || v) = h(B(h(Q, h(S || v, alpha(a)))), beta(a))
F(a,u || S) = h(B(h(Q, h(u || S, alpha(a)))), beta(a)).
```

The SDK salt is `sigma = "QPeriapt-SDK-HKDF-SHA256-v1"`, of length 27.
Set `sigma32 = sigma || 00^5`; this leaves both HMAC pad blocks unchanged.
The first equation with `a = sigma32` is the initial-confirmation Extract.
`bootstrap::schedule` copies the first 32-byte contribution followed by the
second into a 64-byte IKM and uses the Reply core as salt in the second or
third equation. Its three labelled calls recompute one deterministic PRK.

The remaining initial-confirmation Expand/MAC and all later protocol outputs
are recomputed from the current experiment's PRKs. They keep their actual
interfaces and real algorithms with this same public oracle. An independent
whole-SHA3 oracle may remain available for transcript and ContextBound work.

## 2. Available controller and the two services

Sample `S` uniformly on 256 bits independently of `h` and initial auxiliary
state. A controller obtains `S` through the declared private service or an
opaque retained handle. It can choose later salts and known halves from its
available prefix: its coins, public-oracle results, previous outputs and
permitted disclosures. It never receives or otherwise uses the raw `S`.
Any source-level disclosure experiment invoking the theorem must realize this
interface, with its own established stopping and record-simulation argument.

**Hidden-first service.** The controller may use the fixed SDK short Extract
`P0 = F(sigma32,S)` and may request `PB(a,v) = F(a,S || v)` for 32-byte `a,v`.
All contexts using this same contribution share the same `P0`; their distinct
initial-confirmation information strings retain their ordinary downstream
computations.

**Hidden-second service.** The controller may request
`PB(a,u) = F(a,u || S)` for 32-byte `a,u`. All computations involving the
known first contribution, including initial confirmation, are part of the
ordinary continuation. This service has no short Extract under its hidden `S`.

The bytes of a known half may numerically equal a hidden value. The theorem
does not condition on inequality. Its restriction concerns available uses,
and all ordinary calls at such coincident points remain shared-oracle calls.

### Raw classes and final descriptors

For the hidden-first service, a raw class is `x = (v, alpha(a))`; the SDK
short call uses `x0 = (P, alpha(sigma32))`. Thus a long call with `v = P`
and the same inner-pad state shares its first private compression point
with the short call. They use one raw class, even though they are different
public operations. The hidden-second raw class is `x = (u, alpha(a))`.

The complete long-Extract descriptor is

```text
e = (known_half, alpha(a), beta(a)).
```

Equal descriptors reuse a PRK. The theorem indexes the short PRK separately
after the shared raw layer. A salt-string cache, an original-operation cache,
and a cache by only `alpha(a)` implement different relations. The first merges
too little when pad states alias; the latter two can merge too much or split
effective aliases. The full descriptor is the relation used here.

Number raw classes by first allocation; retain those indices across retries.
Fix before execution a bound `C` on the number of raw classes and, for each
allocation slot `i`, bounds `A_i` and `B_i` on its distinct short and long
outer-state queries. In the hidden-first service each `A_i <= 1`, and at most
one distinct short outer query occurs in total. Its raw class can occupy different slots in
different executions, so the sum of fixed per-slot worst-case bounds may
exceed one. For the hidden-second service every `A_i = 0`. `B_i` bounds
distinct `beta` values within raw class `i`. Unallocated slots make no calls.
All per-slot bounds hold uniformly in every comparison experiment.

## 3. The two-contribution entry theorem

Use the existing hidden-input bound

```text
Phi_n(d,q) = min(1,
    4 sqrt(2 d^2 q / 2^n) + 4 sqrt(2 q^2 d / 2^n)).
```

Don, Fehr and Huang, Theorem 2, applies when each fixed private query encodes
a point of probability at most `2^-n` and different effective queries encode
different points for every secret value. Exact repeats are cached. The
published statement covers adaptive classical private queries with quantum
public queries. This is the same input theorem used in
`paper/continuity/primitive-inputs.tex`.

**Theorem (joint short/long Extract tables).** Replace the hidden-first service
by an independent uniform short PRK `V0` and a private random table
`VB(known_half,alpha,beta)` of 32-byte long PRKs. Replace the hidden-second
service by the same long table, retaining its normal known-first continuation.
All aliases and the available controller above are preserved. For every
efficient output-bit test, the distinguishing gap is at most

```text
Delta_entry = min(1,
    Phi_256(C, q_raw)
  + sum_i Phi_256(A_i + 1, q_mid_i)
  + sum_i Phi_256(B_i, q_outer_i)).                    (1)
```

Each `q` counts all ordinary calls to the same public `h` in its complete
derived reduction: preparation, all other real entries, downstream initial
confirmation, the three bootstrap labels, later protocol operations and the
terminal test. There is no per-call reset. The `+1` is a conservative slot
for the long-message padding call; it can be omitted at a slot whose allowed
interface has no long call. Numerical equality between independently sampled
private values is part of the experiments and introduces no conditioning.

### Proof

**First replacement: the complete raw-input table.** For hidden-first `S`,
cache the private calls by `(v,s)` and encode them as `(S || v,s)`. Include
the SDK query `(P,alpha(sigma32))` in that same cache. For hidden-second `S`,
use `(u,s) -> (u || S,s)`. For either orientation and a fixed query, every
768-bit compression input has at most one preimage `S`. Distinct effective
queries have distinct encodings for every `S`. The hidden-input theorem
therefore replaces the raw service by a private random function `Z(x)` at
cost `Phi_256(C,q_raw)`.

Write `z_i = Z(x_i)` at the `i`th allocated class. Its value is uniform
independent of the public oracle and of the earlier private entries. It is
used internally through the two exact descendant interfaces

```text
short_i(b) = h(B(z_i), b)
pad_i     = h(Q, z_i).
```

The long PRK is still `h(B(pad_i),b)`. The short interface is present only
at the source's fixed SDK class and outer state. It remains useful to write
its distinct-call bound as `A_i`, since the argument preserves the entire
tagged interface.

**Second replacement: the shared raw class's descendants.** Replace classes
in first-allocation order. At slot `i`, presample a hidden uniform challenge
`z`, leave it unused throughout the executed prefix, and assign its opaque
handle to `Z(x_i)` when that class is allocated. The parent is already a
private raw-class table; it exposes no other observation of the value. Other
classes use their preceding or subsequent hybrid. A never-allocated slot
gives identical games.

Use the tagged encodings

```text
(short,b) -> (B(z), b)
pad       -> (Q, z).
```

Each is injective in `z`, and distinct short queries preserve their different
chaining states. The short and pad ranges are disjoint for every `z`:
`B(z)` ends in `BE64(768)` whereas `Q` ends in `BE64(1024)`. This remains
true when `b = z`. Consequently the hidden-input theorem with at most
`A_i + 1` private calls supplies an independent short table `U_i(b)` and
an independent uniform pad value `w_i`, independent also of `h`. Its cost
is `Phi_256(A_i+1,q_mid_i)`.

The exact raw collision `v=P` has been retained throughout the first step.
The second step now separates its two descendants by their actual padding
encodings. The long outer call is evaluated with the resulting `w_i`; it
is not frozen to a value from the preceding game.

**Third replacement: the long outer table.** After all second replacements,
each `w_i` is independent uniform and has only the uses
`b -> h(B(w_i),b)`. Replace these interfaces in the same fixed allocation
order. The parent pad entry becomes one opaque challenge handle before
any child outer call. The encoding `(B(w_i),b)` is injective in `w_i`, and
different `b` values give distinct inputs for every `w_i`. The hidden-input
theorem supplies an independent private table `V_i(b)` at cost
`Phi_256(B_i,q_outer_i)`.

In every child reduction, the locally known values of other entries may
equal its hidden challenge numerically. Real branches evaluate those other
entries under the same public oracle, so those coincidences are preserved
and their ordinary queries are counted. The replacement theorem bounds the
full resulting distribution. No test for hidden-key equality is inserted.

There is one independent final value for each `(x_i,b)`, exactly the
descriptor `(known_half,alpha(a),beta(a))`. The source's sole short entry
is independent of all those values. Replacing the internal table names by
`V0,VB` is an exact distributional relabelling. The triangle inequality
gives (1). **QED.**

### One conservative query budget

Let `D` bound distinct salt byte strings used by this entry service, including
the SDK salt when present; cache their two public pad states. Let `A` and `B`
be uniform global bounds on the total distinct short and long outer calls in
one execution. Here `A=1` for hidden first and `A=0` for hidden second; a
conservative choice is `B=sum B_i`. The global `A` is distinct from the sum
of per-slot maxima in (1). Let `W` bound all ordinary compression work outside
the entry equations, including their entire continuation and test, uniformly
over the derived experiments. Then every `q` in (1) can use

```text
q_bar = W + 2D + A + C + B.                           (2)
```

The derived simulator memoizes repeated classical entry subcalls by available
interface descriptors: `(salt,pad-kind)`, `(raw-class,short,beta)`,
`(raw-class,pad)` and `(raw-class,long,beta)`. Each fixed descriptor determines
the same compression input, so determinism of `h` makes this an exact
distributional rewrite of the source's repeated computations. The simulator
does not compare the hidden bytes of different handles. If different class
descriptors happen to encode the same point, their ordinary calls retain
the common public oracle's equal answer, and the budget counts both calls.
Public adversarial queries also use that unchanged oracle.

The additional terms then count public pad states, short outer calls, at most
one long padding call per raw class, and long outer calls. The raw compression
points are private calls at the first comparison and a table at later
comparisons. Repeating an available descriptor retrieves its cached answer
without another call in that simulator interface. This is a conservative
finite budget, with no claim of tightness.

## 4. Composition at a fresh bootstrap descriptor

For this composition, instantiate the entry controller with the three-label
tail wrapper: each long PRK is installed in an opaque retained handle before
its first private use, and its only raw uses are those three labelled Expand
calls. The wrapper exposes their declared descendants and supplies no raw PRK
disclosure channel. Unprotected activation roots retain the disclosure and
real-activation behavior specified in the tail assessment.

In the table game, a first long descriptor receives a uniform PRK independent
of the executed prefix, the public oracle and `V0`. Presample that value and
defer its assignment until the descriptor's first use. This is the uniform
bootstrap PRK required by section 3 of the joint-schedule assessment under
that wrapper. The entry comparison applies to its whole continued execution.

For finitely many long descriptors, compose that assessment's tail in their
first-allocation order, retaining its protected/unprotected root marks,
complete root descriptors and real activation of disclosed unprotected roots.
The complete triple of bootstrap labels is a service under each PRK; its
internal raw representation is removed by the row-table replacement before
embedding any selected seed or child root. The short PRK and all initial
confirmation work remain an independent shared-oracle continuation.

Thus a bit comparison from either entry service to its protected activation
tables has cost at most `Delta_entry + sum_e Delta_tail,e`, capped at one,
with fixed finite slot budgets and the same complete-continuation convention.
The first-allocation construction introduces no guess of an eventual selected
descriptor. This is composition within the stated available interface.

The terminal theorem indexes full `(ctx,x,y)` transcript classes. The new
entry theorem deliberately retains effective descriptors. Their reconciliation
still uses the existing full-wire collision accounting and an explicit
pad-state-alias term wherever distinct protected transcript classes share a
downstream descriptor. Salt strings or original operation IDs do not silently
replace the effective descriptors.

## 5. Source adapter and disclosure integration

The next source-specific step places one of these two services after the
original component challenge and complete-tuple ContextBound comparison.
It must use the actual first private generation/encapsulation invocation,
retain every selected challenge-ciphertext alias across contexts, and route
nonchallenge decapsulations through the existing component interface. The U3
phase map supplies the corresponding retained-record recipe classifier.

For hidden first contribution, the adapter supplies the SDK short interface
and every actual long use of that contribution. For hidden second contribution,
it supplies all long uses and computes the known-first path locally. It also
establishes which raw contribution disclosures are excluded by the original
selected-component/recipe stop, and accounts explicitly for any other stop
introduced by its simulation. The primitive theorem's raw-use condition is
checked against that source adapter rather than added to the terminal event
after observing an execution.

This leaves a precise integration task: original-contribution/source exposure
accounting and terminal full-class reconciliation. The two entry services and
the conditional downstream schedule are completed analytical inputs to it.

## 6. Reproducible controls and proof inputs

The [evidence packet][evidence] records the exact inspected source/proof
bytes. Its independent public-input calculations check the 32/64-byte
compression equations against Python's HMAC, both hidden-half orientations,
the forced short/long raw alias, all-secret encoding separation on declared
finite domains, effective pad-state aliases, fixed-slot ordering and query
accounting. Faulty split-cache and compressed-descriptor variants are included
as distinguishing controls. These finite controls audit encodings and table
semantics; the computational bound is the analytical reduction above.

Primary proof input: J. Don, S. Fehr and Y.-H. Huang, *Adaptive Versus Static
Multi-oracle Algorithms, and Quantum Security of a Split-Key PRF*, TCC 2022,
Theorem 2, [author manuscript](https://arxiv.org/pdf/2206.08132), pp. 9–10.
The theorem's point-entropy and all-secret freshness hypotheses were checked
against that primary text. The repository bibliography retains the same
`dfh2022` entry. The existing tail also retains its cited HMAC row, finite
root-entry and exact Expand-table inputs.

[evidence]: ../../research/sdk-alpha1/evidence/20261109-bootstrap-joint-entry/README.md
