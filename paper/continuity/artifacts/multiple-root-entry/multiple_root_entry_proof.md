# Finite root entries from one recovered contribution

This note proves the multiple-root entry used by the companion manuscript fragment `multiple-root-entry.tex`. It builds on the retained shared HMAC row/column and row-instance lemmas in `joint-primitive-bounds.tex`, and connects the resulting fresh root to the existing joint first-message continuation. All results below concern one specified finite controller.

## 1. Result

Let one hidden uniform 32-byte contribution `S` feed root derivations

\[
P_r=F(r,S),\qquad R_{r,I}=F(P_r,I\Vert\mathtt{01}),
\]

where `F` is HMAC-SHA256 over the common public quantum compression oracle `h`, `r` is an available 32-byte salt, and `I` is the complete native 97-byte root-information string. The parent contribution has these Extract uses, and each PRK has its class's root-Expand uses.

The exact root-use descriptor is

\[
e(r,I)=(\Gamma(r),I),\qquad
\Gamma(r)=(h(I_{\rm pad}(r),\mathrm{IV}),h(O_{\rm pad}(r),\mathrm{IV})).
\]

Root requests with equal descriptors share an entry across endpoints, original sources and resumptions. The private ideal interface is an independent uniform root table `W(Gamma(r),I)`.

With the finite budgets defined below, the whole-interaction output-bit gap is at most

\[
\boxed{\Delta_{\rm mr}=\min\left\{1,
\varepsilon_{\rm Hjoint}(C,0,q_S,32)
+\sum_{i=1}^{C}\varepsilon_{\rm Hrow}(N_i,q_i,98)\right\}.}
\]

An online target may mark a new `(Gamma(r),I)` entry **inside an already used class**. Every class is covered by the row comparisons, and the fresh table assignment then embeds the selected root. Thus target selection adds **no class-guessing factor**.

The target's aliases all retrieve one retained schedule handle. Its uses jointly obey the existing confirmation, traffic, ACK, successor and first-message interface. Under that controller,

\[
\boxed{|\mathbb E Z|\le\min\{1,
2\Delta_{\rm mr}+2\Delta_{\rm sched}+2\varepsilon_{\rm AEAD}\}.}
\]

A preceding complete-tuple ContextBound comparison adds `2 Phi_256(d,Q_H)` to this candidate's signed-score bound. The established original-game attribution/projection residuals, record correspondence and operational component terms retain their definitions.

## 2. Oracle model and exact interface

The experiment initially samples `S`, `h` and independent auxiliary state. Oracle-dependent preparation is executed within the experiment and counted. An independent whole SHA3 oracle `H` may remain available throughout; this is the same additional interface retained by the preceding ContextBound argument.

For a 32-byte key, let

\[
I_{\rm pad}(r)=(r\Vert0^{32})\oplus\mathtt{36}^{64},\qquad
O_{\rm pad}(r)=(r\Vert0^{32})\oplus\mathtt{5c}^{64},
\]

and, for a 32-byte message, let

\[
B(x)=x\Vert\mathtt{80}\Vert0^{23}\Vert\mathrm{BE64}(768).
\]

Writing `Gamma(r)=(alpha(r),beta(r))`, the retained compression identity is

\[
F(r,S)=h(B(h(B(S),\alpha(r))),\beta(r)).
\]

Consequently `Gamma(r)=Gamma(r')` implies `F(r,S)=F(r',S)` for every `S`. If the complete information strings also agree, their root values agree exactly. This justifies the descriptor quotient, including distinct salt strings that share the two pad states.

Descriptor equivalence means **exact equality of `(Gamma(r),I)`**. Roots and PRKs at distinct descriptors/classes may also coincide numerically; the proof retains those events through the common oracle. Descriptor identity gives mandatory sharing, whereas numerical coincidences are part of the sampled distribution.

### Lifetime tables

The proof service maintains three finite tables over the whole execution:

| Table | Index | Retained value |
|---|---|---|
| Salt cache | Actual 32-byte salt `r` | Its two public pad states `Gamma(r)` |
| Class map | Exact `Gamma` pair | First-allocation index `i` and private Extract value `P_i` |
| Root table | `(i, complete I)` | Root value or the marked retained schedule handle |

The first request for a new `Gamma` class allocates its next lifetime index. It calls the hidden column once for one representative salt. Later equal classes use that Extract value. The first request for a new complete `I` in that class performs the one-block root Expand; later requests retrieve the retained result.

This cached rendering has exactly the real functional behavior. The shared random oracle is stateless, and repeated deterministic primitive evaluations give the same bytes. Native checks, writes, public responses and their timing in the abstract event ledger remain in the controller. The reduction's private cache survives process loss and physical copying; its lifetime index is not reset by a resident-state eviction or an original-operation identifier change.

### Available controller state

Salt strings, complete information strings, class scheduling, the fresh-target mark and the terminal qualification test are computed from:

- the executed initial state and original provenance/event ledger;
- independent local coins and ordinary public-oracle responses;
- all unmarked root values and computations from them;
- the outputs declared by the one retained marked-root schedule.

The parent `S` is accessed through the root-entry Extract service. Its internal PRKs are accessed through their class's root-Expand service. The marked root is accessed through its retained schedule handle. These interface rules supply the reductions with every byte string they must actually compute.

For example, a previously disclosed root may become a later salt, and a new info may depend on an earlier ACK or confirmation. The rule is about the origin of available data. If a known salt happens to have the same numeric value as a protected root or PRK, it remains an available salt, and its ordinary shared-oracle computation is counted.

### Marking and aliases

The service invokes the selection rule only when it is about to allocate a previously unused root descriptor. The rule may mark at most one such entry, before its value is evaluated. The choice uses the available prefix, including the resolved public `Gamma` and complete info.

The marked entry installs one schedule handle, containing the chosen root. Every subsequent equal descriptor retrieves this same handle. All aliases contribute to that schedule's one session salt, its `{0,s}` root columns, its confirmation and successor uses, its globally cached complete traffic-info table, and its existing budgets. The later fresh traffic-info/direction mark is the one in the retained first-message theorem.

Every unmarked root may be disclosed, retained and used for further available computation. If no marked application challenge occurs, the designated signed score is zero. This is the declared experiment's score code.

## 3. Finite budgets

Choose the following upper bounds before the experiment:

- `D`: number of distinct available salt byte strings supplied to the entry service;
- `C <= D`: number of allocated `Gamma` classes;
- `N_i`: number of distinct complete infos in the `i`th class, for each `1 <= i <= C`;
- `B`: all ordinary compression work outside the entry service, including preparation, other contributions/roots, records, the full selected schedule, adaptive feedback and terminal test.

These are uniform bounds for the complete derived algorithms in all comparison games. They can follow from fixed resource limits of the declared controller. If a controller uses an explicit budget-exhaustion action, that same action is retained in every game. The proof does not use counts measured afterwards from one real transcript.

A newly presented salt can have an already existing `Gamma` pair. Its two public pad computations still count. Caching `Gamma` by the actual salt bytes bounds this external class-resolution work by `2D`.

Let `N=sum_i N_i`. A root Expand evaluates HMAC on the 98-byte message `I || 01`. After the 64-byte key pad, its inner message and padding occupy two compression blocks; the outer digest and padding occupy one. Including the two key-pad calls gives five compression evaluations per fresh root entry. Equivalently, the retained convention has `ell(98)=3`.

The following conservative ordinary-query budgets therefore suffice:

\[
q_S=B+2D+5N,\qquad
q_i=B+2D+5\sum_{k=i+1}^{C}N_k.
\]

In the column comparison all root rows are real. In the `i`th row comparison, classes with index smaller than `i` are already private tables; classes with index larger than `i` are still evaluated with known sampled keys and the same `h`.

The column primitive itself includes its own public pad-state work in the retained C.1 bound. The displayed `2D` pays separately for external class resolution. This intentionally permits a conservative duplicate computation and covers all new-salt aliases. A tighter implementation may reuse those public states; the theorem uses the stated upper bounds.

When the downstream key-schedule and AEAD comparisons are invoked, their own complete budgets include this entire entry controller, including its `Gamma` computations and all known-root work. Each hybrid charges its full derived distinguisher.

The case `D=C=N_1=1` supplies the single-entry interface. The existing direct `Delta_init` keeps its tighter query accounting; the displayed `Delta_mr` offers one uniform conservative convention for several classes and infos.

## 4. Column comparison

Let `G_real` be the real finite entry service with its complete controller. Replace each class's hidden column output by

\[
P_i=V(\Gamma(r)),
\]

where `V` is a private random function independent of `h`. Call the result `G_col`.

For a new class, the column reduction receives the numeric output of its challenge interface and stores it as the class's PRK. It can compute all root Expands and the full continuation locally. Equal classes retrieve the same response, and the real branch renders the exact formula from Section 2.

There are at most `C` column calls, zero row calls to the hidden `S`, and at most `q_S` ordinary compression calls by the derived reduction. The retained **Independent-table shared-root bound**, `lem:appendix-joint-hmac`, gives

\[
\operatorname{gap}(G_{\rm real},G_{\rm col})
\le\varepsilon_{\rm Hjoint}(C,0,q_S,32).
\]

The operational bound already permits adaptive salts chosen from earlier replies and arbitrary counted ordinary quantum access to the same oracle. Its private ideal is indexed by the entire `Gamma` pair. All source-ledger and output processing remains in the controller.

The stated primitive bound is used directly. Its conservative unused-row allowances remain valid when its row-call budget is zero.

## 5. Adaptive class-by-class row comparison

Define `G_i` for `0 <= i <= C` as follows. The column interface is ideal throughout. Classes allocated in positions `1,...,i` use independent private row functions; later classes use real HMAC under their independent private PRKs. Thus `G_0=G_col`.

The class index is assigned by each game's actual first-allocation order. Adaptive changes of earlier root outputs may change later salts, classes and ordering; each game executes the same scheduling code on its own trace.

For the hop `G_(i-1) -> G_i`, construct a reduction to the retained adaptive row experiment:

1. Start with its uniform hidden challenge key `K_i`, independent of `h` and initial auxiliary state. Withhold it during the complete executed prefix.
2. For each allocated class before position `i`, simulate the already ideal row by an independent local table.
3. At the `i`th new class, assign its PRK slot the opaque key `K_i`. This newly allocated ideal-column value is fresh uniform, exactly as the private `V` table requires.
4. Route root Expand calls in that class to the row interface on the exact message `I || 01`, caching complete-info repeats.
5. For each later new class, sample an independent local PRK and evaluate its HMAC rows using the same public `h`.
6. Run the full continuation and terminal test from the resulting root values. The reduction receives each row reply and can therefore execute that continuation. The public interface still exposes only the declared roots/handle operations.

The hidden row key has its first use at step 3. Before that event its unused presampling is independent of the prefix, even though that prefix may contain earlier table responses, known-key HMAC evaluations and quantum oracle computation. The selected PRK slot is used only through the row, so the reduction can simulate class resolution and target selection from available state.

The real row branch is `G_(i-1)` and the ideal row branch is `G_i`. If position `i` is never allocated, the two branches execute identical visible code. There are at most `N_i` distinct 98-byte messages and at most `q_i` ordinary compression queries. The retained **Row and single-column instances** lemma, `lem:appendix-hmac-instances`, gives

\[
\operatorname{gap}(G_{i-1},G_i)
\le\varepsilon_{\rm Hrow}(N_i,q_i,98).
\]

### Numerical PRK coincidences

Independently sampled PRKs for different `Gamma` classes can have equal byte values. The reduction keeps the class slots defined above. If a locally sampled later-class key happens to equal `K_i`, its actual HMAC evaluation uses the same `h`; the real row branch automatically has the same functional correlations. The ordinary queries from that known key are included in `q_i`. In the ideal row branch the challenge row is the prescribed independent table. The row distinguishing bound covers the whole pair of distributions.

Thus there is no extra equality test on an unknown key and no conditioning away a collision. A class already replaced has its own independent table, as required by the intervening hybrid. Summing the fixed sequence of row comparisons yields the stated joint bound.

## 6. Root-table identity and adaptive target embedding

In `G_C`, every root-row interface is a private random function. For each class,

\[
I\longmapsto I\Vert\mathtt{01}
\]

is injective. Therefore the complete service is exactly a table of independent 32-byte entries indexed by `(Gamma(r),I)`, with all repeats and aliases retained.

A fresh info in a class that has already produced many other roots is a fresh table entry. The same statement holds when its info depends on earlier replies, public-oracle computation or available protocol outputs. Its value is sampled only after the complete descriptor and mark decision have been determined.

To embed the selected root in the existing uniform-root experiment, presample that experiment's hidden uniform root `R*` at initialization and withhold it. Simulate every unmarked table allocation using independent local randomness. When the available controller marks a new descriptor, assign `R*` to that entry and hand its retained schedule handle to the controller. All aliases retrieve that handle. Continue sampling every other fresh entry independently.

This is exactly the private table distribution: before its allocation, the marked value has never influenced the available prefix. The construction implements the entire interactive continuation, including previous root allocations, later entry requests, confirmations and traffic. It makes no assertion about a root's distribution after conditioning on a future transcript.

All class rows have already been compared. Consequently the target can be chosen adaptively in any class without guessing a class position or multiplying by an additional number of classes.

## 7. First-message corollary and ContextBound entry

Let

\[
Z=\mathbf1_{\mathcal A}(2\mathbf1[g=b]-1)
\]

be the qualified signed score for the marked first-message experiment. The predicate `A` is computed from the available classical view and provenance ledger, and the score is zero when its marked challenge is absent. Every comparison evaluates the same code on its own execution.

For each fixed application challenge bit, use the terminal randomized test with success probability `(Z+1)/2`. The root-entry bit bound changes the expected score by at most `2 Delta_mr`; average the two fixed-bit comparisons afterwards. In the table experiment, Section 6 supplies exactly the initial root and complete controller required by the retained joint-schedule theorem and first-message corollary. Their comparison and complete AEAD game contribute `2 Delta_sched + 2 epsilon_AEAD`.

In the AEAD reduction, output the adversary's guess on qualified runs and an independent fair guess otherwise. This realizes half the absolute expected qualified score, including any ciphertext-dependent protocol behavior admitted by the available predicate. Thus the displayed message bound uses the actual AEAD endpoint.

If the parent contribution is the freshly allocated selected output of the complete-tuple ContextBound comparison, the combined candidate continuation bound is

\[
|b_j|\le\min\{1,
2\Phi_{256}(d_j,Q_{H,j})+2\Delta_{{\rm mr},j}
+2\Delta_{{\rm sched},j}+2\varepsilon_{{\rm AEAD},j}\}.
\]

This substitution applies when that protected table output's complete root-use family is represented by the available controller above. The existing native one-root instance remains a direct source instance of its own single-entry bound. A source adapter for several root uses supplies this module's descriptors, data availability and shared marked-handle correspondence. This is a concrete interface obligation for that selected finite family.

The original candidate accounting then keeps `rho_j`, `a_j^+ + a_j^- + 2 delta_j`, and the original-game attribution/projection residuals in their established places. Distinct candidates retain their own compared continuations.

## 8. Constructive finite example

Consider one available old root `r0` and four distinct complete known info strings. The controller can perform this sequence:

1. Allocate and disclose `R0 = Root(r0,I0)`.
2. Allocate and disclose `R1 = Root(r0,I1)`.
3. Mark a fresh `(Gamma(r0),I*)` and install its retained schedule handle.
4. Use the available value `R0` as a new salt for `Root(R0,I2)`; disclose that unmarked result.
5. Resume `Root(r0,I*)` through any number of descriptor aliases, retrieving the marked handle and its cached native schedule state.

Freshness is tested on complete descriptors when each info is supplied. Repeated infos retrieve existing entries. The example's mark is made only on the allocation in step 3; the public choice of a new complete info can use prior responses.

For executions with these four root allocations, `D=2`, `C=2`, `N_1=4`, `N_2=1` are uniform conservative bounds. They cover both the case where `Gamma(R0)` is new and the case where it equals `Gamma(r0)`. Hence `N=5` and

\[
q_S\le B+29,\qquad q_1\le B+9,\qquad q_2\le B+4.
\]

The target belongs to the already used first class. Its aliases use one marked schedule. Later root generation from a disclosed earlier root is fully represented by available salt bytes. This gives a finite constructive instance beyond a single old-root/info pair.

## 9. Counterexamples and precise repairs

### Per-origin root tables

Take two original call sites with the same `S`, `r` and complete `I`. The real outputs agree with probability one. An ideal table keyed separately by call-site or origin identifiers gives independent roots, which agree with probability `2^-256`. A test comparing the two disclosed unmarked roots has gap `1-2^-256`.

**Repair:** use the exact descriptor `(Gamma(r),I)` across all callers and resumptions. Original source identity remains in the provenance ledger.

### Retrospective marking of a disclosed entry

First disclose `v = W(gamma,I)`, then designate that previously allocated descriptor as the supposedly fresh target. Conditional on the available `v`, the target root equals `v` with probability one. A fresh independent root would equal `v` with probability `2^-256`. The root's prior disclosure also allows local evaluation of the downstream key schedule.

**Repair:** selection occurs before the descriptor's first root evaluation. Prior use of the class with other complete infos is compatible with this rule.

### Truncating the complete info

Choose distinct complete infos `I0` and `I1` that map to the same proposed shortened cache key. In the correct private row game, the inputs `I0 || 01` and `I1 || 01` are distinct, so their replies are independent. A shortened-key cache makes them equal deterministically.

**Repair:** retain all 97 info bytes. In the native format, the digest field is the actual effective field, while the provenance ledger separately retains whatever source data its correspondence needs.

### Counting classes as all salt work

A controller can present many distinct available salts whose `Gamma` pairs fall in existing classes. Each new salt requires its actual public pad-state computation, even if it allocates no new PRK.

**Repair:** retain the external work bound `2D` or an explicit total `Gamma`-resolution query count. The column call bound remains the number of allocated classes.

### Handle feedback and schedule ownership

The available controller can feed a disclosed root back as salt. Passing the selected handle's protected raw bytes as a new parent-contribution salt instead asks for an additional operation: the entry scheduler would need to compute `Gamma(R*)` from that handle. Similarly, routing an alias into a separate session salt asks for additional root-column uses.

These observations identify interface extensions, rather than a demonstrated cryptographic attack. **The present repair is the explicit retained-handle contract:** every marked alias participates in one declared joint schedule; subsequent entry inputs are computed from its available outputs and other available data. Numeric coincidence of a known salt with `R*` remains an admitted event handled by the shared-oracle bounds.

## 10. Dependencies and established status

The theorem uses the operational bounds of the existing `lem:appendix-joint-hmac` and `lem:appendix-hmac-instances`, with their published compression-QROM inputs and complete-query conventions. It supplies a new finite interface composition, an adaptive class-allocation reduction, the complete descriptor table and the fresh-target embedding. The message consequence invokes `thm:joint-message-leaf` and `cor:joint-first-message`; a preceding combiner hop invokes `lem:cb-hidden-component`.

The algebraic descriptor identity, column/row hybrid chain, explicit conservative counts and whole-controller fresh-root coupling are proved above. The counterexamples identify actual failures of alternative cache/freshness constructions. The protected-handle examples identify the precise added operation that a different controller would need to supply.
