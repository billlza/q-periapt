# Independent derivation of a finite multiple-root entry

7 November 2026. This is a research review note for the forthcoming exact
manuscript module. It is not the final review receipt. It relies on the
retained operational HMAC primitives in `joint-primitive-bounds.tex` and the
retained joint first-message continuation, without re-proving those inputs.

## 1. The entry interface

Let S be a uniform 32-byte value initially independent of the public
compression oracle h and auxiliary state. Executed preparation is counted.
The contribution interface evaluates

    P_r = F(r,S),       R_(r,I) = F(P_r,I || 01),

where r is an available 32-byte salt and I is a complete 97-byte root
information string. S is used through these columns; each P_r is used
through its one-block Expand row. Ordinary additional algorithms use the
same h throughout.

Write Gamma(r) = (h(Ipad(r),IV), h(Opad(r),IV)). Equal Gamma values give
identical real columns for every S. Thus a root request can compute Gamma
using available salt bytes, allocate one column reply for a new class, and
retrieve a class row entry for the complete I. Salt bytes and class names
are different cache keys. The first class order is determined online by
the actual available prefix, including previous replies and public-oracle
computation.

The root-entry table lemma can permit its output roots as concrete values
to the controller. The first-message connection additionally designates
one fresh table pair and retains it as a schedule handle, as described in
Section 4 below. These are separate steps of the argument.

## 2. Complete table comparison

For fixed finite budgets, let C bound allocated Gamma classes and N_i
bound distinct complete information strings queried in the i-th allocated
class. The first comparison gives every selected-S column request to
epsilon_Hjoint(C,0,q_S,32). The result is P_c = V(c), with V a private
random function independent of h. All Expands and subsequent algorithms
remain real in that comparison.

Next replace the class rows in their first-allocation order. In the i-th
adjacent comparison, classes before i already use their ideal rows;
classes after i use locally sampled known keys and the actual HMAC
algorithm. Presample the row primitive's hidden uniform key and install
it at the first allocation of class i. Before that allocation the
controller has no access to this key. The class identifier and allocation
decision use available data rather than the raw private PRK. Equal Gamma
aliases retain the same handle. The reduction queries the challenge row
on each actual adaptive message I || 01. If class i never occurs, no
challenge query is necessary.

The i-th output-bit cost is epsilon_Hrow(N_i,q_i,98). This is a sequence
of adjacent comparisons of the complete controller; it does not condition
on a class name determined in another game. Dynamic allocation order is
recomputed within every experiment. Therefore

    Delta_multi <= min(1,
        epsilon_Hjoint(C,0,q_S,32)
        + sum_(i=1)^C epsilon_Hrow(N_i,q_i,98)).

The final interface is exactly a private table W(c,I). The map
I -> I || 01 is injective, so equal pairs retrieve one value and new pairs
receive independent uniform replies. No target class was guessed: all
class rows have been compared before a marked-root argument is applied.

## 3. Adaptive values, collisions and budgets

Adaptive salts and information strings may depend on available previous
root replies and on the same h. The operational column and row primitives
already permit that adaptivity. Their premises do not require a fixed
complete transcript.

Different Gamma classes have independent uniform PRK replies, which may
coincide numerically. In a real row, equality of those numeric keys gives
the usual shared-h HMAC equality. The adjacent reduction evaluates every
other real class under its locally known key using that same h. Its
primitive bound therefore already covers accidental overlaps with the
challenge key. There is no collision-free conditioning and no need for an
extra birthday assumption. The hybrid's intentional row identity remains
the Gamma class, not an equality test on an unavailable PRK.

Let D be a fixed bound on distinct available salt byte strings. Cache
their public Gamma computations, so external class dispatch uses at most
2D ordinary compression queries. Let B bound all remaining ordinary work
in each complete derived experiment, including preparation, other
contributions and roots, persistence interfaces, target schedule,
adaptive feedback, and terminal testing. A 98-byte HMAC call uses five
compression calls: two key-pad calls plus ell(98)=3 continuation calls.
With N = sum_i N_i, conservative bounds are

    q_S <= B + 2D + 5N,
    q_i <= B + 2D + 5 sum_(k>i) N_k.

The selected challenge row's own queries are counted by its private-query
and length parameters. Earlier ideal rows do not call HMAC, but all of
their subsequent controller work remains in B. The column primitive's
internal public salt-pad work is accounted in its own retained bound,
in addition to the explicit external 2D dispatch work. Different new salt
bytes can reach an old class, so 2D cannot generally be replaced by 2C.
All these constants must dominate the respective complete experiments in
advance; observed counts from one native trace do not establish that fact.

## 4. A fresh marked pair and the message connection

Before the first query to one new pair (c*,I*), an available controller
marks that pair. Its class c* may already have other information entries.
In the final private table, W(c*,I*) is fresh uniform independent of h
and the executed prefix. It can be presampled and withheld until this
allocation. No selection after observing this value is used.

Represent the marked pair by one retained schedule handle. Every later
equal-pair alias retrieves that handle. Its complete uses jointly obey
the retained first-message schedule interface, including the fixed
session salt and its {0,s} columns, information tables, direction mark,
successor inputs, disclosure interfaces and finite budgets. Other root
entries are concrete locally available values. The controller forms any
later parent salt or information string from available values: public
state, independent randomness, ordinary oracle outputs, nonmarked roots,
and declared schedule replies.

This supplies the initial uniform root for the existing schedule proof
without a class-guessing or target-guessing factor. For its available
signed message score, the complete bound adds

    2 Delta_multi + 2 Delta_sched + 2 epsilon_AEAD.

If preceded by the complete-tuple ContextBound comparison, add its
2 Phi_256 term at the same score convention. Existing record, component,
correctness and original native residual terms retain their locations.

The distinction between an available numeric value and a protected handle
is a computation interface. A known value may happen to equal the marked
root numerically; its ordinary h computations remain permitted and
counted. Taking the marked handle's raw bytes as a salt for the same
parent contribution instead introduces the operation Gamma(R*) or
F(R*,S*) outside the retained schedule interface. That is a different
interface, rather than a forbidden numerical coincidence.

## 5. Counterexamples that delimit the interface

1. **Salt bytes alone as ideal class identity.** Two different salts can
   have the same Gamma. For the same I their real root replies agree
   exactly. Independent per-salt ideal rows agree only with probability
   2^-256. Exact Gamma aliases therefore share a row.
2. **Incomplete information cache.** One Gamma class evaluated on two
   different complete information strings has different row inputs.
   A table that omits I, or only retains an unproved digest of I, merges
   inputs that the actual Expand keeps distinct.
3. **Retrospective target selection.** After revealing several table
   values, selecting one with a desired first bit biases the selected
   value. A fresh unknown key cannot simply be embedded at that later
   designation. A mark before a new pair's first response avoids this
   obstruction, including when the class itself was previously used.
4. **Alias disclosure after marking.** If the marked pair returns a
   protected handle but a later equal-pair alias returns the raw value,
   that second call reveals the selected root. All equal-pair aliases
   must retrieve the same retained schedule handle.
5. **A second session through the marked pair.** An additional session
   salt creates a root column beyond the retained {0,s} schedule unless
   it is already represented there. The entry table lemma still holds;
   the existing schedule bound must cover all marked-handle uses.
6. **Parent feedback through a raw marked root.** Using the selected
   hidden root as a salt in F(R*,S*) requires bytes or an additional
   private interface unavailable to the retained schedule reduction.
   A known salt that only coincides numerically with R* has no such
   simulation problem.

These examples identify exact interface obligations. They are not attacks
against a controller that satisfies the stated available-data and handle
definitions, and they do not challenge the retained primitive theorems.

## 6. Presentation recommendation

Define the finite root-entry controller and the marked schedule handle
once, positively, before stating the result. Give the column-to-rows
comparison, exact table rewrite and fresh-installation argument in that
order. Put the numerical-collision observation and the distinction from
raw-handle feedback in one short scope paragraph. Present the native
single-use profile as the concrete C=N_1=1 specialization. There is no
need for version names or repeated qualifications after each assertion.

