# Adaptive target accounting for original KEM operations

This note supplies a conditional event/score localization for the
[fixed-pair KEM adapter](KEM_CHALLENGE_ADAPTER_V1.md). It permits a classical
target choice after the observed protocol execution. It does not establish the
native private-record abstraction, the target's source-origin map, the random
component continuation bound, or the complete multi-epoch theorem.
Source observations below are checked at
`01ed008334a4aa0aee720ee7cbeec9b5394dc816`; no runtime, protocol or MAIN predicate
is changed.

## Fixed budgets and original-operation origins

Fix public finite budgets `G,C >= 1` for generation and encapsulation reservation
invocations in one complete experiment. They are proof-resource bounds, not new
SDK configuration limits. Count at the original entropy reservation boundary,
including attempts that later fail. A missing invocation is an unused slot.
An exact replay keeps the original slot. A new attempt after definite absence
gets a new slot even if its operation identifier is reused.

The source distinguishes these events:

- [`RecoveryKey::reserve`](../../crates/q-periapt-sdk/src/expert/replay.rs)
  performs runtime/key/binding admission before drawing entropy, then draws the
  wrapping nonce and seals the token. Computation through `generate_key` and
  `encapsulate` opens the retained token and consumes its bytes; it does not draw
  replacement KEM entropy.
- [Offer reservation](../../research/continuity-identity-candidate/src/durable/messages/rekey.rs)
  calls `reserve_key` only when the control plan is absent, persists the plan
  before computation, and returns a ready wire from the retained plan.
- [Response reservation](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs)
  authenticates the offer first. A retained response binds the exact original
  offer; a new reservation is stored before encapsulation computation.
- [Response acceptance](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs)
  restores the key from the retained offer token after wire/prefix checks and
  verifies its public key against that offer before decapsulation.

These are source facts supporting an origin ledger, not a proof of every
possible recovery or acquisition history. An operation ID, epoch counter,
image revision, ciphertext equality or number of resident records is not a
substitute for an invocation origin. Nor does a bound on retained records bound
the number of lifetime attempts. The generation and encapsulation indices are
chosen from fixed budgets before execution; choosing an index uniformly from
the final realized number of operations would require a separate causal
simulation.

Let `J={1,...,G} x {1,...,C}` and `N=GC`. A successful target must be attributed
to a unique pair `I in J`, whose encapsulation uses the public key of that
generation. Public-key aliases do not merge independently sampled operations.
Establishing this attribution requires the original authenticated-history,
collision and private-record premises; this note does not assume them proven.

## Experiments and the event to compare

Let `V` be one real-component virtual protocol experiment. Its complete run may
include adaptive protocol actions, permitted disclosures, classical target
selection and quantum public-oracle queries. The final target and score are
classical outputs; the argument does not measure the adversary's other quantum
state or its oracle queries.

Let `E` be the unchanged selected-target eligibility predicate. It retains both
post-Cut reservations, the two actual signing keys across their uses, absence
of the selected epoch's entropy disclosure, and absence of acquisition of a
selected-session post-Cut saved record. Earlier/later epoch entropy disclosure
remains allowed. Successful confirmation by both parties is not added.

Let `A` mean that a unique usable original pair has been established. Keep
`eta >= Pr_V[E and not A]` explicit. Until the source-origin bridge supplies such
a bound, `eta` is an unresolved premise, not zero.

Every test used below, including eligibility, `A`, `I` and the final event/score,
must be efficiently evaluable by the adapter from its known semantic state,
observations and locally sampled randomness. Existence of a mathematical origin
does not supply such an algorithm. In particular, a test cannot require unknown
challenge coins or the component challenger's hidden real/random bit.
Mapping symbolic `K(payload)` to a computational experiment with an explicit
adversary output remains a separate step.

For every fixed `j in J`, let `V_j` be the adapter's specified random-component
override game for that pair. Its complete transcript, selector, eligibility and
origin classification are recomputed in that game. It is not the real transcript
with one value replaced afterward. Define `E_j = E and A and I=j`.

For a classical event `W` satisfying that evaluability condition and
`W implies E`, the fixed-pair adapter supplies binary distinguishers for

```text
| Pr_V[W and A and I=j] - Pr_V_j[W and A and I=j] |
    <= a_j(W) + delta_j.
```

Here `a_j(W)` is the component IND-CCA advantage of the actual derived
distinguisher, including the selector, surrounding computation and every
relevant oracle query. `delta_j` is the same challenge pair's correctness term.
Repeating its exact ciphertext does not add another correctness event.
This application still assumes the fixed-pair virtual interfaces can be
simulated; unknown coins are not fabricated in native storage.

## Adaptive winning-event bound

Write `p_j = Pr_V[W and A and I=j]` and
`r_j = Pr_V_j[W and A and I=j]`. In the single real game the events indexed by
`j` partition `W and A`. Consequently,

```text
Pr_V[W]
  <= min(1, eta + sum_j r_j + sum_j (a_j(W) + delta_j)).
```

Proof: decompose `W` into its attributed disjoint events and its unattributed
part; bound the latter by `eta`. Apply the fixed-pair inequality to each
attributed event and sum. The selector can depend arbitrarily on that game's
observed transcript; no independence of selector and transcript is used.

If separately proved bounds give `r_j<=beta`, `a_j(W)<=a` and
`delta_j<=delta` for every slot pair, the conservative consequence is

```text
Pr_V[W] <= min(1, eta + GC * (beta + a + delta)).
```

This is useful only with an appropriate random-component winning-event bound.
It is not a claim that a uniform KEM component already makes native messages
secret. An absent or unmatched pair contributes zero only when the corresponding
event is impossible in that game's actual execution.

The probabilities `r_j` belong to different override games. They are not
automatically the pieces of one global ideal distribution, and their sum need
not be at most one. In particular, a bound on a purported all-random game cannot
replace `sum_j r_j` without proving the relationship.

## Centered scores for an indistinguishability game

A raw success-probability union bound should not be applied to a bit-guessing
game's baseline one half. Let `S in {-1,+1}` denote an incorrect/correct binary
guess of an application-test bit sampled by the surrounding simulator, and use the
unconditioned score `E*S`. This is not the component challenger's hidden bit;
the simulator must be able to evaluate the score. Invalid or absent
targets contribute zero. The score magnitude is `|E_V[E*S]|`. The quantity
`|Pr[correct]-1/2|` is half this magnitude when invalid runs are completed by an
independent fair guess.

For each `j` apply the fixed-pair adapter separately to the positive and negative
events `E_j and S=+1` and `E_j and S=-1`. Let their component advantages be
`a_j^+` and `a_j^-`, and put `b_j=E_V_j[E_j*S]`. Then

```text
| E_V[E*S] |
  <= min(1, eta
       + sum_j |b_j|
       + sum_j (a_j^+ + a_j^- + 2*delta_j)).
```

Proof: the unattributed score has absolute expectation at most `eta`. On each
attributed event, its signed expectation is the positive-event probability minus
the negative-event probability. Apply the two binary-event bounds, then triangle
inequality over the pair indices. The factor two on correctness is a conservative
signed-score bound, not a charge for two actual decapsulation retries.

If `|b_j|<=beta` and each event distinguisher's advantage is at most `a`, the
right side is at most `min(1, eta+GC*(beta+2*a+2*delta))`.
Bounding `b_j` must include target choice and eligibility in the same override
game. An independently uniform marginal key, or a plaintext assertion obtained
after conditioning on eligibility, does not establish this premise.

## Two invalid shortcuts

**Conditioning away failures.** For any `0<epsilon<1`, consider two distributions.
The first assigns mass `epsilon` to `(E=1,D=1)` and the remainder to `(0,0)`.
The second assigns mass `epsilon` to `(1,0)` and the remainder to `(0,0)`.
Their unconditioned `E and D` probabilities differ by `epsilon`, but their
conditional `Pr[D=1 | E=1]` values differ by one. A small unconditioned reduction
bound therefore cannot be reused after dividing by an uncontrolled eligibility
probability. Ordinary failures and unknown outcomes stay in the experiments.

**Normalizing different guessed worlds.** With two indices, suppose the selector
chooses one or two with equal probability in the real game. In override game one
an observed marker makes it choose one; in override game two a marker makes it
choose two. Each override's matching-index probability is one, so their sum is
two, whereas the matching-index probabilities in the real game sum to one.
This elementary example invalidates the normalization shortcut. It is not a
Continuity transcript, a primitive attack or a new product counterexample.

## Early termination and the remaining connection to MAIN

The fixed-pair reduction may terminate with zero once an actual mapped event
irrevocably falsifies its candidate's original eligibility. It may not terminate
merely because serialization is difficult, an API failed, a response is delayed,
or an endpoint started cleanup. An earlier target message can remain relevant
after later cleanup, and `FinalReady` can enable sending before peer receipt.
Other-epoch disclosure and ordinary unrelated errors keep their real behavior.

This localization preserves the full native-to-virtual obligation. In particular,
the source-origin error `eta`, allowed partial-record acquisitions, report-key
dependencies, accepted-flight authentication, shared-oracle preparation,
multi-root/traffic composition and the bounds `r_j` or `b_j` remain to be supplied.
Errors comparing a native game to `V` must also be composed explicitly; none is
silently included in the component advantage.

For background, the multi-user/multi-challenge distinction and a generic
`n*q_C` IND-CPA KEM loss appear in
[section 2.1 of the OCAKE security analysis](https://eprint.iacr.org/2023/1368.pdf).
That different primitive/game result is not used as a theorem for Continuity;
the event and score identities above follow directly from the stated
fixed-pair interface and probability algebra.

The result here is a manual conditional reduction, not a Tamarin certificate,
an end-to-end implementation proof, a numerical concrete security level or
completed native adaptive-target security. MAIN, all forty retained queries and
their current verified/incomplete inventory remain unchanged.
