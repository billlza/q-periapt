# From bootstrap schedule descriptors to terminal transcript classes

Source assessment: `360aa8107aa7df502108627a4dcf89f30d106594`, 9 November
2026. This completes the terminal-class connection identified in section 7 of
the [joint-schedule assessment][schedule]. It uses the completed
[joint Extract entry][entry], the conditional bootstrap-PRK tail, and the
[online terminal theorem][terminal]. The source pins and executable controls
are retained in the [evidence packet][evidence].

## Result

The conditional schedule comparison now reaches the terminal theorem's exact
ACK-only experiment. Its online registration can occur after the bootstrap
root has been retained and before the first activation. The connection keeps
the real confirmation outputs and all permitted sibling observations, reuses
one ACK value for both endpoints and exact retries, and accounts explicitly for
distinct signed transcripts sharing an effective SHA-256 pad descriptor.

Three arguments supply this connection. First, an unopened private root-table
entry can be sampled at its first permitted exposure, so allocation of an
opaque handle need not fix its protection decision. Second, a complete
transcript has a unique effective root descriptor in the absence of the
already declared transcript-hash event and one specified compression-collision
event. Third, two schedule comparisons reach a common full-table experiment:
one starts with the real ACK, the other with an independent ACK replacement.
This last step retains the actual distribution of the other outputs in the
two endpoint experiments.

The input to this theorem is the same opaque bootstrap-PRK service required by
the existing tail proposition. The original component/disclosure adapter
provides that service from actual bootstrap operations; section 6 records its
precise boundary and the resulting substitution into U1. Thus terminal-class
reconciliation is a completed U2 input, with original source realization
remaining as the construction task.

## 1. The source order and the two comparison experiments

Write `c = (ctx,x,y)` for the complete terminal class, with the exact signed
Initial and Reply wires. Let `p` name an effective bootstrap-PRK family.
Aliases of one PRK input reuse `p`; independent original-operation identifiers
alone are not a PRK cache key. The incoming service supplies a fresh uniform
32-byte `P_p`, independent of `h` and its previously available state, at the
first family allocation. Its only raw uses are the three bootstrap Expand
labels. The resulting seed is used through its root-entry Extracts. This is
the opaque interface of the existing conditional tail.

The controller supplies a consistent family assignment for each `c` at both
endpoints, together with all effective aliases. The original source adapter
has responsibility for that assignment and its component-correctness cost.
We retain the actual source computations

```text
Fpub(c) = "QPBSF001" || ctx || H_initial(x) || H_reply(y)
sid(c)  = H_session(Fpub(c))
I_B(c)  = D_B || "session-root/" || ctx
I_A(c)  = D_M || "initial/HKDF-SHA256/ChaCha20Poly1305" || ctx
e(c)    = (p, Gamma(sid(c)), I_B(c)).
```

`H_initial`, `H_reply`, and `H_session` use the source's complete framed
SHA3-256 domain/input strings. `Gamma(a) = (alpha(a),beta(a))` is the pair of
SHA-256 compression outputs at `(I(a),IV)` and `(O(a),IV)`, as defined in the
entry proof. The bootstrap domain `D_B` and message domain `D_M` have 48 and
43 bytes. Hence `I_B` has 93 bytes and `I_A` has 111 bytes.

The relevant execution order is visible in the pinned source:

| Source transition | Root and ACK state |
| --- | --- |
| `prepared_response` | Forms the complete signed Reply, calls `pending`, and retains `K_B` in `PendingSession` before responder Final acceptance. |
| `finish_initiator` | Authenticates the Reply, creates Final, then calls `pending` and retains `K_B` before initiator activation. |
| `activate_initiator_messages` | Requires `FinalCommitted`, retires the original pending root, and invokes `State::new`. |
| `activate_responder_messages` | Requires `Complete`, retires the original pending root, and invokes `State::new`. |
| `State::new` | Evaluates activation Extract and a single 160-byte Expand; blocks are `(R0,chainI,chainR,ackI,ackR)`. |
| `Traffic::from_material` | Makes block 4 the initiator send-ACK key and responder receive-ACK key used by READY. |

In particular, root creation and ACK-key computation are separate source
events. The first private activation at either endpoint computes the ACK key.
The U1 registration rule is therefore evaluated before that first activation;
it can use public events that occurred after root creation. Exact restoration,
pending-target reconciliation and a second endpoint retrieve the same logical
schedule handle.

For `b in {0,1}`, let `G_b` be this stopped incoming-service experiment.
`G_0` uses all actual schedule outputs. `G_1` samples a fresh independent
32-byte `Z_c` when a class is registered and uses `Z_c` as its `ackI` at both
endpoints and on all retries. Every other computation is the actual algorithm
of that experiment, including MAC0/MACR/MACI, unprotected ACKs, permitted
sibling disclosures and the adversary's adaptive continuation. This is the
ACK-only replacement required by U1.

The replacement in `G_1` changes the exported block-4 key. The actual internal
block 4 still enters HKDF's computation of block 5 before that replacement.
Feeding `Z_c` back into the block-5 computation would change `ackR` and define
a different experiment.

Both games use U1's online registration and cumulative recipe stop, including
its latched terminal event. Both already stop at U1's `Coll` event for the
relevant context, complete-wire and session-ID hash inputs. All computation
depending on either public oracle, including preparation and the final test,
is executed and counted.

## 2. Deferred protection of an unopened root

The finite-entry comparison changes the bootstrap root interface to a private
table `W(e)` of independent uniform 32-byte entries. Its parent Expand rows
have already been removed by the exact table representation; retaining an
extra raw parent-row interface would not be this experiment.

Before its first exposure, an entry supplies only an opaque handle and its
public descriptor. The interface may store or copy that handle in the
declared opaque records, compare its public identity, and recover it on an
exact retry. The available prefix contains no value-dependent observation of
its `W(e)`, including a root-derived test, partial leakage, ordinary-oracle
call made with that root, or ciphertext observation outside the justified
opaque-record comparison. Public-oracle queries on values chosen from other
available data are permitted throughout.

Define a first exposure as the first raw-root return or the first activation
evaluation for this entry. An entry whose root was already returned remains
unprotected. Before a protected first activation, registration has succeeded
and no past declared recipe recovers its root or ACK. Future disclosure that
would supply such a recipe stops before returning it. A first unprotected
activation also fixes the class as unprotected, as in U1.

**Lemma 1 — deferred root-table sampling.** Under this handle interface, eager
sampling at first descriptor allocation and sampling at first exposure have
the same joint distribution of every available classical and quantum view.
At an online protected first activation, its root can be assigned a fresh
independent hidden challenge key. Order those assignments by protected first
activation, using a fixed upper bound on their number.

**Proof.** Maintain the dictionary of allocated descriptors separately from
their values. Until first exposure, the program accesses an entry only through
its identity. In the eager experiment, its independent sampled value is an
unused random register. The available quantum state and every decision before
its exposure are independent of this register: their circuits have no access
to it. Sampling this register immediately before its first use therefore
commutes with the complete intervening computation. This includes public
oracle queries and adaptive choices based on already exposed other entries.
The shared oracle itself is unchanged.

Repeat the argument at each first exposure. A raw return or unprotected
activation draws an ordinary local value; a protected first activation uses
the next presampled independent challenge value. Its index is determined
before that value has any use. Equal descriptors retrieve their existing
handle and value. Values drawn for different handles can coincide, with
exactly the ordinary independent-sampling probability; no distinctness
conditioning occurs. This supplies a coupling of the full interactive views
and proves the lemma. **QED.**

This lemma permits the later registration used by U1. It does not postpone
actual source execution. It changes the sampling order only after the
finite-entry and record comparisons have supplied a private table and opaque
handles. In particular, the source's already encrypted checkpoint cannot be
treated as value-independent merely because the adversary has not received
its decryption key; the corresponding record comparison is part of the
incoming source interface.

The U3 classifier supplies the structural disclosure translation. Normalize
all acquired versions and disclosed wrapping keys, then apply the bootstrap
recipe closure. A root returned before registration makes that class
ineligible. A later request opening a previously acquired root-containing
checkpoint stops a protected execution before the return, even if the live
checkpoint has been deleted. A shared-seed recipe reaches every affected
class. These decisions use the original source/guard graph and public ledger
identities, not a test on an unknown hidden root. The existing guarded-history
proof makes this translation exact for the declared acquisition interface.

## 3. Complete transcripts and effective root descriptors

Within one incoming family `p`, define `Alias` as the first pair of encountered
classes `c != c'` for which `e(c) = e(c')`. Encounter a class when its complete
signed transcript is available to a root request or registration. Compute and
retain the relevant pad-state pairs then. The monitor runs before any new
activation or response that could exploit the equality, and keeps any earlier
latched terminal event when it stops.

**Lemma 2 — descriptor collision witness.** Before U1's `Coll`, an `Alias`
event supplies two distinct compression inputs with equal output. A witness
is

```text
(I(sid(c)),  IV) != (I(sid(c')), IV),
alpha(sid(c)) = alpha(sid(c')).
```

**Proof.** Descriptor equality implies equal `I_B`, whose fixed-length context
suffix gives equal `ctx`. If `sid(c) = sid(c')`, absence of the session-ID
hash collision gives equal complete Final prefixes. Absence of the relevant
complete-wire hash collisions then gives `x = x'` and `y = y'`, contradicting
`c != c'`. Thus the salts differ. The 32-byte-salt pad map `I` is injective,
so the two displayed inputs differ. Descriptor equality includes equality of
their `alpha` outputs. **QED.**

Let `Q_h,b` include every compression query of the complete `G_b` collision
finder, including all honest schedule work, the pad monitor and witness
extraction. For a 256-bit random-function output, write

```text
chi_h(Q) = min(1, C_col (Q + 2)^3 / 2^256).
```

Here `C_col` is the universal constant of the quantum random-function
collision theorem, using the same operational convention as
`confirmation-traffic.tex`. Applying that theorem to the complete 768-bit
compression input gives

```text
Pr_Gb[Alias before Coll] <= chi_h(Q_h,b).
```

The independent SHA3 oracle and all local coins are retained auxiliary
computation. The witness need only collide the inner pad state; equality of
both pad states is a stronger event. Consequently the bound requires neither
an independence assumption about the two observed states nor a birthday
estimate for adversarially selected session IDs. It is a single global
collision-finding bound, with no pairwise union factor over transcripts.

Stop both games additionally at this monitor and call them `G_b^*`. The change
in any output-bit probability is at most its corresponding alias probability.
In the stopped games, within each family, distinct terminal classes have
distinct effective root handles. Equal complete classes retrieve the same
handle and registration. Distinct incoming families retain their specified
independent table entries; numerical equalities between their values remain
part of the shared-oracle comparison. Family consistency for one complete
class remains the incoming source-adapter premise from section 1.

## 4. A common full-table experiment

Fix finite family, root-descriptor and whole-continuation query bounds before
execution. For each incoming family `p`, let `N_p` bound its total distinct
root descriptors. For each `b`, define

```text
D_b = min(1, sum_p [
    epsilon_Hrow(3, q_Bp,b, 71)
  + Delta_ent,p,b(info length 93)
  + sum_{j=1..N_p} (
        epsilon_Hjoint(1, 0, q_Apj,b, 32)
      + epsilon_Hrow(5, q_Tpj,b, 144))
]).
```

`Delta_ent` is the existing information-length finite root-entry bound. The
three bootstrap row messages have lengths 63, 71 and 71. Activation has one
32-byte Extract column and five Expand row messages of lengths
`112,144,144,144,144`. The activation index `j` now follows protected first
activations in Lemma 1; `N_p` also bounds their number. Empty slots make no
private call. Unprotected activations retain real HMAC evaluations under their
current-game roots and enter the ordinary query budgets.

Every displayed `q` bounds the entire derived reduction for that step. It
includes preparation, all other families, real confirmation and signature
work, prior and later unprotected entries, public queries before a root is
materialized, later uses and disclosures of allowed siblings, and the final
test. It is not restarted at registration or at a KDF call. The budgets must
hold for both endpoint experiments and the intervening hybrids.

**Proposition 3 — the deferred conditional tail.** For each `b`, `G_b^*` has
output-bit gap at most `D_b` from an experiment `T_b` in which the three
bootstrap outputs and all root entries use their full descriptor tables and
every protected activation supplies five independent cached blocks. `T_1`
also performs its independent ACK-only replacement. All declared stops and
the full interactive controller remain present.

**Proof.** Replace the bootstrap Expand row and root-entry service exactly as
in section 3 of the joint-schedule assessment, in fixed first-family-allocation
order. All incoming PRKs have their stated opaque three-label interface.
This yields the complete root table, including unprotected entries.

Apply Lemma 1 to that table. At a protected first activation the selected
root is fresh and unused, so assign it the next independent column-challenge
key. Its only raw uses are the activation Extracts at its descriptor. Equal
`Gamma(sid)` and equal `I_B` give one effective column and the same `I_A`.
The column bound and five-message row bound therefore replace that activation
by its ideal row. Use the exact prefix-consistent Expand-table identity to
represent its five outputs as independent cached blocks. This removes the
parent row inputs containing previous output blocks; subsequent permitted
sibling uses are part of the continuation, not an extra raw parent-row
interface.

At step `j`, earlier protected activations use their tables and later ones
use real primitives with locally sampled independent roots. Unprotected
activations always use real primitives. Numerical key coincidences trigger
the actual common-oracle computations in the real branch and are counted
in the established primitive gap. The challenge is assigned by the fixed
protected-first-activation index, not by a later winning-class guess.
Summing the comparisons gives `D_b`. The same proof applies to `b=1`: its
ACK override is an available postprocessing operation, and the actual block 4
still supplies the internal HKDF predecessor for block 5. **QED.**

**Lemma 4 — equality of the common-table endpoints.** `T_0` and `T_1` have the
same available joint distribution.

**Proof.** In `T_0`, the ACK block of each protected class is an independent
uniform cached value, independent of its four sibling blocks, all other
protected class blocks and the unchanged oracle. By Lemma 2's stop, no
different class in the same family shares its root handle. Both endpoints
and retries share its class cache.

Couple this block to `Z_c` in `T_1`. Any internally generated table block 4
that `T_1` overwrites has no other use: the exact Expand-table rewrite has
already removed its raw block-5 row input. Assign all other table values and
the complete controller identically. Registration can be adaptive but takes
place before any ACK-key computation or use, so `Z_c` is fresh at precisely
the same first use. All later MAC calls, verifications, sibling disclosures,
stops and latched outputs agree in the coupling. Independently drawn numeric
key coincidences have their usual distribution in both experiments. **QED.**

## 5. Conditional ACK-only schedule theorem

**Theorem 5.** For the incoming service, source-consistent class mapping,
opaque records and online stopped interface of sections 1–2,

```text
epsilon_ACK|PRK <= min(1,
    D_0 + D_1 + chi_h(Q_h,0) + chi_h(Q_h,1)).
```

With common valid budgets `D` and `Q_h`, this is
`min(1, 2D + 2 chi_h(Q_h))`.

**Proof.** Use the experiment chain

```text
G_0 -> G_0^* -> T_0 == T_1 <- G_1^* <- G_1.
```

Lemma 2 bounds the outer stopping changes, Proposition 3 bounds the two
schedule comparisons, and Lemma 4 couples the common-table experiments.
The triangle inequality proves the result for every efficient output-bit
test, including U1's latched historical-activation failure event. **QED.**

The two schedule costs have a specific purpose. U1 preserves the actual
other outputs in `G_0` and `G_1`; the full-table intermediary jointly
randomizes some of those outputs. Comparing both endpoint experiments to
that common distribution restores the required ACK-only statement.

## 6. Source-adapter composition and U1 substitution

For each endpoint bit `b`, let `E_src,b` bound the original-operation and
record comparison that realizes the selected opaque surviving-contribution
services, including its source association, component correctness, permitted
disclosures, and original stopping/partition costs. Let `E_entry,b` be the
sum of the completed joint-entry comparisons applied to those services.
The adapter must realize the following concrete interface:

| Boundary | Required source correspondence |
| --- | --- |
| Original component challenge | The initial case uses the selected responder prekey and original Initial encapsulation; the reply case uses the initiator's original reply key and responder's original response encapsulation. First actual private computation, failed writes, exact retries and copies retain their original ledger slots. |
| Component/ContextBound table | Route the selected challenge ciphertext through its challenge cache, retain native rejection for the other leg, and index the ContextBound table by all ten effective fields. The existing `lem:cb-hidden-component` then supplies `Phi_256(d,Q_H)` after the component replacement. |
| Effective bootstrap family | Preserve the joint entry's complete `(known half,alpha(t1),beta(t1))` descriptor, the initial-confirmation cross-use in the hidden-`S0` case, and all cross-endpoint repeats. Source correctness/association makes one full class use one effective family. |
| Retained bytes and disclosure | The U3 guarded-history evaluator gives the exact recipe classification. Its record-hiding/unknown-tape comparison must supply the opaque observations used above, including checkpoints acquired before first ACK registration. |
| Local identities and other operations | Simulate the declared local signing-identity disclosures, all other original owners and non-target calls, using the existing purpose/body and native signing-reservation reductions for the chosen protected signer. |

The accepted next-rekey adapter in `contextbound-connection.tex` supplies the
operational component-game template: prechallenge decapsulation, a challenge
at the first original encapsulation, cached challenge returns thereafter,
and ordinary calls on every other ciphertext and owner. Its selected-owner
and opaque-record premises are instantiated by the bootstrap adapter above;
the table does not identify bootstrap source slots with next-rekey slots.
In particular, any raw parent-PRK or seed disclosure before protection is a
source-adapter branch or partition cost. It is not hidden by the deferred-root
lemma, whose fresh objects are the already established root-table entries.

The completed schedule substitution is

```text
epsilon_schedule <= min(1,
    E_src,0 + E_src,1
  + E_entry,0 + E_entry,1
  + D_0 + D_1
  + chi_h(Q_h,0) + chi_h(Q_h,1)).
```

Substituting this term into U1 gives

```text
Pr[latched Bad] <= min(1,
    Pr_real[Coll] + epsilon_schedule + epsilon_mac
  + q_v / (2^256 - q_v + 1)).
```

Every component, entry and tail comparison must bound both endpoint bits;
the ACK-only replacement is retained as part of their complete continuation.
The original U1 online eligibility and latched-stop semantics remain the
same. This completes the descriptor/registration/terminal connection and
localizes the remaining U2 work to the original component/disclosure adapter
`E_src,b` and its concrete family assignment.

## 7. Retained checks and sharp boundary controls

The accompanying checker verifies exact source hashes, independently evaluates
the bootstrap/root/activation equations, exhausts a finite root-table
sampling model, and executes controls for the theorem's interfaces:

- Eager and first-exposure sampling have equal finite joint distributions
  with adaptive public-oracle queries, a disclosed unprotected root, later
  protection of another allocated handle, exact retries and numeric key
  coincidences.
- A partial root observation before protection biases the selected value;
  sampling it freshly afterwards changes the observed distribution. This
  detects removal of the handle-independence premise.
- A deliberately forced two-salt pad collision produces equal root and ACK
  outputs for distinct full-wire classes. It is an explicit finite oracle
  witness for the necessity of `Alias`; it is not an observed SHA-256 collision.
- A full five-block random table and an ACK-only replacement have the same
  finite joint distribution of the four sibling blocks and used ACK key.
  An independent HMAC calculation detects the incorrect variant that feeds
  the replacement ACK into block 5.
- Historical acquired checkpoints remain in the recipe closure after local
  deletion; a later matching-key return stops a protected execution while
  preserving an earlier latched event.

These are executed checks of encodings, source correspondence and finite
model invariants. Lemmas 1–4 and Theorem 5 provide the general analytical
argument; the controls exercise its distinct hypotheses and comparison
endpoints.

## Proof inputs

The existing primitive inputs are `paper/continuity/joint-primitive-bounds.tex`
(shared-oracle HMAC row and column comparisons),
`paper/continuity/sdk-purpose-connection.tex` (information-length entry),
`paper/continuity/multiple-root-entry.tex` (complete root descriptors), and
[the exact Expand identity](HKDF_EXPAND_TABLE_V1.md).
`paper/continuity/guarded-provenance.tex` supplies the record normalization and
retained-history proof. The compression-collision bound uses Mark Zhandry,
*A Note on the Quantum Collision and Set Equality Problems*, Quantum
Information and Computation 15(7–8), 557–567 (2015), Theorem 7,
[primary text](https://www.rintonpress.com/xxqic15/qic-15-78/0557-0567.pdf),
with the same `C_col` convention already retained in
`paper/continuity/confirmation-traffic.tex`.

[schedule]: BOOTSTRAP_JOINT_SCHEDULE_REVIEW_V1.md
[entry]: BOOTSTRAP_JOINT_ENTRY_V1.md
[terminal]: BOOTSTRAP_TERMINAL_AGREEMENT_V1.md
[evidence]: ../../research/sdk-alpha1/evidence/20261109-bootstrap-terminal-schedule-connection/README.md
