# Online selection within a finite recovered message chain

## Result and experiment

The theorem in `../../chain-prefix-continuation.tex` extends the existing
uniform-recovered-root continuation to an online selected message inside
one designated traffic direction. The controller marks an index before
that index's first private computation at any alias. It can use all
earlier returned message keys and the history of actual network
authentication when choosing. The target key remains behind its one-key
AEAD service; its successor seed can be disclosed.

The fixed lifetime bound L counts potentially protected prefix indices.
The native step rejects index `u64::MAX`, so the stated range is
`1 <= L <= 2^64 - 1`, with evaluated indices `0 <= i < L`.

Before a mark, prefix seeds and Extract values have only their stated
chain and justified opaque-persistence uses. Other message keys may be
exported. After a mark at index ell, real suffix computation proceeds
from the disclosed successor seed. The protected object is the complete
traffic-material identity, direction and index, shared across matching
endpoints, skipped-key evaluations and exact retries. Epoch/index pairs
alone do not identify it.

## Ordered hybrids

The first three hybrids are the existing joint-root comparison and the
at most two column-PRK row comparisons. They use the expanded controller
as their whole continuation. All values supplied to its chain operations
are locally available in those reductions. Their cost is Delta_traffic,
with recomputed whole-execution query budgets.

The traffic row is then rewritten exactly as its HKDF block table. This
matters because the original second Expand input contains the first block
(the designated seed). The exact table representation removes that hidden
raw-seed occurrence while retaining every observable block and every alias.

Define G_i, for i from 0 to L, as the world in which the first i prefix
steps reached before or at a mark have independent cached block pairs.
Steps strictly after a mark remain real. For each i, compare G_i with
G_(i+1) using a column hop and a row hop:

1. If an earlier index was marked, there is no step-i intervention on
   this branch. Its suffix uses known material and can run locally.
2. Otherwise the preceding ideal pair, or the traffic table at i=0,
   generates a new private uniform seed s_i. Whether the preceding index
   was marked is already decided at that point. The column challenger
   can therefore supply the hidden seed for this pair exactly on the
   branch where it is still protected.
3. The controller may delay, crash, retire the chain or never call step i.
   All its observations in that interval use available values and opaque
   handles. If a call occurs, its only use of the hidden seed is
   HMAC_(zero)(s_i); subsequent original aliases retrieve the same reply.
   The returned Extract value suffices to compute the real Expand and
   all future work. The single-column game applies to this complete
   possibly-unused interface. There is no conditioning on selection or
   successful completion.
4. The independent Extract reply from the column ideal can be the row
   challenger's hidden key. The first Expand reply is known and becomes
   the prefix of the second query. Both queries and the complete real
   continuation are therefore simulatable. Their lengths are always
   57 and 89 bytes: the message domain is 43 bytes, `chain` has five
   bytes and the index has eight bytes.
5. Apply the exact block-table representation again. The two replies are
   independent blocks. This removes the second row query's raw use of
   the successor seed and provides the private seed for the next hop.
   If i itself was marked, the successor is available instead, so this
   branch permanently enters the real suffix.

At each column hop the hidden seed is installed before it has any raw
use. At each row hop the hidden Extract value is installed before its
first use. Earlier message keys are locally known. A later marking
decision can depend on them, but does not determine a retroactive
embedding. Every hybrid regenerates that decision within its own
execution. The reduction never guesses the eventual target index.

The bound sums the two comparison gaps for the fixed L slots, with
deterministic worst-case ordinary-query budgets. Branches that do not
reach a slot make no challenge call. Budgets include all other real
primitives, the suffix after the target, adversarial computation with
earlier keys, oracle-dependent preparation and terminal tests. An
observed chain length does not replace the fixed worst-case bound.

All ideal replies are ordinary independent samples and may coincide
numerically. Known-key work uses the common public compression oracle.
The primitive experiment already includes that work; the proof never
conditions on samples being distinct or creates an uncharged collision
exclusion. Intentional original-step aliases share the same hidden
handle and cached reply throughout.

## Target AEAD reduction

In G_L the controller marks before the next independent pair is
generated. Its choice depends only on the available prefix. The
challenger's key can therefore be installed at that pair's message-key
handle, with its successor sampled locally. The reduction performs all
previous-key operations and all real suffix operations itself, including
an arbitrary available computation from the disclosed successor.

The honest application owns the target plaintext and delivery. Public
Resume accepts the retained identity and returns original ciphertext;
it supplies no new plaintext-bearing query. The encryption origin
ledger is written on the first private encryption, before a later
commit can fail. All resumptions, both before and after commitment,
therefore reuse that encryption query. The selected decryption service
retains the preceding paper's exact-challenge authenticated marker and
ordinary plaintext/failure behavior.

For confidentiality, the event-qualified terminal guess returns a fair
guess when the selected event is absent. Its centered success equals
the declared score in the final hybrid. The statistical comparison
cost is doubled for a score in [-1,1]. The one-key AEAD term is twice
the absolute guessing advantage over one half.

For integrity, a fresh selected-key inbox installation outside its
honest encryption ledger gives a successful new ciphertext pair to
the one-key integrity challenger. This uses a Boolean comparison and
incurs the prefix cost once. Earlier disclosed keys can authenticate
earlier indices; the stated event is the selected index's fresh
installation. It is not an integrity claim about an already exposed
earlier key.

## Source correspondence and explicit counterexamples

The three source files in `sources/` have matching Git blob identities
at native pin `228c944fc476e3e57d6c08063cacb19bca5b360e` and integration
checkpoint `6a0ac0bbd7a5be77443e10b22c20a31f4b3be271`. The source map
identifies the exact chain equation, zero nonce, once-only send
advancement, outbox reuse, receive skipping and transaction-private
rollback. The source profile's private persistence remains the
previously justified image/intent abstraction.

A receive operation can derive and retain a skipped key before the
sender's later send call. Thus a selector using only the first send
would permit retroactive selection after the key already existed.
The complete first-private-computation ledger closes this ambiguity.
The finite controls exercise the same index through two aliases and
reject a later mark.

If the target is selected after its key is returned, the selection can
choose a particular observed key value. The ideal selected-key
distribution then loses independence. Exact enumeration detects this
retrospective policy. The online model enumerates every binary
three-step marking policy and retains uniform selected-key fibres
conditional on the observed earlier keys, mark and successor state.

Exposing a prefix seed has a different consequence from exposing an
earlier message key. Given s_i, the public chain equations compute
every later key along that direction. The executable HMAC/HKDF control
reconstructs a selected later key from such a seed. This is why the
prefix seed interface is a premise of the theorem.

For L=1 the new comparison reduces to the old five-term schedule
bound. A fixed index ell has L=ell+1. The new result establishes the
finite-chain continuation and selected-key application reductions.
The existing complete native next-rekey statements keep their
first-message controller and evidence identity. Composing the new
controller with a broader native experiment requires realizing its
online mark and observation interfaces in that experiment.
