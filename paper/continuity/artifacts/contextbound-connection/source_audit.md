# Accepted ContextBound operations and a concrete next-rekey adapter

Source audit and constructive interface argument, 7 November 2026.

The source pin is `228c944fc476e3e57d6c08063cacb19bca5b360e`. The fourteen files
identified in `source_map.json` are byte-identical at that pin, at development
checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`, and in the inspected native
checkout. The map gives exact ranges, Git blob identities and SHA-256 digests.
Statements marked C01–C14 below refer to that map.

## 1. Result of this pass

The native program supplies a usable adapter for one explicit profile: the
**next rekey of one established session**, starting with matching old roots at
the two endpoints and keeping the already stated authoritative-history storage
interface. It admits failed reservations, failed or uncertain writes, process
loss and exact resumption, adversarial public packets, ordinary old-epoch
traffic, asynchronous confirmation, the marked first-message continuation,
and later epochs. The challenge component for this native instance is
**ML-KEM-768**. The X25519 contribution is computed by its actual algorithm.

Two separate facts establish the useful interface:

1. Original reservation identity fixes the selected KEM computation despite
   retries and physical copies. A component challenge is cached by that
   original invocation, while its decapsulation routing uses the challenged
   **PQ ciphertext bytes**.
2. All protected uses of the selected complete ContextBound tuple in this
   next-rekey profile have one old-root/complete-root-info pair. This follows
   from the retained full offer and control state, not merely from equality of
   a hash output or a public key.

The private-hash table must be indexed by the **complete effective encoded
tuple**. Origin, journal, authority and operation identifiers remain separate
provenance metadata. The code does not hash every such identifier into the
ContextBound input, so adding them to an ideal hash-cache key would change the
comparison.

This is a source correspondence and a hand induction over the specified
native call surface. The component, hidden-input hash, root-entry and message
bounds are cryptographic comparisons supplied by their respective proof
modules. The checks executed here are described in Section 8.

## 2. The exact hash input

Write `LP(x) = BE64(len(x)) || x`, and let `H` be the public SHA3-256 oracle
used in the corresponding idealized experiments. C01, C02 and C05 give

\[
\begin{split}
S=H(&\operatorname{LP}(D_{\rm CB})\Vert\operatorname{LP}(\mathit{suite})
\Vert\operatorname{LP}(\operatorname{BE32}(v))\\
&\Vert\operatorname{LP}(s_M)\Vert\operatorname{LP}(s_X)
\Vert\operatorname{LP}(c_M)\Vert\operatorname{LP}(p_M)\\
&\Vert\operatorname{LP}(c_X)\Vert\operatorname{LP}(p_X)
\Vert\operatorname{LP}(C_{\rm policy})),
\end{split}
\]

where

\[
C_{\rm policy}=
\operatorname{LP}(D_{\rm policy})\Vert
\operatorname{LP}(\mathit{policyDigest})\Vert
\operatorname{LP}(C_{\rm app}),
\qquad
C_{\rm app}=H(\operatorname{LP}(D_R\Vert\texttt{response-kem})
                   \Vert\operatorname{LP}(O)).
\]

Here `O` is the **entire retained signed offer**, including its envelope and
signature bytes. It is not just the offer body, public key, or semantic
description. The outer policy digest is the exact digest of the verified
policy used by the admitted runtime. C07 supplies the length framing for the
rekey domain hash; C10 supplies the call `kem_context(offer)`.

| Field | Actual bytes | Native length |
| --- | --- | ---: |
| `D_CB` | `Q-PERIAPT-HYBRID-KEM/v1` | 23 |
| suite | `ML-KEM-768+X25519` | 17 |
| policy version | big-endian `u32` | 4 |
| `s_M`, `s_X` | two distinct secret fields | 32 each |
| `c_M` | ML-KEM-768 ciphertext | 1,088 |
| `p_M` | ML-KEM-768 public key | 1,184 |
| `c_X`, `p_X` | actual traditional ciphertext/public-key wire bytes | 32 each |
| `D_policy` | `Q-PERIAPT-POLICY-CONTEXT/v1` | 27 |
| policy digest | admitted policy's digest | 32 |
| application context | domain hash of the entire offer | 32 |
| nested policy context | three LP fields above | 115 |
| complete ContextBound hash input | ten outer LP fields | 2,639 |

In this native-width encoding the `s_M` bytes occupy offsets 76 through 107
(zero based). Thus, with all remaining effective fields fixed, inserting a
32-byte hidden uniform `U` has point probability at most `2^-256` for any
specified complete input. Distinct effective field tuples encode different
inputs for every value of `U`, by parsing the fixed-width length prefixes.
The statement is about the input encoding, not an assumption that hash outputs
are collision-free.

The reservation header has a different binding. `Runtime::policy_binding`
contains `SHA256(trust_root) || BE32(policy_version) || policyDigest`, totaling
68 bytes. The trust-root digest is checked by the reservation replay code;
it is **not an additional outer ContextBound field**. C03's encapsulation-input
binding is

```
SHA256("Q-PERIAPT-SDK-SEALED-ENCAPSULATION-INPUT/v1"
       || peer_public_key[1216] || BE32(len(application_context))
       || application_context)
```

The hash oracle `H` used by ContextBound is distinct from the public SHA-256
compression oracle `h` used in the later HMAC/HKDF comparisons. The whole
experiment retains both. The concrete SHA3/SHA256 source algorithms do not
by themselves establish the ideal-oracle assumptions used by a reduction.

## 3. What one original reservation means in the actual code

C03 draws one 96-byte tape for a generation reservation and one 64-byte tape
for an encapsulation reservation. It then separately draws the token's
24-byte sealing nonce. C02 consumes the tapes in these orders:

| Original operation | First part | Second part |
| --- | --- | --- |
| Generation | 64-byte ML-KEM generation seed | 32-byte X25519 scalar |
| Encapsulation | 32-byte ML-KEM coins | 32-byte X25519 ephemeral scalar |

The sealed token has a 141-byte binding prefix and a 24-byte nonce, followed
by the encrypted tape and a 16-byte tag. Its total lengths are 277 bytes for
generation and 245 bytes for encapsulation. Those lengths match the retained
native plan formats (C09, C10). These counts distinguish original KEM entropy,
token-sealing randomness and the outer journal's randomness.

`open` recomputes the expected binding, compares the complete prefix, and
authenticates the token. `generate_key` and `encapsulate` then supply a bounded
cursor over the reopened tape to the existing SDK operations and require the
cursor to be exhausted. They draw no replacement entropy on execution. A
malformed, incorrectly bound or unauthenticated token returns an error.

The native journal persists `Plan::Key(token)` or
`Stage::Encapsulation(token)` before executing that KEM operation. A retained
token survives an exact retry or a committed write whose caller saw an
unknown outcome. If an unsuccessful reservation never becomes authoritative
and a later attempt draws again, the later draw is a **new original slot**,
even when its external operation ID is the same. A reduction must retain
these two cases separately.

### Failure and replay table

| Actual case | Adapter action |
| --- | --- |
| Public scope, runtime, policy or capacity guard fails before a draw | Return that error; create no original entropy slot. |
| A fresh reservation is drawn, including one in an attempt that later fails | Record a new original slot and its real event order. |
| The retained reservation is first executed | Obtain this slot's KEM result and cache it before any subsequent write or release. |
| Execution is repeated from the same retained reservation | Retrieve the same KEM challenge/result; run the actual downstream checks and persistence. |
| Computation succeeded but target persistence did not commit | Keep the private computation cache; recover the authoritative original reservation. The cache does not authorize dispatch. |
| The target committed but the caller saw an error | Recover the committed target and its retained public result. |
| A different offer is supplied while a response plan exists | Preserve `Conflict`; do not rebind the existing encapsulation token. |
| The current plan is already completing or completed | Use the native cached control-flight path; do not allocate another KEM challenge. |
| The selected reservation or its target authentication key is explicitly revealed | Use the already justified candidate-local stop when its original eligibility is permanently false. |
| A permitted projection lacks such a certificate | Render it or retain its genuine charged comparison term; do not call it a full-session acquisition. |

Runtime and resource admission still occur at their actual sites. An abstract
key owner can carry a selected generation handle and the same lease/accounting
metadata without containing the challenger's unknown PQ seed. Reconstructing
such an owner after a process loss does not allocate a fresh generation slot.

## 4. Component-challenge routing

The concrete selected component is ML-KEM-768. C06's X25519 backend computes
ECDH and copies `shared.as_bytes()` directly, after rejecting a
noncontributory output. There is no intervening KDF that makes a source-level
claim of a uniform 256-bit component key. This pass therefore does not assert
the same real-versus-uniform32 KEM assumption for both native slots.

For candidate `j=(g,a)`, retain the exact original offer and admitted binding.
The ML-KEM challenge public key is assigned only to the original generation
slot `g`; its X25519 scalar is sampled locally from the source distribution.
At the first actual encapsulation computation of `a` on that original offer,
obtain the ML-KEM challenge ciphertext/key pair `(c_M^*, K_ch)`, compute the
actual X25519 ciphertext and DH value from `a`'s locally sampled scalar, and
feed the actual complete tuple into ContextBound. Repeated computation of
`a` returns this same component result. The adversary does not receive the
selected unknown tape merely because a wrapping key has been disclosed;
its acquired objects and the existing stop rules still determine that path.

For every later PQ decapsulation under the selected generation owner:

```
if pq_ciphertext == c_M_star:
    pq_shared = K_ch
else:
    pq_shared = component_decapsulation_oracle(pq_ciphertext)
traditional_shared = actual_X25519_decapsulation(local_scalar, traditional_ct)
if traditional decapsulation fails:
    return the actual error
return ContextBound(complete effective fields)
```

The target test is on the PQ ciphertext alone. It applies even if another
traditional ciphertext, application context, policy wrapper or eventual
hybrid tuple accompanies those same PQ bytes. Passing that PQ ciphertext to
an IND-CCA decryption oracle would violate its challenge-query restriction.
The actual X25519 error path is preserved, and it reaches no ContextBound
call. C04 shows that PQ decapsulation happens before the traditional leg in
the native program, so any counted primitive work before that error remains
in the reduction's budget.

Before challenge creation, ordinary selected-key decapsulation follows the
primitive experiment's prechallenge interface. A prechallenge query that
happens to equal the later sampled challenge is not silently removed.
Selected-origin challenge returns are not reassigned to a different generation
origin just because the other origin's public key happens to be equal. Other
generated key owners use their locally known actual keys. The real challenge
branch agrees with these relations up to the stated selected-pair correctness
term. The random branch is the explicitly defined component replacement
game; it is not a claim that all ordinary honest KEM computations continue to
agree after that replacement.

If `a` never targets the original retained offer arising from `g`, it cannot
be a usable member of this candidate pair. That conclusion uses the original
operation ledger and its attribution definition, not public-key equality.
Missing reservations and unaccepted calls still retain the ordinary public
execution unless a permanent-zero certificate justifies stopping.

## 5. Hidden-input hash family and cache identity

In the random-component branch, write `U` for the independent uniform
32-byte selected PQ challenge value. Every protected use of `U` in the native
profile is a ContextBound call. Define `m` to contain **all other effective
fields**, including the traditional shared secret and complete nested policy
context, and put `f(U,m)=encode(complete tuple)`.

The private interface caches by `m`, equivalently by the complete effective
tuple for this fixed hidden `U`. This is not a cache by `(g,a)` alone:

- a selected-PQ-ciphertext decapsulation with a different traditional
  ciphertext can produce a different tuple and requires its own table entry;
- exact tuples from several protected call sites retrieve the same answer;
- a different traditional shared secret must not be dropped from the key;
- two raw offers whose application-context hashes coincide do not create
  different effective tuples solely because their raw offer bytes differ;
- the original reservation, owner and full-offer metadata remain available to
  the provenance and root-use arguments, separately from the hash table.

For fixed `m`, `U -> f(U,m)` is injective; for distinct effective `m,m'`,
`f(U,m) != f(U,m')` for every `U`. Thus the retained hidden-input theorem can
be applied with entropy parameter 256, private-query count equal to the
number of distinct protected tuples, and the complete ordinary `H`-query
budget. Exact repeats are cached before they consume a new private query.

This comparison can materialize all actual KEM tapes locally, run their real
algorithms, and replace the selected component returns by `U`. It need not
reuse the previous component reduction's inability to see the challenge
tapes. Each reduction implements its own adjacent pair of experiments.
The source's unknown-tape record simulator continues to supply the public
record observations in either representation.

All ordinary SHA3 computation is retained: oracle-dependent setup, known
native records, policy and transcript digests, other KEM computations and the
final test. The complete later execution and any SHA3 work performed inside a
declared backend also count. The experiment retains the same additional
oracle `h`, and its preparation is not supplied as uncharged oracle-correlated
advice. Exact numeric query costs depend on the selected implementation of
the declared primitive interfaces and are not inferred from source-line counts.

The private ideal-hash comparison deliberately distinguishes its protected
table from the ordinary public oracle. An unrelated locally known computation
that accidentally hits a protected input still uses the ordinary `H`; that
event is covered by the hidden-input comparison's ordinary-query budget.
It is not silently assigned a fresh private answer, and no assumption that
independent values never collide is made.

## 6. Why the selected combined contribution has one root use here

### Concrete profile

Run the oracle-dependent preparation explicitly and count it. At the chosen
starting state, the two authoritative endpoints of one selected session have
matching established old root `r`, confirmed epoch and control parent, and no
pending selected rekey. The old root and wrapping keys may be disclosed.
The experiment then studies the **next** rekey of that session and its marked
first message. It allows the usual native preparation, response, final,
receipt, traffic, status and plaintext-free-resume calls, as well as subsequent
epochs after the selected rekey completes. It does not additionally hand the
selected private owner to an arbitrary low-level SDK caller or reactivate a
read-only physical copy as a second live history.

This fixes the initial state and supported call surface. It does not alter the
original recovery eligibility predicate. The original cut, entropy,
authentication, acquisition and final attribution tests are still evaluated
in their actual comparison-world traces.

### Source lemma

Fix original reservation slots `j=(g,a)` and a prefix at which their
immutable admitted binding identifies `a` as encapsulating on the **complete
retained original offer `O` produced from `g`** for this next rekey. The
source ledger, retained offer and admitted binding establish this fact
online; no future acceptance, eligibility or final attribution event is
assumed. If `a` is actually computed, let `c^*=(c_M^*,c_X^*)` be its original
full ciphertext and `m^*` its effective protected tuple suffix. Every
protected ContextBound use of `(U,m^*)` feeds the same pair

\[
\bigl(r,I_R\bigr),\qquad
I_R=D_R\Vert\texttt{pending-root/HKDF-SHA256/}
                 \Vert H(\operatorname{LP}(D_R\Vert\texttt{response-core})
                              \Vert\operatorname{LP}(C^*)).
\]

Here `C^*` is the complete native response core, before its confirmation tag.
Those uses are one original root initialization and its exact repetitions.
The invariant holds for every supported continuation of the matching prefix,
up to an already declared local stopping event if one occurs. It includes
continuations that never accept the target, fail eligibility, or end with
candidate score zero. Before any such computation there is simply no
selected root use.

An immutable nonmatching binding permits a local stop only through the
separately proved permanent-zero attribution rule. A later lack of acceptance
is not used to retroactively justify an earlier stop or this invariant.

**Proof by the native plan invariant.** Before installation, ordinary message
operations can change counters and retained traffic but do not replace
`state.rekey`; the only live assignments are the final and receipt
installation sites in C11. The preparer's generation token moves from
`Plan::Key` to `Plan::Signing` to `Plan::Ready` while preserving its original
identity. C09 checks the regenerated offer body against its saved bytes and
then preserves the exact signed offer. Each selected-key decapsulation in
C11 reconstructs this same owner from that token, verifies that its complete
public key matches the retained offer, and uses `kem_context(O)`.

At the responder, C10 stores the raw `O` with the encapsulation token. An
unequal offer conflicts before a retained token can be reused; a completing
or committed response returns its saved public flight. While the token is
live, recomputation therefore has the same original input and ciphertext.

The response prefix contains the fixed profile digest, context digest,
session, current and next epoch, responder role, control parent and
`H(offer-wire,O)`. The endpoints' initial established control state agrees,
and that prefix cannot change while this target's plan is pending. Equality
of the effective target tuple fixes the **entire hybrid ciphertext**, since
both ciphertext fields are present. Consequently its response core `C^*`
and the complete root information string `I_R` agree. The pending old root
is still the same initial `r` at both endpoints. A reply differing only in
signature or confirmation-tag bytes cannot change this core; its actual
verification result is still executed.

The responder changes its plan to `Stage::Signing{root,...}` before its
response is released, discarding the encapsulation token from the active
state. A crash before that persistence returns to the same token and old
root; a committed target returns the saved root. The proposer changes its
plan to `Completing` before root installation, discarding the generation
token. Thus an old target token is not executed under the newly installed
root. Completed or resumed controls use their saved flights. Authoritative
recovery preserves whichever transition actually committed. These facts
close the induction over calls, writes and crashes. Physical read-only
copies do not add an execution transition. ∎

This lemma concerns the **protected hidden-U family**. Known independent
origins and ordinary `H` queries keep their own computations and costs. It
does not assert that independently sampled numeric secrets never coincide.

### Why the source condition matters

For the source formula, choose one fixed combined value `S` and two known
old roots `r0 != r1`. Then

```
HKDF(r0, S, I0, 32)
HKDF(r1, S, I0, 32)
```

are different root allocations, even though their ContextBound tuple is
identical. Likewise, changing the complete root information creates another
allocation. The independent checker retains concrete values witnessing both
distinctions. These are algebraic counterexamples to deriving one-use from
tuple equality alone, not claimed attacks against the declared next-rekey
native profile.

A broader interface that imports or actively forks the selected owner,
reuses it across unrelated root states, or selects arbitrary earlier epochs
needs a corresponding source argument or a finite multiple-root-entry
construction. The tuple cache itself must remain correct in either case.
The concrete profile above already has the source property required by the
existing single-root entry.

## 7. Composition information supplied by this audit

The resulting chain keeps four identities separate:

| Layer | Identity used for consistency |
| --- | --- |
| Original KEM computation | original generation/encapsulation source slots and complete admitted bindings |
| ML-KEM decryption-oracle prohibition | selected key owner and exact challenged PQ ciphertext bytes |
| Protected ContextBound hash | full effective encoded tuple, including both shared-secret fields |
| Selected root initialization | old root and complete native root-information string |

It therefore supplies concrete calls for a component real/random comparison,
a hidden-input SHA3 comparison, and the existing uniform-contribution
root/message continuation. The component terms retain their whole derived
distinguisher and correctness term. A hidden-hash output-bit gap contributes
twice that value when applied to the candidate's `[-1,1]` score. Native
record/report correspondence and genuine projection residuals stay at their
existing comparisons. This audit does not relocate those terms or claim
that candidate-local games are one global ideal experiment.

## 8. Checks actually executed

`audit_source.py` was run with an explicit native checkout. It required all
fourteen mapped worktree files and both exact revisions to agree, and it
passed twelve named static assertions over the reviewed source. It fails on
missing objects, wrong worktree bytes or changed assertions. Those checks
bind the source facts; they do not mechanically prove the induction above.

`check_contextbound_adapter.py` passed **36** independent Python format and
finite adapter-model checks. They include the six already pinned core KAT
digests, a new realistic-width nested-policy encoding fixture, complete-tuple
aliasing across origin labels, distinction of all ten fields, two deliberately
incorrect cache-key controls, original-slot versus external-ID retry
semantics, target-PQ-ciphertext routing under changed hybrid suffixes, and the
same-contribution/multiple-root algebraic witness. Its fixed source KATs are
recomputed using Python's SHA3 implementation, separately from the Rust
combiner. The new width fixture uses synthetic bytes and is not represented
as a signed native protocol execution.

No Rust toolchain is present in this executor. This pass did not run the
existing Rust sealed-operation tests, native crash trajectories, Tamarin or
reference benchmarks; their retained results keep their original identities.
The self-contained checker requires no native checkout and is appropriate
for the manuscript CI. The explicit native source audit remains a separate
command with its receipt, so an unavailable source checkout cannot be hidden
behind a successful model-check run.
