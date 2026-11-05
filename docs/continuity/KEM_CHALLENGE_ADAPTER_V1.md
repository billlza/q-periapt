# Original-operation KEM challenge adapter

This note gives a reduction for a **specified virtual original-record game**.
It is an intermediate argument, not a completed simulation of the native
Continuity prefix or a multi-epoch security theorem. The missing refinement
between actual private storage/output paths and the game below remains explicit.
Source observations are pinned to `baa4e975a2502cbb2a33e1e18dd19b37be663abe`.
The [source capture](../../research/sdk-alpha1/evidence/20261105-kem-challenge-adapter/README.md)
records the relevant call order and the unchanged MAIN predicate. No new
primitive execution, Tamarin run or external review is claimed here.

## Source association before decapsulation

Consider one honest original-operation history for the selected session. The
[storage contract](STORAGE_RECOVERY_V1.md) already assigns the host responsibility
for one authoritative lineage per configured device; it does not claim protection
from a hostile same-UID host. This argument does not turn a snapshot interface
into authorization to restore/fork private state or forge records using a leaked
wrapping key. Such behavior needs its actual storage/authority model.

Outside a fresh accepted purpose/body forgery and the relevant digest-collision
events, an accepted new response has the following source provenance:

1. The only production signing site for `Purpose::RekeyResponse` is
   [`respond_rekey_offer`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs).
   It authenticates the offer before reservation. An existing response/completion
   plan rejects a different full offer wire; a ready plan returns its retained
   response after rechecking authority and the cached signature.
2. The responder's body prefix binds profile, context, session, local/target
   epochs, role, parent and the hash of the actual supplied offer. Its ciphertext
   and root are computed from the retained encapsulation token. The complete
   body/root/signing reservation is persisted in phase 5 **before** the signing
   call. The ready response is persisted before release.
3. For one such retained history, an exact retry cannot create a second signed
   response body from new encapsulation coins. Before a reservation is retained,
   a failed attempt may have sampled unused coins; it has not passed the
   subsequent persistence/signing boundary. After retention, computation resumes
   the original token. An unknown commit must be reconciled, not treated as a
   fresh slot.
4. [`accept_rekey_response`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs)
   verifies the response signature and exact prefix against its retained offer
   **before** reconstructing the key or decapsulating. Equality of the offer-wire
   digest identifies that original wire outside its collision event. The
   reconstructed public key must also equal the public key in that offer.

Consequently, under those origin/history premises, the new accepted response
body belongs to the honest encapsulation of that original offer, and the
proposer uses the corresponding retained key-generation operation. This is
stronger than body-origin alone but still conditional on the honest history,
surrounding signing-interface simulation and collision bounds. It is not a
proof that every body passing the cryptographic verifier has current authority.

Exact cached returns are separate: a matching completed response returns its
retained final, while a different response on a completion plan conflicts.
These paths do not perform a new decapsulation. A classical-only response
signature alias can preserve the body and root confirmation yet change the
full-wire traffic-transcript input. The [executed alias cases](../../research/sdk-alpha1/evidence/20261105-rekey-classical-alias/README.md)
remain relevant. `FinalReady` installs the proposer's sending epoch before its
receipt arrives; successful final acceptance or confirmation by both peers is
not added as a prerequisite for application-message simulation.

## Primitive experiment and correctness event

Define a single-key component experiment explicitly. Its challenger samples
`(ek*,dk*) <- KeyGen`, then `(K*,c*) <- Encaps(ek*)`. It gives an algorithm
`ek*,c*,T`, where `T=K*` in experiment 0 and `T` is an independent uniform
32-byte value in experiment 1. Classical decapsulation requests on `c != c*`
are answered using `dk*`; requests on `c*` are forbidden. The algorithm may be
quantum. Any public hash-oracle interfaces are the same ones used by the
challenger and the surrounding protocol, with the intended query accounting.
No independent per-layer SHA3 oracle is invented.

Let `Adv_CCA(B)` be the absolute difference between `B`'s output-one
probabilities in these two experiments. Define

```text
BadCorrectness := Decaps(dk*,c*) != K*
delta_corr := Pr[BadCorrectness].
```

This is one challenge pair's correctness event, not an assertion of perfect
correctness. All exact decapsulation retries of `c*` share this same event.
For ML-KEM, length-admitted ciphertexts preserve implicit rejection; the adapter
does not obtain or return a secret-dependent validity bit. The actual seed,
parameter and byte boundary is described in the
[ContextBound note](CONTEXTBOUND_SECRET_HOP_V1.md) and
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
Neither that standard nor this definition establishes the needed concrete
primitive advantage or its shared-oracle instantiation.

## The virtual original-record interface

Fix a selected session, a generation-reservation invocation and an
encapsulation-reservation invocation intended to be that session's original
rekey pair. Count invocations at the actual randomness reservation call,
including attempts which later fail before persistence; an epoch counter or
reused operation identifier alone is not an invocation index. The selected
encapsulation must use the public key of the selected generation. Connecting
every eligible MAIN message to such a unique pair, and lifting this fixed-pair
experiment to an adaptive target, are separate proof obligations.

The virtual machine retains ordinary semantic protocol state and original
operation handles with exact kind, policy, operation, peer/context bindings,
length, persistence disposition and retry identity. A selected handle contains
an opaque PQ reservation instead of fabricated private coins. Its X25519
component is sampled and computed normally. Nonselected PQ operations use
ordinary locally generated keys and coins.

The private-record interface has these defining properties:

- Original writes, unknown-commit reconciliation and retries retain the same
  handle and known metadata. A genuinely new reservation receives a new handle;
  it does not silently inherit an abandoned reservation's unknown coins.
- Public commitments of selected opaque records are supplied by the separately
  specified ideal commitment interface, with consistent original-record caches.
  Public metadata/status and protocol messages are computed from semantic state,
  known bindings and component results. Raw opaque token/image bytes are not
  output by this interface.
- A returned error remains the real modeled error. The adapter cannot substitute
  `InvalidCheckpoint`, an empty record or success because it cannot serialize
  unknown coins. Public runtime/policy/resource gates remain in order.
- Acquisitions and entropy requests are classified using their actual asset
  origins and the unchanged recovery predicate. A successful prohibited
  disclosure makes the selected recovery experiment ineligible. A request for
  nonexistent state which returns an ordinary error is not a disclosure event.

This defines the intermediate game; it is **not** a claim that the full SDK
persistence API already satisfies this interface. In particular,
`SealedOperation::as_bytes` is public to its SDK caller. In the selected
Continuity path those tokens are inside private protocol records; their actual
visibility must be established, not inferred from a Rust type name. The SDK
replay module explicitly assumes a trusted host and does not authenticate a
host which controls its sealing key against that same host.

Let `Eligible` include the unchanged selected recovery restrictions: reservation
origins after Cut, absence of target-identity disclosure across all uses, absence
of selected-epoch entropy disclosure, and no acquisition of a selected-session
post-Cut saved state. Actual aggregate/pending/archive acquisitions need a
content/provenance mapping to that last condition. Missing selected events or
a nonmatching fixed pair do not form the selected experiment. Other permitted
disclosures must still receive their real answers.

For the reduction, define the observed bit as
`Eligible AND D_output`. This uses an unconditioned event probability; it does
not divide by `Pr[Eligible]` or discard difficult eligible executions. Once a
successful disclosure has irrevocably falsified the original restrictions,
the reduction can stop with bit zero. That is termination of the security
experiment, not an SDK response or an assertion that disclosure was rejected.
If the eligibility classification itself requires an unestablished asset map,
the native-to-virtual simulation remains unproved at that point.

## Adapter and coupling

The adapter receives `ek*,c*,T` from its primitive challenger and retains them
privately until the corresponding virtual events. It never tries to reconstruct
the missing PQ seeds, `dk*`, or selected encapsulation coins.

| Virtual operation | Adapter behavior |
| --- | --- |
| Reserve selected generation | Retain an opaque PQ handle and normal X25519 material under the original metadata; do not publish `ek*` early. |
| Execute/replay selected generation | Apply the same gates, return `ek*` paired with that original X25519 public key, and retain the same key handle. |
| Reserve selected encapsulation | Check the exact original peer/context/policy binding and retain a distinct original encapsulation handle plus its normal X25519 reservation. |
| Execute/replay selected encapsulation | Return `c*` paired with the original X25519 ciphertext and use `T` as the PQ component; retain exact original results. |
| Decapsulate with the selected key, PQ ciphertext `c*` | Use cached `T`; **no primitive decapsulation-oracle request**. Then execute the normal classical component, combiner and downstream checks. |
| Decapsulate with the selected key, another PQ ciphertext | Query the permitted primitive oracle, preserving length/error and implicit-rejection semantics, then continue normally. |
| Any nonselected key/encapsulation operation | Compute normally from its retained locally sampled material, even if public bytes happen to coincide with a selected value. |
| Permitted acquisition/reveal | Return the real known material. An eligible view requiring unknown selected coins is an unresolved simulation failure, not a default value. |

In experiment 1, replacing the selected-key decapsulation at `c*` applies to
every such call, including a call before the selected encapsulation is publicly
released. This is the definition of the intermediate hybrid. There is no
forbidden pre-challenge query hidden in a timing exception. Other independently
generated keys and encapsulations are not silently replaced just because some
public bytes coincide; they remain ordinary operations in both experiments.
The adapter knows their material and can implement this rule exactly.

In the real component branch, pre-sampling the selected key and encapsulation
is equivalent to keeping their unused independent random tapes until their
invocations: the SDK's fixed ML-KEM component does not take protocol context or
operation IDs as key-generation/encapsulation inputs. The public effects are
still delayed until their actual protocol release points. The prior oracle
interaction is reproduced by the same shared oracle, not supplied as free
oracle-correlated advice. The random branch is the explicitly defined virtual
override game above; it need not be a literal execution of the concrete KEM.

Conditional on no `BadCorrectness`, every selected-key decapsulation of `c*`
in the real branch equals `T=K*`. All other selected-key ciphertexts use the
actual decapsulation oracle, and all other keys use their real local material.
Thus the real adapter and the real virtual machine couple on all component
results, known metadata, failures and exact retries. The downstream machine
recomputes roots, tags, signing reservations, signatures and traffic using
those results. It does not keep a real-world signed body after changing its
root input. In the random branch, the adapter implements the virtual override
game exactly by definition.

For this fixed-pair virtual experiment, with those identical surrounding
interfaces, the resulting bound is

```text
| Pr[V_real outputs 1] - Pr[V_override outputs 1] |
    <= Adv_CCA(B) + delta_corr.
```

There is one correctness term for the repeated challenge pair. The adapter
makes at most one oracle request per nonchallenge decapsulation call, or fewer
when exact results are safely cached; it makes none for `c*`. Its running time
and all wrapper/hash queries must be included in the primitive experiment.
No classical-component secrecy is used to implement this reduction.

## What this does and does not close

This supplies an explicit challenge adapter, its forbidden-query handling,
original retry behavior, early challenge-ciphertext case and correctness loss
for the stated virtual game. The [ContextBound hop](CONTEXTBOUND_SECRET_HOP_V1.md)
can then use the independent test secret in the override branch, but only with
its complete full-tuple cache and whole-prefix query ledger. The PQ component
cache and the combined-secret cache must not be collapsed into one cache.

To connect the game to the actual accepted prefix, the remaining work includes
the complete private-record abstraction and its error bound across images,
all acquisition/partial-write/retained-copy paths, source provenance for the
selected pair across allowed recovery histories, adaptive target accounting,
and the actual shared-oracle primitive assumptions. The existing
[six-domain commitment argument](HIDDEN_RECORD_COMMITMENTS_V1.md) and
[aggregate-copy experiment](RECOVERY_DEPENDENCIES_V1.md#aggregate-image-lineage)
support parts of that work, but do not establish it as a whole. The ML-DSA
surrounding simulation is also still required when excluding fresh bodies.
No assumption that both peers have confirmed, no new corruption exclusion and
no product-contract change is introduced to make the native prefix qualify.
