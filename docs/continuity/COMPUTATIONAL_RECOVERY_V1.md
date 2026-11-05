# Computational recovery: root extraction and transcript composition

Status: a source-derived conditional argument, checked on 2026-11-04 against
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. This isolates a necessary part of
the existing computational-security obligation. It neither changes the protocol
nor closes that obligation. The [joint multi-epoch symbolic result](RECOVERY_DEPENDENCIES_V1.md#multi-epoch-symbolic-successor)
remains valid within its stated ideal-primitive model; its 13 incomplete queries
and the separate implementation/release obligations remain recorded.

The specific question is whether a fresh hybrid contribution can restore a
usable secret root when the preceding root is known. Ordinary HMAC PRF security
does not by itself answer this question: the known value occupies the HMAC key
slot during Extract. There is, however, a concrete literature route for the
actual fixed-length inputs. This note also identifies the correct point at
which to replace a contribution in a hybrid argument and preserves the shared
calls that must be handled before concluding message secrecy.

## Actual derivation and shared calls

Write `F(k, x) = HMAC-SHA256(k, x)`, and `E(p, i, l)` for HKDF-Expand with
PRK `p`, information `i` and byte length `l`. Let `D` be the exact
[`REKEY_DOMAIN`](../../research/continuity-identity-candidate/src/contract.rs),
`DM` the distinct `MESSAGE_DOMAIN`, and `h(label, bytes)` the existing rekey
domain-separated digest. Every salt, root, combined secret and HMAC key below
has exactly 32 bytes; `0` denotes 32 zero bytes. In particular, absent salt in
HKDF is normalized to that value, not an absent Extract call. The dependency
lock selects `hkdf = 0.13.0` and `hmac = 0.13.0`.

For epoch `e`, with prior root `r`, combined KEM secret `s` and response core `c`:

```text
p  = F(r, s)
i  = D || "pending-root/HKDF-SHA256/" || h("response-core", c)
R  = E(p, i, 32) = F(p, i || 0x01)
```

This is [`response::derive_root`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs).
The responder constructs `c` from the admitted prefix and KEM ciphertext before
computing `R`, its confirmation tag and its signed response. Its KEM input is
the exact [sealed encapsulation reservation](../../crates/q-periapt-sdk/src/expert/replay.rs),
bound to the offer-derived context and current signed SDK policy.
The 32-byte `s` is the SDK's [ContextBound combination](../../crates/q-periapt-core/src/lib.rs),
using [streaming SHA3-256](../../crates/q-periapt-backends/src/streaming_sha3.rs)
over length-prefixed component secrets, public keys, ciphertexts, suite, policy
and context. It is not the raw ML-KEM output.

| Consumer of a new root | Exact key-schedule relationship | Public or later use |
| --- | --- | --- |
| Responder confirmation | `z = F(0, R)`; `k_resp = E(z, D || "responder-confirmation", 32)` | HMAC under `k_resp` over the response-core digest, then signed response |
| Final and receipt confirmation | The **same** `z = F(0, R)`; expand with `D || "final-confirmation"` or `D || "receipt-confirmation"` | HMAC over the respective domain-separated core, including the recorded old-chain closing count |
| Epoch traffic | `t = F(session_id, R)`; expand 128 bytes with the epoch-traffic label, context, epoch and digest of complete signed offer/response | Two directional chain seeds and two ACK keys |
| Next epoch's root | `F(R, S[e+1])`, then its pending-root expansion | `R` now occupies the **key** slot, including when another epoch's entropy is disclosed |
| A directional message step | `w = F(0, chain_seed)`; expand 64 bytes with `DM || "chain" || index_be64` | Next seed and one message key |

The final/receipt calls are in
[`control_mac`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs),
traffic in that file's `State::add_epoch`, and chain steps in
[`messages::step`](../../research/continuity-identity-candidate/src/durable/messages.rs).
`Traffic::from_material` assigns the directional and ACK slices; the sender
uses the resulting per-message key with ChaCha20-Poly1305 and a zero nonce.
Initial session installation separately expands 160 bytes under its initial
label, taking the first 32 bytes as the initial rekey root. It is not a fresh
recovery epoch and is outside the one-step argument below.

Repeated `(key, message)` pairs in this table must produce the same value in
every proof game. Do not replace the three `F(0, R)` calls by three independent
extractors. If a session identifier equals zero, the traffic Extract also aliases
that call; the subsequent labels differ. A proof must either account for this
case directly or bound an appropriate collision event, without inventing an
input check that the implementation does not perform.

## The prefix at which a secret can be replaced

Let `Z_pre` contain the preceding root, public offer, public keys, ciphertext,
response core, session/context/epoch values, all allowed prior leakage and the
adversary's state immediately before the target-root confirmation is generated.
The first unresolved premise is a construction-specific secret replacement:

```text
(Z_pre, S[e])  approximately equals  (Z_pre, U256)
```

The right-hand secret is independently uniform. This premise must be justified
for the actual ContextBound combiner and allowed attack interface, including
classical-secret disclosure in the PQ branch. A KEM theorem or SHA3 collision
resistance alone does not establish it. An accepted-prefix simulation must also
cover the honest decapsulation endpoint and any allowed oracle interactions.
For the compression-QROM route below, this requires a complete interactive
simulation with all oracle-dependent preparation counted, not only the displayed
marginal relationship with a fixed classical transcript.

The [ContextBound conditional hop](CONTEXTBOUND_SECRET_HOP_V1.md) now resolves
the encoding/ideal-SHA3 step **after** the component KEM secret has validly been
replaced by an independent uniform value. It uses the actual 2,639-byte rekey
combiner input and retains all policy/context fields in the distinct-input cache.
The preceding KEM simulation and shared-oracle setup remain obligations; the
lemma does not assume that a real component secret is already independent of
its ciphertext or oracle prefix.

The complete transcript is an unsuitable fixed auxiliary value for the same
claim. It contains a tag derived from `R`. Given a candidate root, an observer
can compute its responder-confirmation key and test the public tag. The real
root passes that relation; an independently sampled candidate need not. Under
the intended pseudorandom-key/MAC assumptions this distinguishes the proposed
joint distributions. The corresponding test for a candidate `S[e]` first uses
the known prior root and public core to derive `R`.

Therefore each replacement must consistently recompute the subsequent
confirmation tags, signatures, final/receipt messages, transcript digests and
traffic. Existing signature bytes cannot simply be retained after changing the
body they authenticate. This is a restriction on the proof game, not a proposed
runtime change: actual retries must continue returning the exact original bytes.

### Bridging the actual ContextBound contribution

The repository's existing [EasyCrypt binding result](../../formal/easycrypt/BindingViaCR.ec)
does not establish the prefix replacement. `bind_le_cr` and `malbind_kct_le_cr`
turn an output collision with different encoded fields into a hash collision.
Their games contain no challenge secret or real-versus-uniform secret test;
component decapsulation is abstract. The [paper's stated scope](../../paper/q-periapt.tex)
likewise distinguishes binding from secrecy. Those proved binding results remain
useful, but cannot be used as the missing `epsilon_K` bound.

[Giacon, Heuer and Poettering, sections 3.3 and 4.2](https://pure.royalholloway.ac.uk/ws/portalfiles/portal/29298086/kemcom.pdf)
give the relevant combiner structure: replace a secure component's challenge
secret by a uniform value, then apply a split-key PRF to the components and
ciphertext vector. Their Figure 5 permits the other component keys to be chosen
by the adversary per fresh public input. Theorem 1 supplies the KEM reduction;
Lemma 6 supplies a hash-based RO instance. Its correctness and challenge-query
conditions still have to be matched to the actual protocol interface. In
particular, the honest recipient internally processes the target ciphertext;
it is not simply the external decapsulation oracle forbidden to process a KEM
challenge. That internal use needs a consistent simulated response.

There is also a concrete route for the hashing step with quantum hash queries.
[Don, Fehr and Huang, section 4.2, Theorem 2](https://arxiv.org/pdf/2206.08132)
analyze `F(k,x) = H(h(k,x))` with a uniform hidden `k`, quantum queries to random
oracle `H`, and classical queries to `F`. The theorem requires an upper bound
`epsilon` on each encoded point's probability for fixed `x`, and distinct encoded
points for fresh `F` queries for every possible `k`. It supplies a bound in terms
of `epsilon` and the two query counts. This is an ideal-hash construction result,
not a claim that a concrete SHA3 implementation has been proven quantum secure.

After the still-required ML-KEM challenge replacement, instantiate these encoding
conditions as follows. Let `k` be the uniform 32-byte PQ secret and let `x` contain
the classic secret and every other **effective encoded field** of the actual
policy-bound ContextBound call. `h` is exactly the LP transcript absorbed by the
streaming backend, including the fixed domain and nested policy context. For
fixed `x`, the complete `k` occurs at a fixed 32-byte field with its length prefix.
Thus `h(k,x)` is injective in `k`, giving point probability at most `2^-256`.
For different effective field tuples `x`, LP injectivity gives different encoded
bytes for every `k`. This argument uses the actual tuple, not two semantic objects
that happen to serialize identically.

Exact repeated tuples must be served from the same proof-game cache. Only a
previously unseen effective tuple is passed as a fresh `F` query; replaying one
operation cannot sample a second random result. This matches the implementation's
sealed-operation replay and immutable response outbox. A known or adversarially
selected classic secret is part of `x`, rather than an assumption that X25519
remains confidential. These checks discharge the elementary encoding conditions
for this conditional hash step. They do not establish that the real `ss_pq` was
uniform given the permitted protocol view in the first place.

The remaining prefix bridge has three explicit interfaces to justify:

1. `verify_offer` precedes the responder's reservation, and the proposer checks
   that the restored private owner matches the public offer before decapsulation.
   Reduce accepted target flights to the corresponding honest KeyGen/Encaps
   under the actual identity-signature and authorization assumptions. The
   corresponding source checks are in
   [`rekey`](../../research/continuity-identity-candidate/src/durable/messages/rekey.rs),
   [`response`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs)
   and [`completion`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs).
   The [conditional body-origin reduction](AUTHENTICATED_BODY_LEMMA_V1.md)
   isolates the hybrid wrapper's implication under a chosen-rnd signature
   interface. It does not supply that primitive premise or original-wire,
   authorization and matched-flight authentication; existing classical-alias
   regressions demonstrate why these boundaries must remain distinct.
2. Simulate other reservations, allowed earlier/later entropy disclosure and
   public queries while embedding the target ML-KEM challenge. Account for the
   component's correctness-failure term and fixed versus adaptive target
   selection. The current SDK takes separate seed/scalar and encapsulation-randomness
   segments, but secrecy/independence still requires the stated recovered random
   source; API call ordering is not an entropy proof. Preserve all original
   post-Cut acquisition restrictions and allowed other-epoch leakage.
3. Specify how the combiner's SHA3 oracle relates to component and other protocol
   SHA3 calls. A separate independent oracle cannot be invented for two actual
   uses merely by renaming them in a proof. The effective-domain encoding and any
   shared-query simulation must be included, with the later confirmation and
   traffic consistently recomputed as above.

This narrows the prefix obligation to a concrete KEM/interface bridge plus an
identified RO/QROM hash theorem. It supplies neither a counterexample to the
actual combiner nor a completed Continuity computational secrecy proof.

### Concrete SHA3 input separation and reservation views

The fixed SDK runtime selects `MlKem768`, `X25519` and
`StreamingSha3_256Xof` in
[`Runtime`'s KEM construction](../../crates/q-periapt-sdk/src/lib.rs).
For a rekey response, `kem_context(offer)` is exactly 32 bytes. The effective
policy-bound ContextBound input therefore has the following byte lengths, in
the actual absorb order. Each outer field additionally has an 8-byte big-endian
length prefix.

| Field | Payload bytes |
| --- | ---: |
| `Q-PERIAPT-HYBRID-KEM/v1` | 23 |
| `ML-KEM-768+X25519` | 17 |
| Policy version | 4 |
| PQ secret, classical secret | 32 each |
| PQ ciphertext, PQ public key | 1088, 1184 |
| Classical ciphertext, classical public key | 32 each |
| Nested policy context | `(8 + 27) + (8 + 32) + (8 + 32) = 115` |

Thus the complete rekey input is **2639 bytes**, with the PQ secret at zero-based
byte offsets `[76, 108)`. More generally the same fixed suite's policy-bound
input is `2607 + application_context_length` bytes. This is arithmetic from
[`combine_validated` and `policy_bound_context_len`](../../crates/q-periapt-core/src/lib.rs),
not a claim based on sampling hash outputs.

In the selected native ML-KEM implementation,
[`mlk_hash_h`](../../crates/q-periapt-mlkem-native-sys/vendor/mlkem-native/src/symmetric.h)
is SHA3-256. Its three algorithm call sites in
[`kem.c`](../../crates/q-periapt-mlkem-native-sys/vendor/mlkem-native/src/kem.c)
hash the encoded public key during key checking, key generation and encapsulation.
For ML-KEM-768 each input has 1184 bytes; the same source's other parameter sets
use 800 or 1568 bytes. None can equal a policy-bound input of this fixed hybrid
suite. `mlk_hash_g` and `mlk_hash_j` instead call SHA3-512 and SHAKE256;
this observation does not prove independent security of the underlying Keccak
instantiations.

The rekey `hash` helper and the vault's `image_hash` use
[`crypto::digest_start`](../../research/continuity-identity-candidate/src/crypto.rs):
`LP(domain) || length_be64 || payload`. Their domains are longer than the
combiner's 23-byte first field, so their initial length prefixes already differ.
This establishes disjoint input points for these concrete honest SHA3-256
calls, even when a digest payload depends on the selected exchange.

For an ideal random function on complete byte strings, restrictions to these
disjoint sets are independent random tables: every complete assignment is the
product of its assignments on the sets and their complement. A public query
still addresses that **one** function, including a superposition across sets.
Any simulation using separate tables must route the query coherently by its
input bytes and retain consistency; the distinction does not remove queries
from the accounting or justify an oracle-independent starting state after
uncounted prefix queries. The SDK also hashes authenticated policy bytes directly
with SHA3-256. Those public inputs and other primitive calls remain in the full
simulation. These checks resolve the input-overlap question for the calls above,
not the complete shared-oracle/KEM reduction.

The durable view has two encryption layers whose contents must also be modeled:

| Observed value | Actual dependency |
| --- | --- |
| Sealed-operation header | `QPSOP001`, kind, 68-byte policy binding, operation ID, input binding and a fresh 24-byte nonce. The binding is constructed before drawing the reserved entropy. |
| Sealed-operation payload | XChaCha20-Poly1305 encryption of 96 key-generation bytes or 64 encapsulation bytes, authenticated against that header, plus its 16-byte tag. |
| Durable image and pending target | The encoded record payload, including any reservation, is encrypted again under the journal key. The pending write intent retains the exact sealed target before image apply. |
| Witness head | Fence, revision and `image_hash(sealed_image)`, rather than a hash of the plaintext reservation. |

The [SDK replay owner](../../crates/q-periapt-sdk/src/expert/replay.rs),
[offer and response reservation paths](../../research/continuity-identity-candidate/src/durable/messages/rekey.rs),
[response path](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs),
[image sealing](../../research/continuity-identity-candidate/src/durable.rs),
[write intent](../../research/continuity-identity-candidate/src/durable/write_intent.rs)
and [Witness head construction](../../research/continuity-identity-candidate/src/durable/anchoring.rs)
give this dependency chain. The offer operation ID uses the journal/session/control
prefix; the response operation ID additionally binds the authenticated offer.
Neither is constructed by hashing the newly reserved plaintext coins. This removes
one possible direct public commitment to unknown challenge coins, but does not
establish a simulator for the encrypted records or their public head hashes.

In particular, `rekey_recovery_key` derives the SDK wrapping key from the same
journal key used for the outer image. A disclosed journal key plus later access
to the target token or image is still a disclosure of its coins. Encryption
cannot justify replacing those coins while retaining a decryptable old record.
The reduction must preserve the original allowed acquisition interfaces,
including pending targets, and simulate their complete views or charge the
applicable existing disclosure event. Public heads, ciphertext-only access and
decryptable private-state acquisition are distinct cases; silently removing the
last case from the threat model is not a proof step. The earlier
[executed disclosure traces](RECOVERY_CONDITIONS_V1.md#durable-freshness-is-reservation-freshness)
continue to apply.

### A conditional hop for one hidden-image head

There is a more specific route for a head-only view, even when the journal key
is known. It does **not** apply when the observer obtains the corresponding
image, nonce or a decryptable pending target. Let `x` contain the journal key,
bounded plaintext and admissible fixed public image-header fields. Let `N` be a fresh independent
uniform 192-bit outer-image nonce, used only inside the following private map:

```text
g(N, x) = LP(image_digest_domain) || length_be64 || sealed_image(N, x)
head(N, x) = H(g(N, x))
```

The actual sealed image contains `N` verbatim at outer-header offsets `[80, 104)`.
Consequently `g(N, x)` is injective in `N` for each fixed `x`, independently of
whether the observer knows the encryption key or plaintext. Its point probability
is at most `2^-192`. The function `g` uses deterministic image encoding and
XChaCha20-Poly1305 with the supplied nonce; it does not call `H` internally.

In [Don, Fehr and Huang, Theorem 2](https://arxiv.org/pdf/2206.08132),
set the hidden key to `N`, `epsilon = 2^-192` and the classical function-query
count to one. The freshness condition is then vacuous. For an algorithm making
at most `q_H` quantum queries to the global ideal SHA3-256 oracle, the difference
between its output probabilities with this private head call and with an
independent uniform 256-bit reply is bounded by

```text
min(1, 4 sqrt(2 q_H 2^-192) + 4 sqrt(2 q_H^2 2^-192)).
```

The algorithm may choose `x` adaptively from its preceding oracle interaction.
All prefix and later queries, including honest queries outside this one private
call, count toward `q_H`; uncounted oracle-dependent auxiliary state is not
allowed. Exact reads and retries of this one head reuse the first reply. This
experiment does not additionally expose the nonce or preimage: the theorem's
private function interface does not provide them. Merely hiding the plaintext
while publishing the nonce would not satisfy these premises.

This supplies a conditional random-oracle replacement for **one** public head.
It uses the nonce field's injectivity, not confidentiality of encryption under a
leaked key. A [pending-recovery proposal](../../research/continuity-identity-candidate/src/durable/write_intent/pending_recovery.rs)
also commits to the original write intent; that additional digest cannot simply
be left out of the game. The ordinary, unbound intent admits the following
two-call extension.

`PendingWrite::new_bound(..., None)` encodes `QPWINT01`, the original journal and
owner, expected revision/digest, target revision/digest, a four-byte target
length, the complete sealed target, then its HMAC. Its fixed header has 156
bytes, so the same target-image nonce occurs at intent offsets `[236, 260)`.
The published intent commitment uses `crypto::digest` with
`Q-PERIAPT-CONTINUITY-PENDING-WRITE-INTENT/v1`. That domain has 44 bytes, while
the image-digest domain has 45 bytes.

Define a single private function keyed by `N` with two permitted query types.
The first returns the image head above. The second returns the intent digest,
constructing the exact same sealed image and taking the first returned head as
the explicit target-digest field. The intent map includes its HMAC under the
derived journal write-intent key; both that KDF and the HMAC use SHA-256, not the
modeled SHA3-256 oracle. Each map is injective in `N` because its input retains
the nonce verbatim. Their distinct first length prefixes make the two hash
inputs different for **every** nonce and every admissible choice of the other
fields. With at most one fresh query of each type, Theorem 2's two conditions
therefore hold with `epsilon = 2^-192` and `q_O = 2`. The resulting bound is

```text
min(1, 4 sqrt(8 q_H 2^-192) + 4 sqrt(4 q_H^2 2^-192)).
```

In this ideal experiment the two replies are fresh independent uniform values;
the second query and later proposal/metadata/signature construction still use
the first reply consistently. Every honest reread of either original digest
uses its cached reply. Both the image and intent remain private; their public
digests do not confer permission to expose their preimages. The metadata
projection for a message record reports identities, epoch progress, counters,
ciphertext digests and retained input lengths; it does not serialize that
record's rekey root or KEM reservation. See
[`historical_session`](../../research/continuity-identity-candidate/src/durable/messages/retired.rs)
and the [public encoder](../../research/continuity-identity-candidate/src/durable/retired_report.rs).

This extension covers these two digest interfaces for one ordinary intent.
It does not establish an inventory of all output paths or a multi-image
composition, and it does not cover bound credential/policy/roster intents by
analogy. Applying it to the whole accepted prefix still requires consistency
across revisions and retries and the mapping of aggregate/pending acquisitions
to the unchanged disclosure conditions. The source's fresh `getrandom` call is
not itself a proof of uniform independent
entropy. This hop neither admits later ciphertext acquisition nor closes the
ML-KEM challenge simulation, the concrete SHA3 instantiation or the multi-epoch
computational claim.

The follow-up [original-record commitment inventory](HIDDEN_RECORD_COMMITMENTS_V1.md)
identifies four additional raw-intent digest domains in retirement, Witness
selection and account-root recovery. It derives a conditional six-interface
hop for one private original write, with explicit offsets for all eight write
tags and separate handling of target-free cancellation records. Its full-domain
separation argument also handles the two distinct 44-byte domains. This is a
larger single-record experiment; the accepted-prefix simulator and multi-record
acquisition/composition obligations remain open.

## Public-salt extraction has a specific sufficient assumption

After the first replacement the necessary extraction direction is
`G_U(r) = F(r, U)`, with uniform hidden `U`. The value `r` can be public and may
depend on the prior history. This is the swapped direction of HMAC; ordinary
PRF security instead makes the first input the hidden key.

[Backendal, Bellare, Guenther and Scarlata, CRYPTO 2023, Theorem 11](https://eprint.iacr.org/2023/861.pdf)
proves swap-PRF security under compression-function PRF and collision-resistance
assumptions and a specified padding-related-key PRF assumption on the swapped
compression function. The original HMAC key-input set must be feasible. Here it
is `{0,1}^256`, a single length below SHA-256's 512-bit block length, so that
condition is met. The hidden message also has 256 bits: their parameters become
`a = 256` and `n = 1`. Thus the theorem gives the sufficient classical bound
`epsilon_swap <= 2 epsilon_padding_RKA + epsilon_compression_PRF + epsilon_CR`
with the theorem's corresponding adversary resources. This is a parameter
instantiation, not verification of those assumptions for SHA-256, a PQ lifting,
or the later joint composition. Theorem 10 treats the conventional direction;
neither direction is justified merely by saying that HMAC is widely used.

[RFC 5869, sections 2–3](https://www.rfc-editor.org/rfc/rfc5869.html#section-3)
permits a public salt while retaining requirements on the input distribution
and context. [Krawczyk's extract-then-expand theorem, section 4.1](https://eprint.iacr.org/2010/264.pdf)
separately assumes extraction and PRF expansion. These sources support separating
the two obligations; they do not supply a theorem for this entire ratchet.

For comparison, ordinary PRF security cannot logically imply the missing
direction for an arbitrary function family. Given a secure `(n-1)`-bit PRF
`A_a` and an `n`-bit secure permutation `P_b`, define
`F_(a,b)(x) = P_b(0 || A_a(x))`. With both keys hidden, replace `A` by a random
function and `P` by a random permutation. On `q` distinct inputs, unless there
is a birthday collision in `A`'s outputs, the results are uniformly distributed
distinct `n`-bit values. Its ordinary PRF distinguishing error is bounded by
the two primitive advantages and `O(q^2 / 2^n)`. Once `b` is known, invert `P_b`
and inspect the first bit: actual outputs always give zero, whereas uniform
outputs give zero with probability one half. This remains true for an unknown
uniform `x`. This logical separation is not an attack on HMAC-SHA256.

## A conditional one-step hybrid

For a fixed target epoch and admitted prefix, consider only an efficient
key-schedule continuation whose target-secret dependence is through the derived
root. Its remaining inputs must be simulatable without the unrevealed target
reservation coins; any authentication/oracle simulation belongs to the prefix
premise. Give the continuation the root internally, and release only the outputs
of the prescribed game. Do not additionally reveal a challenge root while
retaining a fixed confirmation transcript.

1. `G0`: use the actual `S[e]`, Extract and Expand, then run the continuation.
2. `G1`: replace `S[e]` by `U256`, then recompute all downstream values. The
   prefix/combiner premise bounds this change by `epsilon_K`.
3. `G2`: replace `F(r, U256)` by independent `V256`. The swapped PRF at the
   allowed 32-byte input `r` bounds this change by `epsilon_swap`. The
   continuation consumes the derived root, not the replaced raw contribution.
4. `G3`: replace `F(V256, i || 0x01)` by independent `W256`, and run the same
   continuation consistently from `W256`. Here `i` is fixed by `Z_pre`, and
   the ordinary PRF direction bounds the change by `epsilon_prf`.

By composing the three distinguishers, the difference between the output
distributions of `G0` and `G3` is at most
`epsilon_K + epsilon_swap + epsilon_prf`, with continuation cost included in
each reduction's resources. This gives a conditional root-replacement step.
It does **not** show that message keys in `G3` are independent of the public
transcript, nor establish the prefix premise, authentication, adaptive target
selection or the multi-epoch theorem. Those must be supplied separately.

## Remaining composition needed for the declared claim

The table identifies the next finite proof obligation. A uniform `R` is used in
the message slot of `F(0, R)` and `F(session_id, R)`, while later epochs use it
in the key slot of `F(R, S[e+1])`. Separate forward and swapped PRF guarantees
do not automatically supply their joint guarantee with the same hidden value.
The traffic information field also contains a response tag derived from `R`.
Key separation must be established before treating that information as harmless
auxiliary data. The three confirmation keys, directional chains and ACK keys
must retain their exact labels and repeated-call relationships.

A possible alternative is a single keyed-random-oracle model for **all** these
HMAC calls, preserving equal input pairs and shared queries. The fixed 256-bit
key length satisfies the restricted-key shape considered by
[Dodis et al., section 4.4](https://homes.cs.washington.edu/~tessaro/papers/h2fullprelim.pdf).
Their indifferentiability results assume an ideal underlying primitive. They
are not a concrete SHA-256 theorem or a quantum-oracle argument for Continuity.
This route has not been selected as a replacement security assumption.

A subsequent [single-root ideal-oracle lemma](SHARED_ROOT_ORACLE_V1.md) gives a
finite coupling for the shared row/column interface, including repeated calls
and the zero-session-id alias. Its real-game statement counts all preparatory
oracle queries; a retained counterexample explains why root independence alone
does not justify holding an oracle-correlated prefix fixed. This closes that
conditional ideal-game calculation, not the HMAC instantiation, accepted-prefix
premise or full protocol composition. It does not select a new product
assumption or change the obligations below.

The subsequent [shared-root HMAC reduction](SHARED_ROOT_HMAC_V1.md) works one
level closer to the implementation: one ideal SHA-256 compression oracle and
the actual 32-byte HMAC encodings, including the consumed-key-pad length offset.
It handles both classical root-row and root-column calls in each hybrid, with
public quantum compression queries, and retains public-salt state-pair aliases.
Its DFH/HI theorem applications and exceptional shared-pair coupling were checked
independently; the actual pinned HMAC/HKDF/SHA-256 dependencies also passed finite
encoding comparisons. This closes the stated conditional primitive calculation.
It does not establish that the real prefix supplies its required joint product
initialization, that concrete SHA-256 is an ideal compression function, or that
the whole protocol exposes only those interfaces. In particular, it does not
silently select a new product assumption or discharge the obligations below.

The [root-extraction corollary](ROOT_EXTRACTION_QROM_V1.md) applies that primitive
calculation twice to this source's actual Extract and 98-byte Expand input.
It gives an explicit same-oracle conditional root-replacement bound, including
single-entry resampling with a quantum prefix state and the two simulations'
ordinary-query costs. Pinned-library encoding checks support the source mapping;
they do not prove the required independent-contribution or disclosure premises.
The actual accepted-prefix bridge and the full continuation below remain open.

To connect the argument to the existing main claim, retain these obligations:

- Establish fresh target contributions under the actual identity and reservation
  leakage model. Other-epoch entropy disclosure remains allowed; excluding it
  would weaken the [original main formula](../../research/continuity-recovery-symbolic/multi-epoch.spthy).
  Map whole-image/pending-write acquisition to every retained target secret.
- Establish accepted-flight authentication and matched honest KEM inputs,
  including the PQ identity branch and permitted signing-randomness auxiliary
  information. Possession of the old root or TLS alone does not provide this.
- Prove the shared key-schedule composition, then message/ACK security and
  direction/epoch separation with explicit resource and target-selection bounds.
  The zero-nonce [traffic implementation](../../research/continuity-identity-candidate/src/durable/messages/traffic.rs)
  requires distinct per-message keys and exact retry semantics;
  [RFC 8439 section 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4)
  explains the consequence of key/nonce reuse. A new plaintext cannot reuse an
  old reserved key, and retained traffic cannot be treated as erased.
- State and justify the quantum-adversary assumptions/reductions used for the
  PQ claim. A classical game argument is not silently promoted to QROM security.

These are the construction-specific computational obligations already named in
the recovery contract, now with a concrete extraction route and game boundary.
No attack on the actual HMAC construction is asserted. No product source,
protocol bytes, threat-model exclusions or proof-query formulas changed here.
Verification in this note consists of source-path/equation checks, theorem-input
matching and the conditional argument above; no machine-checked computational
proof or new empirical security experiment is claimed.
