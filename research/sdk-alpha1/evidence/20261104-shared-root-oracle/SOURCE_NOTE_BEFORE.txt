# Computational recovery: root extraction and transcript composition

Status: a source-derived conditional argument, checked on 2026-11-04 against
`21e00e9c3cfd193b9f51491888347f583620dfe0`. This isolates a necessary part of
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
