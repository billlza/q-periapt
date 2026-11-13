# ContextBound after a component-secret replacement

This closes one conditional encoding/ideal-hash step of
[computational recovery](COMPUTATIONAL_RECOVERY_V1.md). **It starts after** a
valid component-KEM simulation has replaced the selected ML-KEM secret with an
independent uniform 32-byte value. It does not establish that preceding
simulation, the full accepted prefix, or multi-epoch message secrecy. In
particular, an actual ML-KEM output is not assumed uniform independently of
its public ciphertext merely because it has 32 bytes.

The source pin is `f6de14a347bbd9865077ce4a09d24164b41fe51e`.
The [encoding readback](../../research/sdk-alpha1/evidence/20261105-contextbound-secret-hop/README.md)
executes the actual core encoder on public chosen-byte fixtures, computes real
SHA3-256, and independently parses and hashes its output. It does not execute
ML-KEM, prove a random-oracle theorem, or change product code.

## Actual component and input boundary

The [SDK runtime](../../crates/q-periapt-sdk/src/lib.rs) constructs
`HybridKem<MlKem768, X25519, StreamingSha3_256Xof>` through `new_policy_bound`.
The suite is `ML-KEM-768+X25519`, and the profile is ContextBound. P-256 belongs
to the separate hybrid-signature path; it is not this KEM's classical component.
The [KEM composition layer](../../crates/q-periapt-kem/src/lib.rs) keeps both
component secrets in local zeroizing buffers and passes them to the combiner.
Only the combined secret crosses this composition API boundary.

The [sealed replay owner](../../crates/q-periapt-sdk/src/expert/replay.rs)
reserves 96 bytes for key generation and 64 for encapsulation. The SDK consumes
them in order: 64 ML-KEM key-generation seed bytes then 32 X25519 scalar bytes;
32 ML-KEM encapsulation bytes then 32 X25519 ephemeral scalar bytes. These are
internally sampled reservations, separate from the 24-byte token-wrapping nonce
and the journal image's outer nonce. Re-execution consumes the original bytes.
[FIPS 203 algorithms 16–18](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
specify the component's two 32-byte key-generation seeds, one 32-byte
encapsulation input and deterministic decapsulation. Within admitted ciphertext
lengths, invalid ciphertexts use implicit rejection, so a simulator must not
replace that component interface
with a public ciphertext-validity flag.

Let `LP(b) = len_be64(b) || b`. The actual
[`combine_policy_bound`](../../crates/q-periapt-core/src/lib.rs) input is

```text
LP("Q-PERIAPT-HYBRID-KEM/v1") || LP("ML-KEM-768+X25519")
|| LP(policy_version_be32) || LP(T) || LP(S_X)
|| LP(C_PQ) || LP(PK_PQ) || LP(C_X) || LP(PK_X)
|| LP(LP("Q-PERIAPT-POLICY-CONTEXT/v1")
      || LP(policy_digest) || LP(application_context))
```

`T` is the selected PQ component secret, and `S_X` is the X25519 component
secret. For the actual rekey path, `application_context` is the 32-byte
`response::kem_context(offer)` digest of the complete retained offer wire.
It is not the complete response wire or a caller's shortened representation.
The version occupies four bytes; the signed-policy digest occupies 32.

| Outer field | Payload bytes in this rekey path |
| --- | ---: |
| Combiner domain | 23 |
| Suite | 17 |
| Policy version | 4 |
| PQ secret `T` | 32 |
| X25519 secret `S_X` | 32 |
| PQ ciphertext | 1088 |
| PQ public key | 1184 |
| X25519 ciphertext | 32 |
| X25519 public key | 32 |
| Nested policy/application context | 115 |

Including the ten eight-byte outer length prefixes, the input has **2,639
bytes**, with `T` at offsets **`[76,108)`**. The nested context contains its own
three length prefixes. The streaming backend computes SHA3-256 of these exact
bytes; the trait name `Xof256` does not change that concrete algorithm.

The executed probe captures this input from the actual Rust generic encoder.
Its base fixture and a fixture changing only the first PQ-secret byte differ
only at offset 76. A fixture changing only the first application-context byte
differs only at offset 2607. Independent Python SHA3-256 agrees with all three
Rust outputs. The component key/ciphertext fixture bytes are publicly chosen
serialization inputs, not newly generated or validated ML-KEM objects.

## The conditional private-function game

Let `T` be uniform in `{0,1}^256`, independent of the ideal SHA3-256 oracle `H`
and the entire setup before its use. Let `x` be the complete canonical tuple of
all the other fields above, including `S_X`, policy and context. Denote the
encoded input by `E(T,x)`. The surrounding algorithm may know the classical
secret and choose `x` adaptively from earlier oracle interactions. No secrecy
of X25519 is used in this step.

A private function returns `H(E(T,x))`. The game allows classical calls to
that function and counted quantum queries to `H`. Exact repeats of the entire
tuple `x` use the original cached reply; let `q_O` count distinct tuples.
All other uses of `T` must be absent or represented by this interface. Raw
component-secret exposure, an extra commitment to `T`, and later recoverable
target coins are not granted by this game.

For every fixed `x`, the encoded preimage contains `T` verbatim. Thus for any
preimage `w`, at most one `T` satisfies `E(T,x)=w`, giving point probability
at most `2^-256`. For distinct canonical tuples `x` and `x'`, length-prefixed
decoding distinguishes their first differing field for **every** `T`, including
fields inside the nested context. Consequently `E(T,x) != E(T,x')` for every
key. This supplies the point-probability and fresh-input premises of
[Don–Fehr–Huang, Theorem 2, equations (6)–(7)](https://arxiv.org/pdf/2206.08132).
Our substitution gives

```text
epsilon_combiner(q_H,q_O) = min(1,
    4 sqrt(2 q_O^2 q_H 2^-256) + 4 sqrt(2 q_H^2 q_O 2^-256)).
```

The private function can therefore be replaced in this experiment by independent
uniform 256-bit replies indexed by the full tuple, with the stated bound. For
one original input, `q_O=1`; the actual accepted-prefix proof must justify that
count or retain the general bound. It cannot assume it from an epoch number.
This is an application of the cited theorem to the source encoding, not a
theorem in that paper about this protocol.

`q_H` includes the complete oracle-dependent setup and continuation, including
honest computations outside this private function. If the KEM public key and
ciphertext are generated using the same ideal hash family, their setup belongs
inside the experiment and its accounting. A precomputed prefix containing free
oracle-dependent advice is not substituted for that execution. The preceding
KEM reduction must likewise expose the actual shared hash interfaces, rather
than silently assign an independent SHA3 oracle to each layer.

## Two different caches in the KEM simulation

For the selected KEM challenge, the component-level simulator caches its test
secret for the exact PQ challenge ciphertext `C_PQ*` under the selected public
key. It must never submit that challenge ciphertext to the forbidden KEM
decapsulation oracle. Other ciphertexts use the permitted component oracle,
including its implicit-rejection behavior. This description is a required
simulation rule, not a completed simulator.

The combined-secret cache has a **different key**: all of `x`. Reusing the
component value for `C_PQ*` does not permit reusing one combined secret when the
classical ciphertext, key, secret, policy or application context changes. The
readback's context-only fixture provides a concrete input/output distinction
for that mistaken cache rule. Exact original-operation retries retain the same
full tuple and therefore retain the same combined secret.

In particular, the [classical-signature alias experiments](../../research/sdk-alpha1/evidence/20261105-rekey-classical-alias/README.md)
must be interpreted at the correct boundary. An offer-wire alias supplies a
different input to the KEM-context hash; the executed alias response is rejected
by the proposer's retained-offer prefix. The accepted-prefix argument must
account for the relevant digest-collision events.
A response-wire alias preserves its body and the original offer, so it can
preserve the combined secret/root confirmation while changing the later
full-wire traffic-transcript input. The proof cannot silently identify these cases,
or require both peers to have confirmed before the proposer's `FinalReady`
application send.

## Remaining bridge to recovery

The step above requires an independent component test secret. Establishing that
game for the actual original key-generation/encapsulation reservations still
requires the fixed-target KEM reduction, target-selection accounting, correctness
failure treatment, full signature/body provenance, and all allowed disclosures.
The [hidden-record commitments](HIDDEN_RECORD_COMMITMENTS_V1.md) and
[aggregate lineage](RECOVERY_DEPENDENCIES_V1.md#aggregate-image-lineage) explain
why unknown challenge coins cannot simply be fabricated inside recoverable
private records or refreshed by resealing them.

After this hop, the [root-extraction corollary](ROOT_EXTRACTION_QROM_V1.md) applies
only when its full prefix and joint-oracle premises are established. Subsequent
root, confirmation, traffic and signature computations must be regenerated
consistently with each game's secret. The complete transcript already contains
secret-dependent confirmations and is not fixed auxiliary input. Multi-root
composition, actual acquisition mapping and the final AEAD argument remain open.
