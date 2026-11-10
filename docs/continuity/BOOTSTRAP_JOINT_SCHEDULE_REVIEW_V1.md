# Bootstrap joint schedule and retained-state assessment v1

Assessment draft against `a4c089570c787522210d16226219c0cc8aa9b05e`, prepared
on 2026-11-09. This continues U2 and U3 of the
[bootstrap construction review](BOOTSTRAP_COMPROMISE_REVIEW_V1.md), using the
existing [0.2.0 admission plan](RELEASE_0_2_ADMISSION_PLAN.md). The
[source pins and reproducible calculations][evidence] identify the inspected
bytes. It is an internal construction assessment for review; it records no
external review or release-budget decision.

## Assessment result

The existing results already settle the signature-randomizer bridge, the
complete-tuple ContextBound comparison, the finite root-entry comparison and
the exact ideal HKDF block-table identity. They also settle the general
retained-record readability and copying semantics. This assessment applies
those results to the actual bootstrap fields, completes a conditional
downstream schedule derivation, and completes the U3 correspondence for the
declared bootstrap records and acquisition interface. The subsequent
[joint entry proof](BOOTSTRAP_JOINT_ENTRY_V1.md), assessed at `b1cff2a0`,
completes both surviving-contribution primitive entry services with the
initial-confirmation cross-use retained.
The [terminal schedule connection](BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md),
assessed at `360aa810`, completes the registration-time and descriptor-to-class
connection and derives the ACK-only comparison required by U1.
The [original reply-source adapter](BOOTSTRAP_REPLY_SOURCE_ADAPTER_V1.md),
assessed at `68549dbc`, instantiates the reply-surviving profile with original
reservation slots, native owner restoration, online opening certificates and
an explicit two-endpoint immutable-record acquisition term.
The [original initial-source adapter](BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md),
assessed at `471900bf` on 10 November 2026, supplies the complementary
prekey/Initial-encapsulation comparison. It retains initial confirmation
before adaptive Reply families and localizes the later PRK-table allocation
after the joint entry comparison.

| Existing item | Result available for this assessment | Disposition |
| --- | --- | --- |
| U1 terminal conversion | Exact signed-wire agreement at responder Final acceptance, followed by the online protected-family ACK-to-historical-activation theorem. | Completed in [the terminal assessment](BOOTSTRAP_TERMINAL_AGREEMENT_V1.md); retain its stated joint-schedule input. |
| U2 surviving signature component | The purpose/body wrapper reduces a fresh accepted body to the surviving component's fresh-message experiment. The native ML-DSA reservation bridge supplies an ordinary hedged-ML-DSA instantiation while retaining opened randomizers and exact retries. | Established conditional reductions; use the actual protected signer family and the declared classical/PQ model. |
| U2 hidden ContextBound input | `lem:cb-hidden-component` treats the full effective tuple, permits the other component to be known, and preserves all tuple aliases. | Established after the selected component replacement. Bootstrap source attribution and disclosures supply its concrete invocation. |
| U2 HMAC/HKDF composition | The shared-oracle row/column lemmas, finite root-entry theorem and exact Expand-table identity supply the required downstream operations. | Reusable results. Section 3 instantiates the bootstrap lengths and five activation blocks. |
| U3 retained-state correspondence | `thm:guarded-normalization` and `cor:guarded-history`, instantiated by the phase and acquisition maps in section 5. | Complete for the named bootstrap records, passive acquisitions and declared key disclosures along one authoritative history. |
| U2 bootstrap entry | The [joint entry theorem](BOOTSTRAP_JOINT_ENTRY_V1.md) compares the hidden-`S1` long Extract and the hidden-`S0` short/long service to complete-descriptor PRK tables under the common compression oracle. | Primitive services completed; section 7 records both original-source instantiations and their acquisition partitions. |
| U2 terminal-family connection | The [terminal schedule connection](BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md) permits online protection after opaque root allocation, charges the complete-class pad-alias event, and compares both ACK endpoint experiments to one full-table game. | Completed for the incoming source-consistent opaque PRK service; its two-sided bound supplies the exact substitution into U1. |
| U2 original reply source | The [reply-source adapter](BOOTSTRAP_REPLY_SOURCE_ADAPTER_V1.md) binds the selected generation and response encapsulation at their original slots, retains import validation and fixes the complete tuple/PRK family before response signing. | Completed bound for its stated reply-surviving profile, including exact acquisition residuals; the marked-record acquisition-free branch instantiates the constructive renderer. |
| U2 original initial source | The [initial-source adapter](BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md) binds the inventory PQ generation and Initial encapsulation, retains the joint short/long service and then selects an online complete-descriptor table rank. | Completed bound for its stated initial-surviving bootstrap/ACK profile; the later-family count multiplies the tail terms, while the original component and joint-entry comparisons occur once per source pair and endpoint. |

The result for U3 is a source and derivability correspondence. The
confidentiality comparison that hides an acquired ciphertext, or embeds an
unknown component tape in a retained record, has its own cryptographic terms.
This is the same separation made by the existing guarded-record and opaque-image
results, and keeps the construction assessment attached to its original scope.

## 1. Source-defined experiment

Use the admitted context `ctx`, one authoritative journal history at each
endpoint, and the original reservation identities. The complete signed Initial
and Reply wires are `x` and `y`. Exact retries preserve those originals;
different valid signatures on the same body retain their actual wire bytes.
The [terminal assessment](BOOTSTRAP_TERMINAL_AGREEMENT_V1.md) registers each
protected class `(ctx,x,y)` online, before its first private ACK-key computation
or use, and retains real verification replies and the declared disclosures.

`BootstrapContext::{new,from_historical_inputs,check}` binds the suite, exact
protocol and SDK policy, role-ordered device/account/generation/credential and
authority data, authenticated prekey selection, and independent directory
expectation. Its current-policy owner governs fresh operational permission;
historical reconstruction preserves the original binding. These are the public
inputs to the key-schedule analysis, with the current-authority checks retained
at their existing release sites. [Source: `bootstrap.rs`][bootstrap]

Write `F(k,m) = HMAC-SHA256(k,m)`. Let `D_B` be the actual 48-byte bootstrap
KDF domain, and `D_M` the actual 43-byte message domain. The source uses
HKDF-Expand's concatenation of info components; the full concatenated bytes
are the descriptor, including the context bytes where present.

| Operation | Complete computation | Source |
| --- | --- | --- |
| Initial contribution | `S0 = ContextBound(C0, selected responder keys, initial KEM context)` | `InitiatorOperation::start`, `authenticate_initial`; staged equivalents. |
| Initial confirmation | `P0 = F(sigma,S0)`; `K0 = F(P0,I0 || 01)`; `MAC0 = F(K0,t0)` | `initial_key`; SDK `purpose::{derive,hkdf32}`. `sigma` is the 27-byte SDK salt. |
| Reply contribution | `S1 = ContextBound(C1, original reply key, reply KEM context)` | `prepare_response`, `ResponsePlan::compute`, `finish_initiator`. The context includes the hash of the complete Initial wire. |
| Joint bootstrap Extract | `P_B = F(t1,S0 || S1)` | `schedule`, through `derive`. The IKM has exactly 64 bytes. |
| Three bootstrap outputs | `seed = F(P_B,D_B || "handshake-seed" || 01)`; `KR/KI` use the responder/initiator confirmation labels. | Three calls in `schedule` recompute the same deterministic Extract; they share one logical PRK. |
| Confirmation and transcript | `MACR = F(KR,t1)`; Reply is signed; `Fpub = "QPBSF001" || ctx || H(x) || H(y)`; `MACI = F(KI,H("final-core",Fpub))`; `sid = H("session-id",Fpub)`. | `response_body`, `prepared_response`, `final_prefix`, `finish_initiator`. |
| Bootstrap root | `P_s = F(sid,seed)`; `K_B = F(P_s,I_B || 01)`, where `I_B = D_B || "session-root/" || ctx`. | `pending`, `derive`. |
| Activation | `P_A = F(sid,K_B)`; `(R0,chainI,chainR,ackI,ackR) = Expand(P_A,I_A,160)`, where `I_A = D_M || "initial/HKDF-SHA256/ChaCha20Poly1305" || ctx`. | `State::new`, `Traffic::from_material`. |

The SDK info `I0` encodes suite `1`, profile `2`, the 36-byte policy state,
32-byte trust-root digest, purpose `3`, the 39-byte label
`ContinuityBootstrapCandidate/v1/initial`, the 32-byte `t0`, and the output
length. Its length is 178 bytes. Zero-extending `sigma` to 32 bytes preserves
its HMAC key pads exactly, as in `sdk-purpose-connection.tex`.

The activation order is significant: `R0` is block 1, the two chains are
blocks 2–3, and the ACK keys are blocks 4–5. Role 1 stores
`send_ack = ackI`; role 2 stores `receive_ack = ackI`. The epoch-zero READY
proof received by the initiator therefore uses `ackI`. `K_B` reconstructs all
five blocks. A disclosure naming only `R0` is a different asset from either
`K_B` or a complete serialized `State`. [Sources: activation][messages],
[traffic][traffic], [ACK encoding][ack]

## 2. Effective inputs and aliases

Three indexing relations have distinct jobs:

| Index | Identity preserved |
| --- | --- |
| Original reservation/signing family | The first sampled operation and its admitted binding, across private computation, failed writes, pending targets, reopen and retry. |
| ContextBound tuple | All ten effective length-prefixed fields, including both component secrets, both ciphertexts and public keys, suite, policy and actual application context. |
| HMAC/root descriptor | Actual pad-state class and complete info bytes, across endpoints and full-wire aliases. |

For a 32-byte salt `a`, define the source primitive's public pad-state pair
`Gamma(a) = (h(I(a),IV), h(O(a),IV))`. The established finite-entry result
indexes root values by `(Gamma(a),I)`. Different salt strings may have the same
pair; those requests use one entry. Separately allocated random output values
may also coincide numerically; the shared-oracle reductions retain that
distribution. [Proofs: multiple-root entry][multiple],
[shared-oracle primitives][primitive]

A same-body Reply signature alias preserves `t1`, `P_B` and its three
outputs, while its complete wire can change `sid` and the subsequent root
entry. This is exactly the situation for the finite-entry table. The retained
classical-alias execution in the construction review supplies a concrete
instance; section 3 retains every relevant descriptor rather than selecting a
convenient transcript after the fact.

The terminal theorem's classes are complete `(ctx,x,y)` tuples. The schedule
table first preserves its actual cryptographic aliases. The
[terminal schedule connection](BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md)
now reconciles these indices: before the declared transcript-hash collision,
distinct classes sharing one effective root descriptor yield an explicit
inner-pad compression collision. Its global quantum collision bound accounts
for adaptive salt selection. The connection also permits protection after
opaque root allocation and compares both real-sibling ACK experiments to a
common full table, retaining the terminal theorem's exact output interface.

## 3. Completed conditional derivation from a bootstrap PRK

The following proposition isolates the downstream work from the two-contribution
entry comparison. It is useful independently of which contribution supplies
the surviving secrecy in section 4.

**Proposition — bootstrap PRK to a protected activation table.** Consider one newly
allocated uniform 32-byte `P_B`, independent of the public compression oracle
and the initial auxiliary state, with all oracle-dependent preparation counted.
Its only raw uses are the three labelled Expand calls in section 1. The seed
has only its root-entry Extract uses. Private retained records use the
previously justified opaque interface, with its separate comparison cost.
Preserve the admitted online controller, real confirmations, signatures,
verification replies, declared downstream operations and disclosure stops.
Fix finite descriptor and query budgets before execution.

At the first allocation of `e = (Gamma(sid),I_B)`, before revealing its root
value or evaluating its activation Extract, the available-prefix controller
irrevocably marks `e` protected or unprotected. All descriptor aliases inherit
that mark and the same retained handle; an unprotected descriptor is never
promoted. A protected handle has only its matching activation interface, and
the existing cumulative recipe stop applies before a disclosure that recovers
that handle's root or ACK material. Unprotected entries may reveal their
current-game root values; their activation always uses real HMAC under the
same public oracle, including during every protected-entry hybrid.

Then the service can be compared to a mixed service with five independent
activation blocks per protected fresh descriptor, while preserving all aliases
and the real activation of every unprotected current-game root, with output-bit
gap at most

```text
Delta_tail = min(1,
    epsilon_Hrow(3, q_B, 71)
  + Delta_ent(A_i = 93)
  + sum_{j=1..N} [epsilon_Hjoint(1, 0, q_Aj, 32)
                 + epsilon_Hrow(5, q_Tj, 144)]) .
```

`Delta_ent` is the information-length finite-entry bound of
`lem:entry-information-length`; `N` bounds all first root-descriptor allocations
in this service. An unprotected slot is skipped in the activation hybrids;
the displayed sum is a conservative bound over the fixed allocation slots.
Every `q` bounds the entire associated reduction, including preparation, other
real primitives, all unprotected activation work, public-oracle calls and the
terminal test. They are not budgets reset at each KDF call. Never-allocated
slots contribute no actual call.

**Derivation.** Apply the established adaptive HMAC row bound to the three
different messages under `P_B`. Their lengths are 63, 71 and 71 bytes. The
ideal row therefore supplies independent cached `seed`, `KR` and `KI` entries.
The complete continuation computes its actual `MACR`, Reply signature, `MACI`
and all later results from those entries in that experiment.

The seed is now a fresh independent entry. Apply the finite root-entry theorem
in its information-length form, with `I_B` of length 93 and row input length
94. Its table is `W(Gamma(sid),I_B)`. The controller can choose `sid` after
confirmation and signing, and can allocate several entries from the same seed.
All requests for an existing descriptor retrieve its same handle. Before any
activation reduction starts, the parent Expand rows have been rewritten to
this private full-descriptor table. A child `K_B` challenge therefore occupies
one opaque table-value handle; the parent exposes no separate row or internal
raw-value observation. This is the exact final table representation in the
finite-entry proof, not a change postponed until after child initialization.

Replace protected activation entries in first-allocation order, skipping the
unprotected slots without a target guess. For one protected entry, `I_B`
determines `ctx`, and all aliases have the same `Gamma(sid)`. Thus their
activation Extracts agree for every `K_B`, and their complete `I_A` values
agree. There is one effective column and one five-block Expand for that entry.
The shared HMAC bound with one column gives an independent activation PRK;
the adaptive row bound gives an ideal Expand row. The exact prefix-consistent
Expand identity then produces five independent cached blocks. Unprotected
entries retain their real activation from their current-game root values;
other protected entries follow their preceding or subsequent hybrid.
All ordinary computations use the same public oracle. Numerical
coincidences with locally known keys remain ordinary shared-oracle computations,
as in the existing finite-entry proof.

Finally, the Expand-table rewrite removes internal row inputs containing a
previous output block. It therefore supplies the claimed sibling separation
without leaving a hidden `R0` input in the parent row. Declared disclosure of
`R0` or an unprotected sibling can be represented while the protected ACK entry
is used through its real MAC/verification interface. A triangle inequality
gives the displayed bound. [Proof inputs: information-length lemma][sdk-proof],
[HMAC instances][primitive], [exact Expand identity][expand]

| Source call | Info bytes | Actual HMAC message bytes | Blocks |
| --- | ---: | ---: | ---: |
| SDK initial confirmation | 178 | 179 | 1 |
| Bootstrap seed | 62 | 63 | 1 |
| Bootstrap responder / initiator confirmation | 70 / 70 | 71 / 71 | 1 / 1 |
| Bootstrap root | 93 | 94 | 1 |
| Initial activation | 111 | 112, 144, 144, 144, 144 | 5 |

This proposition supplies the tail of the schedule comparison. Its uniform
`P_B` input is the precise output required from the joint entry analysis below.
For several original bootstrap PRK families, retain their actual alias relation
and protection marks and apply the finite hybrids across the original allocation
ledger. This proposition's protected-entry interface is an explicit input to
the full bootstrap schedule comparison, including its original stopping rule.

## 4. Component and identity assessment matrix

The matrix follows the disclosed asset, including all records made readable by
that disclosure. The terminal theorem's online stop uses the resulting ACK
recipe closure. A local identity disclosure is compatible with a KCI profile
when the acquisition does not also supply such a recipe.

| Disclosed asset / fixed target | Consequence established by source or existing proof | Joint entry instance |
| --- | --- | --- |
| Responder selected X25519 private component; protected ML-KEM generation/coins remain private | The actual X25519 result may be known. The full-tuple ContextBound hop is designed to retain that value while replacing the protected ML-KEM component. | Apply the chosen original ML-KEM challenge adapter, then the complete-tuple hop, for the affected contribution. |
| Selected ML-KEM private component; classical component retained | This identifies a surviving-X25519 profile for a classical adversary. Its classical-component experiment is the premise to use for that case. | Keep this premise separate from the PQ profile, whose surviving component is ML-KEM. |
| Keys or recoverable reservations whose restored public components collectively match both selected responder prekeys | Public `C0` reconstructs `S0`, and `K0/MAC0` are computable. The original fresh reply contribution is a separate source. | Hidden-`S1` case: compare `F(t1,known_S0 || S1)` jointly with all later outputs and permitted histories. |
| Only original `sk_reply`, or its generation reservation with its key | Public `C1` reconstructs `S1`. | Hidden-`S0` case: retain both `F(sigma,S0)` for `MAC0` and `F(t1,S0 || known_S1)` in one comparison. |
| Initiator full signing identity, fixed original context | The peer's purpose-6 signature family is still distinct; `S0`, the reply private key and `S1` are separate assets. | Initiator-side KCI instantiates the protected peer-signature reduction and the chosen surviving-contribution case. Current-context admission and the original ACK recipe stop remain in force. |
| Responder full signing identity, fixed original context | The peer's purpose-5 signature and `MAC0` remain the initial checks; identity keys and selected KEM prekeys are separate inputs. | The [initial-source adapter](BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md) instantiates this profile with the protected initiator body ledger, known reply contributions and surviving original initial PQ source. Newly attacker-approved contexts have their own admission premise. |
| One peer's classical signing component, preserving an issued body | Purpose-bound hybrid verification permits an alternative valid classical signature on that same issued body. The complete wire still enters `sid` and Final. | Preserve the full-wire descriptor family and use the terminal conversion. The retained alias regression already exercises this case. |
| Signing reservation's binding and 32-byte `rnd` | These are the external ML-DSA randomizer and the exact retained command binding. The P-256 signer uses its native deterministic operation. | Use `thm:native-mldsa-reservation-bridge` and `prop:reservation-signature-components`; the randomizer bridge is a completed input. |
| Only `R0`, after activation | `R0` is the first of five siblings. The complete `State` additionally serializes the traffic keys and other retained state. | Section 3 establishes the conditional sibling-table comparison for the narrowly named asset. |
| `K_B`, both `S0/S1`, readable full initiation state, or readable responder response plan | The explicit graph reconstructs the applicable ACK key once its full public transcript is available. | Apply the existing recipe-based stop before returning a protected-family disclosure. These cases have a constructive derivation, rather than an unresolved secrecy premise. |

Prekey inventory coverage is component-specific. `respond_from_inventory`
recovers `pq_ref` and `classical_ref` separately and checks the corresponding
public component against the authenticated selection. One leaf's generation
token recovers its underlying hybrid owner, but this establishes knowledge of
the complete selected prekey pair only if that owner's restored components
actually match both selected public components. The general inventory case
uses the matching keys or tokens for both references. [Source: inventory
recovery and `respond_from_inventory`][prekeys]

`prekeys::consume` clears only the selected one-time entries. A reusable
selected leaf retains its token; transferring a bootstrap root to marker 3
does not change that inventory record. Consumed or abandoned entries contain
an operation tombstone, while a retired entry has no token. Their public
metadata is not a replacement generation reservation.

The signature bridge keeps the complete `(rnd,mu)` cache, original signer
families and first-private-invocation message ledger. It bounds the native
reservation-aware event by ordinary hedged-ML-DSA EUF plus its stated randomizer
collision and shared-XOF comparison terms, in its declared classical or quantum
random-oracle model. Non-target signing owners may be disclosed. A protected
target key or signer-file disclosure stops that component comparison at its
specified boundary. The same-body aliases above are issued-message aliases,
so fresh-message unforgeability is used for body origin, not wire uniqueness.
[Proofs: signing adapters][source-proof], [native reservation bridge][sig-proof]

### Exact 64-byte entry boundary

The existing hidden-message column equation is for a 32-byte HMAC message.
The bootstrap's 64-byte IKM has an additional compression block. With `h` in
message-block/chaining-state order and `alpha/beta` the public pad states,

```text
z = h(S0 || S1, alpha(t1))
u = h(80 || 00^55 || BE64(1024), z)
P_B = h(u || 80 || 00^23 || BE64(768), beta(t1)).
```

These are exact SHA-256 padding equations, including the consumed 64-byte
HMAC key pad. The SDK's Extract for `S0` uses the private block
`S0 || 80 || 00^23 || BE64(768)`. In the hidden-`S0` case the two raw-input
interfaces consequently need one full `(known suffix, chaining state)` cache:
when `S1` is that 32-byte padding suffix and the states agree, their first
private compression calls are the same point. The independent check records
this equality on chosen public fixture bytes. It is a constraint on a valid
hybrid encoding, with no implication that the implementation has failed.

In the hidden-`S1` case, `S0` and the entire initial-confirmation path are
locally computable; the protected block has the form `known_S0 || S1`.
The [joint entry theorem](BOOTSTRAP_JOINT_ENTRY_V1.md) now proves both
services. Its first replacement preserves that complete raw cache; its second
uses the disjoint short-outer and full-padding encodings, and its final
replacement yields the full `(known_half,alpha,beta)` PRK table. The SDK
initial PRK remains independent in the final table experiment. Section 3
supplies the three-label and activation tail under its stated wrapper.

## 5. U3: completed disclosure and retention correspondence

### Key guards and acquired objects

Let `J` be the actual journal key. The actual fixed public derivations give
`J -> O` for the SDK operation-wrapping key and `J -> G` for the signing-owner
key. The image is encrypted directly under `J`; operation tokens are encrypted
under `O`; a signer file is encrypted under `G`. The inner operation token binds
kind, the 68-byte SDK policy binding, operation ID and the 32-byte digest of the
complete original input binding. Replay supplies those original public
peer/context inputs; the digest does not reconstruct them.
Generation and encapsulation tokens contain respectively 96 and 64 bytes of
original entropy, and have lengths 277 and 245 bytes. [Replay source][replay],
[journal source][journal], [signer persistence][signer]

An acquisition history records every obtained image, pending intent, token or
signer file, and the disclosed keys. A pending intent embeds its intact target
image; extracting that ciphertext does not require an authentication key.
Reading its private payload still requires `J`. For a token obtained through
an image, the path guard is `{J,O}`; since `J -> O`, obtaining `J` satisfies
both guards. A directly acquired token has guard `{O}`. A separately acquired
signer file has guard `{G}`. The record graph includes all records in an
acquired aggregate image, including prekey inventory and other sessions.
[Source: `PendingWrite::{new_bound,authenticated_target}`][intent]

### Bootstrap phase map

The table describes the serialized phase, with any matching keys and public
inputs stated in the guard above. The phase numbers are private encodings.

| Retained object / phase | Private contents attributable to this bootstrap | Constructive consequences |
| --- | --- | --- |
| I: `InitialKeyReserved` (10) | Original reply-key generation token, nonce, context and operation scope. | Recovers `sk_reply`; later public `C1` yields `S1`. No original encapsulation token is present in this phase. |
| I: `InitialKemReserved` (11) | Same generation token plus original encapsulation token bound to the selected prekeys and initial KEM context. | Replays `sk_reply` and `S0`; later `C1` completes both contributions. |
| I: `InitialSignatureReserved` (12) | Same tokens, complete Initial body, signing binding and `rnd`. | Same contribution closure; the stored randomizer follows the bridge in section 4. |
| I: `Prepared` / `AwaitingReply` (2 / 6), checkpoint marker 1 | Direct `S0` and expanded original reply private key, with exact signed Initial. | Later public Reply gives `S1`, then `P_B`, seed, `K_B` and all five activation blocks. |
| I: `ProcessingReply` (9) | Same marker-1 checkpoint plus the exact selected Reply. | Both contributions and all subsequent schedule values are already reconstructible. |
| I: `FinalPrepared` / `FinalCommitted` (8 / 7), marker 2 | Exact Reply and Final, direct `K_B`. | All activation material is reconstructible directly. |
| R: `Executing` (1) | Exact public Initial and inventory claims. | This record has no response tape. Other readable prekey records in the same image reconstruct `S0` when their restored components collectively cover both authenticated selections. |
| R: `ResponseKemReserved` (13) | Direct authenticated `S0`, original encapsulation token, nonce, complete Initial and bound scope. | Replays `S1` even before Reply dispatch. Its eventual full signed Reply supplies the transcript used for `K_B`. |
| R: `ResponseSignatureReserved` (14) | Same contents plus complete Reply body and signing reservation. | Same contribution closure, with the original signing randomizer retained. |
| R: `Prepared` / `AwaitingFinal` (2 / 3), marker 1 | Direct `K_B` and `KI`, exact Initial and Reply. | All activation material; also the retained Final-confirmation key. |
| R: `Complete` (4), marker 2 | Direct `K_B` and accepted Final; the `KI` option has been taken. | All activation material. |
| Either: `Messages` (19), marker 3 | Bootstrap checkpoint's `K_B` field is zero. At initial activation a separate message record holds `R0` and epoch-zero traffic; later versions contain their actual current root, retained epochs and message/rekey state. | Acquire and inspect the whole image at its actual version. The marker-3 checkpoint alone and the message record are different assets. |
| Rejected / cancelled bootstrap | I retains its public request ID; R retains the public Initial, with applicable public cancellation metadata. | The current bootstrap payload has no private recipe. Previously acquired versions keep their original closure. |
| Selected prekey inventory | Available/reserved generation tokens for the actual selected leaf references, or consumed/abandoned/retired records with their declared metadata. | Each retained token and key recover its original KEM owner; deriving `S0` requires coverage of both selected public components. Consumption replaces each selected one-time token with the operation tombstone in the same transaction as Reply release. |
| Separate signer file | Two signing seeds and the corresponding public key, encrypted under `G`. | An acquired file plus `J` or `G` exposes identity authority. A journal-only acquisition does not silently include that file. |

Sources are the exact codecs and transitions:
[`InitiationPlan`][initial-plan], [`ResponsePlan`][response-plan],
[`InitiatorOperation` / `ResponderOperation` checkpoints][bootstrap],
[`durable::initiator`][initiator], [`durable::responder`][responder],
[`State::encode` and `Traffic::encode_into`][messages],
[`prekeys::consume`][prekeys], and [`cancel_bootstrap`][cancel].

### Derivation closure and preservation argument

Compute the least positive closure of acquired objects and directly disclosed
keys/values. First project an acquired pending wire to its embedded target
ciphertext, using its public encoding. Then follow the fixed key edges and
decrypt readable image/token paths. Apply the actual deterministic replay and
schedule rules to the resulting known fields and original public inputs:

```text
generation tape + original binding                 -> original KEM owner
encapsulation tape + original peer/context binding -> original contribution
reply KEM owner + public C1/context                 -> S1
selected responder prekeys + public C0/context      -> S0
S0 + S1 + reply core                                -> P_B, seed, KR, KI
seed + complete transcript                         -> K_B
K_B + complete transcript                          -> R0, chainI, chainR, ackI, ackR
```

These are rules for reconstructing the named values by decryption, replay and
the specified schedule. A row requiring a later public Reply derives its
transcript-bound descendants when those exact wire bytes become available;
the retained recipe is already identified at capture. For fixed record objects the existing exact guarded
normalization theorem proves that the route formula and iterative decryption
closure agree at every acquisition prefix. Applying the deterministic rules
after each new readable fact yields the corresponding bootstrap recipe closure.
In this declared rule set, those recipe rules add KEM/session facts and no new
`J`, `O` or `G` storage-key facts, so the public projection, guarded decryption
and recipe closures compose in that order.
The finite supplement checks that the phase map and late-key histories use this
closure consistently. [Proof: guarded normalization and history][guarded]

The source correspondence is preserved by the following induction. A new
reservation receives its original source at sampling. The journal retains the
token before the corresponding private KEM computation; first computation and
first signing invocation register that original source and full input, including
an invocation whose later write fails. Staged advancement either preserves the
token or replaces it with the exact deterministic result shown in the phase
table. Checkpoint restore validates the phase and original public binding.

`seal_next_image` serializes all record payloads before sampling a fresh outer
nonce. Therefore a sibling operation or reseal copies the same original source
where the record is unchanged. `PendingWrite` retains the complete target, and
reconciliation installs that exact target. A failed acknowledgment of a write
does not create a new entropy origin. Consumption, root transfer and cancellation
change the next live image's fields as shown; they do not remove previously
acquired record versions from the acquisition history. Copying, deletion and
later key disclosure thus obey `cor:guarded-history` without a new epoch or
save-time interpretation.

This completes U3 for these source objects and histories. It supplies the
readability/recipe classifier needed by the bootstrap disclosure experiment.
Its acquisition model is passive capture along the existing authoritative
history; active host-controlled forks and physical-media erasure are separate
contracts, and no such result is claimed here.

## 6. Verification and evidence use

The accompanying [check and receipt][evidence] verify the exact base blobs,
independently recalculate the existing public synthetic bootstrap/activation
vectors, check the actual information lengths and role-to-ACK mapping, and
exercise the declared finite closure/alias fixtures. The calculations include
the 64-byte padding boundary and a forced pad-state-alias model. They are
deterministic encoding and model checks; no new Rust, KEM, provider, CI or external
review execution is represented by that receipt.

The previous construction review's retained executions remain evidence for
their original source identities and scopes: real independent bootstrap,
classical same-body aliases, native/portable READY enforcement and deterministic
recovery. This assessment uses those outcomes through that ledger and the new
exact source pins. The finite calculations add reproducible checks of the
derivations written here.

## 7. Completed terminal connection and original source profiles

The two primitive entry services are complete in the
[joint entry theorem](BOOTSTRAP_JOINT_ENTRY_V1.md), including adaptive salts,
the exact short/long raw-input alias, complete pad-state descriptors and
whole-continuation query budgets. Their table comparison composes with section
3 under its opaque three-label wrapper. The
[terminal schedule connection](BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md)
completes the subsequent integration. It samples unopened root-table entries
at first exposure, reconciles the complete signed-wire classes with effective
descriptors, and reaches U1's ACK-only endpoint through two full-table
comparisons. With valid common budgets its conditional cost is
`2 Delta_tail + 2 chi_h(Q_h)`. The two schedule terms preserve the actual
siblings in the real and ACK-replaced endpoint games.

The [original reply-source adapter](BOOTSTRAP_REPLY_SOURCE_ADAPTER_V1.md)
now supplies a concrete source comparison for the profile with available
`S0` and traditional material, a surviving reply PQ source, and the expected
responder signing owner protected. The initiator signer can be disclosed.
The original generation/encapsulation pair fixes the complete ContextBound
tuple and PRK family before signing. A finite adjacent-ACK decomposition
handles parent opening before protection through candidate-local free stops;
later opening retains U1's global pre-return stop and latched event.

The adapter preserves native expanded-owner consistency checks. It monitors
collisions with other honest encapsulations before and after challenge
creation and counts all original fresh randomness slots, including unused
reservations. Its explicit `nu_enc` term follows from equal ciphertexts
implying equal original messages outside the declared K-PKE correctness
event. The resulting source, entry and tail terms substitute directly into
the terminal theorem with their complete continuation budgets.

The [original initial-source adapter](BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md)
supplies the complementary profile: the inventory PQ prekey and original
Initial encapsulation protect `S0`, with traditional material and actual
reply contributions available. The initiator purpose-5 signing ledger
supplies Initial body origin, and the responder signer may be disclosed
within the original admitted context. The inventory restores its selected
owner from the sealed generation seed; the separate initiator reply owner's
expanded-key import retains its ordinary validation.

Its first comparison covers `S0`'s initial `MAC0` computation and all later
adaptive long Extracts through one complete short/long cache. The proof then
partitions the independent long-PRK table by the descriptor's first request,
including failed attempts and exact aliases. This yields the resource form
`2 R alpha + sum_r eta_cap,r + 2 R G A (E + L T)`, clipped at one, where
`E` contains the source, record, component and joint-entry terms and `T`
contains one terminal-tail and pad-alias term. The later allocation count
`L` consequently multiplies the tail comparison only. Its stated operation
surface includes bootstrap admission and recovery, activation, epoch-zero
ACKs, typed sibling observations and the declared disclosure interfaces.

For immutable records containing any selected opaque value or descendant,
both source bounds retain the exact two-endpoint capture residual `eta_cap,r`.
The branch with no successful raw acquisition of those marked versions has
zero capture residual and uses the existing constructive record renderer.
The captured-byte extension supplies the joint journal-encryption and
derived-wrapping-key comparison. Additional closure or fanout observations
over the complete serialized message state enter through their own declared
report comparison. These inputs identify the next extension of the recorded
bootstrap/ACK operation surface.

The U3 correspondence, signature bridge, primitive entries, downstream
derivation, terminal connection and both stated original-source bounds are completed
assessment inputs. Package, platform qualification and workload-budget
choices retain their existing acceptance roles.

[evidence]: ../../research/sdk-alpha1/evidence/20261109-bootstrap-joint-schedule-review/README.md
[bootstrap]: ../../research/continuity-identity-candidate/src/bootstrap.rs
[initial-plan]: ../../research/continuity-identity-candidate/src/bootstrap/staged.rs
[response-plan]: ../../research/continuity-identity-candidate/src/bootstrap/response_staged.rs
[initiator]: ../../research/continuity-identity-candidate/src/durable/initiator.rs
[responder]: ../../research/continuity-identity-candidate/src/durable/responder.rs
[journal]: ../../research/continuity-identity-candidate/src/durable.rs
[intent]: ../../research/continuity-identity-candidate/src/durable/write_intent.rs
[prekeys]: ../../research/continuity-identity-candidate/src/durable/prekeys.rs
[cancel]: ../../research/continuity-identity-candidate/src/durable/cancellation.rs
[messages]: ../../research/continuity-identity-candidate/src/durable/messages.rs
[traffic]: ../../research/continuity-identity-candidate/src/durable/messages/traffic.rs
[ack]: ../../research/continuity-identity-candidate/src/durable/messages/acknowledgement.rs
[replay]: ../../crates/q-periapt-sdk/src/expert/replay.rs
[signer]: ../../research/continuity-identity-candidate/src/crypto/persistence.rs
[source-proof]: ../../paper/continuity/source-attribution.tex
[sig-proof]: ../../paper/continuity/reservation-signature-bridge.tex
[multiple]: ../../paper/continuity/multiple-root-entry.tex
[primitive]: ../../paper/continuity/joint-primitive-bounds.tex
[sdk-proof]: ../../paper/continuity/sdk-purpose-connection.tex
[expand]: HKDF_EXPAND_TABLE_V1.md
[guarded]: ../../paper/continuity/guarded-provenance.tex
