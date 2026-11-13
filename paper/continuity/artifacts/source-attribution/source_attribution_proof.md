# Executed sources and signing reservations

## Research question and outcome

An accepted next-rekey traffic allocation should identify the original KEM
operations that supplied its contribution. The existing general selector can
name a failed, never-executed reservation with matching metadata. This note
constructs an executed-slot selector, proves its source association through the
actual retained-plan transitions, and specifies the signature experiment needed
by that proof. It leaves the general selector and its existing accounting intact.

The result has three parts:

1. Persist-before-compute gives at most one executed generation origin and one
   executed encapsulation origin in each authoritative local epoch, despite
   failed reservations, unknown write outcomes, crashes and repeated computation.
2. With these independently registered slots, an eligible local traffic
   allocation has the required source association except on an accepted fresh
   signed body or a relevant framed-hash collision. Whole-response signature
   aliases remain possible at the proposer's first sending cutover and retain
   the same source pair.
3. A reservation-aware signature experiment makes the signing-coin interface
   explicit. The native deterministic P-256 constituent gives an exact
   classical reduction for the specified signing-owner interface. The ML-DSA
   branch uses its stated reservation-aware advantage. A generic construction
   separates ordinary EUF-CMA from unforgeability with signing-coin disclosure.

The source and proof artifacts contain finite model checks and a source audit.
Those checks execute neither Rust nor a formal verifier; the mathematical
claims are supported by the arguments below and their separate review.

## 1. Native controller and original slots

Use the established-session next-rekey controller already fixed by the
ContextBound and live-core results. Fix the actual two endpoint identities and
one authoritative history per endpoint for the selected session. A session
history includes its admitted context, endpoint role, epoch and control parent.
Native immutable images and pending targets can be captured, copied passively,
reconciled and reopened. A second live journal controlling the same
signer/session/epoch is outside this controller. This matters because the
journal identity appears in operation scope but does not appear in the signed
control-body prefix. Terminal retirement ends that history; a new session has
its own session identity.

Maintain a ghost register `ExecG[history, session, epoch]` for the proposer and
`ExecA[history, session, epoch]` for the responder. On reaching the first actual
private KEM invocation, install its **original reservation slot** immediately
before invoking the primitive. A retry with that slot retrieves the same
register entry. The registration reads retained-plan identity and public
bindings; it does not read the unknown KEM tape. Slots still originate at the
actual random draw, as in the existing manuscript. This register does not
renumber them. An attempt that never reaches a KEM invocation remains a genuine
reservation event without an executed designation.

The executed-slot selector chooses the target's accepted logical send and cut
as before and obtains its two source handles from these registers. A missing
register supplies a missing invocation and fails the existing reservation-event
test. The selector does not choose sources by equality of public keys or by
testing whether the final transcript is honest. In particular, it does not
assume the attribution property it is intended to establish.

### Lemma A: stable executed sources

For a fixed authoritative local epoch, the executed generation register and
the executed encapsulation register each contain at most one original slot.
All later computations in that local epoch use that slot and its immutable
binding. The statement includes computations followed by failure, crashes or
unaccepted control flights.

**Proof.** The proposer sets `Plan::Key(token)` and calls
`store_message_state` before `recovery.generate_key`. If the call returns an
error, execution exits before generation. Reopening a target that did become
durable recovers that token. If no target became durable, a later attempt can
draw a new slot, while the earlier slot has not reached generation. After
generation is reached, the authoritative plan therefore already carries its
slot. Subsequent local phases are `Key`, `Signing`, `Ready` and `Completing`.
`Signing` and `Ready` retain the same key token; a failed later write recovers
one of the earlier phases with that same token. The completing phase retains
the offer/response and its derived root; it performs no replacement generation.
The plan becomes empty only when completion advances the epoch or the whole
session becomes terminal.

For the responder, `Stage::Encapsulation(token)` with the exact offered wire is
persisted before `recovery.encapsulate`. Every later call checks its offered
wire against that saved wire and rejects a different wire. `Signing` and
`Ready` retain the result and pending root; a failed phase update recovers the
same encapsulation token or a successor of its result. Completion changes the
epoch. Thus no second slot can reach the corresponding KEM computation at the
same local epoch. The source identity is a causal identity, independent of any
coincidence between sampled keys or ciphertexts. Induction over the native
transition sequence proves both claims. **End proof.**

The proof uses successful authoritative retention, not the caller's belief
about a failed or unknown commit. Unknown outcomes that retain a target keep
its source. Mere copying, resealing or process loss creates no new register.

## 2. Source association of an accepted allocation

Record every honest private device-signing invocation together with its actual
key identity, purpose, complete body, retained plan and registered KEM origin
when applicable. Record the invocation at its first primitive computation,
before any later persistence or release. A signer query that is completed
privately and whose later publication fails stays in this ledger. Exact replay
reuses the original signing reservation and signature. A verifier's own check
does not add an issuance entry.

The signed string is exactly

`SIGNATURE_CONTEXT || purpose[1] || BE32(len(body)) || body`.

The signing ledger contains every honest invocation under the actual key,
across public purposes and exact owner aliases. Absence from that actual-key
ledger implies absence from the corresponding projected owner-index ledger.

The control body contains the fixed tag/profile, context digest, session,
current and target epochs, proposer/responder role and control parent. The
response also contains the framed digest of the **complete offered wire**.
Final/receipt contain the corresponding complete-wire digests. These byte
equalities are checked by the native code.

Let `Bad_sig^0` be a successful target-key verification, before the first
target signing-key or signer-file disclosure, of a purpose/body
whose complete signed string is absent from the honest private-signing
invocation ledger. This is a fresh-message event, not a new-signature event.
Different valid signature encodings on an already-issued body do not belong to
`Bad_sig^0`. The issuance ledger includes all honest invocations under the actual
key, across its exposed public purposes; the source profile controls which
invocations can construct the selected rekey bodies.

Let `Bad_H` be a collision between distinct classical framed SHA3 inputs used
by the source association checks. The reduction records the actual input
strings, rather than assuming every pair of hash outputs is unequal. An
ordinary full-query collision advantage may upper bound this event. Its query
budget includes complete adversarial preparation, honest computation and the
terminal witness extraction.

### Proposition B: executed-slot source association

Under the controller above, let `E` be the unchanged recovery eligibility and
let `A` be the manuscript's usable source-attribution event for the
executed-slot selector. Then, pointwise,

`E AND NOT A  =>  Bad_sig^0 OR Bad_H`.

Consequently, for any valid upper bound `epsilon_sig` on the fresh-body event
in the signing-reservation execution stopped before returning a target
signing key or signer-file capture,

`eta_attr_exec <= min(1, epsilon_sig + chi_H(Q_H))`.

Here `chi_H` is the same complete-query quantum collision bound used in the
confirmation theorem. The implication itself is deterministic and applies to
classical protocol executions driven by either a classical or a quantum
network adversary.

**Proof.** On `E`, neither target signing key nor signer file is disclosed
anywhere in the complete history. Stop a comparison execution immediately
before returning its first such disclosure, and retain whether a fresh-body
verification has already succeeded. Native and stopped executions have
identical classical-prefix instruments up to that point. Thus the probability
of `Bad_sig^0` is exactly the fresh-body event probability of this stopped
execution; no challenger-key or owner-file bytes need be returned. This
coupling applies equally to an adversary with private quantum state.

Work on an eligible execution before either bad event. Consider a newly installed target
traffic allocation. Cached returns refer to its earlier installation, so it
suffices to analyze first installation.

For a proposer allocation, `accept_rekey_response` starts from its own
`Plan::Ready`, whose retained offer and key token descend from the unique
registered generation `g`. It verifies the response's signature and complete
prefix, including the digest of its retained offer `O`. In the absence of
`Bad_sig^0`, that response body has an honest signing invocation. The complete
prefix locates that invocation in the configured responder's same session,
epoch and parent. The responder's unique executed encapsulation is `a` by
Lemma A. Its signing body carries exactly the ciphertext computed from `a`
and the digest of its retained offer `O_a`. Equality of the two checked
offer digests, together with absence of `Bad_H`, gives `O_a = O`. Therefore
the encapsulation input is the public key obtained from `g`, with the exact
offer-dependent KEM context used by the proposer. The proposer regenerates
the key from the retained token, explicitly compares its public bytes with
the offer, decapsulates the response ciphertext, and derives and confirms the
root using the actual response core. These are the original component calls
and root inputs in the existing adapter. Source attribution asserts that these
are the original matching calls and bindings. Any mismatch between their
encapsulation and decapsulation outputs is a primitive-correctness event;
the existing `delta_j` accounts for it at the component comparison. Source
association does not assert unconditional equality of those outputs.

The outer response signature may be a different valid encoding of the same
body. It preserves `g`, `a`, ciphertext, KEM context and pending-root inputs.
The actual presented complete response is retained for the traffic-info
derivation and the final flight. The joint schedule already indexes traffic
by this complete information string; source association does not impose
whole-response-wire uniqueness.

For a responder allocation, `finish_rekey` begins with its unique `a`, saved
offer and ready response. It verifies the final signature and the full final
prefix against **both** of those wires before installing traffic. Its honest
final-signing invocation, supplied by the absence of `Bad_sig^0`, came from
the proposer's `accept_rekey_response` transition. Absence of `Bad_H` makes
that invocation's retained offer and presented response equal to the two
wires checked by this responder. The preceding proposer argument therefore
identifies the same unique `g` and `a`. Receipt acceptance advances receiving
state without making another root or traffic allocation. Failed writes,
restart and retransmission retain the same identities by Lemma A.

Every allocation carrying the selected accepted logical send thus has the
unique registered usable pair. All association tests read retained object
identity, complete public strings and ledger indices. They remain computable
in the component adapter when the selected random tape is unknown. The
eligibility and source tests are recomputed from each game's own execution.
This proves the implication. A union bound gives the probability statement.
**End proof.**

The previous `(g1,a2)` failed-first-persistence witness still applies to the
general metadata selector. Its first reservation never reaches generation;
the executed-slot rule records `g2` before generation returns. Thus the new
rule addresses that witness through an independently specified source
interface. It leaves the original sampling times and cut predicate intact.

## 3. Reservation-aware fresh-message signatures

Fix a multiuser signature scheme whose internal signing procedure is
deterministic given `(sk, M, r)`, and a finite controller. Give each of at most
`U` independently generated honest signing owners an index and its own
component signing-query ledger. Reopening or reusing an owner retains its
index. Accidental public-key coincidences remain in the distribution and the
native admission checks are performed normally. No reduction conditions its
experiment on every public key being different. For each indexed key,
the challenger provides its public key and retains the secret. Its service
has the following classical operations, with the same additional public
oracles and adversary class as the enclosing experiment:

* `Reserve(key, operation, purpose, body)` samples fresh independent signing
  randomness `r`, binds the full tuple, and creates an original reservation
  handle.
* `Open(handle)` returns the original binding and `r`. It may precede or
  follow the signing computation. Repeated openings return identical bytes.
* `Execute(handle, tuple)` checks the original tuple, computes the actual
  signature at the first private invocation and caches its exact result.
  The complete signed string enters the query ledger at that invocation.
  Exact retries return the cache. A failed outer write has no effect on
  either ledger.
* `Verify(key, M, signature)` uses the ordinary public verifier. A successful
  verification of a message absent from that key's private-signing query
  ledger is a win.

Exact tuple matching in this service describes the controlled native call
surface: each retained plan supplies its original operation, purpose and
complete body, with an explicit recomputed-body equality check at the proposer.
The standalone native reservation stores a hash binding. The controller
exposes no arbitrary raw tuple-retarget API, so this correspondence does not
assume that a hash is an injective encoding for unrestricted callers.

The secret key and its serialized owner file have no byte-return or
key-dependent commitment interface in this primitive game. Owner identifiers,
public keys and close/reopen bookkeeping can be supplied by its wrapper.
For a confidentiality score, an actual target-key/file disclosure is handled
by its previously established permanent-exposure stop. A wrapper exposing
additional observations of the target owner file needs its own simulation
cost. This restriction concerns the **owner's secret seed file**; the
signing-reservation records in `Open` are supplied exactly.

For the native pair signature, the bound string `M` above is the exact
length-framed purpose/body encoding. The ML-DSA context is the fixed source
context. Native `SigningReservation::encode` contains only a 32-byte public
binding and the 32-byte ML-DSA signing randomizer. P-256 signing uses the
deterministic RFC 6979 `try_sign(message)` path and is independent of that randomizer.
Both components are checked by `PublicKey::verify`.

The ordinary P-256 game below uses this exact native RFC 6979 signing
distribution and low-S canonicalization. The pinned `ecdsa` 0.17.0 source
routes `Signer::try_sign` through `try_multipart_sign`, `try_sign_digest`
and `sign_prehash` to `sign_prehashed_rfc6979` with an empty additional-data
argument. The wrapper reduction does not replace this deterministic signer
by a randomized ECDSA oracle.

### Proposition C: two component adapters

For the specified owner interface, write `epsilon_pair_res` for the
reservation-aware fresh-body success probability of the native pair. Then

`epsilon_pair_res <= epsilon_MLDSA_res`,

with the same adversary class, and for classical adversaries

`epsilon_pair_res <= epsilon_P256_EUF`.

The advantages include all users and complete simulation work, with no further
multiuser factor. A single-user definition for the exact native deterministic
P-256 scheme gives the explicit upper bound
`min(1, U * epsilon_P256_EUF_single)` with complete simulation time and at
most the original Execute-call budget of challenger signing queries. Exact
owner aliases are not counted twice. Each probability is capped at one.

**PQ-component adapter.** Generate each classical key locally. Route the
ML-DSA key, reserve/open/execute calls to its reservation-aware challenger,
including the actual fixed context and bound message. Eagerly call `Open`
privately for each original reservation to obtain its randomizer before
serializing any native record, and count these service calls. Opening changes
no game eligibility; the wrapper discloses those known bytes to the network
only through the original requested observations. Produce the
deterministic P-256 component locally and apply the native canonicalization.
The challenger supplies the exact ML-DSA randomizers needed for binding and
record serialization when opened; it caches the original internal signing
call. A pair verification on an unqueried `M` yields an ML-DSA verification
on the same unqueried `M`. All other operations use available values. This
is an exact simulation, followed by projection of the successful signature.

**Deterministic-component adapter.** Generate ML-DSA keys locally, draw every
reservation randomizer locally, and serialize all reservation records exactly.
Use the standard multiuser P-256 signing challenger for the deterministic
component at the first private signing computation of each reservation.
Normalize its result exactly as in the source. Cache by reservation origin;
distinct original reservations of the same body can have different ML-DSA
signatures while their deterministic P-256 signatures agree. Revealing a
reservation only reveals locally known randomness. No challenger-key byte
is needed by this declared owner interface. A successful pair signature on
an unqueried bound message projects to a standard P-256 forgery. Public
verification, hashes and other known-key algorithms are performed normally.
Thus this simulation too is exact. **End proof.**

FIPS 204 specifies a 32-byte randomizer for hedged ML-DSA and deterministic
internal signing when that randomizer is fixed. It does not by this syntax
alone equate ordinary signing-oracle security with `epsilon_MLDSA_res`.
The next proposition identifies the mathematical distinction between these
two interfaces. The deterministic P-256 inequality supplies a classical
instantiation, while the reservation-aware ML-DSA term is the stated
post-quantum signature assumption. Protocol code continues to require both
signature components.

## 4. A separating construction for signing-coin disclosure

### Proposition D: ordinary EUF-CMA and reservation disclosure separate

Let `Sigma_0` be an EUF-CMA signature scheme with a fixed-length secret-key
encoding `s` of length `L`, and deterministic signing. Construct

`Sign_plus(s, M; r) = (Sign_0(s, M), r XOR s)`,

where every ordinary signing call samples a fresh uniform `r` in `{0,1}^L`.
Verification checks the fixed width of the second component and verifies the
first using `Sigma_0`. Its public key equals the base public key.

The ordinary signing-oracle games of `Sigma_plus` and `Sigma_0` have exact
transcript-preserving reductions in both directions, with their simulation
time counted. In the reservation-open game, one opened
signing reservation and its signature reveal `s`; the adversary subsequently
forges on a fresh message with probability one, subject only to the base
scheme's correctness probability.

**Proof.** Condition on any base key and signing transcript. For each fresh
`r`, the appendix `r XOR s` is independent uniform. An ordinary reduction
can query the base signing oracle and append fresh independent uniform bytes
without knowing `s`. Projection of a fresh-message forgery gives a base
forgery. Conversely, a base forger can ignore the appendices; append any
fixed-width string to its final signature. These two explicit simulators
preserve success probability, with appendix generation and parsing included
in their running-time bounds.
In the reservation game, opening the original `r` and observing its appendix
recovers `s` by XOR. The adversary now runs the actual base signing algorithm
on a fresh message and appends any fixed-width string. Verification accepts.
**End proof.**

This is a generic separation witness, not a claim of an attack on ML-DSA or
the native implementation. It establishes why the original-coin interface is
part of a persistent signature assumption. The component adapters above
provide positive ways to account for that interface.

## 5. Integration with the current bound

For the executed-slot selector, Proposition B can replace its attribution
residual in the live-core bound by

`min(1, epsilon_sig + chi_H(Q_H))`.

When the controller realizes the exact signing-owner interface of Proposition
C, `epsilon_sig` can be instantiated by its ML-DSA reservation-aware term, or
by the P-256 ordinary term for classical adversaries. Additional owner-file
observations remain an explicit adapter obligation and are not silently
included in this substitution. The generic metadata-selector theorem retains
its original attribution residual and counterexample.

Record-simulation costs, original KEM component advantages, correctness terms
and the joint root/message continuation keep their earlier meanings and
positions. The source-association result does not spend the joint-schedule
bound again and does not impose joint peer confirmation before a proposer
can send its marked first message.

## 6. Primary sources and validation plan

Native source at the inspected integration commit
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9` supplies the signing serialization,
reservation ordering, complete prefixes, conflict checks and traffic
installation. The overlapping native files are compared to the earlier
source identities already pinned in the confirmation artifact. Exact hashes
and extraction assertions are recorded by the accompanying checker.

Primary algorithm references:

* NIST, FIPS 204, *Module-Lattice-Based Digital Signature Standard*, 2024,
  Algorithms 2 and 7: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
* Thomas Pornin, RFC 6979, *Deterministic Usage of the Digital Signature
  Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)*,
  2013: https://www.rfc-editor.org/rfc/rfc6979.html
* The pinned RustCrypto `ecdsa` 0.17.0 signing implementation:
  https://docs.rs/ecdsa/0.17.0/src/ecdsa/signing.rs.html

The finite checker will enumerate fault-boundary histories, preserve
unknown-outcome targets, compare original-reservation and executed-slot
selectors, and test transcript aliases with an independent expected matrix.
Its signature models check exact randomness-opening/replay behavior and
the algebraic separation witness. These finite checks do not estimate
cryptographic forgery probabilities.
