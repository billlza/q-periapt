# Conditional body-origin reduction for the candidate hybrid signature

Status: elementary conditional reduction and source correspondence, 2026-11-05.
This discharges the wrapper implication stated below, not the underlying
ML-DSA assumption, accepted-prefix simulation or multi-epoch recovery theorem.
It refines the existing authentication obligation in
[COMPUTATIONAL_RECOVERY_V1.md](COMPUTATIONAL_RECOVERY_V1.md); it changes no
protocol, threat model, product promise or release requirement.

## Exact interface and event

Let `D` be the fixed 42-byte candidate signature context. The accepted message
encoding in [`crypto.rs`](../../research/continuity-identity-candidate/src/crypto.rs)
is

    E(p, b) = D || p_u8 || length_be32(b) || b.

The current 39 purpose tags are distinct. Bodies exceeding the implementation's
bound are rejected before signing/verification. Thus equality of two accepted
encodings implies equal purpose, equal length and equal body. This is an
injectivity argument about bytes; it needs no hash-collision assumption.

For one honestly generated target ML-DSA verification key, define the following
**chosen-rnd message-unforgeability interface**. A signing query supplies a
message `m` and 32-byte `rnd`, under fixed external ML-DSA context `D`, and
receives the exact result of the fault-free seeded signer. Record every queried
message in `Q`, even when signing returns failure. Exact `(m, rnd)` repetitions
return the same deterministic result. The adversary wins by returning a valid
signature on a message outside `Q`. If the implementation admits failures,
termination or failure behavior must be included in this interface; an oracle
with a different behavior does not automatically instantiate it.

The target secret key and its key-generation coins are unavailable. Other
observations must be simulatable from the public key, the specified signing
interface and the simulator's own state. This premise does not silently grant
simulation of encrypted signing-key storage, arbitrary secret-dependent advice,
other-epoch disclosure or the candidate's whole persistence interface. A public
hash oracle, if present, is shared exactly as in the assumed primitive game;
all wrapper queries count. No uncounted oracle-correlated prefix is assumed.
The simulated classical key must have the experiment's actual distribution
jointly with the PQ public key and other views. The implementation draws the
two seeds separately and bounds classical rejection sampling to eight attempts;
source calls to the entropy provider do not prove independence. Any mismatch
between that experiment and the simulator belongs in the simulation premise
or its explicitly bounded error.

`BadBody` occurs when hybrid verification accepts `(p, b, signature)` for that
target PQ key, but `E(p, b)` has never been submitted to its signing interface.
Freshness is per PQ key across **all** purposes and all classical keys paired
with it. A body that the signing interface processed under another classical
key is not fresh merely because the hybrid key pair has a different encoding.
This definition concerns body origin, not current authorization, a designated
peer, a unique operation, an original flight, freshness of time or policy, or
proof that a particular honest protocol state machine emitted it.

## Single-target reduction

Assume a simulator for the surrounding interface with the premises above.
Given the target ML-DSA verification key and signing oracle, the reduction
generates the classical signing key itself and runs the adversary and wrapper.
For each hybrid signing request it computes `E(p,b)`, queries the ML-DSA signer
with the selected `rnd`, and computes the canonical classical signature using
its own key. It preserves exact retry results and all admitted failures.
It can disclose the entire classical secret key: no classical unforgeability
or secrecy premise is used. It cannot disclose the unavailable target PQ key
or any view that the surrounding simulator cannot generate.

At the first `BadBody`, the implemented hybrid verifier has parsed exactly the
two expected signature components and accepted both. Its PQ component is
therefore a valid ML-DSA signature on `E(p,b)` under external context `D`.
By the event definition that message is outside `Q`. The reduction outputs
this component and message as its forgery. It makes one primitive signing
query per distinct `(message,rnd)` pair, with cached exact retries. Therefore,
for this exact single-target simulation,

    Pr[BadBody] <= Adv_seeded-message-EUF(B).

There is no collision term or P-256-security term in this implication. If the
surrounding simulation differs from the intended experiment by at most `delta`
for this event, the bound is instead `delta + Adv_seeded-message-EUF(B)`.
The value of `delta` has not been established for Continuity's accepted prefix.

For at most `N` honest PQ-key generation events, an adaptive first-event bound
can use the usual guessed generation index, multiplying a single-key bound
by `N`. That argument additionally requires simulation of the other keys and
all corruption requests, no corruption of the forged target, and a primitive
public-key distribution matching the target event. Related-key generation,
reusing the same PQ key under several identities, and arbitrary registration
are not resolved by writing this factor. No multi-user primitive theorem is
being claimed here.

## Why persisted rnd needs its own premise

[`SigningReservation`](../../research/continuity-identity-candidate/src/crypto.rs)
stores a 32-byte input binding and 32-byte `rnd`. The binding includes the
public key, operation and complete signed message. The backend passes `rnd`
to `fips204` 0.4.6's seeded signer, which computes an internal 64-byte seed from
`K || rnd || mu`. This matches the distinction between supplied randomness
and the internal seed in [FIPS 204, section 6.2](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).
It does not identify persisted `rnd` with the internal seed or mask, and it
does not by itself prove unforgeability after permitted `rnd` disclosure.

Choosing `rnd` in the interface above gives a simulator the exact input it can
later disclose; ordinary fresh-randomness signing access need not do so.
The [Kosuge–Xagawa analysis](https://eprint.iacr.org/2025/904) is a candidate
route for a nonce-aware assumption. Applying that paper still requires a
checked match to its precise game, oracle interfaces, rejection-loop bound
and the pinned implementation. The present wrapper reduction neither applies
the paper's full theorem nor assumes away these differences.

## Exact wire and protocol correspondence remain separate

The source-bound Release regression
`bootstrap::classical_alias_tests::classical_signature_alias_preserves_reply_authentication_but_final_rejects_root_split`
keeps the body and PQ signature unchanged while replacing the canonical
classical signature after classical-key disclosure. Hybrid verification and
the initiator's initial reply checks accept; final scope checking rejects the
root/session split. Two native connection tests separately exercise the final
READY boundary. Their existing complete Release run passed, with four controls
and four aliases; the eight relevant current source files match that run.
This reuses an observed run, not a new execution or an observed rekey attack.
The [source and historical-run capture](../../research/sdk-alpha1/evidence/20261105-authenticated-body/README.md)
retains the exact source hashes and the original-run locations and digests.

That example is compatible with `BadBody` remaining false. Even strong
unforgeability of the PQ component alone would not stop changing only the
classical component. Accordingly, accepted-flight authentication also needs
the actual pinned identity/role and policy checks, operation binding, stored
wire comparisons, transcript/digest collision events, matching accepted
endpoints and confirmation stages. Honest key-generation/encapsulation origin
and a simulation of permitted reservation/state disclosure remain obligations
of the full accepted-prefix bridge. The conditional body-origin implication
cannot replace them.
