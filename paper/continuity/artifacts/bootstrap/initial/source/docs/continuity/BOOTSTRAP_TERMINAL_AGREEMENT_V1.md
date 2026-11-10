# Bootstrap terminal agreement and exact transcript recovery

Assessment of `billlza/q-periapt` at
`6a0ac0bbd7a5be77443e10b22c20a31f4b3be271`, 9 November 2026.

## Result

The bootstrap has two complementary terminal guarantees. Responder Final
acceptance checks the complete signed Initial and Reply selected by its original
operation. Initiator connection success additionally authenticates an epoch-zero
ACK derived from that complete transcript's bootstrap root. The first guarantee
is an exact source invariant. The second follows from an explicit joint
key-schedule and MAC experiment by the reduction below.

Together these results explain the retained classical-signature-alias execution:
the same signed body can pass Reply authentication while producing a different
full-wire transcript. The responder's Final gate rejects that transcript, and the
initiator's READY gate requires its own transcript's ACK key. Ordinary signature
unforgeability need not imply unique signature encodings for this conversion.

The authenticated conclusion is **historical activation of the same transcript
under the expected responder identity**. Exact retries can reuse an earlier valid
proof. Each connection still checks its own current authority before success;
fresh remote availability or a fresh remote-authority statement has a different
event definition.

This assessment completes the terminal-conversion subproblem of U1 in the
[construction matrix](BOOTSTRAP_COMPROMISE_REVIEW_V1.md). Its stated joint
schedule hypothesis identifies the existing U2 task precisely. The original
external assessment process and release decisions retain their existing roles.

## 1. Exact objects and events

Let `I` and `R` denote role-ordered verified device identities in an admitted
context `ctx`. `x` is the complete canonical signed Initial wire and `y` the
complete canonical signed Reply wire. Both include their signature bytes. With
the source's domain-separated SHA3-256 function `H`, define

```
P(ctx,x,y) = "QPBSF001" || ctx || H("initial-wire",x) || H("reply-wire",y)
sid       = H("session-id",P(ctx,x,y))
K_B       = HKDF(t=sid, IKM=seed, info=bootstrap-domain||"session-root/"||ctx)
Z         = HKDF(t=sid, IKM=K_B,
                 info=message-domain||"initial/HKDF-SHA256/ChaCha20Poly1305"||ctx,
                 length=160)
```

Here `t` denotes HKDF's salt. The exact domains and 32-byte output sizes are the
ones in the construction matrix. The activation output is

```
Z = R_0 || chain_I || chain_R || ack_I || ack_R
```

in five 32-byte blocks. Thus the ACK which confirms R to I uses `ack_I`, the
key for acknowledging I's application direction. R stores it as `receive_ack`;
I stores it as `send_ack`. I's own emitted ACK uses `ack_R` and direction 2.

The byte string authenticated by a responder's epoch-zero ACK is

```
message-domain || "acknowledgement" ||
"QPCMACK1" || sid || 0x01 || consumed_floor:u64be
```

followed on the wire by a 32-byte HMAC-SHA-256 tag. The ACK is 81 bytes. A
positive epoch uses a different tag and an additional epoch field; both
connection clients require the original epoch-zero encoding for READY.

Use these events:

* `FinalI(ctx,x,y)` means an honest original initiator operation has accepted `y`
  and committed its exact Final. Its durable phase is `FinalCommitted`.
* `CompleteR(ctx,x,y)` means the responder has accepted the exact Final prefix
  and MAC and has durably committed `Complete` for its saved `x,y`.
* `ActivateR(ctx,x,y)` means that original responder operation has durably
  installed its role-2 `Messages` state. An already installed original state
  reconciles to the same event rather than creating a fresh transcript.
* `AcceptI(ctx,x,y)` means the native client returns `Established`, or the
  portable client returns `Session`, after the READY proof, archive and final
  current-authority checks succeed.

Transcript equivalence is equality of `ctx,x,y`. Repeated calls and reopened
owners belong to that same class. The events identify a logical original
transcript, independent of how often its process or transport is restarted.

## 2. Exact-wire agreement at Final

**Proposition 1 (Final binding).** Suppose `FinalI(ctx_I,x_I,y_I)` produces a Final
accepted by a responder retaining `(ctx_R,x_R,y_R)`. If `H` has no collision on
the observed context and signed-wire inputs, then

```
ctx_I = ctx_R,   x_I = x_R,   y_I = y_R.
```

When both honest operations' KEM computations satisfy correctness, they also
derive the same `seed`, `K_B` and initial traffic/ACK tuple.

**Proof.** `ResponderOperation::finish` first computes its own `final_prefix`
from the saved `initial` and `reply` and compares all 104 bytes with the supplied
prefix. It then verifies MACI over that expected prefix. Successful comparison
equates the fixed tag, the 32-byte context and both complete-wire digests.
Absence of the stated collisions equates the full signed wires. The same Initial
therefore binds the same responder prekeys, reply public key and initial KEM
context; the same Reply binds the same second ciphertext and reply KEM context.
KEM correctness gives the same `S0,S1`, and the source's deterministic schedule
then gives the claimed equality. Repeated Final acceptance compares the exact
previously accepted bytes. The journal commits `Complete` before releasing its
result. **QED.**

This proof permits several valid signatures on one body. A changed Reply
signature changes the input to `H("reply-wire",...)`; the comparison above is
therefore exactly where the source resolves the same-body ambiguity.

## 3. Terminal agreement under a joint key schedule

### 3.1 Security experiment

Allow an active adversary to create concurrent admitted contexts, schedule
messages, replay complete flights and ACKs, and invoke the declared disclosure
interfaces. Protected targets name an expected responder identity executing the
honest code with the stated authenticated-persistence premise. Physical copies
and exact retries of one complete transcript belong to one logical class; valid
same-body replies with different signature bytes belong to distinct classes.

The experiment maintains a finite **online protected family**. A registration
rule, fixed independently of the real-versus-ideal bit, receives the complete
`(ctx,x,y)` class before the first private computation or use of its ACK key
at either endpoint and chooses whether to protect it. Classes already used outside the family remain unprotected. A
protected class stays protected; exact retries use its original registration.
Registration is refused if the past declared disclosure history already contains
a recipe reconstructing that class's `ack_I`.

The recipe interface includes direct ACK-key disclosure, `K_B`, `seed`, both
`S0` and `S1`, and readable stored reservations/checkpoints which recover those
values. Records and wrapping keys enter the closure according to the declared
source/guard graph. Source overlap is preserved across all transcript classes.
For example, learning a shared `seed` reaches both full-wire aliases, whereas
one derived root is not treated as an inverse for that seed. The time of public
dispatch does not move a reservation's origin.

If a later disclosure request would reveal a recipe for **any protected class's**
ACK key, both games record `Stop` and end before returning that disclosure. A
request which maliciously replaces a protected target's trusted private state
also stops the experiment. Other disclosed values and unprotected classes are
handled by their real algorithms. This is a declared stopped interface; the
implementation's actual disclosure semantics remain unchanged. The theorem
concerns events before `Stop`, with no retrospective selection of surviving
classes. A result allowing later protected-key disclosure requires a separate
stopping/partition argument and its explicit cost.

Define `epsilon_schedule` to be the distinguishing gap for consistently
replacing each class's `ack_I` by a fresh uniform 32-byte key **when that class is
registered**. Both endpoints and all exact retries use the same replacement.
The experiment retains the actual public transcript, MAC0/MACR/MACI, other
available outputs, allowed disclosures and adaptive verification replies.
Unprotected classes use their actual keys, including any outputs correlated
through a shared source. The replacement is therefore an online joint-family
experiment, with a declared finite family-size bound. Individual marginal key
uniformity does not supply its hypothesis.

The corresponding HMAC game replaces the MAC under each registered uniform key
by an independent random function on the complete authenticated byte string.
Every other known-key operation remains in the simulated view. Uniform sampling
allows numerical key coincidences; the games do not condition on pairwise
distinct keys. Their resulting correlations are included in the multi-key PRF
gap. Let `epsilon_mac` be its multi-key PRF distinguishing gap for that same family
bound and stopped interface. Key reuse within a class is preserved. The games
allow local signing-identity disclosure when it does not reveal the protected
ACK recipe; an instantiation of `epsilon_schedule` must establish its gap with
those actual disclosures.

Let `Coll` be a collision among the source's relevant context, complete-wire
or session-ID hash inputs in the original real experiment; both distinguishing
gaps also stop at this event.
Let `q_v < 2^256` bound the total number of distinct MAC-verification guesses
across registered classes before their corresponding historical responder
activation and before `Stop`, including unsuccessful retries. The registration
rule and the total family/query budgets are fixed before the experiment.

### 3.2 Theorem and proof

**Theorem 2 (historical responder activation).** In this experiment, let `Bad`
mean that, before `Stop`, some registered `AcceptI(ctx,x,y)` occurs with no earlier
`ActivateR(ctx,x,y)` under its expected honest responder identity. `Bad` is a
latched flag: a later `Stop` preserves an already observed bad acceptance. Then

```
Pr[Bad] <= min{1, Pr[Coll] + epsilon_schedule + epsilon_mac
                   + q_v / (2^256 - q_v + 1)}.
```

The explicit last term permits adaptive tag guesses and negative verification
feedback without a per-session target-guessing factor. For small `q_v` it has
the familiar scale `q_v / 2^256`.

**Proof.** First charge `Coll`. Equal `sid` values then identify the same exact
Final prefix and, by its component hashes, the same context and complete signed
wires. Apply the online joint-family schedule replacement; its registered set is
monotone and never selected from later outcomes. The change in `Bad` probability
is at most `epsilon_schedule`. Apply the multi-key MAC replacement, charging
`epsilon_mac`.

Before any `ActivateR` in a target class, the responder has no admitted role-2
message state from which to produce its direction-1 epoch-zero ACK. Its first
activation requires the original `Complete` record. An initiator's ordinary ACK
oracle uses direction 2 and the other key; it cannot supply a previously issued
tag for the direction-1 input accepted here. Other protected classes have independent ideal functions; unprotected-class
behavior remains in the retained auxiliary view. Sibling confirmation outputs and all allowed
leakage were retained by the joint schedule experiment.

The protected recipe and state premises hold up to `Stop`. The client accepts
only a well-formed epoch-zero ACK with its exact `sid` and
direction 1. Before the first bad acceptance, the relevant random-function value
has therefore never been released through an honest responder activation. For
each query, its tag remains uniform among at least `2^256 - q_v + 1` unexcluded
values. A union bound over at most `q_v` distinct guesses gives the final term.
Replaying the same failed guess cannot increase that count. If a valid ACK was
already produced by an honest responder state, that state's earlier activation
already satisfies the theorem's origin condition. Both clients perform the ACK
check before returning their terminal success value. **QED.**

For a KCI experiment which discloses the initiator's signing identity while
retaining this online protected interface, this is the same terminal reduction.
The remaining cryptographic task is to establish `epsilon_schedule` with that
disclosure and the actual two ContextBound contributions. Thus the conversion
has a concrete proof, while U2 retains the precise primitive-level obligation.

### 3.3 Reconciliation and exposure consequences

An authentic old READY proof establishes the earlier matching activation even
when the adversary delays it. Multiple successful initiator calls may refer to
one such activation. The theorem uses this correspondence intentionally.

Initiator activation precedes ACK verification in both connection clients. A
failed proof can consequently leave the original initiator `Messages` state
durable. The error return supplies no connection success; recovery reconciles
the same original initiation, Final and session identity.

Disclosure of `K_B` constructively gives all 160 activation bytes and a valid
READY tag. A request for that value therefore
triggers the protected experiment's `Stop`. Disclosure of only
`R_0` supplies one output block of that expansion. It is a distinct input to the
joint schedule question; the storage assessment must preserve which other
blocks the acquired record actually contained.

## 4. Source correspondence and executed controls

The [evidence packet](../../research/sdk-alpha1/evidence/20261109-bootstrap-terminal-agreement/README.md)
binds 16 inspected implementation/specification files to the complete Git tree of the assessed
commit with both Git-blob and SHA-256 digests. It contains the executable
independent equation/control check and its actual result.

| Claim | Inspected implementation |
| --- | --- |
| Exact Final binding, Reply-input binding and root derivation | `bootstrap.rs`: `finish_initiator`, `ResponderOperation::finish`, `final_prefix`, `pending`, `schedule` |
| Durable completion before responder activation | `durable.rs`: `DeviceJournal::finish`; `durable/messages.rs`: `activate_responder_messages`, `install_messages` |
| `K_B` activation graph and correct ACK key orientation | `durable/messages.rs`: `State::new`; `durable/messages/traffic.rs`: `Traffic::from_material` |
| Exact epoch, session, direction, MAC and consumed-floor checks | `durable/messages/acknowledgement.rs`: `wire_epoch`, `acknowledgement`, `accept_acknowledgement` |
| Native terminal return ordering | `connection_transport/client.rs` and `server.rs` |
| Portable terminal return ordering | `session_exchange/client.rs` and `server.rs` |

The new execution reproduces eight public synthetic vectors already asserted
by the native Rust tests, covering the three bootstrap outputs, MACR, `sid`,
`K_B`, the initial root/chains and a directional ACK. Eighteen additional controls
exercise the same-body/full-wire split, Final and READY rejection, reflection,
old-session grafting, positive epochs, consumption ceilings, exact proof replay
and the constructive root-disclosure case. Fourteen online-family controls
exercise registration timing, monotonicity, cross-class source overlap and
guarded record disclosure. A complete 192-case scope matrix
varies transcript, direction, epoch, consumed floor and key source. Its two
accepted entries are precisely the correct transcript and key, direction 1,
epoch 0, with the admitted floors zero and one.

These are executed public-input equation and parser controls. They complement
the retained real KEM/signature runs R1–R4 in the construction matrix; they are
not substituted for those runs. The theorem is the analytical reduction above,
and the controls make its encoding, directional and exposure boundaries
independently reproducible.

## 5. Admission disposition

The current Final and READY mechanisms satisfy the exact source obligations of
the terminal conversion. The implemented classical-alias repair and its retained
native regressions remain valid evidence. No wire, package, cryptographic
primitive, retry policy or runtime permission is changed by this increment.

The next cryptographic dependency is the bootstrap joint schedule experiment
with the selected hybrid/component and local-identity disclosures, together
with its source-retention interpretation. Package identity, workload selection
and the external assessment retain their existing admission entries.
