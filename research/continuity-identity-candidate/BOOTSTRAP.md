# Authenticated three-flight bootstrap candidate

This executable candidate connects actual verified account/device chains,
authenticated prekey selections and a signed protocol policy to the SDK's owned
ContextBound KEM operations. It remains isolated from published packages. ABI
major **2**, extension **1**, the 43 C exports and 26 JNI registrations remain
unchanged. These candidate encodings are not the frozen Continuity wire format.

## Authority and scope

The host independently provisions both account roots and exact roster heads,
the protocol-policy authority and exact policy head, the SDK algorithm-policy
root/state, trusted time and the expected directory checkpoint. A checkpoint
comparison does not prove directory consistency. Incoming messages cannot choose
those trusted expectations. Policy and roster replacement still need the service's
durable transaction fence.

The protocol policy uses both ML-DSA-65 and P-256/SHA-256 signatures, purpose **4**
under the identity candidate's envelope. Its 165-byte body is:

`QPSESP01[8] || family[32] || version:u64 || interval[16] || suite[32] || sdk[68] || modes:u8`

`family = D("POLICY-AUTHORITY", policy public pair)` and the exact policy checkpoint
is `(version, D("SESSION-POLICY", body))`, where `D` is defined in [README](README.md).
`sdk` is the actual runtime's SHA-256 algorithm-policy root digest followed by
policy version:u32 and SHA3-256 of the exact signed policy document. The version
is in `1..u64::MAX`, with the upper bound excluded. Unknown mode bits fail;
bit `quality-1` permits exactly one of the four `PrekeyQuality` values. Empty
permissions disable bootstrap. Nonempty permissions cannot bind a disabled SDK.
No fallback or exhaustion claim is inferred from a permitted reusable mode.

The fixed suite digest is `D("BOOTSTRAP-SUITE", ASCII(`
`ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256`))`.
Account/device family must match the policy authority. Either device signing
component must differ from its peer's and the protocol authority's component;
the device's ML-DSA public key must also differ from the SDK policy root. Account
issuance already rejects a device sharing either of its account-root components.

`BootstrapContext` also requires the selection's responder identity and roster
authority to match the verified responder, its algorithm-policy digest and suite
to match the runtime/profile, and its directory digest to match trusted state.
It checks both credentials, both rosters, policy and all referenced prekey validity
intervals at construction and each operation boundary. This candidate's strict
handshake expiry rule is not an established-session lifetime policy.

## Domains and role-ordered context

All integers are unsigned big-endian. Fixed fields have no padding or length
prefix unless stated. Define:

`H(label, bytes) = SHA3-256(u64(len(domain)) || domain || u64(len(bytes)) || bytes)`

where `domain = ASCII("Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/") || ASCII(label)`.
The context digest is `H("context", ...)` over:

1. Suite[32], protocol family[32], protocol version:u64, protocol body digest[32], SDK binding[68].
2. Initiator account[32], device[16], generation:u64, credential digest[32], roster authority[32].
3. The same fields for the responder, in that order.
4. The complete canonical authenticated PrekeySelectionV1[492], directory checkpoint[32].

Peer public KEM bytes are the selected ML-KEM-768 public[1184] followed by
X25519 public[32]. Runtime encapsulation checks primitive admissibility. The
responder's typed component borrows must reproduce these exact bytes, and both
owners must belong to the specified policy runtime. A second runtime with the
same policy is still a different local revocation/admission authority.

## Three flights

Every nonce and encapsulation uses OS randomness. The initiator's reply key is a
fresh owned hybrid key; it is not an account or manifest signing key. Both signature
components are required, with the identity candidate's purpose separation and
low-S requirement. The first two flights use its u32-length signed envelope.

| Flight | Body and exact size | Authentication |
| --- | --- | --- |
| Initial | `QPBSI001[8] || context[32] || nonceI[32] || replyPublic[1216] || C0[1120] || MAC0[32]` = 2440 bytes; envelope 5817 | Initiator dual signature, purpose 5 |
| Reply | `QPBSR001[8] || context[32] || H0[32] || nonceR[32] || C1[1120] || MACR[32]` = 1256 bytes; envelope 4633 | Responder dual signature, purpose 6 |
| Final | `QPBSF001[8] || context[32] || H0[32] || H1[32] || MACI[32]` = 136 bytes | Initiator confirmation MAC |

`C0, S0` come from encapsulating to the authenticated responder selection with
application context `H("kem-initial", initial prefix[1288])`.
Let `t0 = H("initial-core", initial prefix || C0)`.
`K0` is SDK purpose derivation from S0 using `InitiatorConfirmation`, ASCII label
`ContinuityBootstrapCandidate/v1/initial` and context t0. The SDK derivation also
binds its algorithm policy and root. `MAC0 = HMAC-SHA-256(K0, t0)`.
The responder verifies the signature, scope, actual selected key owners and MAC0
before generating its own contribution. Correct-length invalid PQ ciphertexts
retain implicit rejection and fail the confirmation; they are not accepted
as an authenticated session.

`H0 = H("initial-wire", entire signed initial)`.
The responder encapsulates to the signed reply public key with application context
`H("kem-reply", reply prefix[104])`, producing fresh `C1, S1`.
Let `t1 = H("reply-core", reply prefix || C1)`.
Derive three independent 32-byte outputs by HKDF-SHA-256 with salt t1, IKM
`S0[32] || S1[32]` and info:

`ASCII("Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF-CANDIDATE/v1/") || label`

Labels are `handshake-seed`, `confirmation-responder`, `confirmation-initiator`.
`MACR = HMAC-SHA-256(confirmation-responder, t1)`.
After authenticating the responder and verifying MACR, the initiator erases
its reply key and retained S0. `H1 = H("reply-wire", entire signed reply)`.
`MACI = HMAC-SHA-256(confirmation-initiator, H("final-core", final prefix[104]))`.
Only successful MACI validation completes the responder's cryptographic operation.

The session ID is `H("session-id", final prefix[104])`. The private root uses
another HKDF-SHA-256 extraction with salt=session ID and IKM=handshake-seed;
its info is the same KDF domain followed by `session-root/` and context[32].
This binds the root to both complete randomized signed flights without requiring
a signature or confirmation to depend on itself. Confirmation outputs and roots
are owned zeroizing buffers; no root export, traffic API or serialization is
provided here. Provider/compiler temporary copies are outside that owner guarantee.

## Operation state and failures

An initiator operation retains its exact initial wire, reply key and S0 until a
valid reply arrives. Invalid replies leave it pending. Success pins the exact reply
and final wire; byte-identical duplicates return that cached result, while any
different reply returns `Conflict`. Closing drops retained secret owners.

A responder operation begins idle. Invalid initial signatures, scopes or MAC0
produce no response and do not change its phase. Once MAC0 succeeds, the operation
is marked closed before fresh response computation: entropy, provider or signing
failure cannot silently return it to idle for a new attempt. Success stores the
exact initial/reply pair and pending root. An exact initial duplicate returns the
same response without private-key access or new randomness. A different initial
conflicts. Invalid final confirmation leaves the prepared state available; success
pins its exact bytes and erases the confirmation key. Different final bytes then
conflict. Finishing an idle operation returns `State`, not a false success.

These are **volatile** state transitions. A new operation can process the same
initial again, including a one-time selection: the cryptographic object cannot
enforce global one-time use. Each such response introduces fresh KEM randomness
and a fresh nonce; its session root differs, and an initiator that pinned a response
rejects the other one. This is not a substitute for durable reservation or replay
handling. The result types intentionally provide no receipt authorizing dispatch,
prekey consumption, session installation or plaintext release.

The product integration must implement the ordered contract in
[G1 effect lifecycle](../../docs/continuity/G1_EFFECT_LIFECYCLE.md): durable sealed
reservation, bounded cryptographic effect, exact result pin, required anchors,
atomic prekey/session/inbox/outbox/dedup commit and idempotent release. Unknown
commits, cancellation, crash recovery, current roster/policy/directory fences,
rekey/ratchet transitions and multi-device effects remain required implementation
work. They cannot be represented by caller-supplied success booleans.

## Validation and limits of the evidence

Tests use two separately verified runtimes and real owned keys/signatures for
all four modes. They cover both signature components, signed ciphertext/MAC/context
substitution, selected-owner/runtime mismatch, replay conflicts, exact duplicates,
expiry, policy/runtime close, distinct response roots and failure after initial
confirmation. Synthetic KDF vectors are independently calculated with Python
HMAC/SHA-256 and SHA3-256. The public fixture oracle separately verifies the SDK
policy signature, both identity chains, session policy, manifest membership,
selection, role-ordered context, signed flights and final transcript/session ID.
It receives no live shared secrets and therefore does not verify live confirmation
MACs or root equality; actual peer tests cover those computations.

The construction assumes authenticated independent pins, trusted time, functioning
entropy/providers and uncompromised relevant secret owners. Signature and KEM
tests do not prove protocol security, forward secrecy after arbitrary compromise,
post-compromise recovery, directory consistency or durable at-most-once effects.
Formal treatment and the ratchet/storage integration must address those precise
claims before product protocol promotion. The earlier Signal/RFC comparison is
background; this candidate does not inherit another protocol's security result.
