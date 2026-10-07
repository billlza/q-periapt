# Continuity wire contract, revision 1

This specifies the currently implemented identity candidate and its v6 rekey
profile. It is the byte contract for adapter work, not the completed product
protocol freeze or a security proof. The independent identifiers below are part
of cryptographic inputs; an SDK version, C ABI major **2**, or a successful TLS
handshake does not select or replace them. The candidate is still unpublished.

The [shared Rust contract](../../research/continuity-identity-candidate/src/contract.rs)
supplies the bounds actually used by its codecs, journal and carriers.
[BUDGETS_V1.json](BUDGETS_V1.json) records those values and their units. Limits apply
together: an individual count limit does not promise that all maximum-sized
objects also fit the aggregate image. The signed application-send allowance is
issuer-selected in `1..65535`; this document supplies no unsigned default.

## Representation and verification boundary

`u8/u16/u32/u64` are unsigned, big-endian integers. `x[n]` is exactly n bytes.
Concatenation has no padding, native struct layout, implicit string terminator or
alignment bytes. All complete records reject truncation, surplus bytes and unknown
discriminants. Counter arithmetic is checked. Generations and content revisions
are positive and below `2^64-1`; a traffic epoch/index may be zero but cannot be
`2^64-1`. An interval is `from:u64 || until:u64`, denotes `[from, until)`, has
`from < until`, and excludes `until = 2^64-1`. Time is an independent trusted input.

Lengths below describe encoding, not admission. An adapter must retain the original
verified policy owner, account pins/checkpoints, exact intended device generations,
directory expectation and requested prekey quality independently of received bytes.
Current authority, required witnesses, signature/MAC validation and durable phase
checks still govern every operation and release. Parsing never provisions a device,
creates a trust pin, consumes a prekey or acknowledges application effects.

Define `LDH(domain, data) = SHA3-256(u64(len(domain)) || domain ||
u64(len(data)) || data)`. Domain strings below are exact ASCII bytes. Fixed hash
outputs are 32 bytes. A body digest excludes its randomized signatures; a digest
explicitly named `*-wire` includes the complete signed envelope. These two kinds
of commitment must not be interchanged.

## Hybrid identity envelope

The signing public key is `ML-DSA-65[1952] || compressed-SEC1-P-256[33]` (1985
bytes). P-256 points must have their canonical compressed representation. A
signature is `ML-DSA-65[3309] || ECDSA-r[32] || ECDSA-s[32]` (3373 bytes).
ECDSA uses SHA-256 and rejects high S. Both components are mandatory.

Let `I = "Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1"`. Both signatures cover
`I || purpose:u8 || body_length:u32 || body`. ML-DSA also uses I as its external
context, with the ordinary ML-DSA message encoding. The signed envelope is
`body_length:u32 || body || signature[3373]`. The common body cap is 16384 bytes;
each record below imposes its own tighter grammar and expected purpose. A length
prefix is not permission to allocate outside that cap.

| Purpose | Signed record |
| --- | --- |
| 1, 2, 3 | Device credential, account roster, prekey manifest |
| 4, 5, 6 | Session policy, initial bootstrap, bootstrap reply |
| 7, 8 | Witness request, witness reply |
| 9, 10, 11, 12, 13 | Rekey offer, response, final, receipt, request |
| 14, 15 | Enrollment request, same-key credential renewal |
| 16 | Joint policy-continuation approval (both independent roots) |

Purpose numbers are signature inputs, not a free-form signing API. No application
message acquires a dual signature merely by belonging to a signed session.

The enrollment and credential-renewal records are specified in the candidate's
[enrollment](../../research/continuity-identity-candidate/ENROLLMENT.md) and
[credential-renewal](../../research/continuity-identity-candidate/CREDENTIAL_RENEWAL.md)
contracts.

### Joint policy-continuation approval

The separate candidate identifier is `qperiapt-policy-continuation/1`. Each
purpose-16 approval signs the same exact 490-byte body, in this order:

```
QPPCTN01[8], operation[32], journal[32], original_owner[32],
original_credential[32], previous_credential[32], credential_statement[32],
target_credential[32], target_authority[32], policy_family[32],
previous_roster_version:u64, previous_roster_digest[32],
original_policy_version:u64, original_policy_digest[32],
previous_policy_version:u64, previous_policy_digest[32],
target_policy_version:u64, target_policy_digest[32],
previous_authorization_present:u8, previous_authorization[32], permission:u8
```

An absent prior authorization is exactly `0 || zero[32]` and is allowed only
for the original P0 predecessor. A present authorization is `1 || nonzero[32]`
and names the exact prior joint statement. The only permission is `1`, for
retained established sessions. The container is
`QPPCTB01[8] || account_length:u16 || account_envelope || policy_length:u16 ||
policy_envelope`; each envelope is exactly 3867 bytes and the container is exactly
7746 bytes. Both independently supplied roots must verify both signature
components; the two bodies must be byte-identical. The statement commitment is
`LDH("Q-PERIAPT-POLICY-CONTINUATION-CANDIDATE/v1", body)`.

Approvals cannot select trust pins, the original journal or predecessor state.
Current target policy and credential admission, original profile equality and
durable predecessor comparison remain mandatory. The current implementation
supports a coupled same-key credential and policy validity extension for local
retained sessions only. It supplies neither fresh-bootstrap permission nor
required-witness continuation. See the [operational and recovery contract](../../research/continuity-identity-candidate/POLICY_CONTINUATION.md).

## Account, device, roster and prekey materials

For this section, `D(name, x) = LDH("Q-PERIAPT-CONTINUITY-" || name ||
"-CANDIDATE/v1", x)`.

| Record | Body fields in order | Body bytes |
| --- | --- | --- |
| Credential | `QPCERT01[8], account[32], device[16], generation:u64, interval[16], family[32], public_key[1985]` | 2097 |
| Roster | `QPROST01[8], account[32], version:u64, interval[16], count:u16, entries[count]` | `66 + 56*count` |
| Manifest | `QPMANF01[8], scope[248], count:u16, merkle_root[32]` | 290 |
| Unsigned leaf | `QPLEAF01[8], kind:u8, interval[16], public_key[32 or 1184]` | 57 or 1209 |

A roster entry is `device[16] || generation:u64 || credential_digest[32]`.
At most 32 entries occur, in strictly increasing byte order of device ID with no
duplicates. Zero entries is an explicit empty roster, not a lookup failure.
Account ID is `D("ACCOUNT", root_public_key)`; credential/roster digests use
`D("CREDENTIAL", credential_body)` / `D("ROSTER", roster_body)`.
The device ID and required commitments are nonzero. Device/root and peer/policy
key-separation checks are part of verification, not inferred from different IDs.

Manifest scope is `account[32] || device[16] || generation:u64 ||
credential_digest[32] || roster_version:u64 || roster_digest[32] ||
bundle_epoch:u64 || sdk_policy_digest[32] || suite_digest[32] ||
directory_checkpoint[32] || interval[16]`. Count is in 1..1024. Manifest validity
is contained in credential and roster validity; leaf validity is contained in it.

Leaf kinds 1/2 are reusable-signed/one-time X25519; kinds 3/4 are last-resort/one-time
ML-KEM-768. Public lengths are exactly 32 or 1184; all-zero keys and unknown kinds
fail shape checks. Primitive admissibility remains a later required check.
Leaf ID is `D("PREKEY-LEAF", scope || leaf)`; public-key fingerprint is
`D("PREKEY-PUBLIC", algorithm:u8 || public_key)` with algorithm 1=X25519, 2=ML-KEM.

The issuer sorts leaves by ID. A single leaf is its own root. Otherwise split at
the largest power of two strictly below the count and recursively hash the two
roots with `D("PREKEY-NODE", left || right)`, without padded leaves. A proof is
`index:u16 || leaf_length:u16 || leaf || depth:u8 || siblings[depth*32]`.
Index is below count, depth is at most ten, and count/index determine the exact
path and directions. Siblings run from leaf toward root. A membership proof does
not prove uniqueness or sorting of leaves withheld by a malicious issuer.

The authenticated selection is the exact 492-byte, sixteen-field LP8 encoding in
[PrekeySelectionV1](PREKEY_SELECTION_V1.md). Its existing digest domain and 555-byte
preimage are retained; they do not acquire the identity-candidate suffix. Quality
codes are 1=one-time both, 2=reusable both, 3=signed classical/one-time PQ,
4=one-time classical/last-resort PQ. Both baseline leaf IDs remain bound.

### Bootstrap-material container

`QPBNDL01[8] || quality:u8 || nine (length:u16 || field)` has a 65536-byte complete
cap and an 8192-byte cap per field. The ordered fields are initiator credential,
initiator roster, responder credential, responder roster, responder manifest,
signed-classical proof, last-resort-PQ proof, one-time-classical proof,
one-time-PQ proof. The first seven are nonempty. The eighth occurs only in modes
1/4 and the ninth only in modes 1/3. An absent field is exactly zero length;
missing required or extra optional proof data is invalid. It carries neither
trust roots nor permission to change the caller's requested mode. It is an import
container, not an additional network flight and not a new context hash.

## Session policy and bootstrap

The purpose-4 policy body is exactly 200 bytes:

`QPSESP03[8] || family[32] || version:u64 || interval[16] || suite[32] ||
sdk[68] || modes:u8 || anchor_mode:u8 || witness_binding[32] || send_budget:u16`.

`sdk = SHA256(pinned SDK policy root)[32] || SDK_version:u32 ||
SHA3-256(exact SDK policy document)[32]`. Only the low four mode bits are defined;
bit `quality-1` permits that exact quality. Empty permissions disable bootstrap.
Anchor mode 0 requires zero witness bytes; mode 1 requires a nonzero, independently
pinned witness binding. Other modes fail. Send budget is nonzero. Old QPSESP01/02
bodies are not aliases for this format. Family and policy-body digests use
`D("POLICY-AUTHORITY", policy_public_key)` and `D("SESSION-POLICY", policy_body)`.

The suite is `D("BOOTSTRAP-SUITE", "ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256")`.
Let `B = "Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/"` and
`H_B(label,x) = LDH(B || label,x)`. Context is `H_B("context", ...)` over:

1. suite[32], policy family[32], policy version:u64, policy body digest[32], sdk[68];
2. initiator account[32], device[16], generation:u64, credential digest[32], roster authority[32];
3. the same responder fields; then selection[492] and directory checkpoint[32].

Roster authority is `D("AUTHORITY", account || roster_version:u64 ||
roster_digest || family)`. Roles are fixed by this context, not by socket direction.
KEM public bytes are ML-KEM public[1184] then X25519 public[32]; ciphertext is
ML-KEM ciphertext[1088] then X25519 share[32].

| Flight | Body fields | Body / complete wire bytes |
| --- | --- | --- |
| Initial, purpose 5 | `QPBSI001[8], context[32], nonceI[32], reply_public[1216], C0[1120], MAC0[32]` | 2440 / 5817 |
| Reply, purpose 6 | `QPBSR001[8], context[32], H0[32], nonceR[32], C1[1120], MACR[32]` | 1256 / 4633 |
| Final, MAC only | `QPBSF001[8], context[32], H0[32], H1[32], MACI[32]` | 136 / 136 |

`H0=H_B("initial-wire", signed_initial)` and
`H1=H_B("reply-wire", signed_reply)`. Session ID is
`H_B("session-id", final_without_MAC[104])`. The exact non-circular KEM, KDF and
confirmation graph is specified in [BOOTSTRAP.md](../../research/continuity-identity-candidate/BOOTSTRAP.md#three-flights).
Correct-length invalid ML-KEM ciphertexts retain implicit rejection and must fail
confirmation; adapters cannot turn them into an alternate accepted mode.

## Application frames and consumption proofs

Let `M = "Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/"`. A 93-byte header is
`QPCMSG03[8] || session[32] || direction:u8 || epoch:u64 || index:u64 ||
message_id[32] || plaintext_length:u32`. Direction 1 means original
initiator-to-responder, 2 the reverse. Epoch/index range is 0..`2^64-2`.
Message ID is `epoch:u64 || index:u64 || first16(LDH(M || "epoch-message-id",
session || direction || epoch:u64 || index:u64))`. Checking nonzero ID bytes
alone does not establish this scope binding or allocate a new send slot.

Frame is header, ciphertext of exactly plaintext_length, then a 16-byte
ChaCha20-Poly1305 tag. Plaintext may be empty and is at most 16384 bytes. The
complete frame is 109..16493 bytes. AEAD AD is `M || "aead" || header ||
app_ad_length:u16 || app_ad`; application AD is at most 1024 bytes. It is a separate
argument to the message API and is included by the application carrier below.
Nonce is twelve zero bytes under an enforced one-use message key; exact-operation
reconciliation is essential. [MESSAGES.md](../../research/continuity-identity-candidate/MESSAGES.md#fixed-candidate-cryptography-and-bytes)
specifies the chain/KDF and retained-input commitments.

| Epoch | ACK bytes before final MAC | Complete bytes |
| --- | --- | --- |
| Zero only | `QPCMACK1[8], session[32], direction:u8, consumed_prefix:u64` | 81 |
| Positive only | `QPCMACK2[8], session[32], direction:u8, epoch:u64, consumed_prefix:u64` | 89 |

Append `HMAC-SHA256(directional_epoch_ack_key, M || "acknowledgement" || prefix)`.
Direction identifies the acknowledged sender, not the producer of the ACK.
A valid prefix cannot exceed that epoch's sent count and cannot regress the
retained floor. The old format is only the canonical zero-epoch form; accepting
it as a positive-epoch ACK would cross an authority boundary. An ACK commits
contiguous application consumption, not merely receipt or queued work. Below an
erased receive prefix, reconciliation can prove prior consumption of the ID,
not authenticity of new replacement bytes supplied with that ID.

## Signed rekey and independent progress requests

Let `R = "Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/"` and
`H_R(label,x) = LDH(R || label,x)`. The exact profile description is:

```text
ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;accountable-epoch-ratchet/v6;messages/v3;retained-epochs=4;settled-prefix-attestation/v1;application-send-budget/v1;control-request/v1
```

Profile is `H_R("offer-profile", description)`:
`67e912ec03fe626d642b19f3dd6a30b6934950846620656bf3863093158cfa11`.
Every control has a 153-byte prefix:
`tag[8] || profile[32] || context[32] || session[32] || prior:u64 || target:u64 ||
role:u8 || predecessor[32]`. Target is exactly prior+1, positive and below
`2^64-1`. Original initiator proposes odd targets; responder proposes even ones.
Request/response/receipt use the other role. Initial predecessor is
`H_R("genesis", session || context)`; subsequently it is
`H_R("completed-epoch", offer || response || final || receipt)` over full wires.

| Record | Tag / purpose | Suffix after common prefix | Body / wire bytes |
| --- | --- | --- | --- |
| Request | QPRKRQ01 / 13 | none | 153 / 3530 |
| Offer | QPRKOF01 / 9 | public key[1216] | 1369 / 4746 |
| Response | QPRKRP01 / 10 | offer hash[32], ciphertext[1120], MAC[32] | 1337 / 4714 |
| Final | QPRKFN01 / 11 | offer hash[32], response hash[32], old send count:u64, MAC[32] | 257 / 3634 |
| Receipt | QPRKRC01 / 12 | offer hash[32], response hash[32], final hash[32], old send count:u64, MAC[32] | 289 / 3666 |

Hashes use `H_R("offer-wire", ...)`, `"response-wire"` and `"final-wire"`.
All five use the mandatory dual-signature envelope. The MAC/KDF graph and
asymmetric send/receive cutovers are specified in
[REKEY_OFFERS.md](../../research/continuity-identity-candidate/REKEY_OFFERS.md#fixed-public-grammar-and-kdf-graph).
Offer and response also assert locally settled history below `max(0,target-3)`.
A request asserts no such settlement and grants no send credit. Replaying control
never creates new entropy or refunds a signed send allowance. Local completion is
not a claim about attacker knowledge or delivery of the last reply.

## Native carriers over the standard SDK connection

Both carriers use the exact [SDK TLS/application framing](../SDK_CONNECTION.md#version-1-application-bytes),
including pinned mutual TLS, policy confirmation, request/response sequence and
one outstanding request. The SDK payload cap is 65536 bytes; its outer body cap
is 65545, not 65536. TLS client/server direction is independent of bootstrap roles.
No alternate JSON, plaintext or classic-only carrier is negotiated.

QPCNET01 uses SDK application context
`"Q-PERIAPT-CONTINUITY-CONNECTION-TLS/v1/" || context[32]`. Its payload is
`QPCNET01[8] || kind:u8 || nonempty_body`, at most 32768 bytes total.

| Kind | Body |
| --- | --- |
| 1 | Original signed initial, nonempty and at most 8192 bytes before its exact flight verification |
| 2 | initial_length:u16, original initial, original final |
| 3 | app_ad_length:u16, application AD, original encrypted message |
| 129 | Original signed reply |
| 130 | Exact activated session[32] |
| 131 | Original epoch-specific consumption ACK |

QPCCTL01 uses SDK application context
`"Q-PERIAPT-CONTINUITY-CONTROL-TLS/v1/" || context[32] || session[32]`.
A request is `QPCCTL01[8] || signed_control[1..8192]`. A reply is either
`QPCCTL01[8] || 0:u8` (exactly nine bytes), or
`QPCCTL01[8] || 1:u8 || signed_control[1..8192]`. The empty reply is only a carrier
disposition. The caller must independently reach its exact requested target in
the journal before reporting completion; an old valid receipt is not that proof.

The outer carrier rejects malformed splits/kinds before dispatch; original inner
decoders still enforce exact sizes, roles, context, epoch and authentication.
Each invocation has 1..128 exchanges, a nonzero total timeout <=120 seconds and
nonzero connect timeout <=5 seconds. Reconnect preserves the total deadline.
Cancellation cannot undo a local or remote commit. These limits do not forcibly
preempt crypto, storage or host callbacks.

## Witness commands and receipts

These are separately pinned, signed witness operations, not application messages.
Authority binding is `LDH("Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1",
instance[32] || public_key[1985])`. Subject is `journal[32] || owner[32] ||
policy_digest[32]`. Head is `fence:u64 || revision:u64 || image_digest[32]` (48
bytes); its counters are positive and below `2^64-1`, with a nonzero digest.

Command is `kind:u8 || expected_head[48] || next_head[48]` (97 bytes).
Query=1 requires all 96 head bytes zero. Advance=2 increments revision only and
changes digest. Fence=3 increments fence only. Other fields remain exact.
Command ID is `LDH("Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1",
authority[32] || subject[96] || command[97])`.

| Purpose | Body | Body / envelope bytes |
| --- | --- | --- |
| 7 | `QPANRQ01[8], authority[32], subject[96], command_id[32], challenge[32], command[97]` | 297 / 3674 |
| 8 | `QPANRS01[8], authority[32], subject[96], request_digest[32], command_id[32], outcome:u8, observed_head[48], has_last:u8, last_command[32]` | 282 / 3659 |

Each attempt has a fresh nonzero challenge. Request digest is
`LDH("Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", request_body)`. Outcome values
Current=1, Advanced=2, AlreadyAppliedExact=3, Conflict=4 have the exact
[witness consistency rules](../../research/continuity-identity-candidate/ANCHOR_WITNESS.md#exact-signed-wire).
`has_last=0` requires zero last-command bytes and head 1/1; later states require 1.
A receipt must answer that attempt, subject and immutable command under the
independently configured witness key. Incoming bytes cannot enroll or reset a
subject. A signed conflict is not successful advancement.

The reference witness TCP adapter carries `length:u32 || signed_request`, then
`length:u32 || signed_reply`, requiring lengths 3674/3659 before body allocation.
Signatures authenticate the contents; this TCP adapter does not encrypt metadata.
Application carrier TLS confidentiality must not be attributed to this separate
connection. A failed/timed-out attempt may already have committed at the witness.

## Local-only formats and remaining freeze requirements

The journal, wrapping/signing files, installation configuration, write intents,
catalogue, closure archives and loss reports are local persistence inputs. They
are not interchangeable with these network/import records. Current journal schema
21 uses `continuity_device_candidate_v21`, `QPVLT021`, `QPVIMG21`, message state
`QPMST011`, traffic `QPTEPO04`, control `QPRKST03`. Old images are refused without
an implicit reset or migration. Fanout emits the same pairwise application frames;
it has no independent aggregate network packet in this implementation.

This revision fixes the observed byte grammar and distinguishes its trust and
resource boundaries. Product scheduling/budget selection, authority renewal,
complete multi-device lifecycle, storage/migration policy, metadata analysis,
construction-specific security analysis, independent endpoint implementation and
the final specification lock still require their own completion evidence. None is
inferred from a matching profile digest or successful parsing.
