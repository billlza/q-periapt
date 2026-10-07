# MigrationContextV1 candidate encoding

> **Status: non-normative research model; not an ABI and not a session
> protocol.** This document specifies the exact application-context body emitted
> by `q-periapt-migration`. It does not modify Q-Periapt ABI 2, authenticate a
> migration transition, maintain monotonic state, or establish peer acceptance.

## 1. Purpose and boundary

`MigrationContextV1` gives a protocol one canonical, role-normalized byte string
to pass unchanged as ABI 2 `application_context`. It commits candidate migration
semantics to the existing `ContextBound` KDF without changing any ABI 2 symbol,
constant, decision layout, trusted-state layout, combiner domain, or field order.

The encoder returns only the 315-byte application body defined below. It MUST NOT
prepend the ABI 2 policy wrapper and MUST NOT replace the body with a hash. ABI 2
already constructs:

```text
LP8("Q-PERIAPT-POLICY-CONTEXT/v1")
|| LP8(execution_policy_digest)
|| LP8(MigrationContextV1 application body)
```

That outer value is 398 bytes: `(8 + 27) + (8 + 32) + (8 + 315)`.
The `policy_version` from the same execution decision is separately bound by the
existing `ContextBound` combiner.

Both peers MUST independently authenticate the same exact execution-policy bytes
under an appropriate pinned authority and MUST use identical canonical 40-byte
ABI 2 decisions. A peer-supplied raw decision is not evidence of authentication.
Different execution decisions produce different KDF inputs even when the 315-byte
body is identical.

## 2. Canonical LP8 encoding

For every field `x`:

```text
LP8(x) = u64_be(len(x)) || x
```

`MigrationContextV1` is the concatenation of exactly twelve LP8 fields, in this
order, with no optional or trailing bytes:

| Index | Field | Value and raw width |
| ---: | --- | --- |
| M0 | domain | ASCII `Q-PERIAPT-MIGRATION-CONTEXT/v1`, 30 bytes |
| M1 | schema version | `u16_be(1)`, 2 bytes |
| M2 | protocol ID | version-qualified, nonzero `[u8; 16]` |
| M3 | encapsulator role | `Initiator = 1`, `Responder = 2`, 1 byte |
| M4 | migration epoch | `u64_be(epoch)`, 8 bytes; `1..=u64::MAX-1` |
| M5 | initiator policy digest | SHA3-256 of exact authenticated initiator policy bytes, 32 bytes |
| M6 | responder policy digest | SHA3-256 of exact authenticated responder policy bytes, 32 bytes |
| M7 | capability transcript digest | nonzero 32-byte commitment |
| M8 | selected suite | stable `HybridSuite` code, 1 byte |
| M9 | effective security floor | closed NIST category `1`, `2`, `3`, or `5`, 1 byte |
| M10 | transition state digest | nonzero 32-byte externally asserted commitment |
| M11 | pre-KEM transcript digest | nonzero 32-byte commitment, 32 bytes |

The raw field payload is 219 bytes. Twelve 8-byte prefixes add 96 bytes, so the
only valid encoded length is **315 bytes**.

Changing this domain, order, width, enum mapping, or field set requires a new
schema and domain. V1 has no extension tail. There is deliberately no public V1
decoder: peers construct the typed value independently from authenticated endpoint
policies plus caller-validated external commitments, then compare or use the
resulting fixed bytes.

## 3. Role normalization

`local` and `peer` are construction-time views and MUST NOT enter the canonical
encoding. Given `local_role` and two authenticated endpoint policies, the
constructor immediately maps them into fixed ownership:

| Local view | M5 | M6 |
| --- | --- | --- |
| local is Initiator | local policy digest | peer policy digest |
| local is Responder | peer policy digest | local policy digest |

M3 is not “my role”. It is the role of the party performing this encapsulation,
a fact on which both peers agree. Thus mirrored local inputs produce identical
bytes, while changing the real direction or role-owned inputs produces distinct
bytes.

Equal initiator and responder policy digests are valid. In that case, reflection
and unknown-key-share separation must come from M3 and the role-ordered identity,
nonce, session, offer, and selection material committed by M7/M11. This encoder
does not authenticate that material and therefore makes no reflection, UKS, or
peer-authentication claim.

## 4. Policy, suite, and floor derivation

`MigrationContextV1::from_authenticated_policies` accepts `AuthenticatedPolicy`
values and one `AuthenticatedResolvedSuite`, not caller-provided policy digests,
a free-standing suite, or a free-standing floor. It:

1. resolves both endpoint policies against the selected closed suite;
2. requires both resolutions to select that suite under `ContextBound` with an
   expanded key format;
3. normalizes the exact authenticated policy digests into M5/M6;
4. derives M9 as the maximum of both authenticated policies' NIST floors; and
5. rejects a suite below that derived floor.

The selected suite comes from an `AuthenticatedResolvedSuite` used as the common
execution decision. The ABI 2 adapter additionally requires
`ML-KEM-768+X25519` (suite code `1`), because ABI 2 is deliberately fixed to that
L3 suite, and carries the expected execution `(version,digest)` state for the
caller to compare with the decision supplied to ABI 2. A generic L5 candidate
context can be encoded for research, but cannot be passed through the ABI 2
adapter.

M9 describes the current policy engine's PQ-component NIST category. It is not a
complete migration predicate such as “classical forbidden”. ABI 2 still combines
ML-KEM with X25519. Any future state that forbids a traditional component must
reject ABI 2 explicitly rather than reinterpret this byte.

M4 and M10 are still externally asserted in phase 1. The encoder checks their
shape but cannot prove that an epoch belongs to the committed state, that the
state is signed, or that either value advanced monotonically. A future typed,
authenticated `MigrationStateV1` must derive them together to close grafting and
rollback attacks.

## 5. Pre-KEM transcript rule

M11 MUST be computed over canonical public material known before the current KEM
encapsulation. At minimum, the protocol using this model should bind:

- the protocol and wire version;
- role-ordered authenticated peer identities and fresh nonces/session ID;
- both complete capability offers and their fixed ordering;
- both endpoint policy digests;
- the common execution decision, selected suite, and derived floor;
- the migration epoch and transition-state commitment; and
- the receiver's public encapsulation keys or another unambiguous reference to
  them.

M11 MUST NOT include the current KEM ciphertext, shared secret, a key derived from
that secret, Finished/confirmation data, AEAD output, this
`MigrationContextV1` body, or a digest of this body. Those values do not exist when
the context is needed and would create a circular definition. The existing
`ContextBound` path directly absorbs both component ciphertexts and public keys.

M7 should be derived from the same canonical negotiation snapshot as M11. M11
must in turn commit M7, both complete offers, and the final selection. Merely
hashing the selected suite does not establish that an attacker did not strip a
stronger offer.

## 6. Failure and acceptance semantics

Construction and encoding fail closed for zero commitments, epoch `0` or
`u64::MAX`, unauthorized or below-floor suites, incompatible profile/key format,
and an output slice whose length is not exactly 315. `encode_into` validates and
encodes into a temporary fixed array before copying, so an error leaves caller
output unchanged. There is no raw-context fallback.

A context or decision mismatch is not an ABI 2 policy error. With otherwise valid
lengths and key material, ABI 2 decapsulation can return `Q_PERIAPT_OK` while
deriving a different secret. A protocol MUST complete role-separated, mutually
authenticated key confirmation over the full post-KEM transcript before exposing
application keys or reporting session acceptance; it must destroy a pending
secret on confirmation failure. That protocol mechanism is outside this phase.

## 7. Claims and non-claims

Phase 1 establishes only:

- one deterministic, role-normalized, fixed-width application-body encoding;
- typed closed-suite/floor consistency at a trusted Rust construction boundary;
- byte-for-byte independent Rust/Python vectors; and
- exact-byte KDF commitment when both peers use the same authenticated ABI 2
  decision and the same body.

It does **not** establish migration-state authenticity, transition authorization,
rollback/reset resistance, fork prevention, capability or identity authentication,
mutual key confirmation, replay/UKS/KCI/reflection resistance, `MIG-AGREE`,
`MIG-ROLLBACK`, `MIG-FLOOR`, hostile same-process resistance, or a new stateful
cryptographic construction.

The precise description is: **candidate canonical migration-context commitment
over unchanged ABI 2; authentication, acceptance, and state continuity remain
future gates.**
