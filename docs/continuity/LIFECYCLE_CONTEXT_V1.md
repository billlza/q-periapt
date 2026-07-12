# Candidate LifecycleContextV1 canonical binding

> **Status:** non-normative G1 candidate, schema version 1. This document and the
> dependency-free encoder in
> [`../../models/q-periapt-continuity-model/src/context.rs`](../../models/q-periapt-continuity-model/src/context.rs)
> define model bytes only. `PREKEY_SELECTION_V1.md` now fixes the nested model
> prekey-selection bytes. Neither document is a deployed wire format, identity
> protocol, prekey service, ratchet, credential verifier, directory-consistency proof, or
> implementation-refinement result.

## 1. Purpose and security boundary

K-CTX is useful only when both authenticated roles commit the same meaningful
protocol context. Hashing an opaque caller string proves little. This candidate makes
the intended bootstrap/root-transition projection explicit and testable while keeping
all protocol semantics outside the existing KEM core.

The encoder establishes only:

- one role-ordered, domain-separated, fixed-field LP8 byte representation;
- an indivisible signed-policy digest plus lifecycle-body wrapper;
- an exact preimage for a fixed-width durable context digest;
- fail-closed stage, role, reserved-sentinel, version and ratchet-epoch movement
  validation;
- indivisible derivation of Bootstrap B21-B23 from one strict canonical prekey
  selection, with outer suite/responder/checkpoint cross-checks;
- structural equality across operation, repository intent, snapshot and restart.

It does **not** establish that a credential signature is valid, a prekey is fresh or
one-time, a directory checkpoint is globally consistent, a roster is current, a
transcript was computed correctly, or a ratchet provides FS/PCS. Those commitments
must be authenticated before construction. A malicious or incorrect digest adapter
can still lie; the test-only model exposes that adapter as a trusted boundary.

## 2. Three byte layers

All lengths are unsigned 64-bit big-endian. `LP8(x) = len(x)_u64_be || x`.

### 2.1 Lifecycle body

```text
body = LP8(B0) || LP8(B1) || ... || LP8(Bn)
```

- Bootstrap: 25 fields, exactly 666 bytes.
- RootTransition: 27 fields, exactly 626 bytes.

### 2.2 Policy-bound K-CTX

```text
full_kctx =
    LP8("Q-PERIAPT-POLICY-CONTEXT/v1") ||
    LP8(policy_digest) ||
    LP8(body)
```

- Bootstrap: exactly 749 bytes.
- RootTransition: exactly 709 bytes.

`policy_digest` is the SHA3-256 identity of one authenticated signed policy. A future
`ResolvedSessionPolicy` must derive `policy_digest` and `suite_digest` together; callers
must not assemble them independently. A future Continuity KEM invocation must pass the
complete `full_kctx`, not a pre-hash, as `CombineInput.context`. No product crate
performs that integration yet.

### 2.3 Durable context-digest preimage

```text
digest_preimage =
    LP8("Q-PERIAPT-CONTINUITY-CONTEXT-DIGEST/v1") ||
    LP8(full_kctx)

context_digest = SHA3-256(digest_preimage)
```

- Bootstrap preimage: exactly 803 bytes.
- RootTransition preimage: exactly 763 bytes.

The fixed digest is for durable state linking and future session KDF inputs. It is not
substituted for the complete KEM context. The model crate deliberately has no hash
dependency; `derive_authenticated_context_with` requires a fallible explicit adapter,
rejects adapter failure, and rejects the all-zero unset sentinel.

## 3. Common fields

The common body uses fixed initiator/responder order. `local/peer` is forbidden because
the two roles would otherwise encode the same session in opposite order.

| Index | Field | Bytes | Requirement |
|---:|---|---:|---|
| B0 | `Q-PERIAPT-CONTINUITY-LIFECYCLE/v1` | 33 | exact domain |
| B1 | schema version | 2 | `1`, big-endian |
| B2 | context kind | 1 | `1=Bootstrap`, `2=RootTransition` |
| B3 | protocol ID | 16 | nonzero, distinct protocol namespace |
| B4 | wire version | 2 | nonzero, big-endian |
| B5 | suite digest | 32 | nonzero, closed suite semantics |
| B6 | pairwise session ID | 32 | nonzero |
| B7 | initiator account ID | 32 | nonzero |
| B8 | initiator device ID | 16 | nonzero |
| B9 | initiator device epoch | 8 | `1..u64::MAX-1` |
| B10 | initiator identity-credential digest | 32 | nonzero |
| B11 | responder account ID | 32 | nonzero |
| B12 | responder device ID | 16 | nonzero |
| B13 | responder device epoch | 8 | `1..u64::MAX-1` |
| B14 | responder identity-credential digest | 32 | nonzero |
| B15 | identity mode | 1 | `1=Accountable`, `2=Deniable` |
| B16 | direction | 1 | `1=InitiatorToResponder`, `2=ResponderToInitiator` |
| B17 | authentication stage | 1 | see below |

The `(account, device)` pairs must differ; a device generation change cannot turn one
logical device into both protocol roles. Same-account traffic between distinct devices
remains representable.

Peer-agreed authentication stages are:

```text
1 PrekeyAuthenticated
2 PeerConfirmed
3 MutuallyConfirmed
```

`ZeroRttSent` is deliberately absent. It is a local outbox/dispatcher state, not a
fact on which both peers necessarily agree.

## 4. Bootstrap tail

Bootstrap requires `PrekeyAuthenticated` and adds:

| Index | Field | Bytes | Requirement |
|---:|---|---:|---|
| B18 | roster version | 8 | `1..u64::MAX-1` |
| B19 | roster digest | 32 | nonzero |
| B20 | directory-checkpoint digest | 32 | nonzero |
| B21 | two-leg prekey quality | 1 | `1=BothOneTime`, `2=ClassicalSignedOnly+PqLastResort`, `3=ClassicalSignedOnly+PqOneTime`, `4=ClassicalOneTime+PqLastResort` |
| B22 | signed-prekey-manifest digest | 32 | nonzero |
| B23 | prekey-selection digest | 32 | nonzero |
| B24 | key-schedule transcript digest | 32 | nonzero, non-circular |

`prekey_selection_digest` is now derived from the exact 492-byte, sixteen-field
[`PrekeySelectionV1`](PREKEY_SELECTION_V1.md) record and its 555-byte domain-separated
digest preimage. The record binds suite, responder identity scope, bundle epoch,
directory checkpoint, manifest, and both legs' mode/signed/selected IDs. Bootstrap
requires `InitiatorToResponder`; B21-B23 cannot be supplied independently. This is
canonical-byte evidence only: manifest authenticity/membership, unique lease,
one-time consumption, split-view detection, rollback and policy authorization remain
unproved. Prekey exhaustion may never silently select signed-only/last-resort modes.

`key_schedule_transcript_digest` contains only authenticated public material available
before the current key is derived. It must not include AEAD/confirmation output derived
from that same key.

## 5. RootTransition tail

RootTransition requires `PeerConfirmed` or `MutuallyConfirmed` and adds:

| Index | Field | Bytes |
|---:|---|---:|
| B18 | transition kind | 1 |
| B19 | prior context digest | 32 |
| B20/B21 | prior/next root epoch | 8/8, full `0..u64::MAX` counter domain |
| B22/B23 | prior/next classical-DH epoch | 8/8, full `0..u64::MAX` counter domain |
| B24/B25 | prior/next PQ epoch | 8/8, full `0..u64::MAX` counter domain |
| B26 | transition transcript digest | 32 |

Legal movement is closed:

| Kind | Root | DH | PQ |
|---|---|---|---|
| `Dh=1` | `+1` | `+1` | unchanged |
| `Pq=2` | `+1` | unchanged | `+1` |
| `Hybrid=3` | `+1` | `+1` | `+1` |

No no-op root transition, skip, decrement, wrong-leg advance or required `MAX + 1`
is legal. Ratchet counters deliberately differ from device/roster generations: zero
is a valid initial epoch, `MAX` is a valid terminal next value, and a non-advancing
leg may remain at `MAX`. Identity, roster, policy or suite changes require a future
explicit Migration variant; a root transition must not read ambient “latest
directory” state.

## 6. Lifecycle integration

`AuthenticatedContext` now stores the complete `LifecycleContextV1`, signed-policy
digest and derived `ContextDigest`. There is no public constructor accepting an
independent `(stage,digest)` pair. Stage is derived from the lifecycle context.

Before reservation, the model checks:

- the authenticated-context policy digest equals `ProtocolScope.policy_digest`;
- protocol ID and wire version equal the trusted protocol scope;
- session ID equals the trusted session authority;
- the fixed initiator/responder devices equal the trusted local/peer pair as an
  unordered set;
- Bootstrap context admits Bootstrap or message-protection work;
- RootTransition context admits root-transition or message-protection work;
- the complete draft context equals the trusted durable current context.

This is trusted-genesis admission, not credential authentication. The first production
constructor must accept only outputs of verified identity, policy, directory and
prekey components.

The abstract durable snapshot is now schema 3 because it retains the structured
context and exact `StateAdvance { expected(version,digest), next(version,digest) }`.
Schema 2 contained only an opaque context digest and has no lossless automatic
migration. A future product must re-enroll/rekey/reset rather than invent missing
preimages.

## 7. Current validation and open gates

Current Rust controls cover exact lengths/field order, big-endian integers, all common
and bootstrap field sensitivity, role reflection, policy binding, domain nesting,
three legal root patterns, full-domain ratchet counter endpoints, stage mismatches,
epoch skips/wrong-leg/required-overflow, reserved all-zero byte commitments,
exact-buffer atomicity, adapter failure and zero digest.

The nested prekey-selection controls additionally cover exact 492/555-byte lengths,
four independent classical/PQ quality quadrants, strict decode/re-encode, every
truncation point, trailing bytes, length overflow, compensated LP8 lengths, unknown
version/modes, zero fields, mode/ID relations, output atomicity, adapter failure, full
Rust/Python byte correspondence, and outer-scope graft rejection. Its separate
EasyCrypt diagnostic proves structural projection injectivity and named omission
collisions; it is not a protocol proof or formal Rust refinement.

Still required before G1 freeze:

- strict decoder for the outer Lifecycle body and production wire/storage records;
- signed prekey manifest/leaf codec, membership/expiry verification, lease and
  consumption state machine;
- explicit Migration context;
- credential, directory, prekey and confirmation state machines;
- a formal-to-exact-field-list and formal-to-Rust correspondence argument beyond the
  current EasyCrypt projection/omission diagnostic;
- malicious-directory ProVerif/Tamarin models after protocol semantics freeze;
- model-to-Rust refinement or translation validation;
- production persistence, kill/restart, rollback-anchor and physical-device evidence.
