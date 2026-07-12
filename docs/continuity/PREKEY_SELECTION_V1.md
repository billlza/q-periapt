# Candidate PrekeySelectionV1 canonical record

> **Status:** non-normative G1 diagnostic, record schema version 1. The
> dependency-free Rust codec is `publish = false` and no product crate, C ABI,
> binding, wire protocol, or deployed service depends on it. This record closes
> one model-level byte ambiguity; it is not a prekey protocol or a release claim.

## 1. Goal and boundary

Lifecycle B21-B23 previously accepted an independently supplied quality byte,
manifest digest, and opaque selection digest. That allowed a caller to attach any
32-byte value to a claimed prekey mode. `PrekeySelectionV1` replaces that tuple with
one validated record whose digest and reduced Lifecycle fields are derived together.

The record makes exact selection semantics machine-visible. It does **not** prove:

- manifest signature validity, expiry, membership, uniqueness, or algorithm policy;
- directory checkpoint consistency, append-only history, or absence of split views;
- server-side one-time deletion, unique leasing, double-lease detection, or local
  at-most-once acceptance;
- forward secrecy, post-compromise security, UKS/KCI resistance, active-PQ identity,
  deniability, rollback resistance, or crash durability;
- that the explicit digest adapter is SHA3-256 or honestly hashes its complete input.

Those remain separate protocol, state-machine, adapter, and proof obligations.

## 2. Exact bytes

All integers are unsigned big-endian. Every field is encoded as
`LP8(x) = len(x)_u64_be || x`. The record is the concatenation of exactly sixteen
fields; unknown versions, unknown enums, wrong field lengths, truncation, length
overflow, and trailing bytes are rejected.

| Index | Field | Bytes | Requirement |
|---:|---|---:|---|
| P0 | `Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1` | 40 | exact domain |
| P1 | schema version | 2 | `1` |
| P2 | suite digest | 32 | nonzero; must equal Lifecycle B5 |
| P3 | responder account ID | 32 | nonzero; must equal Lifecycle B11 |
| P4 | responder device ID | 16 | nonzero; must equal Lifecycle B12 |
| P5 | responder device epoch | 8 | `1..u64::MAX-1`; must equal B13 |
| P6 | responder identity-credential digest | 32 | nonzero; must equal B14 |
| P7 | signed prekey-bundle epoch | 8 | `1..u64::MAX-1` |
| P8 | directory-checkpoint digest | 32 | nonzero; must equal Lifecycle B20 |
| P9 | signed-prekey-manifest digest | 32 | nonzero; becomes Lifecycle B22 |
| P10 | classical mode | 1 | `1=OneTime`, `2=SignedOnly` |
| P11 | classical signed-prekey ID | 32 | nonzero manifest-resolved commitment |
| P12 | classical selected-prekey ID | 32 | nonzero manifest-resolved commitment |
| P13 | PQ mode | 1 | `1=OneTime`, `2=LastResort` |
| P14 | PQ signed last-resort-prekey ID | 32 | nonzero manifest-resolved commitment |
| P15 | PQ selected-prekey ID | 32 | nonzero manifest-resolved commitment |

Payload bytes total 364; sixteen LP8 prefixes add 128; the exact record length is
492 bytes.

Mode/ID relations have one representation each:

- classical `OneTime`: P12 differs from P11;
- classical `SignedOnly`: P12 equals P11;
- PQ `OneTime`: P15 differs from P14;
- PQ `LastResort`: P15 equals P14.

No zero sentinel or alternate equality convention is accepted. `PrekeyId` is a
manifest-resolved 32-byte commitment; freezing the leaf codec that binds algorithm,
role, public-key bytes, device epoch, and validity interval is still open G1 work.

## 3. Digest and Lifecycle reduction

```text
selection_record = LP8(P0) || ... || LP8(P15)

selection_digest_preimage =
    LP8("Q-PERIAPT-CONTINUITY-PREKEY-SELECTION-DIGEST/v1") ||
    LP8(selection_record)

prekey_selection_digest = SHA3-256(selection_digest_preimage)
```

The digest domain is 47 bytes and the complete digest preimage is exactly 555
bytes. The Rust model deliberately has no cryptographic dependency. Its fallible
adapter receives only the complete 555-byte preimage; adapter error and an all-zero
result fail explicitly. Frozen vectors use independent Python `hashlib.sha3_256`.

Lifecycle Bootstrap accepts only `CanonicalPrekeySelection { record, digest }` and
then derives:

| Lifecycle field | Derived value |
|---|---|
| B21 | the lossless two-leg quality code |
| B22 | P9 signed-manifest digest |
| B23 | digest of the complete 555-byte preimage |

Quality codes preserve the prior unambiguous endpoints and add both mixed states:

| B21 | Classical leg | PQ leg |
|---:|---|---|
| 1 | one-time | one-time |
| 2 | signed-only | last-resort |
| 3 | signed-only | one-time |
| 4 | one-time | last-resort |

Callers cannot supply B21, B22, or B23 independently. Bootstrap additionally requires
`InitiatorToResponder` and rejects suite, responder account/device/epoch/credential,
or directory-checkpoint mismatch before a Lifecycle context exists. The full 492-byte
record is then discarded from the reduced Lifecycle value; this avoids giving two
different records distinct Rust equality while they share the same adapter digest.

## 4. Evidence and non-claims

The current diagnostic contains:

- allocation-free Rust encode/decode, typed errors, exact-buffer atomicity, and four
  quality quadrants;
- full-record frozen vectors and a separate Rust emitter;
- an independent strict Python encoder/decoder and SHA3-256 oracle;
- EasyCrypt LP8 injectivity for all sixteen fields plus named omission collisions for
  suite, responder credential, bundle epoch, checkpoint, manifest, both mode bytes,
  and all four signed/selected IDs.

The EasyCrypt result is a structural projection theorem, not SHA3 injectivity,
protocol authentication, or a proof that formal terms refine Rust bytes. The Rust/
Python full-byte correspondence is executable evidence, not a verified compiler or
formal model-to-code refinement.

## 5. Next stateful gates

The candidate codec is allocation-free in Rust: it uses fixed 492- and 555-byte
stack buffers and performs one digest-adapter call during bootstrap, never on the
ordinary-message hot path. The record is a commitment preimage, not automatically an
additional 492 wire bytes; the future wire specification must decide which already-
transmitted manifest/bundle fields are reconstructed versus carried. These structural
facts are not a performance result. Cold/cached bootstrap latency, stack limits,
manifest verification, wire bytes, energy, and comparison with component-conformant
PQXDH must be measured before claiming non-inferiority.

The next prekey layer must freeze a signed manifest/leaf codec and a durable state
machine for lease, acceptance, tombstone, exact/conflicting replay, double lease,
split view, and rollback. At most one local acceptance must be authorized per one-time
ID; server deletion alone is insufficient. External rollback anchoring and privacy
costs of accountability receipts must be specified and measured independently.
