# Hidden original-record commitments: encoding inventory and conditional hop

This note extends the one-image/ordinary-intent argument in
[computational recovery](COMPUTATIONAL_RECOVERY_V1.md). It identifies additional
commitments used by retirement, Witness selection and account-root replacement.
It proves a conditional six-interface statement for **one original image and
one original write intent**. It does not establish the complete accepted-prefix
simulator, an unrestricted output inventory or multi-epoch confidentiality.

The source audit is pinned to `eb08f978d4fa6a3fc1970ab0194007d21ade7355`.
The [capture](../../research/sdk-alpha1/evidence/20261105-hidden-record-commitments/README.md)
contains source bytes, hashes, derived layout tables and the audit procedure.
No protocol, storage or acquisition interface is changed by this analysis.

## Original bytes and the nonce boundary

[`seal`](../../research/continuity-identity-candidate/src/durable.rs) encodes the
bounded plaintext before sampling its 24-byte nonce. The four admitted image
tags `QPVLT021` through `QPVLT024` all have the same outer layout:

```text
tag[8] || journal[32] || owner[32] || revision_be64 || N[24]
       || encrypted_plaintext || authentication_tag[16]
```

Thus `N` occurs verbatim at image offsets `[80,104)`. The image length does not
depend on the value of `N`. `unseal_image` uses `N` to authenticate/decrypt and
returns an `Image` containing the plaintext fields and `image_hash(wire)`; it
does not retain a nonce or ciphertext field. Consequently projections of that
decoded image cannot read its outer nonce through the `Image` fields. This is
a source data-flow observation about this nonce, not a proof that every
plaintext projection hides every KEM reservation or other secret.

[`PendingWrite::new_bound`](../../research/continuity-identity-candidate/src/durable/write_intent.rs)
places a binding immediately after its eight-byte tag, then the 148 remaining
fixed header bytes, the **complete original sealed target**, and a 32-byte HMAC.
The fixed header is 156 bytes including the tag and excluding the binding.
Its target digest is the image-head reply; its previous digest is an explicit
predecessor input. The following offsets are zero-based half-open intervals.

| Write tag | Binding | Binding bytes `b` | Target nonce in original intent |
| --- | --- | ---: | --- |
| `QPWINT01` | Ordinary | 0 | `[236,260)` |
| `QPWINT02` | Credential, no policy | 64 | `[300,324)` |
| `QPWINT04` | Credential, adopt or retain policy | 97 | `[333,357)` |
| `QPWINT08` | Credential, retain independent policy | 97 | `[333,357)` |
| `QPWINT06` | Policy | 64 | `[300,324)` |
| `QPWINT07` | Roster, original authority | 185 | `[421,445)` |
| `QPWINT10` | Roster, credential authority | 185 | `[421,445)` |
| `QPWINT11` | Roster, continued authority | 185 | `[421,445)` |

The 185-byte roster binding follows the actual
[`RosterRefreshScope::encode`](../../research/continuity-identity-candidate/src/anchor/roster_refresh.rs):
32 operation bytes, three `(u64, digest[32])` checkpoints, and a one-byte flag
plus a 32-byte policy authorization. The two meanings of `QPWINT04` retain
their actual flag value; equal layout does not identify their operations.

`QPWINT03`, `QPWINT05` and `QPWINT09` belong to
[`PendingCancellation`](../../research/continuity-identity-candidate/src/durable/write_intent/credential_cancellation.rs).
They contain an account, cancellation descriptor and HMAC, with **no target
image**. The nonce-offset argument below does not apply to those records.

## Direct commitments and their consumers

All six entries use [`crypto::digest`](../../research/continuity-identity-candidate/src/crypto.rs),
whose exact SHA3-256 input is
`len_be64(domain) || domain || len_be64(payload) || payload`.
Domain names below include their complete version suffix.

| Index | Domain | Bytes | Payload and observed use |
| --- | --- | ---: | --- |
| 0 | `Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2` | 45 | Complete sealed image; `Image.digest` and public heads. |
| 1 | `Q-PERIAPT-CONTINUITY-PENDING-WRITE-INTENT/v1` | 44 | Complete original write intent; ordinary pending-recovery scope/proposal. |
| 2 | `Q-PERIAPT-CONTINUITY-RETIRED-LOCAL-INTENT/v1` | 44 | Complete retained pending record; public retired-cleanup inventory and erasure readback. |
| 3 | `Q-PERIAPT-CONTINUITY-ACCOUNT-ROOT-LOCAL-INTENT/v1` | 49 | Complete retained pending record; local account-root fence, including its later preparation checkpoint. |
| 4 | `Q-PERIAPT-CONTINUITY-WITNESS-HANDOFF-PENDING/v1` | 47 | Complete retained pending record; local Witness-selection fence and its original-record checkpoint chain. |
| 5 | `Q-PERIAPT-MANAGED-ROOT-ORIGINAL-RECORD/v1` | 41 | Complete retained pending record; original-child and managed-root preparation checkpoints. The same domain also hashes a selection row separately. |

The source paths are
[ordinary recovery](../../research/continuity-identity-candidate/src/durable/write_intent/pending_recovery.rs),
[retired snapshot](../../research/continuity-identity-candidate/src/durable/write_intent/retired_cleanup.rs),
[retired inventory encoding](../../research/continuity-identity-candidate/src/anchor/store/retired_cleanup.rs),
[account-root fence](../../research/continuity-identity-candidate/src/durable/write_intent/account_root.rs),
[Witness fence](../../research/continuity-identity-candidate/src/durable/write_intent/witness_handoff/codec.rs),
and [original-child checkpoint](../../research/continuity-identity-candidate/src/durable/write_intent/account_root/witness/preparation.rs).
Entries 3 and 4 are local fence fields; this table does **not** assert that
every individual value is sent on the network. Their downstream commitments
must nevertheless be simulated consistently. The conditional experiment below
conservatively makes all six replies available to its surrounding algorithm.

Ordinary recovery explicitly rejects a bound write or cancellation with
`Suspended`. Entry 1 is therefore not an observed generic recovery interface
for all eight write tags. Entries 2–5 accept the `PendingIntent` abstraction;
their write-record case includes the eight tags above, while their cancellation
case needs its own mapping and is not covered by nonce injectivity.

The retired-cleanup encoder includes the stored image digest and pending digest,
not the original image or pending bytes. Account-root and Witness fence encoders
likewise include those digests plus descriptors, receipts/lineage and HMACs.
`original_child_checkpoint` hashes a tuple of journal, owner, image digest and
optional **record digests**; it does not put the raw pending bytes in the outer
child hash. A selection row passed to entry 5 contains the entry-4 digest, not
the original write intent. Once the six replies and the remaining required
inputs are available, these downstream encodings can be recomputed normally;
their hash calls still belong in the query budget.

## Conditional six-interface statement

Fix one bounded original image and, if present, one of the eight original
write encodings. Let `N` be a uniform independent 192-bit value. Define `I(N,x)`
by the actual image encoding/encryption and define `W(N,x,y0)` by the actual
write encoding, using `y0` as its target-head field and including the complete
`I(N,x)` and its write-intent HMAC. Here `x` supplies the fixed image key,
plaintext, header, predecessor fields and binding. These may be known to the
surrounding algorithm; their secrecy is not used in the nonce argument.

Use a single private oracle keyed by `N`. It evaluates the image input for
query type 0 and the corresponding domain-separated `W` input for types 1–5.
The type-0 reply precedes the write queries and is supplied explicitly as
`y0`. Each type has at most one fresh query. Exact rereads, decoder checks and
retries use that type's cached reply for the **same original bytes**; this
does not license caching a changed record under an old operation identifier.
In either game, all five write digests use the same original `W` constructed
with that game's `y0`. Its HMAC and all downstream commitments follow that
choice. Keeping the old real wire while changing its head field is not this
experiment.

The observer has arbitrary counted quantum access to an ideal SHA3 oracle
`H`, but no additional access to `N`, `I`, `W`, or another raw-`N`-dependent
output. All use of this nonce is confined to the private maps just specified.
Prefix queries, honest computations outside those maps and later queries are
included in `q_H`; there is no free oracle-dependent initial advice. The maps'
encryption, SHA-256 KDF and HMAC are fixed deterministic computations here and
do not call `H` internally. A joint model with a separately idealized SHA-256
oracle requires its own composition/query accounting; it is not silently
established by this lemma.

For each fixed admissible query input, the hash preimage contains `N` at a
known fixed offset. Hence at most one nonce maps to any given preimage and the
point probability is at most `2^-192`. Different fresh query types have
different complete domain prefixes for **every** nonce and every other input.
In particular, types 1 and 2 both have 44-byte domains: their distinct domain
bytes, not a length difference, establish separation. Their preimage sets are
disjoint. With at most one query of each type, this establishes both premises
of [Don–Fehr–Huang, Theorem 2 and equations (6)–(7)](https://arxiv.org/pdf/2206.08132).
Substitution of `q_O = 6` gives the distinguishing bound

```text
epsilon_record(q_H) = min(1,
    4 sqrt(72 q_H 2^-192) + 4 sqrt(12 q_H^2 2^-192)).
```

The ideal six replies are independent uniform 256-bit values. Any application
checks on replies, including rejection of a zero digest, must execute in both
games without resampling or silently forcing success. Downstream hashing,
MACs, signatures and error outputs preserve the bound when the surrounding
algorithm can compute them from its existing inputs and these replies, with
all relevant oracle calls counted. This is our conditional application of the
cited theorem, not a theorem in that paper about Q-Periapt.

The statement also holds for fewer used types with the actual `q_O` in
`4 sqrt(2 q_O^2 q_H 2^-192) + 4 sqrt(2 q_H^2 q_O 2^-192)`.
It permits the bound write encodings mathematically because they retain the
nonce, but does not grant them the source's ordinary-recovery API.

## What remains before the accepted-prefix hop

This source audit and single-record lemma do not justify replacing every
commitment in a full execution yet. The bridge must account for each fresh
image and original pending record across revisions, retries, failed writes,
retirement and later acquisition. Independent nonces and domain separation
within one record do not by themselves prove a multi-record hybrid or its
adaptive target bound. Exact repeated records need a consistent cache; changed
records need an explicit new accounting entry.

The surrounding implementation still has raw private-store copies of images,
intents and sealed KEM operations. A later image or pending-target acquisition
can reveal the nonce; with a disclosed journal key it can reveal the original
reservation. The existing aggregate/snapshot and entropy exclusions must be
mapped to every such acquisition, not strengthened to make this experiment
applicable. Local fence-only views, ciphertext views and decryptable images
are distinct. Cancellation records, archive/projection contents, platform
wrappers, host storage and independent recovery checkpoints also require their
actual output mapping; a textual search is not whole-program noninterference.

Finally, consistent ideal commitments are only one prerequisite for embedding
an ML-KEM challenge without its generation/encapsulation coins. The simulator
must still preserve challenge-ciphertext retries without forbidden challenge
decapsulation, signature/body provenance, ContextBound inputs, half-confirmed
`FinalReady` application sends, subsequent roots and traffic. No complete
computational recovery or release qualification follows from this note.

The subsequent [multi-record extension](MULTI_RECORD_COMMITMENTS_V1.md) supplies
the bounded hybrid sum under a stated per-nonce confinement interface and checks
the original Snapshot event semantics. It does not turn this single-record
source inventory into an unrestricted output proof; in particular, cleanup MACs
over private state remain distinct from the six raw-record digest domains.
