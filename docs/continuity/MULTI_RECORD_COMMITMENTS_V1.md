# Multiple original records and acquisition provenance

This note extends the [single-record commitment statement](HIDDEN_RECORD_COMMITMENTS_V1.md)
to a bounded, explicitly defined private-record interface. It also checks what
the unchanged symbolic `Snapshot` action actually discloses. These are steps
toward the accepted-prefix bridge, not a completed whole-journal refinement or
multi-epoch computational theorem. Native source observations are pinned to
`21176899dfa2cfa9e07a15be6e30de8123a8a1df`; the
[readback](../../research/sdk-alpha1/evidence/20261105-multi-record-commitments/README.md)
retains the source and exact frozen model/formula identities. No new runtime or
Tamarin execution is claimed.

## Snapshot means acquisition, not successful decryption

In the [retained multi-epoch certificate](../../research/sdk-alpha1/evidence/20261104-multi-epoch-replay/README.md),
the `Snapshot` rule requires the original `Stored` fact and the corresponding
wrapping key fact. Its action records `Snapshot(session,role,epoch,revision)`
and then outputs an **encrypted** record. There is no decryption-success
condition on that action. `Cut` separately outputs both selected-session
wrapping keys. The unchanged MAIN antecedent excludes a matching Snapshot of
any selected-session record whose `Saved` event occurred after Cut; it does
not limit this condition to the target epoch or require that decryption has
already been performed.

Accordingly, an actual acquisition of a protected record which has already
been mapped to such a post-Cut `Saved` origin falls under that existing
predicate. Calling the bytes ciphertext-only does not remove the Snapshot
event. This observation does not authorize mapping every metadata query to a
Snapshot or inventing a stronger acquisition exclusion. Actual views still
need their source/content mapping.

For the fixed-target [KEM adapter](KEM_CHALLENGE_ADAPTER_V1.md), the observed bit
is `Eligible AND D_output`. Once an acquisition has *actually been shown* to
falsify the original Snapshot or entropy condition, the experiment can stop
with zero before trying to serialize an unknown challenged reservation. This
is not an SDK rejection of acquisition. Conversely, a nonexistent record, an
ordinary error, an unrelated acquisition or a view with no such established
origin must keep its real behavior. Inability to simulate bytes is not itself
evidence that the execution became ineligible.

## The private records counted by the hop

Consider an experiment with at most `M` fresh image-sealing invocations. Index
the invocations themselves, including ones whose later persistence fails;
neither a global revision nor an operation ID alone identifies a fresh nonce.
Invocation `i` samples an independent uniform 192-bit nonce `N_i`. The bounded
plaintext and non-nonce fields are fixed before that draw. Copying the exact
original image or rereading it after restart retains the same origin and cache.
A genuinely fresh sealing attempt has a new index even if the plaintext and
requested revision happen to be unchanged.

For each image there is one cached image-head interface and up to `K_i`
original target-bearing write intents. Each intent can use the five raw-intent
digest domains already enumerated in the single-record note. For one image,
the image plaintext/key/header and intent-authentication key are fixed. Distinct
intents must have distinct canonical fixed headers, whose lengths are fixed by
their write tags; an identical header with the same target and key denotes the
same original bytes. A changed field cannot be hidden behind an old cache ID.
This admits

```text
q_i <= 1 + 5 K_i
```

fresh private digest queries for image `i`. In the previously stated one-image,
one-intent case, `K_i=1` and `q_i<=6`. The target-free cancellation encodings
remain outside this nonce argument. If an actual caller creates a different
encoding family, changes the authentication key for the same image, or supplies
another nonce-dependent output, this interface description must first be
extended and checked; the displayed count is not an inferred native bound.

The machine may adaptively create records and choose later known fields using
earlier replies. For each selected nonce, however, all its uses must be confined
to that record's private maps. Other records may use its returned head or
intent digests; they may not secretly embed its raw nonce/image/intent in a
different observable channel and still satisfy this premise. Raw-byte equality
tests likewise require a faithful original-record identity/equality mapping;
the digest theorem does not silently replace them with fresh object IDs.

## Bounded composition with the same SHA3 oracle

Let `H` be the same ideal SHA3 oracle throughout the experiment. For each image
`i`, let `Q_i` bound every ordinary `H` query made by its hybrid reduction,
including the entire prefix, other real record digests, downstream commitments,
honest primitive computations using `H` and the final distinguisher. There is
no uncounted oracle-dependent initial advice. If a counted slot never occurs,
its reduction makes no private query and contributes no difference.

For fixed inputs, each preimage contains `N_i` verbatim at a known offset, so
its point probability is at most `2^-192`. Different digest domains have
different complete domain prefixes. Within one intent-digest domain, different
admitted canonical headers differ before the common target image for every
possible `N_i`; equal tags fix their header lengths, and different tags already
differ in their first eight bytes. Thus distinct fresh queries for the selected
image satisfy the all-nonces input-separation condition. Exact duplicates use
the original cached query.

Applying [Don–Fehr–Huang, Theorem 2](https://arxiv.org/pdf/2206.08132) to one
selected image's nonce gives

```text
epsilon(q_i,Q_i) = min(1,
    4 sqrt(2 q_i^2 Q_i 2^-192) + 4 sqrt(2 Q_i^2 q_i 2^-192)).
```

Order hybrid games by image invocation index. In hop `i`, earlier images use
their ideal cached replies; later images are computed normally using locally
sampled independent nonces. Their real hashes count as ordinary `H` queries.
Only image `i` uses the challenge private oracle. The unknown `N_i` is never
needed by the surrounding algorithm under the stated confinement premise.
Adaptive later creation and early termination use the same code in both games.
The whole prefix is run, rather than replaced by advice correlated with `H`.
Triangle inequality yields

```text
|Pr[real outputs 1] - Pr[all designated records ideal outputs 1]|
    <= min(1, sum_(i=1)^M epsilon(q_i,Q_i)).
```

A common bound `Q_i<=Q` and one original intent per image give at most
`min(1, M * epsilon(6,Q))`. This is a conservative symbolic bound, not a
numerical product security level. `M` is an execution/query budget; a bound on
simultaneously retained records does not bound a lifetime's sealing attempts.

This proof does not assume that nonces from different fresh invocations are
always unequal. A collision with another real record can give an ordinary
query to the selected hidden point; those queries are already covered by the
single-hop bound. Exact copies of one original object must still share a cache.
If two exact copies were instead assigned independent ideal replies, comparing
their digests would distinguish that incorrect game with advantage `1-2^-256`.
Additional raw equality observations are not established by this argument and
cannot be discarded on the strength of a digest-only calculation.

The statement above keeps the image encryption, SHA-256 KDF and HMAC fixed, as
the original single-record statement does. If an additional public oracle `J`
is sampled independently of `H` and all image nonces, the same SHA3 bound holds
pointwise for each fixed `J`, provided the encoding conditions hold for every
`J` and **no extra raw-nonce channel** is exposed. Condition on `J`: its queries
are part of the algorithm's local computation, the encoding is a fixed function,
and the initial state remains independent of `H,N_i`. Average the uniform
bound over `J`. This observation does not supply the separate security of a
SHA-256/HMAC hop or its resource bound: all relevant `J` calls, including ones
inside honest record construction, must still be counted there. It also does
not justify oracle-dependent initial advice or correlated primitive oracles.

## Native provenance facts and the remaining bridge

The current `seal` encoder writes each record's payload verbatim and samples
the outer nonce only after encoding and checking the plaintext bounds.
`unseal_image` retains the decoded fields and head digest, with no nonce or
ciphertext field in `Image`. `PendingWrite` retains the complete original
target. Its constructor, decoder and atomic apply path bind the target digest
and exact original pending bytes. These facts support the nonce confinement
and original-retry descriptions for those paths; they are not a whole-program
noninterference proof.

The [aggregate-copy regression](../../research/sdk-alpha1/evidence/20261105-aggregate-reservation-copy/README.md)
already shows why global revision and selected-session provenance differ: a
sibling send changes the aggregate nonce/head but preserves the selected
generation token byte-for-byte. Its later acquisition still decrypts the six
tested target messages. The [pending-target capture](../../research/sdk-alpha1/evidence/20261031-pending-image-disclosure/README.md)
similarly prevents restricting acquisition to the applied `image` row. Neither
result is relabeled as an exhaustive acquisition proof or a new execution here.

For a selected challenged reservation, the bridge must track its original
invocation through retained token copies, current images, original pending
targets and intact historical copies. A later aggregate containing that origin
does not create new KEM entropy. An acquisition containing a mapped post-Cut
target state invokes the existing predicate even if the triggering write was
for another session. Public projections that contain only known metadata and
digests must instead retain their actual public semantics. Partial residues,
platform copies and other acquisition surfaces need their stated mapping;
the absence of a public Rust nonce field does not prove their absence.

There is also a distinct plaintext-dependent output: session-closure and
fanout-abandonment report MACs cover private message-state payloads. The former
canonically zeroes its 64-byte report/key tail before MAC computation; the latter
keeps its report/key in the batch tail, outside the member payload transcript.
Thus these paths do not MAC their own report key as part of that transcript.
They still cannot be covered merely by idealizing the six SHA3 digest domains.
Their fresh-key MAC simulation, disclosure handling and allowed error branches
must be accounted for when replacing unknown KEM coins. An irreversible closure
may make a selected future message impossible, but an attempted closure can
fail before that point; it cannot be treated as an automatic early zero result.

The subsequent [cleanup-report argument](CLEANUP_REPORT_MAC_V1.md) supplies a
conditional one-transcript HMAC replacement, including the zero-ID error branch
and exact original-report cache. It records focused native regression results;
the full private-state, acquisition and changed-transcript interfaces remain
explicit prerequisites.

These are concrete parts of the existing accepted-prefix obligation, not a
new product vulnerability or a claim that the declared recovery property is
false. The nonce-hash composition, acquisition projection, cleanup-MAC view,
KEM adapter and subsequent key schedule must be connected before the complete
computational conclusion is made. MAIN, its 24 reusable dependencies and all
40 retained queries are unchanged.
