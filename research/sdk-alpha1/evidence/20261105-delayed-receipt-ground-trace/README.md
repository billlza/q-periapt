# Finite delayed-receipt disclosure witness

This record constructs a finite execution satisfying the original
`delayed_receipt_exposes_pre_cut_epoch_two_reservation` query. B can reserve its
next offer while A still awaits the first receipt. A's later confirmation and
fresh encapsulation do not make B's captured earlier generation reservation
fresh. The operational model and all original queries remain unchanged.

The original `proof/current.spthy` has SHA-256
`dde5d06a071b1560da0d4c28c3f1fd81a3c39708f9fd8564ee391ddc362bcf7f`.
The exact selected formula has SHA-256
`4d63f20316db6037f6886a04bbf905b66d2ad2123b2e76aa554089db1673d06f`.
No rule, equation, restriction, query attribute or existing proof is edited.

| Event | Skeleton step |
| --- | ---: |
| Session setup with distinct signing keys | 6 |
| B confirms symbolic epoch 2; A's receipt is held | 19 |
| B reserves the next generation, retaining root1/parent1 | 20 |
| One B epoch-3, phase-3 snapshot | 23 |
| Cut releases wrapping keys | 24 |
| A accepts the delayed receipt and confirms epoch 2 | 26 |
| A reserves epoch-3 encapsulation | 28 |
| A and B confirm the same epoch-3 root/parent | 36, 38 |
| A sends an epoch-3 application message | 39 |
| Attacker derives that message's actual plaintext | 40 |

The skeleton contains 30 protocol applications, ten attacker sends, 35 fresh
births, 14 successful Eq actions, 14 outputs and 213 actions. As in the
[earlier positive witness](../20261105-two-round-ground-trace/README.md), omitted
fresh-generation, output-reception and internal deduction steps can be inserted
with order-preserving renumbering. These are not native Tamarin trace indices.
The construction uses the fixed equations and standard
[message](https://tamarin-prover.com/manual/master/book/004_cryptographic-messages.html)
and [network](https://tamarin-prover.com/manual/master/book/011_advanced-features.html#different-channel-models)
semantics.

The complete public-output recipe is retained. It decrypts snapshot `out[8]`
with `snd(out[9])`, B's wrapping key from Cut. Pair projections recover the
retained generation key and old root. The public response and the model's
exact `decap(key, ciphertext)` equation supply the next abstract KEM
contribution. Public transcript/root/message-key constructions then decrypt
the actual application ciphertext. No private literal or internal term ID is
an attacker recipe. The abstract contribution is not a claim that real ML-KEM
decapsulation exports its implementation's encapsulation seed.

## Checks and theorem boundary

The frozen ground parser/normalizer replays every rule instance and evaluates
the complete original formula. The separately implemented standard-library
parser, normalizer and multiset calculation from the earlier review is also
replayed on this new trace. Its explicit formula readback checks 14 positive
events, eight strict orders, signer inequality and the three global clauses.
Full source and provenance are included. This reuses a separate semantic
implementation; it is not a new subagent review, verified general-purpose
checker or external review.

Both implementations accept the original and fresh-atom-renamed traces. Both
reject seven legal countertraces at the intended boundary: reversed
decapsulation arguments, wrong wrapping key, no plaintext delivery, an extra
snapshot, identity leakage, entropy leakage and a snapshot acquired after Cut.
Initial construction attempts reversed the model's decapsulation arguments
and failed to derive the contribution. Their sources and failure streams are
retained; only the candidate recipe was corrected.

At the concrete binding, ten of MAIN's eleven antecedent clauses hold. The
sole false clause is `#c < #g`: Cut is step 24 and generation is step 20.
Removing only that clause would admit this disclosure. This is **not a
counterexample to the existing MAIN theorem**. Its premise and the original
record-acquisition, identity and entropy boundaries are preserved.

## Implementation correspondence and reproduction

The actual SDK's existing
`lagging_peer_confirmation_does_not_bound_second_epoch_disclosure` test passed
in the complete Release run on source
`4effa8b2b25e7403ab912b65894a7d1e73695542`, implementation
`f560d803c43a24fff222daa5e5e5bd623bfdf874`. Current test source matches that
run's hash. `SCOPE_READBACK.json` indexes the exact test line and six-message,
two-direction marker by original stream path, size, hash and line number;
the original full run receipt is included. This reuses recorded execution,
not a new SDK run. Symbolic initial epoch 1 corresponds to SDK epoch 0, so
symbolic target 3 corresponds to that experiment's epoch 2. This relates the
asynchronous schedule and phase-3 generation boundary, not the whole journal
or a maximum exposure bound.

After extracting the capture into a fresh directory, run there:

```sh
python3 -I -S -B target/continuity-delayed-receipt/readback.py
python3 -I -S -B target/continuity-delayed-receipt/independent_check.py
```

Both commands ran in a fresh outside-checkout extraction under 60-second
limits, exited zero with empty stderr, and left all extracted inputs unchanged.
Trace SHA-256 is `31d6211b0042cd3adcc6cd1b66a65f71f94db68ba917c12465e942bc6d6d820e`.
`CAPTURE.zip` has 88 byte-readback-verified members and 329,625 bytes, SHA-256
`44710faf7125d5b1a8bf2c9ce4d9672c25c9e0fa1815ec822dc0d58a406b813e`.
`FILES.json` binds every member; `READBACK.json` records the scope and runs.

No Tamarin process, new SDK runtime, hosted workflow or release transaction
was executed for this witness. It is not a Tamarin certificate: that inventory
remains 27 verified / 13 incomplete, including this original search query.
The [complete MAIN/dependency replay](../20261104-multi-epoch-replay/README.md)
retains its separate result. Computational composition, whole-state/interface
correspondence, platform qualification and external review remain open.
