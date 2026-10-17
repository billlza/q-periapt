# Root inheritance in the multi-epoch projection

Status: **one structural property verifies in an independent no-search replay.**
The unchanged [multi-epoch model](../../../continuity-recovery-symbolic/multi-epoch.spthy)
still has no admitted normal two-round witness, delayed-receipt disclosure witness
or arbitrary-epoch message-secrecy theorem. This checkpoint does not establish
post-compromise recovery or SDK refinement.

`reservations_inherit_locally_confirmed_root` states that every reservation's
root and transcript parent occur together in an earlier local Ready event, at
the predecessor epoch. It holds across unbounded modeled rounds and both roles.
It does not assert agreement between the two peers, correct concrete KDF
implementation, or secrecy of that inherited root. The
[source map](../20261015-recovery-multi-epoch-model/MODEL_MAP.md) retains the
concrete correspondence obligations and limitations.

| Check | Result |
| --- | --- |
| Inductive search on the annotated original theory | Verified, 14 steps, 162.763 s |
| Direct search of the same formula, removing only the induction hint | Verified, 11 steps, 159.244 s |
| Independent replay of the inductive certificate, without `--prove` | Verified, 14 steps, 197.542 s |
| Full theory/declaration comparison | All operational rules, equations and restrictions match after search-annotation erasure; all four complete queries match |
| Identity controls | Changed root-origin event, added disclosure restriction, changed complete formula and deleted query all rejected |

The accepted replay has no prior reusable or source lemma. Both existential
queries and the message-secrecy query remain explicitly incomplete in its full
terminal inventory. Their placeholders are not premises of the proved property.
The canonical model SHA-256 remains
`1be3e576722af22586edf62eff1cacb913b981e162f3942e133fac613aaf4977`.
The independently replayed certificate SHA-256 is
`b92fd24e959ecd33780ef7d9ee4d5912b39988ede03036b3c75cee20f6d5d499`.

A separate precompute-only invocation on exact input variant `08` finishes in
189.404 seconds, reporting 38 raw and refined source entries and 266 partial
deconstructions. The tool labels the entries “cases”; its
[implementation](https://github.com/tamarin-prover/tamarin-prover/blob/82780bbaf3328a45f624ddb41e51bf75425f851c/lib/theory/src/ClosedTheory.hs#L547)
counts source-catalogue entries, each of which can contain several branches.
The partial deconstructions are unresolved derivation chains, not vulnerabilities
or counterexamples. The [manual](https://tamarin-prover.com/manual/master/book/009_precomputation.html)
explains why they can complicate later search. Precomputation can therefore
terminate on this input; that observation alone does not explain every earlier
timeout or admit a security property.

The successful searches and replay use `--verbose`. The first replay without
that flag reaches its 300-second deadline. An additional encoding control copies
the exact found proof body into the original source, preserving its builtin
declarations and every query byte; its replay without verbose logging also
times out at 300 seconds. Both failures remain in the archive. These observations
do not establish that logging itself caused the improvement, and do not justify
calling execution timing stable. No deadline, heap bound or derivation check was
relaxed. The accepted replay uses one thread and a 6 GiB heap, with full
derivation checks and `--quit-on-warning` under pinned Tamarin 1.12.0 / Maude 3.5.1.
No CI proof profile is changed by this checkpoint.

The normal two-round query also receives a fresh 600-second, 12 GiB search on
the annotated model; it times out without a terminal verdict. Later witness
investigation is separate from this closed inheritance checkpoint. None of these
timeouts is treated as a refutation. The prior six attempts and the parser-rejected
annotation generator are carried byte-for-byte in `prior/model-CAPTURE.zip`.

For reproduction, `experiments/inheritance-20-proof.spthy` is the input to the
accepted no-search replay. The archived `run-20.py` invokes the pinned tools with
`--verbose`, a 300-second deadline, 6 GiB heap and bounded streams; the exact
argument vector is in `inheritance-replay-27-TERMINAL.json`. Reproduction must
require the complete terminal inventory and the same model/query identities,
not merely exit zero or the presence of the theorem name.

`CAPTURE.json` records all selected terminal results and member hashes;
`READBACK.json` records a full readback of 66 members. The archive is 215,170 bytes
and expands to 1,167,215 bytes. SHA-256:
`c2bb3d301bc3ce83039331dfb0c8752e480bf118f847136dcee48eb220ef8891`.
All selected prover groups are absent at capture. Mutable logs from separate
ongoing witness work are excluded. No private SDK/device cohort was reopened,
and no product code, canonical model or release requirement changed.
