# A finite two-round execution on the unchanged symbolic model

This record constructs and checks one finite execution satisfying the original
`two_rounds_recover_with_exposed_ancestor_is_executable` formula. It follows the
two retained heap-exhausting searches with a concrete source-derived execution;
it does not repeat or increase their search budgets. The operational rules,
equations, restrictions, query formulas and existing Tamarin certificate remain
unchanged.

The pinned model is the original `proof/current.spthy`, SHA-256
`dde5d06a071b1560da0d4c28c3f1fd81a3c39708f9fd8564ee391ddc362bcf7f`,
from the [main-secrecy checkpoint](../20261031-multi-epoch-secrecy/README.md).
The trace has 30 protocol-rule applications and 10 attacker sends, with 35
distinct fresh births, 14 successful Eq actions, 14 protocol outputs and 213
actions. Its 40 steps are an execution skeleton: fresh generation, output
reception and internal attacker deductions can be inserted as finite built-in
steps. The named times are then mapped in order; they are not asserted to be
literal native Tamarin trace indices.

| Required event | Skeleton step |
| --- | ---: |
| SessionKeys for two distinct signing keys | 6 |
| B confirms epoch 2 | 19 |
| B's sole epoch-2, phase-0 Snapshot | 22 |
| Cut releases the wrapping keys | 23 |
| K(root1), derived from that snapshot | 24 |
| B reserves the epoch-3 generation using root1,parent1 | 25 |
| A reserves the epoch-3 encapsulation using root1,parent1 | 29 |
| A confirms epoch 3 | 37 |
| B confirms the same epoch-3 root and parent | 39 |
| A sends an epoch-3 application message | 40 |

The ancestor-root recipe is
`fst(snd^8(sdec(out[7], snd(out[8]))))`. The outputs are the encrypted B record
and Cut's wrapping-key pair. Six projections reach the saved plaintext, then
two projections and fst reach its root field. No private literal or internal
term ID is accepted as an attacker recipe. There is exactly one Snapshot over
the entire trace, and no IdentityLeak or EntropyLeak anywhere in it.
These deductions use the fixed equations and Tamarin's
[message semantics](https://tamarin-prover.com/manual/master/book/004_cryptographic-messages.html)
and [network rules](https://tamarin-prover.com/manual/master/book/011_advanced-features.html#different-channel-models).

## Checks and limits

The generator and no-search replayer parse the frozen source and evaluate the
complete original formula. A separate internal review used another parser,
ground normalizer and multiset calculation importing only Python's standard
library. It checked every rule instance and all 13 positive event predicates,
eight strict time inequalities, signer inequality and global quantifier
clauses. The main task inspected and reran both commands from that review;
their original stdout, stderr and terminal receipts are retained.

Two positive controls pass, including renaming every fresh atom. All 22 negative
controls reject at their expected boundary: freshness and sorts, persistent or
linear premises, signature equality, future outputs, private literals, malformed
DAGs and the target formula. Seven controls are legal finite traces whose extra
snapshot/leakage, premature message/generation or missing ancestor send violates
the exact target. The independent review also checked a wrong-wrapping-key
variant: all protocol steps execute, but K(root1) is absent and the target fails.

This supports a concrete execution witness for this exact target. It is **not a
Tamarin certificate**, a formally verified general-purpose checker, a secrecy
proof or an external security review. The existing Tamarin inventory remains
27 verified and 13 incomplete, including all eleven multi-round search queries.
It does not establish computational security, whole-journal correspondence or
product qualification. The [failed searches](../20261104-two-round-diagnostic/README.md)
and [successful main/dependency replay](../20261104-multi-epoch-replay/README.md)
retain their own outcomes.

The complete diagnostic DAG has 391 nodes, including reduction intermediates.
Unfolding the confirmed epoch-2 root/parent gives 72 / 12,834 tree nodes; epoch 3
gives 38,639 / 7,203,156. These exact term counts motivate investigating sharing
and normalization costs. They do not identify the cause of Tamarin's heap
exhaustion, measure its memory use, or describe product hash-output sizes.

## Reproduction and provenance

`CAPTURE.zip` contains the original model, frozen trace/checker, exact formula
readback, control inputs/results, independent `REVIEW.md` with both complete
commands, root re-execution receipts and a portable no-search replay. The
original `UNREVIEWED` filenames preserve the initial snapshots; review is
recorded separately. The initial incorrect ten-equation inventory guard is
retained in its original parser snapshot. A later control-script quoting error
stopped before execution; that script and original SyntaxError stream are also
retained. The corrected complete control run is `controls-02`.

After extracting into a fresh directory, run the bundled same-checker replay:

```sh
python3 -I -S -B target/continuity-ground-witness/readback.py
```

This was executed with Python 3.14.10 in a separate extraction, completed in
0.316 seconds under a 60-second bound, and left every extracted input unchanged.
The independent review's commands retain their original repository location and
hardened launcher; their semantic Python bodies use standard-library modules.

All 58 archive members were reread byte-for-byte. The archive has 268,346 bytes
and SHA-256 `b7d6113d959ce29f933aab648c22a33263aedbdc06f5d8903f237483eeffdb8a`.
`FILES.json`, `READBACK.json` and `SHA256SUMS` pin the bytes and actual checks.
No Tamarin executable, runtime build, hosted CI or release operation was invoked
for this finite-trace record.
