# Stored reservation closure and payload producer expansion

The generation-secret origin theorem remains **analysis incomplete**. Its
seventeen closed knowledge-source cases are retained from the
[parent checkpoint](../20261028-stored-reservation-origins/README.md).
Within `Snapshot_case_5`, `Key_Reservation_1` and `Response_Reservation_4` now
close completely. The other nine Stored producers retain 35 open leaves after
their actual payload origins are expanded. Multi-epoch message secrecy,
recovery reachability and implementation correspondence remain open.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-snapshot-producers-replay-714/snapshot-producers-replay-proof.spthy`.
Its SHA-256 is
`85b3f4f5fc2f89def1ac5fb841608059da3a543300381bee5e8c4df8583109a5`.
All 29 formulas, quantifier modes and attributes match the parent. The
operational prefix, including its final newline, remains byte-identical:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Actual goals and two independent replays

The first diagnostic focused the four generation-reservation and six
encapsulation-reservation leaves. The other nine producers remained explicitly
open, with their full checked subtrees preserved. From the nineteen starting
leaves, the prover closed `Var_fresh_1_key` from formulas and a response-payload
projection by a cyclic contradiction, and captured seventeen actual goals.
The capture-only oracle ranked no methods.

Eight selected goals contained a unique knowledge chain. After adding those
recorded steps and restoring the nine unselected subtrees byte-for-byte,
independent replay without search or an oracle checked the full 266-step tree
in 319.354 seconds. Both reservation producers were closed, leaving 25 leaves
in the other nine Stored producers.

The next diagnostic used that entire checked tree unchanged: no subtrees were
collapsed. It captured all 25 remaining goals, within the original 32-callback
limit. Eleven supplied a unique knowledge chain; fourteen supplied a unique
actual `PositionedPhaseState` producer premise outside the generation event.
Only those observed methods were inserted. A second independent replay checked
the resulting 301-step partial tree in 308.796 seconds. The two closed
reservation subtrees remained byte-identical.

The final remaining leaf counts are:

| Stored producer | Open leaves |
| --- | ---: |
| Final commit | 3 |
| Final reservation | 4 |
| Offer commit | 4 |
| Offer signing | 5 |
| Receipt accept | 2 |
| Receipt commit | 2 |
| Receipt reservation | 4 |
| Response commit | 4 |
| Response computation | 7 |

The sequence 35 to 25 to 35 reflects closed reservation branches followed by
expanded payload origins. It is not a security completion percentage. All
eighteen knowledge sources and eleven Stored producers remain present.
Fourteen auxiliary all-trace lemmas and the 414-step initial-traffic witness
remain verified. There are no invalid proof steps. Every experiment's Tamarin
process exited 0; every driver exited 1 with `accepted: false`, because the
origin theorem remains incomplete.

## Next bounded diagnostic

Focus `Offer_Signing_2` (five leaves), `Offer_Commit_3` (four) and
`Response_Compute_5` (seven). Preserve the two closed reservation subtrees.
Keep each of the six other open producers explicitly open in the diagnostic
while preserving its full subtree; this yields 22 focused leaves. The maximum
existing prefix is seven steps, leaving nine within total depth sixteen.
Capture actual goals and restore all six unselected subtrees before final
independent replay. Do not raise the callback ceiling or discard pending cases.

`CAPTURE.json` records all four experiments, original goal hashes and method
choices. `READBACK.json` checks all 130 archive members byte-for-byte. The
317,328-byte archive has SHA-256
`303f3021b1d2f4ea7748922b4fbee48e8e3f15632dd014ad9a6fc55889fabeef`.
Each sequential process used 900 seconds, 12 GiB, one runtime capability,
the 60-second derivation check and strict warning handling. Capture prefix/bound
pairs were 7/9 and 6/10. Both oracles ranked no methods.

Replay the final entry with pinned Tamarin 1.12.0 and Maude 3.5.1, without
`--prove` or an oracle, using `--derivcheck-timeout=60 --quit-on-warning` and
`+RTS -N1 -M12G -c100`. Adapt archived local paths only while preserving model,
tool and resource identities. The historical non-reuse
`initial_epoch_counter_is_zero` remains the documented obsolete conjecture,
not an assumption. Earlier failures and timeouts remain in the parent captures.
This checkpoint establishes no device, power-loss, ABI, performance,
installed-interoperability or release acceptance.
