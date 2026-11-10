# Stored Offer and Response payload origins

The generation-secret origin theorem remains **analysis incomplete**. The
seventeen closed knowledge-source cases from the
[parent checkpoint](../20261028-stored-reservation-closure/README.md) remain
unchanged. Within `Snapshot_case_5`, `Offer_Signing_2` now closes completely,
alongside the two previously closed reservation producers. Eight other Stored
producers retain 27 open leaves. Multi-epoch message secrecy, recovery
reachability and implementation correspondence remain open.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-offer-response-final-715/offer-response-final-proof.spthy`.
Its SHA-256 is
`2fea36a4924616476f80dca5172743c7d726b6a3f1cc68b51111c8599960acae`.
All 29 query formulas, quantifier modes and attributes match the parent. The
operational prefix, including its final newline, remains byte-identical:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Observed goals and independent checking

Both diagnostics focus `Offer_Commit_3`, `Offer_Signing_2` and
`Response_Compute_5`. The two closed reservation subtrees remain intact. The
six other open producers are explicitly open during each diagnostic, with
their complete checked subtrees preserved. Both independent replays restore
those six subtrees byte-for-byte.

The first diagnostic captures 22 actual goals without ranking methods. Ten
selected goals supply unique knowledge chains and six supply unique actual
`PositionedPhaseState` producer premises outside the generation event. After
inserting those observed steps and restoring the unselected subtrees,
independent replay without search or an oracle checks the 319-step partial
tree in 290.245 seconds. It retains 37 open leaves.

The second diagnostic starts with 24 focused leaves. The prover closes two
automatically and captures 22 actual remaining goals. Fourteen selected goals
supply unique knowledge chains and two supply phase-producer premises. The
final independent replay checks the resulting 327-step partial tree in
297.488 seconds. `Offer_Signing_2` is closed; the two earlier closed reservation
subtrees remain byte-identical.

| Stored producer | Final open leaves |
| --- | ---: |
| Final commit | 3 |
| Final reservation | 4 |
| Key reservation | 0 |
| Offer commit | 6 |
| Offer signing | 0 |
| Receipt accept | 2 |
| Receipt commit | 2 |
| Receipt reservation | 4 |
| Response commit | 4 |
| Response computation | 2 |
| Response reservation | 0 |

The full-tree sequence 35 to 37 to 27 records changes in proof branches; it is
not a security completion percentage. All eighteen knowledge sources and
eleven Stored producers remain present. Fourteen auxiliary all-trace lemmas
and the 414-step initial-traffic witness remain verified. No invalid proof
step was introduced. Every Tamarin process exited 0; every driver exited 1
with `accepted: false`, because the origin theorem remains incomplete.

## Reproduction and next bounded diagnostic

`CAPTURE.json` records all four experiments, actual goal hashes and inserted
methods. `READBACK.json` checks all 134 archive members byte-for-byte. The
323,114-byte archive has SHA-256
`9dc6aa17a60b2149094ea55ccb27edb684b4908661cdf6bb524f684f78bc947d`.
Each sequential process used 900 seconds, 12 GiB, one runtime capability,
the 60-second derivation check and strict warning handling. Capture prefix and
remaining-bound pairs were 7/9 and 8/8, within total depth sixteen and the
32-callback ceiling. Both oracles ranked no methods.

The next capture can use the entire checked 27-leaf tree unchanged, with no
collapsed subtrees. Preserve all three closed Stored producers. The maximum
existing prefix is nine steps, leaving seven within total depth sixteen.
Only observed methods should be added before independent replay; callback
counts must not be substituted for the final tree's remaining obligations.

Replay the final entry with pinned Tamarin 1.12.0 and Maude 3.5.1, without
`--prove` or an oracle, using `--derivcheck-timeout=60 --quit-on-warning` and
`+RTS -N1 -M12G -c100`. Adapt archived local paths only while preserving model,
tool and resource identities. The historical non-reuse
`initial_epoch_counter_is_zero` remains the documented obsolete conjecture,
not an assumption. Earlier failures and timeouts remain in the parent captures.
This checkpoint establishes no device, power-loss, ABI, performance,
installed-interoperability or release acceptance.
