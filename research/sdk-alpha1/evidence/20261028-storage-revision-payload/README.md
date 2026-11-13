# Stored revision and payload source analysis

The generation-secret origin theorem remains **analysis incomplete**. Fourteen
of its eighteen knowledge-source cases now close. This adds
`Snapshot_case_4` and `Offer_Commit_3_case_1` to the twelve cases checked in the
[parent checkpoint](../20261028-storage-field-origins/README.md).
The main multi-epoch message-secrecy theorem, recovery reachability and
implementation correspondence remain open.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-payload-wire-chain-replay-711/payload-wire-chain-proof.spthy`.
Its SHA-256 is
`b0bea9b7e94e2f9da23f4cd9cd2ba58ec95f5fc0e3d109532c7cc9b71d0729f8`.
All 29 query formulas, modes and attributes match the parent. The operational
prefix, including the newline before the first lemma, remains byte-identical:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Checked proof steps

The first diagnostic restored the parent's two eleven-producer expansions for
stored revision and plaintext, retaining every source case. It captured 26
actual open frontiers without selecting a search step. The same recorded
knowledge-chain method was then checked at all 22 stored-producer leaves by an
independent replay. All eleven revision producers closed. The plaintext
producers instead split into tuple projections and remained open.

The second diagnostic applied the four actual signed-wire shape goals recorded
at the remaining message sources. It retained the thirteen closed sources and
captured 17 remaining frontiers. Public epoch projections simplified away;
the payload and wire-content projections remained explicit. A second
independent replay checked the unique recorded chain method at each of those
17 leaves. The offer source closed; the other sources produced further open
tuple projections. These were not replaced with successful leaves.

The final no-search replay used pinned Tamarin 1.12.0 and Maude 3.5.1 and took
285.434 seconds. It checked the 175-step partial origin tree, fourteen auxiliary
all-trace lemmas and the existing 414-step initial-traffic witness. There were
no invalid proof steps. Tamarin exited 0; the acceptance driver exited 1 and
recorded `accepted: false`, because the origin theorem remains incomplete.
Proof-tree sizes describe decompositions, not completion percentages.

## Remaining sources

| Source | Open leaves |
| --- | ---: |
| `Final_Commit_8` | 4 |
| `Receipt_Commit_0` | 4 |
| `Response_Commit_6` | 2 |
| `Snapshot_case_5` | 22 |

The next diagnostic can start from the exact final entry and capture these
32 leaves, without adding further speculative proof steps. The deepest open
prefix is five steps; a remaining bound of eleven keeps total search depth
at sixteen. New goal addresses must come from that diagnostic, not from an
earlier tree whose variable names may have changed.

## Evidence and limits

`CAPTURE.json` identifies every archived input, launcher, captured frontier,
terminal result and output hash. `READBACK.json` records byte-for-byte reading
of all 133 archive members. The capture is 294,331 bytes, with SHA-256
`00e01eefdd10f2d96bd98d136513a136834c8be61f1dc5505342952e1395395b`.
The two diagnostics and two independent replays ran sequentially. Each retained
the 900-second outer limit, 60-second derivation check, 12-GiB heap and one
runtime capability. Diagnostic prefix/bound pairs were 3/13 and 4/12; each
kept the 32-callback ceiling. No protocol rule or threat was removed.

To check the final entry, use the pinned binaries without `--prove` or an
oracle, with `--derivcheck-timeout=60 --quit-on-warning` and
`+RTS -N1 -M12G -c100`. Archived launchers contain the original local paths;
adapting extraction paths must preserve model, tool and resource identities.

The historical non-reuse `initial_epoch_counter_is_zero` query remains the
documented obsolete conjecture from the initial-traffic checkpoint. It is not
an assumption of the verified helpers. The parent's derivation-check timeout
and controlled comparison remain retained in their original capture. This
checkpoint does not establish device, performance, ABI, installed
interoperability or release qualification.
