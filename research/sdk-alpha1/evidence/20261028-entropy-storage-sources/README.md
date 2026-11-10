# Entropy and stored-state source checkpoint

The generation-secret origin theorem remains **analysis incomplete**. This
checkpoint closes ten of its eighteen knowledge-source cases, adding
`Reveal_Entropy` and `Snapshot_case_1` to the eight previously checked cases.
It does not establish the full origin theorem, multi-epoch message secrecy,
or correspondence to the SDK implementation.

The final entry inside `CAPTURE.zip` is
`experiments/p0-origin-storage-fields-707/storage-fields-replay-proof.spthy`.
Its SHA-256 is
`4736abef8fc97eed60f45dd532e82c15a83118021b50eb57ee2a0da40ac53188`.
All 29 query formulas, modes and attributes match the parent checkpoint.
The operational prefix is byte-identical, including its final newline, with
SHA-256 `3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Checked progress

The entropy diagnostic selected one observed `Entropy` source goal and
retained the resulting frontiers. Replaying the recorded knowledge edges
closed one reservation branch; a subsequent diagnostic simplified the other
branch to a contradiction. Independent replays then checked the complete
entropy source subtree.

The first ordinary snapshot source was expanded through its eleven `Stored`
producers. Nine observed knowledge edges closed directly. The remaining two
producers required their recorded `Wrap` source, followed by four observed
knowledge edges. The complete subtree passed an independent replay.
The model still emits the encrypted snapshot record; no disclosure or
attacker capability was removed.

The four remaining snapshot sources were also expanded through `Stored`.
Each currently has eleven open producer children. This expansion exposes
the next obligations but closes no additional source. The 80-step checkpoint
and this final 124-step partial tree are both retained, with ten closed
sources in each. Step counts describe different trees, not progress
percentages.

The final replay used the pinned Tamarin 1.12.0 and Maude 3.5.1 binaries,
without `--prove` or an oracle, and took 280.934 seconds. It rechecked the
closed subtrees, all fourteen previously verified auxiliary all-trace
lemmas, and the existing 414-step initial-traffic witness. There are no
invalid proof steps in the final entry. The driver exited 1 with
`accepted: false`; the prover's exit 0 does not mean the main theorem passed.

## Remaining obligations and reproduction

Eight sources remain open: `Final_Commit_8`, `Offer_Commit_3_case_1`,
`Receipt_Commit_0`, `Response_Commit_6`, and `Snapshot_case_2` through
`Snapshot_case_5`. The last four contain 44 open producer children whose
actual next goals have not yet been captured. A subsequent diagnostic must
retain all source cases and query definitions, respect its callback limit,
and deduct the existing prefix from the total search depth.

Each run was limited to 900 seconds, 12 GiB and one runtime capability.
Searches at prefix depth two used bound fourteen; diagnostic captures at
prefix depth four used bound twelve. The total search depth stayed sixteen,
with at most 32 diagnostic callbacks. New manual paths have depth at most
five. No timeout or search bound was raised.

`CAPTURE.json` records all member hashes, the parent, tool identities,
per-experiment results and resource bounds. `READBACK.json` records complete
byte-for-byte archive verification. Models, raw frontiers, drivers and
terminal records are preserved, together with compact records of local
pre-launch interpreter, path and leaf-format errors. Preparation records
describe intended work; terminal records determine executed outcomes.

Replay the final entry with the pinned binaries, `--derivcheck-timeout=60`,
`--quit-on-warning`, and `+RTS -N1 -M12G -c100`. Do not add `--prove` or infer
success from process exit alone. Archived launchers describe the original
local environment; rebinding extraction paths must preserve model, tool
and resource identities. Main secrecy, recovery reachability, implementation,
device, performance, ABI and release qualification remain separate obligations.
