# Stored role and phase source proofs

The generation-secret origin theorem remains **analysis incomplete**. Twelve
of its eighteen knowledge-source cases now close, including the newly checked
`Snapshot_case_2` and `Snapshot_case_3`. The main multi-epoch secrecy theorem,
recovery reachability and implementation correspondence remain unproved.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-storage-role-direct-708/storage-role-direct-proof.spthy`.
Its SHA-256 is
`6abc57adbf5518606053af6cfc81f12e59e98d9f9ec868cd1e1a2f3d82f42340`.
All 29 query formulas, quantifier modes and attributes match the parent.
The operational prefix is byte-identical, including its final newline:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Proof changes

A diagnostic expanded two snapshot sources while retaining all eighteen source
cases and all query definitions. Its initial 28 open leaves fit the unchanged
32-callback limit. Automatic simplification closed the eleven stored-phase
producer branches; seventeen actual frontiers were captured for the remaining
leaves. An independent replay subsequently checked that phase closure.

The first role construction followed the eleven stored producers and their
observed `Wrap` premises. It produced 22 open Setup children. A shorter proof
uses the snapshot's original, recorded `Wrap` premise directly. Its two Setup
producers fix the role to the public constants A and B. Each contradicts the
fresh generation-key source. The original expansion remains available as a
control; replacing it changes only the proof decomposition, not the protocol,
attacker capabilities or source cases.

The final replay used the pinned Tamarin 1.12.0 and Maude 3.5.1 binaries without
search or an oracle. In 287.730 seconds it checked the twelve closed source
subtrees, fourteen auxiliary all-trace lemmas, and the existing 414-step
initial-traffic witness. The main origin result is still a 93-step incomplete
tree, with no invalid proof steps. The driver exited 1 with `accepted: false`
although Tamarin exited 0. The intermediate 102- and 124-step trees have
different decompositions; their sizes are not completion percentages.

## Retained timeout and control

The first role replay stopped at the unchanged 60-second derivation check,
before producing any lemma result. Strict warning handling rejected the run.
This was an inner check timeout, not the outer 900-second controller timeout
and not a protocol counterexample.

The immediately preceding 102-step certificate then replayed in 309.825 seconds
with the same operational theory and resource limits. One exact replication
of the failed input completed in 298.040 seconds, retaining the same input
and driver bytes, derivation limit, heap limit and warning checks. The original
timeout remains in the capture. This bounded comparison did not reproduce the
failure; it does not establish its scheduling, Maude or hardware cause.

## Remaining obligations and checking

Six source roots remain open: `Final_Commit_8`, `Offer_Commit_3_case_1`,
`Receipt_Commit_0`, `Response_Commit_6`, `Snapshot_case_4` and `Snapshot_case_5`.
The parent contains the latter two sources' eleven-producer expansions. Those
can be copied into the current tree for a diagnostic with 26 initial open
leaves, using the remaining depth after its existing prefix. Actual pending
goals must be observed before constructing further steps.

The historical `initial_epoch_counter_is_zero` query deliberately remains
unproved and has no `reuse` annotation. The initial-traffic witness contradicts
it after initial sends were enabled, as already recorded in the
[initial-traffic checkpoint](../20261027-recovery-initial-traffic/README.md).
It is not an assumption of the checked helper group, and its recorded tool
status is not relabeled as a directly found counterexample.

`CAPTURE.json` lists every member hash, result and resource limit.
`READBACK.json` records complete byte-for-byte archive verification. The failed
run, successful control, exact replication, original frontier and final proof
are retained. Each run used at most 900 seconds, 12 GiB and one runtime
capability; the derivation check stayed at 60 seconds. The diagnostic used
prefix depth three plus bound thirteen, for total depth sixteen.

To check the final entry, use the pinned binaries with
`--derivcheck-timeout=60`, `--quit-on-warning`, and `+RTS -N1 -M12G -c100`.
Do not add `--prove` or infer theorem success from process exit alone.
Archived launchers describe the original local environment; changing extraction
paths must preserve model, tool and resource identities. This checkpoint does
not confer device, performance, ABI, package or release qualification.
