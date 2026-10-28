# Response knowledge-source closure

The generation-secret origin theorem remains **analysis incomplete**. Seventeen
of its eighteen knowledge-source cases now close. The newly closed case is
`Response_Commit_6`. The remaining `Snapshot_case_5` retains its complete 36-leaf
tree. This does not complete multi-epoch message secrecy, recovery reachability
or implementation correspondence.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-response-restored-713/response-restored-proof.spthy`.
Its SHA-256 is
`17388a2c9dee3d9c3ca497b6bf3f08bdb1f3b070a06f11117dfe89bf8e9843ac`.
All 29 formulas, quantifier modes and attributes match the
[parent checkpoint](../20261028-wire-and-parent-origins/README.md). The
operational prefix, including its final newline, remains byte-identical:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Actual goal and independent replay

A capture-only diagnostic exposed the Response case's remaining knowledge
chain, `(#vr.11, 0) ~~> (#known, 0)`, after its recorded encapsulation producer.
The oracle captured two actual inputs and ranked no method. For this diagnostic
the stored-payload obligation remained explicitly open; its complete checked
subtree was preserved in the parent, not removed from the theorem.

The preparer added only the recorded chain step and restored the complete
stored-payload subtree byte-for-byte. Independent replay without search or an
oracle checked the resulting 256-step partial tree in 309.555 seconds. Response
now closes; all 36 stored-payload leaves remain open. The fourteen auxiliary
all-trace lemmas and 414-step initial-traffic witness remained verified. There
were no invalid proof steps. Tamarin exited 0; the driver exited 1 with
`accepted: false`, preserving the incomplete origin theorem's status.

`CAPTURE.json` records both experiments, all member hashes and restoration
checks. `READBACK.json` verifies all 28 archive members byte-for-byte. The archive
is 138,373 bytes, with SHA-256
`3c8f8c0548a33f4a845980b147f03782e117b4c448cdc19d6716133f0fc8c442`.
Both processes ran sequentially under 900 seconds, 12 GiB, one runtime
capability, the 60-second derivation check and strict warning handling. The
diagnostic's nine-step existing prefix plus bound seven preserved total depth
sixteen and the 32-callback limit.

## Remaining work and evidence boundary

Inspect the stored-payload leaves in bounded producer groups. Preserve all
eleven Stored producers and the full existing subtrees when focusing a
diagnostic, then restore them before independent replay. In particular,
`Key_Reservation_1` has five open leaves and `Response_Reservation_4` has six;
their phase producers expose Ready-parent, old-state and reservation material
that still require origin analysis.

Check the final entry with pinned Tamarin 1.12.0 and Maude 3.5.1, without
`--prove` or an oracle, using `--derivcheck-timeout=60 --quit-on-warning` and
`+RTS -N1 -M12G -c100`. Archived launchers contain original local paths; path
adaptation must preserve model, tool and resource identities.

The historical non-reuse `initial_epoch_counter_is_zero` query remains the
documented obsolete conjecture, not an assumption. Prior failures, timeouts and
unvisited siblings remain in the parent captures. This checkpoint establishes
no device, performance, ABI, installed-interoperability or release acceptance.
