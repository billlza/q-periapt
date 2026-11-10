# Stored generation and encapsulation reservation origins

The generation-secret origin theorem remains **analysis incomplete**. Its
seventeen closed knowledge-source cases are unchanged from the
[Response checkpoint](../20261028-response-source-origin/README.md).
`Snapshot_case_5` now has 35 open leaves across all eleven Stored producers.
The complete multi-epoch secrecy theorem, recovery reachability and
implementation correspondence remain open.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-stored-reservation-replay-713/stored-reservation-replay-proof.spthy`.
Its SHA-256 is
`e43ce04aacc0e10e97b39425752abde81e77ff30b15bec08363f80dfc2e77fe9`.
All 29 formulas, quantifier modes and attributes match the parent. The
operational prefix, including its final newline, remains byte-identical:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Focused diagnostic and full replay

The diagnostic retained the five existing `Key_Reservation_1` leaves and six
`Response_Reservation_4` leaves. Each other Stored producer remained explicitly
open in the focused input, with its complete checked subtree preserved in the
parent. This yielded twenty actual captured goals, within the unchanged
32-callback ceiling. The capture-only oracle ranked no methods.

Nine selected goals exposed a unique knowledge chain. Two other goals required
the actual Ready-state producer for an old root. The preparer inserted only
these eleven observed methods, with the frame hashes recorded in
`CAPTURE.json`, and restored all nine unselected producer subtrees byte-for-byte.

Independent replay without search or an oracle checked the resulting 266-step
partial tree in 302.628 seconds. Seven parent-origin leaves closed. Other steps
expanded old-root, fresh-generation-key and payload branches, leaving four
generation-reservation and six encapsulation-reservation leaves. The total
change from 36 to 35 leaves therefore measures this tree, not progress toward a
security percentage. No source or attacker capability was removed.

All fourteen auxiliary all-trace lemmas and the 414-step initial-traffic witness
remained verified. There were no invalid proof steps. Tamarin exited 0; both
experiment drivers exited 1 with `accepted: false`, retaining the incomplete
origin theorem's status.

## Next diagnostic and limits

Continue with the four generation-reservation and six encapsulation-reservation
leaves. With the other nine producers explicitly open, that focused input would
have nineteen leaves. The deepest current prefix is seven steps, leaving nine
within total depth sixteen. Inspect the actual old-root producer chains, the
`Var_fresh_1_key` branch and the remaining response-payload projections before
choosing steps. Restore the nine complete unselected subtrees before final
replay again.

`READBACK.json` verifies all 64 archive members byte-for-byte. The archive is
167,721 bytes, with SHA-256
`556c668188d84c685a09c28121f2b9cdae3aa4192386a3d92d310f892501492b`.
Both processes ran sequentially with 900 seconds, 12 GiB, one runtime capability,
the 60-second derivation check and strict warning handling. This diagnostic's
six-step prefix plus bound ten preserved total depth sixteen.

Check the final entry with pinned Tamarin 1.12.0 and Maude 3.5.1, without
`--prove` or an oracle, using `--derivcheck-timeout=60 --quit-on-warning` and
`+RTS -N1 -M12G -c100`. Original local paths in the archived launchers may need
adaptation; preserve model, tool and resource identities.

The historical non-reuse `initial_epoch_counter_is_zero` query remains the
documented obsolete conjecture, not an assumption. Earlier timeouts, failures
and partial trees remain in the parent captures. This checkpoint establishes
no device, power-loss, performance, ABI, installed-interoperability or release
acceptance.
