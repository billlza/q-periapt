# Peer-source ordering diagnostic

This checkpoint retains two unsuccessful generation-origin searches and an
explicitly incomplete diagnostic export. The model is byte-identical to the
[tagged-parent search](../20261027-recovery-parent-origin/README.md), including
all 27 queries, operational rules and restrictions. No new assumption or helper
property is added. The SDK runtime source is unchanged.

The first search moved an existing same-role `Peers(s,p,p)` source goal ahead
of protocol-state expansion. Its first six oracle inputs and rankings reproduce
the preceding run exactly; the seventh input is identical but its ranking
changes. The later partial export closes this branch using the existing Setup
sources. The search nevertheless reaches the 900-second deadline without a
certificate, exiting after SIGINT with code -2.

The second search additionally prioritizes other existing `Peers` source goals.
Its first eleven inputs and rankings reproduce the first search; only the next
ranking changes. This binds the roles to A/B before further phase expansion,
but the search again times out without a certificate. Both attempts retain
the depth-16, 12 GiB, single-thread limits. These observations do not establish
an overall search-speed improvement or a security result.

A separate diagnostic reduces the ordinary callback budget to 14 so the
expensive frontier can be inspected. Its first fourteen inputs and rankings
match the second search exactly, and its first stopped input has the same hash
as that search's final input. The stop remains latched for 21 diagnostic calls.
The resulting 40-step origin proof is **analysis incomplete**; the driver
correctly rejects it despite the prover's zero process exit. This is a deliberate
diagnostic stop, not a passing proof under a smaller bound. The eleven existing
auxiliary proofs and 414-step initial-traffic witness recheck in this run; the
other obligations remain explicitly unproved.

The first exported frontier starts in the `Application_Message` knowledge-source
case and follows Ready/Receipt history to `Final_Commit_8`. Several same-session
signer, pinned-key and wrapping-key bindings remain unresolved. Their existing
sources are Setup, whose identity/storage inputs have direct fresh-key sources.
The dependency between those bindings, the application-message source and the
current generation-key goal needs inspection before another search. This is
not evidence that the SDK discloses a generation key.

All 64 callback inputs and outputs were recovered and checked against their
hashes and complete goal inventories: 43 ordinary rankings preserve every goal,
and 21 marked diagnostic stops are retained. The exported JSON graph belongs
to the already checked initial-traffic witness; it is not an origin-frontier
graph. An initial local producer scan mistakenly included premises inside
commented AC variants. Its failure is retained; the corrected scan ignores
only comments and leaves the prover input unchanged.

`CAPTURE.json` binds the archived inputs, drivers, rankings, raw logs, terminal
receipts, partial certificate and verification script. `READBACK.json` records
the complete ZIP member/hash readback. The preceding checkpoint retains the
control run used for the first comparison. Neither this checkpoint nor the
existing structural properties closes the main origin, multi-epoch secrecy,
implementation-equivalence, device, power-loss or release obligations.
