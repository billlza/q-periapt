# Private phase-position uniqueness

Source: `302363aecd2a115e2065a86b9f0ad0ad4b8b7be8`.
Pinned Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS.

`phase_position_event_is_unique` has a 29-step induction proof: for any private
phase owner and any step term, two `PhaseStepMarker` observations with that owner
and step occur at the same event. Session, role, epoch and phase fields need not
be equal in the premise. The proof has no earlier reusable lemma. A separate
execution replays the actual certificate without search. A further combined
replay verifies this helper and the existing 285-step first-responder Ready
helper together. Complete model comparisons retain all 19 query declarations,
rule premises, actions, conclusions, annotations, equations and restrictions.

This step counts internal phase transitions. It is **not an application counter
or protocol epoch**. The result does not establish nonce uniqueness, arbitrary
epoch uniqueness, two-round executability, recovery secrecy, computational
security or SDK correspondence. Other query results remain explicitly incomplete.
The canonical protocol model and product runtime are unchanged.

The extension builds on the [private phase-owner representation](../20261016-recovery-ready-invariant/README.md).
Setup creates a linear `PhasePosition(owner,zero)` for each fresh private owner.
Each of the eleven phase transitions consumes one position and produces its
successor, while emitting the matching marker. There is no step test, bound,
reset, fork, join or network disclosure. Erasing these facts and actions restores
the previous rules and all 17 complete queries. Conversely, any finite trace can
assign the number of transitions taken by each owner. Eight mutation controls
check these conditions. This projection/lifting argument applies to arbitrary
finite trace lengths, but **is not a machine-checked equivalence meta-theorem**.

An additional existential query retains the complete previous witness and adds
19 concrete phase-position observations for its two-round schedule. A separate
check derives those positions from the actual rules and rejects 19 off-by-one
mutations. These anchors constrain only that existential query, not protocol
execution or the universal uniqueness lemma. The new helper brings the complete
query inventory from 18 to 19.

The search oracle only orders existing goals. All 15 captured callbacks match
the recorded input hashes and complete output permutations. The comparison
checks reject missing position premises, weakened helper formulas and missing
original secrecy queries. An actual dependency control inserts an unproved
reusable copy: Tamarin reports the conditional target verified in three steps,
but its prerequisite incomplete. Acceptance correctly rejects the run despite
exit status zero. Normalized comparison text is never used as a prover input.

Failed witness searches and the 300-second built-in-ranking timeout remain in
the archive. A correction records stale wording in one observer report without
rewriting its original bytes. None of these timeouts is a security counterexample.
The subsequent composed witness search is excluded from this checkpoint and is
not counted as a proved result.

`CAPTURE.zip` contains 613 members, expanding to 24,882,609 bytes. SHA-256:
`d54cbaad482f716f5dad6572dd823b58c0189244af115569ef3cff924ac527d3`.
`CAPTURE.json` records each member hash. A separate readback verifies every member,
the three successful terminal/certificate pairs and the rejected dependency
control. It does not repeat prover execution. The archive contains symbolic
research inputs and diagnostics, with no private SDK or device state.

To reproduce the independent proof, extract the archive and invoke the pinned
prover on `experiments/position-induction-search-282-proof.spthy`, passing
`--with-maude=<pinned-maude> --heuristic=i --derivcheck-timeout=60
--quit-on-warning --output=<fresh-output> +RTS -N1 -M6G -c100 -s -RTS`.
Do not pass `--prove`. Require all 19 query results and the helper's
`verified (29 steps)` result. To reproduce the composition, replay
`experiments/position-composed-285.spthy` and require both the 29-step position
helper and the 285-step Ready helper. Exit status zero alone is insufficient.
The other incomplete queries remain incomplete. The archived comparison scripts
also require the recorded repository source and input layout; the base
representation checkpoint retains its earlier evidence separately.

This checkpoint qualifies local structural proofs only. Hosted replay, recovery
secrecy and the full 0.2.0 release requirements remain open.
