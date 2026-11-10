# Tagged parent recovery checkpoint

This checkpoint proves one structural property of the corrected initial-traffic
projection. A `ReadyState` parent is either the genesis transcript hash at the
initial encoded epoch, or a completed-epoch transcript hash at a successor
epoch. The proof uses no reused lemma. Search and independent replay both verify
`ready_parent_has_tagged_epoch_origin` in 12 steps with pinned Tamarin 1.12.0 and
Maude 3.5.1; independent replay took 38.269 seconds.

The operational rules and restrictions are byte-identical to the preceding
[initial-traffic model](../20261027-recovery-initial-traffic/README.md). All 26
baseline query formulas and their trace quantifiers remain present. The new
property makes 27 queries. The isolated search/replay files leave the other
queries explicitly unproved; they do not import the old zero-counter property.
This is a structural lemma, not a secrecy theorem or computational reduction.

The main generation-secret origin obligation remains open. A diagnostic search
with the original ten helpers and the new independently verified property
rechecked all eleven helpers, then returned an incomplete 47-step origin proof.
Its first depth-bound frontier repeatedly unfolded transitions that preserve a
`SendState`. A second run used the identical model and changed only goal order,
preferring positioned protocol states before another send-state producer.
It reached the existing 900-second deadline, exited after SIGINT with code -2,
and produced no proof certificate. Its driver returned failure.

All 12 oracle inputs and returned rankings were recovered from the actual prover
log and matched their captured hashes, byte counts and complete goal inventories.
The last input contained 901,115 characters. It still included `Peers(s,p,p)`,
although the existing rules produce only the distinct A/B and B/A role pairs.
The oracle selected a much larger `Final7` state obligation before that cheap
source contradiction. This identifies avoidable work in one branch; it does not
prove the other branches. Inspecting simple authority constraints before further
history expansion is a candidate next step, not an established successful tactic.

Both origin attempts retain the original depth limit 16, 900-second deadline,
12 GiB heap limit and single runtime thread. The oracle retains every ordinary
goal and has bounded input, callback and capture sizes. No transition, adversary
capability, query or stopping limit was weakened. The timeout, incomplete proof,
raw oracle log and resource statistics remain in `CAPTURE.zip`.

`CAPTURE.json` binds every archived member. `READBACK.json` records the complete
member/hash readback. To replay only the new property, extract
`experiments/p0-ready-parent-tags-700-replay/model.spthy` and run the pinned prover
with an explicit Maude path, `--derivcheck-timeout=60 --quit-on-warning`, and
`+RTS -N1 -M12G -s -RTS`, without `--prove` or an oracle. Require the new lemma to
be `verified`; do not treat the other unproved queries as successful.

This checkpoint does not establish the main generation-origin theorem,
multi-epoch application-message secrecy, nonce uniqueness, implementation
equivalence, physical-device behavior, power-loss safety or release readiness.
It changes no SDK runtime source.
