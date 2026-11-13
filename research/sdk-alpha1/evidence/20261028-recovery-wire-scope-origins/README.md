# Reservation and signed-wire origins

An independent, no-search replay checks three structural obligations in the
initial-traffic model:

- `reservations_inherit_locally_confirmed_root`: every recorded reservation
  inherits the root and parent of an earlier local Ready event at the preceding
  epoch, in 14 steps.
- `generation_and_session_identifiers_are_distinct`: a freshly generated KEM
  secret cannot also be a Setup session identifier, in one step.
- `signed_wire_scope_has_session_and_parent_origin`: every emitted protocol
  packet has a prior Setup event and one of the two signed-envelope shapes,
  binding its session, role, predecessor/current epochs and a hash-constructed
  parent, in 47 steps.

The first obligation already existed, unproved, in this model. The other two
are additional derived lemmas. All 27 preceding queries, their attributes and
the complete operational prefix are unchanged. No observation, rule, restriction,
secrecy assumption or SDK code change is introduced. The final model has 29
queries. These properties do not establish authentication of adversarial input
or secrecy of the message contents.

The first signed-envelope formula was rejected by the guardedness check before
search: existential variables were shared outside a disjunction of shapes.
Distributing those binders into their respective branches makes the logically
equivalent formula guarded. The rejected input and warning remain in the capture;
`--quit-on-warning` remains enabled.

The default smart heuristic then produces a 99-step incomplete proof. It keeps
expanding the unchanged SendState output of Final_Commit instead of establishing
the packet's session and phase origin. Prioritizing the direct Setup bindings
closes every session-origin branch, but spends the depth budget on repeated
bindings before reaching the Ready parent; that 33-step partial certificate is
also retained. Prioritizing the positioned phase before those static bindings
completes the same formula in 47 steps. Every offered goal remains in every
ordinary oracle ranking; all 53 callbacks across the two comparisons were checked,
with no diagnostic stops.

Each search starts at the new helper's root, with the unchanged depth cutoff of
16, 900-second deadline, 12 GiB heap limit and one worker. No depth-limited leaf
is resumed with a fresh budget. The final search takes 313.039 seconds; the
independent replay takes 298.715 seconds. Those times include checking the
existing certificates and do not measure complete recovery-secrecy performance.

The final replay verifies 14 all-trace lemmas and the existing 414-step
initial-traffic witness. The generation-origin conjecture remains the identical
197-step incomplete certificate with its four closed source cases and all
unproved nodes. The new lemmas are appended after it and have not yet been used
to discharge that conjecture. Moving the relevant proved dependencies before
the origin query and checking the resulting proof is a subsequent obligation.
The multi-epoch secrecy theorem, SDK correspondence and release gates remain open.

`CAPTURE.json` binds all six experiments, rejected inputs, partial certificates,
drivers, complete oracle records, replay and verification script in `CAPTURE.zip`.
`READBACK.json` verifies every member against its captured source bytes. The final
independent certificate has SHA-256
`6050a834043bf8ec765712973042be2432847ea751960a2afac9ea312a81cef2`.
