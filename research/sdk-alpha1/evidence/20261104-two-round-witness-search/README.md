# Bounded two-round witness search

This is an unsuccessful research search, not a new proof or a counterexample.
The original `two_rounds_recover_with_exposed_ancestor_is_executable` query
remains incomplete. The retained jointly checked main-secrecy certificate and
its 24 reusable dependencies are unchanged.

The experiment starts from certificate SHA-256
`dde5d06a071b1560da0d4c28c3f1fd81a3c39708f9fd8564ee391ddc362bcf7f`.
It allows the selected witness to use two later, independently checked invariants:
`local_phase_event_is_unique_per_role_epoch_and_phase` and
`no_strictly_ordered_duplicate_local_phase`. The earlier parent-origin exclusion
remains. This tests whether those invariants resolve the repeated-phase ambiguity
in the original two-round trace.

All operational rules and all 40 query formulas and modes are unchanged. Only
the selected witness's two `hide_lemma` attributes change. The isolated search
copy retains all 24 reusable proofs, while replacing the other 15 nonreusable
proof bodies with `sorry` to avoid replaying unrelated proof trees during this
exploration. Their propositions remain present. The canonical certificate was
not edited, and this projected copy is not a replacement acceptance certificate.

The search uses Tamarin 1.12.0 and Maude 3.5.1 with one worker, a 12-GiB RTS heap,
`-c30`, 60-second derivation checks, `--quit-on-warning` and the unchanged
900-second process limit. Search depth 256 targets a complete two-round witness;
the earlier depth 16 belonged to continuation of a partial universal proof.
This changes the recorded exploration depth, not its wall-time or heap budget.

At 23:05:05 UTC, Tamarin exited **251** after **880.886 seconds**. Its stderr
explicitly reports heap exhaustion at 12,884,901,888 bytes. Stdout is empty and no
output certificate was produced. The conditional independent replay therefore
did not run. No limit was increased and no automatic retry occurred. RTS residency
and managed-memory statistics remain in the original stderr; they are not
whole-process peak RSS or evidence of a faulty model.

`CAPTURE.zip` contains the exact original and selected inputs, driver/checker
sources, limits, start/terminal records and complete streams. All 17 members
were reread byte-for-byte. The prover/tool hashes and the canonical input archive
were checked again after failure. Its SHA-256 is
`c22ce6fc7185e3c5ab2d2d760cf2247fba4b3693e59b2dc1d1e5354050853278`
(128,723 bytes).

The [successful joint main replay](../20261104-multi-epoch-replay/README.md)
retains its original scope. This new observation rules out treating this bounded
automatic strategy as a completed witness. A subsequent attempt needs more
specific rule/goal alignment or a separately justified search method, while
preserving the same original statement and disclosure conditions.
