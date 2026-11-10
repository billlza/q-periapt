# First responder Ready event invariant

Source: `4a248e55611b9cfa87bc0b7d8f35ce4f4b9b57c6`.
Pinned Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS.
The isolated phase-state representation has a complete 285-step proof of
`first_responder_ready_event_is_unique`: for a session, role B has at most one
`ReadyState` event at epoch `succ('zero')`, regardless of root and parent values.
Independent execution replays the unchanged certificate without search. A second
no-search replay checks the same helper under the full wire-observation model.
Both replays verify all 285 steps.

This is a structural invariant. It does not establish uniqueness at every epoch,
counter or nonce uniqueness, two-round executability, recovery secrecy,
computational security, or correspondence with the SDK. The canonical protocol
model and SDK runtime are unchanged. The broader recovery obligations remain open.

The representation replaces ten linear phase fact tags with one `PhaseState`
fact. Two fresh private labels are introduced at Setup and propagated along the
two phase lineages. Each of the eleven phase transitions consumes and produces
exactly one phase fact with the same label, session and role. An explicit inverse
decodes the phase tag and payload. Parsed AST comparisons preserve every original
rule premise, action, conclusion, annotation, equation, restriction and complete
query. The original nine queries remain in the ten-query helper certificate.
The wire extension retains its fifteen queries and adds the checked helper as a
sixteenth query; acceptance requires the helper itself to verify.

Projection erases the private label and its Setup freshness premises. The
corresponding original trace can retain the unused fresh resources. Conversely,
any finite original trace can assign new labels at Setup and propagate them along
the linear phase occurrences. No label enters messages, cryptographic terms,
observations, restrictions or original queries. No phase join, fork or comparison
of labels is introduced. This argument applies to arbitrary finite trace lengths;
there is no protocol-round bound. These correspondence conditions are checked
structurally with seventeen mutation controls. **The trace-equivalence argument
is not itself a machine-checked meta-theorem.** Transferring the invariant to the
original representation relies on that stated argument as well as the checked
encoded-model certificate.

The pinned prover's rule view reports `PhaseState(id,=,=,≤,.,(.,.,.))`. This
recognition helps proof search but is not the proof. The custom oracle only ranks
the existing goals. Its 284 recorded callbacks are checked as complete
permutations and matched to prover inputs by hash and ranking multiset. It does
not remove goals, change protocol behavior or supply an axiom.

Six further certificate mutations are rejected, including altered equations,
missing original queries and an added reusable premise. A real control removes
the helper proof body: Tamarin exits zero, but reports the helper incomplete and
the acceptance check rejects it. Certificate comparison excludes proof bodies
only in memory; normalized comparison text is never executed as a proof. The
actual unchanged scripts are checked by the independent prover executions.

The capture preserves failed searches and preparation errors. Earlier searches
exhausted their heap or time bound. Parse-only output initially introduced typed
printer metadata that was unsuitable as a fresh input prelude; the final encoder
retains the original prelude. The first certificate comparison incorrectly
treated proof scripts and printer metadata as model declarations. Replay started
despite that failed comparison because its shell lacked `set -e`; it was not
qualified until the corrected, mutation-tested model comparison passed. The
separate peer-guard variant is retained as unused diagnostic work and is not part
of either successful certificate. No failed experiment is counted as evidence of
secrecy or as a counterexample to it.

`CAPTURE.zip` contains 181 members and expands to 20,661,836 bytes. SHA-256:
`c750a3ea4635b695b3a0b62df8924807c4f46c1156f5db937d04c1148724cf25`.
`CAPTURE.json` records every member hash. A separate readback process checks all
members and binds the three terminal certificates to their recorded outputs.
It does not repeat prover execution. The archive contains symbolic research
inputs and diagnostics, with no private SDK or device state.

To reproduce the independent prover check, extract the archive and use the pinned
tools on `experiments/phase-order-search-242-proof.spthy`, passing
`--with-maude=<pinned-maude> --heuristic=i --verbose --derivcheck-timeout=60
--quit-on-warning --output=<fresh-output> +RTS -N1 -M6G -c100 -s -RTS`.
Do not pass `--prove`. Require the complete ten-query inventory and the helper's
`verified (285 steps)` result; exit zero alone is insufficient. For the wire
extension, replay `experiments/phase-wire-witness-254.spthy` and require its
complete sixteen-query inventory plus the same helper result. Other incomplete
queries remain incomplete. Re-running the archived correspondence scripts also
requires the recorded repository source and their documented input layout.

This checkpoint has local replay evidence only. Hosted replay and the full
0.2.0 release requirements are not qualified by it.
