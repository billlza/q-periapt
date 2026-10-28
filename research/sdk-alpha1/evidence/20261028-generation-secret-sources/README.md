# Generation-secret source proof checkpoint

The generation-secret origin theorem remains **analysis incomplete**. This
checkpoint closes eight of its eighteen knowledge-source cases; it does not
prove the full origin theorem, multi-epoch message secrecy, or correspondence
to the SDK implementation.

The final entry is
`experiments/p0-origin-signerfile-edges-706/signerfile-edges-replay-proof.spthy`
inside `CAPTURE.zip`. Its SHA-256 is
`55b826b3b83dec744c701a68cc0d2cc3164d29d48bc2dcbc79fc9f0f4560c3db`.
All 29 query formulas, quantifier modes and attributes match the prepared
dependency-composition input. The operational prefix is unchanged, with
SHA-256 `3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.
That digest includes the newline preceding the first lemma declaration.

## What changed

The prior certificate closed `Application_Message`, both `Cut` cases, and
`Offer_Commit_3_case_2`. The current certificate additionally closes
`Reveal_Identity` and all three `Snapshot_Signer_File` cases.

The two previously certified helper lemmas were placed before the origin
theorem without changing their statements. Two bounded search controls then
produced incomplete 218-step trees. Neither closed an additional source case:
the first open wire case exhausted the 128 ordinary oracle callbacks before
later sources received search. Those controls remain in the capture.

The first manual identity-source attempt used two invalid `IdentityKey` goal
addresses. It is retained as a rejected attempt. A diagnostic run captured the
actual pending goals without choosing any search step. The corrected replay
resolved the recorded knowledge edge, and the same method was applied to
signer-file sources. No rule, attacker capability, source case or security
condition was removed.

The final replay used the pinned Tamarin 1.12.0 and Maude 3.5.1 binaries,
without `--prove` or an oracle. It checked the eight closed source subtrees,
14 auxiliary all-trace lemmas, and the existing 414-step initial-traffic
witness. The origin theorem is still a 62-step **incomplete** proof tree.
Proof-step counts describe different partial trees and are not a completion
percentage. The driver therefore exited 1 with `accepted: false`, even though
the prover process exited 0. There are no invalid steps in the final entry.

## Remaining obligations

The ten open sources are `Final_Commit_8`, `Offer_Commit_3_case_1`,
`Receipt_Commit_0`, `Response_Commit_6`, `Reveal_Entropy`, and the five ordinary
`Snapshot` cases. The main multi-epoch secrecy and recovery reachability
obligations remain open. The eight closed sources do not replace those
obligations or any product, device, performance, ABI, or release qualification.

## Reproduction and retained boundaries

`CAPTURE.json` records every member hash, the parent certificate, query and
source boundaries, resource limits, and the precise final entry.
`READBACK.json` records complete archive readback. Inputs, drivers, oracle
frames, terminal records, rejected steps and interrupted work are retained.
Preparation files describe the state at preparation time; terminal records
determine actual outcomes. The diagnostic run interrupted when the goal was
paused is a SIGINT interruption, not a timeout or a successful proof.

Each prover run was limited to 900 seconds, 12 GiB and one runtime capability.
The searches restarted open source cases at depth two with bound fourteen,
for total depth sixteen. Diagnostic captures at depth three used bound
thirteen and selected no proof methods. The new manual source paths have
depth four. No previous depth-sixteen leaf received a fresh depth budget.

For independent checking, replay the final entry with the pinned binaries,
`--derivcheck-timeout=60`, `--quit-on-warning`, and `+RTS -N1 -M12G -c100`.
Do not add `--prove` or infer theorem success from a zero prover exit code.
Inspect the retained partial-tree result and all reuse dependencies. Archived
drivers and launcher paths describe the original local environment; rebinding
an extraction directory must preserve the model, tool and resource identities.
