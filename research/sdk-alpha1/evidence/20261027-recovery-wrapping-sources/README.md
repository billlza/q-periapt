# Wrapping-key source analysis

This checkpoint independently replays a **197-step incomplete** generation-secret
origin proof. Four of its eighteen top-level knowledge-source cases are closed:
the existing `Application_Message` case, both `Cut` cases, and
`Offer_Commit_3_case_2`. The other cases retain explicit unproved nodes. Eleven
auxiliary proofs and the 414-step initial-traffic witness also recheck. This
does not complete the origin conjecture or multi-epoch message secrecy.

The input is the checked [application-source partial
certificate](../20261027-recovery-application-source/README.md). All 27 queries,
their modalities and lemma attributes remain unchanged, as does the complete
operational prefix. The original entropy and phase-capture alternatives remain
part of the conjecture, including exposure of retained state under leaked
wrapping keys. No assumption, rule, threat restriction or SDK runtime change is
introduced.

Tamarin 1.12.0's [batch
loader](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/src/Main/TheoryLoader.hs#L602)
uses [replacement of annotated unproved
nodes](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/lib/theory/src/Theory/Proof.hs#L641).
Its automatic depth bound applies to each replacement subtree. The original
open source cases already have two preceding nodes, so this continuation uses
`--bound=14` to retain the previous total target cutoff of 16. The 900-second,
12 GiB and single-worker limits remain unchanged.

Continuing with the preceding oracle still times out after 17 callbacks,
without an origin certificate. The retained first inputs show that the oracle
expands recursive `Ready` history while three wrapping bindings are unresolved.
The model's only `Wrap` producer is Setup, whose keys come from the direct
`Storage_Key` fresh source; Cut outputs these wrapping keys. The controlled
comparison moves only existing `Wrap` and `StorageKey` goals ahead of recursive
state expansion. Every ordinary ranking still contains every offered goal.

The two runs have identical first two inputs. Their first selected method is
the same; the next selection changes from protocol history to a wrapping
binding. The comparison closes both Cut source cases and the additional Offer
case. It exports the partial certificate in 277.349 seconds, after 128 ordinary
callbacks and twelve explicitly latched callback-budget stops. It also retains
depth-cut and unvisited nodes. The prover exits normally, while the acceptance
driver correctly rejects the incomplete result. The earlier timeout, all 157
oracle exchanges across the two runs, and all stop reasons are preserved.
These are not complete-proof performance measurements.

A separate no-search, no-oracle replay completes in 251.420 seconds. It checks
the same four closed source subtrees and preserves every unproved node; the
normalized main proof is unchanged. Its certificate has SHA-256
`259264abd13b7cc76d9a1d946beeeed7f4cda9f025b510d861e09c809ba9fc80`.
The overall origin status remains **analysis incomplete (197 steps)**, and
the acceptance driver again exits with failure.

Remaining frontiers include scope-parent/session projections and recursive
Ready/receipt history. Several already reach the total depth cutoff of 16.
Continuing each of those with another full fourteen or sixteen levels would
change the resource bound. Further work must inspect those dependencies and
existing shape facts, or establish appropriate auxiliary lemmas, without
discarding cases or weakening the model.

`CAPTURE.json` binds the inputs, drivers, complete oracle histories, partial
certificates, independent replay and verification script in `CAPTURE.zip`.
`READBACK.json` verifies every archive member and hash. The original preparation
mistakenly expected the entire first ranking to stay identical; only its chosen
method stays identical, while the lower-priority wrapping goals move. The
correction and both full rankings are recorded before the comparison ran.
The origin, multi-epoch secrecy, SDK correspondence and full release obligations
remain open.
