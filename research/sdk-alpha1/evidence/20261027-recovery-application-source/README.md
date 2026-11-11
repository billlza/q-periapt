# Checked application-message source case

This checkpoint closes one source case of the generation-secret origin
conjecture. It does **not** complete that conjecture or multi-epoch secrecy.
All 27 query names, modalities, formulas and lemma attributes are preserved
from the [peer-source diagnostic](../20261027-recovery-peer-order/README.md).
The complete operational prefix is byte-identical; no rule, restriction,
adversary capability or assumed lemma has been added. SDK runtime code is
unchanged.

The earlier diagnostic repeatedly expanded protocol history within the
`Application_Message` source case. Read-only inspection reveals an existing
deduction-chain constraint, `(#vr.3, 0) ~~> (#known, 0)`, which is absent from the
oracle's offered methods. Tamarin 1.12.0's
[goal-selection code](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/lib/theory/src/Theory/Constraint/Solver/Goals.hs#L66)
filters some message-variable chains from `openGoals`. Its
[proof-method checker](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/lib/theory/src/Theory/Constraint/Solver/ProofMethod.hs#L254)
can still check an explicitly supplied constraint already present in the system.
The distinction matters: changing an oracle ranking cannot select a goal that
the oracle never receives. This is search guidance within the existing calculus,
not a new cryptographic assumption.

Two no-search, no-oracle replays distinguish the cases. Applying only the
existing A/B role disjunction leaves both children open. Applying that same
disjunction and then the original deduction-chain constraint in each child
closes the entire application-message source subtree. The latter certificate
has SHA-256 `ad82ad10bc84864209cf5019b7c23210ed73859e47c825515dc3e0fd69ef1a27`.
Both replays recheck eleven auxiliary proofs and the 414-step initial-traffic
witness. Both still report the overall origin as **analysis incomplete (23
steps)**, with the other source cases explicitly unproved; the acceptance driver
therefore exits with failure despite the prover's normal process exit.

A separate automatic search changes only the finite-role priority. Its twenty
captured oracle exchanges preserve every offered goal. Even immediately after
the role split, the deferred chain is still absent from the offered set, and
the search again expands phase history. It reaches the existing 900-second
deadline and requires SIGKILL after the five-second SIGINT grace period. It
produces no origin certificate. Role ordering alone has not solved the search
problem, and no overall speed improvement is claimed. The checked partial
certificate is prepared as the next continuation input; that continuation
search has **not** been started in this checkpoint. Depth 16, 12 GiB and one
worker remain unchanged.

The two bounded interactive viewers preserve their inputs and terminate at
their 900-second lifetimes. Those viewer stops are not proof verdicts. The
first 30-second HTTP observation timeout and a deeper view exceeding the
16 MiB read bound remain recorded; the retained DOT graph comes from the
isolated application-source prefix. No proof method was applied through the
interactive interface. An initial local comparison rejected pretty-printer
line wrapping in lemma attributes. The corrected comparison normalizes only
whitespace between unquoted attribute tokens and still checks every attribute,
exact formula and operational-prefix byte; the failed comparison is retained.

`CAPTURE.json` binds the inputs, replay certificates, terminal receipts,
inspection responses, oracle history and verification script in `CAPTURE.zip`.
`READBACK.json` records the archive's complete member/hash verification.
The main origin conjecture, multi-epoch message secrecy, implementation
correspondence, physical-device, power-loss and release obligations remain open.
