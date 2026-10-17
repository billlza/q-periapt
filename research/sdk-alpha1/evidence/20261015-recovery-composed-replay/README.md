# Complete shared-storage certificate composition

Source: `72587c2a867b9b9e9aa06e3fe25d8016e2b18b2d`.
Pinned Tamarin 1.12.0 and Maude 3.5.1, on Apple Silicon macOS.
The actual `continuity_recovery_proof.main` shared-storage profile passes all
20 original universal properties and both original witnesses. Independent
readback rechecks every generated input, complete verdict inventory, checked
output and dependency edge. This remains a single-exchange symbolic result;
multi-epoch secrecy, computational security and SDK refinement are not proved.

## Failure and resource observations

At predecessor `e860b55e`, both the
[push run](https://github.com/billlza/q-periapt/actions/runs/38800600903) and
[PR run](https://github.com/billlza/q-periapt/actions/runs/38800623985) pass the
independent and key-scoped profiles, then time out in the shared-storage positive
group at 900 seconds. Artifacts `12007025915` and `12006697888` were downloaded
and checked against their GitHub API digests. Their terminal receipts and the
failed whole-group input are retained here.

The historical local whole-group replay completed in about 856 seconds and
reported 11,623,932,144 bytes of maximum GHC residency. A separate `-A64m`
allocation experiment still timed out without a verdict or certificate; it is
retained and was not adopted. These runs are not a controlled timing comparison.

In the accepted production composition, the positive group takes 746.07 seconds;
the complete profile, including both witnesses, takes 847.00 seconds. The longest
property takes 117.52 seconds. Across the twenty property processes, the largest
reported GHC residency is 2,706,188,488 bytes (about 2.52 GiB). This is GHC live-heap
residency, not whole-process peak RSS or SDK memory consumption. Linux CI still
needs to establish the new path's actual resource behavior.

## Why the conjunction is complete

Tamarin's pinned [prover implementation](https://github.com/tamarin-prover/tamarin-prover/blob/82780bbaf3328a45f624ddb41e51bf75425f851c/lib/theory/src/Prover.hs#L147)
checks the stored proof bodies while closing a theory. Its
[reuse handling](https://github.com/tamarin-prover/tamarin-prover/blob/82780bbaf3328a45f624ddb41e51bf75425f851c/lib/theory/src/Prover.hs#L279)
admits formulas from earlier reuse declarations without inspecting their proof
status. Consequently, checking one body alone is conditional and cannot qualify
the original conjunction.

The composition retains the exact pinned operational prefix, every complete
declaration and its attributes, and each selected original proof body. Other
bodies are explicitly incomplete. Dependency order comes from that pinned source,
not from the catalog's property-list ordering. Every original universal property
is independently checked, including properties that are not reuse premises.
The checker reconstructs every earlier reuse dependency and admits a node only
after those dependencies have verified. There are no global source lemmas in
this certificate; that feature is explicitly rejected by this composition.
Induction over the resulting acyclic graph establishes the same twenty-property
conjunction. No new restriction, axiom, protocol round bound or query is added.

The experimental conjunction and the actual production entrypoint both pass.
Independent production-checker readback also passes. Controls remove the first
helper or main theorem, make a helper incomplete, substitute another source, or
introduce a cycle; every control is rejected. The production input generator's
twenty fingerprints match the executed experimental inputs exactly. The existing
sibling-wrapping attack (85 steps) and shared-owner execution witness (168 steps)
remain separate complete-certificate checks.

Each process retains its 900-second deadline, 4 MiB stream/certificate bounds,
one thread and the prior heap ceiling. Shared-storage now uses 22 processes;
the existing 50-minute CI step bounds their aggregate. The positive group no
longer shares one 900-second process budget. Every process must pass; there is
no retry, omitted property, suppressed warning or automatic proof search.

The standalone source checkout passes 211 related tests and the SDK source gate.
`CAPTURE.zip` contains 375 members, expands to 7,842,992 bytes, and has SHA-256
`50db0f27ea79cf9de6ba86833f8450a1619fa2f6c3e512e120d0c2ddce68f77c`.
All members were read back and rehashed. `CAPTURE.json` identifies commands,
sources, experimental/production outputs and remaining qualifications. No private
SDK/device cohort was reopened or included. Hosted verification and the complete
0.2.0 release obligations remain open.
