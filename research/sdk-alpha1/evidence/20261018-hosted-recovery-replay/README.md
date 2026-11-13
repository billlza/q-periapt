# Hosted recovery certificate replay

The [Tamarin job](https://github.com/billlza/q-periapt/actions/runs/39115804790/job/117641228507)
at `714217739d642b7f78ea1d15abc523491a4133f1` completes all three reviewed recovery
profiles on Linux. Independent readback checks the exact model/certificate pins,
checker identities, every command and terminal inventory, checked-output hashes
and the complete shared-storage dependency graph. No local prover rerun is used.

| Profile | Universal properties | Executable witnesses | Positive replay |
| --- | ---: | ---: | --- |
| Independent identities | 20 | 3 | Complete certificate |
| Key-scoped identity sharing | 20 | 2 | Complete certificate |
| Shared storage ownership | 20 | 2 | 20 acyclic conditional proof nodes |

The shared-storage nodes each retain all original theorem declarations while
replaying one proof. Other proof bodies remain explicitly unfinished in that
individual node. Acceptance requires every original universal property and all
reuse dependencies to be discharged in source order; the retained composition
checker rejects missing nodes, altered declarations, cycles and global source
lemmas. A single node is not treated as the complete conjunction.

The seven witnesses include the original retained-randomness and later-storage
exposure cases, cross-role identity disclosure, sibling wrapping-key exposure,
and executable recovery under the stated profile assumptions. These are symbolic
witnesses under ideal primitives. The results do not extend to arbitrary shared
journal snapshots, unbounded multi-epoch recovery, computational security or
correspondence with the complete SDK. The canonical broader recovery argument
remains a release requirement.

`CAPTURE.zip` is the exact 528,063-byte GitHub artifact, ID `12133106525`, with
159 members. `CHECKS.json` records its SHA-256, each verified inventory and the
local reader hash. Reproduction uses a checkout containing the pinned model and
prior certificate archives: copy the capture to
`target/ci-714-01/recovery-proof.zip`, place `review-recovery.py` in that directory,
and invoke it with the repository Python bootstrap. The reader checks the
recorded hosted output without starting Tamarin; it writes a fresh
`RECOVERY_READBACK.json` and refuses to replace one.

The hosted UTF-8 certificate path now has completed execution evidence. The
parent CI run retains separate source-inventory, strict-C11 caller and Android
emulator failures. Those outcomes are preserved and handled separately; full
CI and 0.2.0 release admission remain pending.
