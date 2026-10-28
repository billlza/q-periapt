# Actual wire producers and stored parent origins

The generation-secret origin theorem remains **analysis incomplete**. Sixteen
of its eighteen knowledge-source cases now close. This adds `Final_Commit_8`
and `Receipt_Commit_0` to the fourteen cases in the
[parent checkpoint](../20261028-storage-revision-payload/README.md).
`Response_Commit_6` has one open leaf; `Snapshot_case_5` has 36. The main
multi-epoch secrecy theorem, recovery reachability and implementation
correspondence remain open.

The final entry in `CAPTURE.zip` is
`experiments/p0-origin-restored-replay-712/restored-origin-proof.spthy`.
Its SHA-256 is
`121d2751b4fc076aa5b84138d7c20afc0b7867cab98c34dad37c0e2315a1948e`.
All 29 formulas, quantifier modes and attributes match the parent. The
operational prefix, including its final newline, remains byte-identical:
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

## Construction and independent check

The first diagnostic captured 29 actual goals from the parent's 32 open
leaves. A no-search replay then checked 18 projection-chain steps and eleven
phase-producer steps. It retained the existing closed sources and produced a
223-step partial tree. The new phase subtrees expose where stored parents and
outgoing tags originate; they do not by themselves establish secrecy.

Generic optional-tag shape splits duplicated work for the three remaining
wire sources. A focused diagnostic instead followed their actual Final,
Receipt and Response phase producers using previously recorded premises. The
full stored-payload subtree remained preserved in the checked 223-step parent;
the diagnostic retained that obligation explicitly open. No source case,
statement or attacker capability was removed.

The subsequent directed searches first applied the observed signed-wire shape
goals, then ranked only a unique actual knowledge-chain goal. They retained
every callback, input and selected index. Their 26 and 17 callbacks selected
22 and 15 chain steps respectively, within the unchanged 32-call ceiling.
Recorded public-role disjunctions and a Wrap premise resolved role frontiers.
The actual Response encapsulation-producer premise was then selected from its
remaining recorded goal.

Before the final check, the complete 36-leaf stored-payload subtree was restored
byte-for-byte. Independent replay, without search or an oracle, checked the
resulting 256-step partial tree in 316.206 seconds. The fourteen auxiliary
all-trace lemmas and 414-step initial-traffic witness remained verified. There
were no invalid proof steps. Tamarin exited 0; the driver exited 1 with
`accepted: false`, because the main origin theorem remains incomplete.

## Retained preparation failure

The initial merge preparer expected four open leaves from four empty oracle
rankings. The output actually retained twelve leaves: four recorded stops and
eight unvisited siblings after `--stop-on-trace=SORRY`. Its assertion stopped
preparation before creating a replay stage. A following launch therefore found
no script; it did not start another prover.

The corrected preparation matched only the exact oracle-stop annotations to
the recorded inputs and preserved all eight other leaves. The failed preparer
and its diagnostic receipt are archived. This was a local bookkeeping error,
not a CI failure, protocol counterexample or accepted incomplete branch.

## Remaining work and limits

The next diagnostic should first inspect the Response source's single remaining
leaf. For that diagnostic, retain the stored-payload obligation explicitly
open and preserve its full subtree for reassembly. The deepest current open
prefix is nine steps, leaving a bound of seven within total depth sixteen.
The 36 stored-payload leaves can subsequently be inspected in bounded producer
groups, while retaining all eleven Stored producers and restoring all checked
subtrees before final replay. Do not silently increase the 32-callback limit.

`CAPTURE.json` records all six experiments and their resource limits.
`READBACK.json` verifies all 226 archive members byte-for-byte. The archive is
467,674 bytes, with SHA-256
`60ec078cf090c36e96c54d73761768ab03f04f59c91025a82ed1cccf320cf188`.
Every prover ran sequentially with 900 seconds, 12 GiB, one runtime capability,
the 60-second derivation check and strict warning handling. Search prefix/bound
pairs were 5/11, 3/13, 4/12 and 9/7.

Check the final entry with the pinned Tamarin 1.12.0 and Maude 3.5.1 binaries,
without `--prove` or an oracle, using `--derivcheck-timeout=60 --quit-on-warning`
and `+RTS -N1 -M12G -c100`. Archived launchers contain original local paths;
adapting those paths must preserve model, tool and resource identities.

The historical non-reuse `initial_epoch_counter_is_zero` query remains the
documented obsolete conjecture, not an assumption. Earlier timeouts and partial
trees remain retained in their parent captures. This checkpoint establishes no
device, performance, ABI, installed-interoperability or release qualification.
