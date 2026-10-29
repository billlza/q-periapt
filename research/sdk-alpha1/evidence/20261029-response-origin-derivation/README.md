The direct published-response source of the generation-secret origin lemma is
closed in the current, complete replay. The origin lemma still has 40 open
snapshot leaves. The main multi-epoch secrecy theorem and implementation
correspondence remain incomplete.

This capsule continues the valid 720 proof from
[phase-root observations](../20261029-phase-root-observations/README.md).
Its protocol rules, equations, restrictions and all 34 query formulas are
unchanged. No new assumption or lemma was added. All 18 already established
all-trace auxiliary results and the 414-step initial-traffic witness replayed
successfully.

The response proof follows the actual current deduction goals. It projects the
public response fields, uses the existing wire-constructor result for the parent,
resolves the responder role through the existing signer source, and follows
`Response4` back to the original reservation. That reservation exposes the
fresh encapsulation-coins event needed by the previously proved separation from
generation secrets. Each manual `solve` names a method captured from that exact
proof context.

The retained sequence is:

| Execution | Purpose | Result |
| --- | --- | --- |
| response capture | Read the current source obligation without selecting a method | Two diagnostic contexts; snapshot subtree retained separately |
| response guided | Follow current projections and existing constructor facts | Eleven callbacks; nine selected methods; two diagnostic stops |
| tail capture | Resolve the captured signer-role premise and read the remaining tails | Three diagnostic contexts |
| full replay | Restore all snapshot branches and check the complete tree | 374 steps; two response leaves and 40 snapshot leaves |
| payload guided | Trace the remaining response payload to its original reservation | Seven callbacks; five selected methods; two diagnostic stops |
| final replay | Resolve the exact post-reservation edge and restore the complete tree | 382 steps; zero invalid steps; only 40 snapshot leaves remain |

During focused diagnostics the unselected snapshot subtree was represented by
one honest hole and retained byte for byte. Those intermediate counts are not
whole-proof frontiers. Both full replays restore the entire original snapshot
subtree, and the final comparison checks its exact bytes. The final replay
contains 17 closed top-level sources out of 18; the remaining source is
`Snapshot_case_5`.

All six prover processes returned zero without timeout or warning admission;
the strict drivers returned one because the selected origin lemma remains
incomplete. The guided searches used remaining depths 12 and 8 under a total
search-depth bound of 16, at most 32 oracle calls, one prover, a 900-second limit,
12 GiB heap and one runtime worker. The final replay performed no new search.

The capsule retains the original valid 720 tree, all six inputs and outputs,
bounded drivers, oracle inputs and choices, terminal receipts, preparers, and
the complete remaining frontier. Its 116 files were read back byte for byte.
`CAPTURE.json` records every member size and SHA-256; `READBACK.json` records
the independent archive readback.

- Final proof SHA-256:
  `f7910208a18aaf438e82eb2a2e37812f49322534252a47eae6a54c80b3d56e0b`.
- Capture SHA-256:
  `d40c0e0035c97a84700d9076f9b3af8b13b25b99434c38d69286b8c892497255`.
- Capture size: 461,012 bytes.

The older 382-step, 42-leaf baseline and the
[719 invalid-step correction](../20261029-wire-payload-shapes/README.md)
remain separate evidence. Equal step counts do not identify equal proofs, and
changes in open-leaf counts are not a security score. This result does not
establish full origin secrecy, multi-epoch PCS, physical-device recovery,
power-loss behavior, or release qualification.
