# Native successes and remaining old-source prerequisite failures

At 2026-11-05 05:18:37 UTC, the four main-CI job inventories and both unchanged
PR heads were refreshed. The eight other terminal run inventories are identical
to the committed 04:29 snapshot, with explicit readback in `TERMINAL_REUSE.json`
inside the capsule. Across the twelve runs there are now 334 jobs: 295 successes,
22 failures, four running, eleven queued and two skips. A second dependent
coverage join accounts for the additional job; the total is not fixed at 333.

Full log readback establishes these successes on their original sources:

| Hosted job | Actual checkout | Candidate tests | SDK tests | Independent public verification |
| --- | --- | ---: | ---: | --- |
| [PR #117 push Release](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126445737664) | `475cd23923e45819b01b6041c91c44540ec056ec` | 1451 library + 32 other | 31 | Skipped in this matrix row |
| [PR #117 push Debug suite](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126445737915) | `475cd23923e45819b01b6041c91c44540ec056ec` | 1450 library + 32 other; one library case filtered | 31 | Executed and passed |
| [PR #118 merge Release](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/126446853524) | `59bde0fd1a268de4d0e183c33bf3fc5e09c9be97` | 1456 library + 32 other | 31 | Skipped in this matrix row |

The Debug suite's public validators report 20 candidate envelopes, 30 proofs,
nine selections and 100 signature negative controls, plus 57 anchor envelopes,
26 requests and 285 signature negative controls. Both its native and public
artifact uploads succeeded. The two Release native uploads also succeeded.
The separate capacity row is still running; this is not an all-Debug-partitions
pass. These old-source successes do not qualify the newly added local tests,
the corrected artifact ordering or the complete current release candidate.
They do not erase or explain the earlier PR-merge Debug `ENOTFOUND` failure.

[PR #118 merge Swift Release job 126489776973](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/126489776973)
failed on `59bde0fd` in `qualify_c` at the old exact `== 142` server-census
check. This is the sixteenth observed P0 checker failure. The hosted numeric
count is not disclosed, and the log does not establish Swift consumer execution.
Its reported artifact is 13389851439, 47,591,726 bytes, digest
`e46e0502133d04da5715723d906b34914cf6808851b821f9f14d3eea27163c61`.

The [dependent coverage job 127060936059](https://github.com/billlza/q-periapt/actions/runs/41791861104/job/127060936059)
downloaded six artifacts, then rejected the first parsed partition at the
completion/claim predicate. The pinned `59bde0fd` join source is byte-identical
to the earlier `6084f3bf` source and visits Swift Debug first. The log exposes
the compound condition, not its specific failing field. No local artifact
download was used to strengthen that conclusion. This is the second observed
coverage-gate consequence, separately counted from a runtime P0 occurrence.
No coverage report was written; the upload was skipped. The join is unchanged.

`CLASSIFICATION.json` lists all five successful-upload artifact identities and
digests from the logs. None of those archives was downloaded locally.
`CAPTURE.zip` preserves all five complete decoded logs, exact job/step metadata,
the snapshot, pinned join source, terminal-row provenance and classifier output.
All twelve members were reread: 435,539 bytes, SHA-256
`4b8164a5595a44eac0756178e2cd85398c452cdda0ed46f4c417066c3f13ce69`.

The separate `RUN_DISCOVERY.json` re-queries all workflow runs for both exact
current heads. It finds only the same six attempt-one runs per head. Both
PR #118 main-CI runs are now terminal failures; the two PR #117 main-CI runs
remain nonterminal, with live/queued jobs recorded above. Its standalone hash
and readback receipt are in `RUN_DISCOVERY_SHA256.json`. No new run IDs, push,
rerun, cancellation or new workflow were introduced by this readback. The
effective wave remains open, so the next producer/fix wave has not been uploaded.
