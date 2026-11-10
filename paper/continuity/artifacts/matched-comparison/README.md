# Matched directed-opportunity comparison

The manuscript integrates the executed 49-profile/schedule comparison from research revision `fec8472060728cc1bb35cf15042c117dda00e336`. The hosted checkout was synthetic PR merge `0d12e77d0c7c1cfb4760b654947f2838bb05d4ee`; the runner archived protocol checkpoint `358b921ab3469ce49f166633fc9a762ff6ed7e3d` into its isolated execution tree. [Run 42537214047](https://github.com/billlza/q-periapt/actions/runs/42537214047) performed the builds and executions. The source-bound qualification receipt identifies job 128904069349, archive 13641008832, four compiled executables and the original runtime.

## Evidence packet

`sources/matched-report.json.gz` decompresses to the exact 1,563,144-byte original uploaded report, SHA-256 `66d854b5c720a614008bef27593834a395ac41e1766510b28901507f3ba60f6b`. The compressed stream is deterministic and has its own pinned digest. The packet also retains the original 49-row JSON/CSV projection, qualification and public-audit receipts, public manifest, executable/runtime receipts and exact original schedule/validator source snapshots. `source_identity.json` identifies each input.

The original public audit checked all 126 manifest entries, reconstructed 14 native traces and 35 reference traces/snapshot results, and checked 35 reference envelope schedules. Its receipt retains the executed native plaintext and reference private-key AEAD audit boundaries. Those cryptographic operations belong to the hosted execution. The compact packet supports the manuscript projection; the full 152-member archive is identified by SHA-256 `b08e6675c2cb226af28b7bfa40edd888c8b5333a1ae34dd261ec5a9b0cac8d76` and retained with the research delivery.

`audit_matched_traces.py` and `independent-review.json` retain a separate public-trace recount of all 49 rows and 126 manifest hashes. Its additional native analysis distinguishes first successful delivery, duplicate consumption and suspension at each retry. At the alternating cut it counts 592/572 application retransmissions after the request's first logical delivery, occupying 83,472/80,652 emitted bytes. This uses the analyst's observed delivery history; the sender still awaits its ACK. It identifies the measured policy cost without assigning a counterfactual throughput gain.

## Interpretation

All runs use 2,048 directed opportunities and offer one 32-byte request per opportunity. Each opportunity emits at most one frame, capped at 8,192 bytes. Control packets, ACKs and exact retries consume the same budget as new applications. The snapshot cut lies after opportunity 0's checkpoint and before opportunity 1's local computation. Each endpoint is captured in a separate passive experiment. One request has already been committed, giving post-capture denominators 687 and 717 in the native alternating rows.

The native session snapshot supplies the epoch-zero chain seeds and matching session-record wrapping key; its independent identity signer stays separate. The reference harnesses use their session MAC states. Each result is the specified predictor's exact reconstructed set. Native counters cover real journal revisions and `sync_data`; the references return component state and preserve `null` physical counters. The native driver uses fair cyclic control/ACK/retry/application arbitration, with immediate retry eligibility for unacknowledged frames.

The `2b-1` observation is the remaining current-epoch first-allocation capacity at this cut: the two directions have budgets `b`, one allocation precedes capture, and retries preserve their original index. Full use of both directions attains the capacity in the alternating runs. A true one-way schedule commits only `b` requests, remains at epoch zero and exposes all `b-1` later commitments; additional requests remain queued.

## Reproduce the manuscript projection

From the repository root:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/matched-comparison/analyze_matched.py --check
sh artifact/python-run.sh paper/continuity/artifacts/matched-comparison/check_input_controls.py
```

The generator verifies every retained input's fixed digest, reprojects the complete executed report, checks equality with the original audited JSON and CSV, and checks the generated `analysis.json` and manuscript tables. It verifies profile/schedule and capture-owner completeness; admission, exposure and frame partitions; exact post-capture denominators; reference envelope work; and each implementation's persistence boundary. Fourteen directed incorrect-report/JSON controls reject wrong denominators, duplicate identities, uncharged frames, fabricated persistence, omitted envelope bytes and a false one-way recovery label. Both entry points run under the repository's hardened launcher, including from its root working directory. `make check` includes both.

To regenerate after an intentional change to the analysis source, omit `--check`. Changing recorded inputs requires an explicit new source identity and evidence record.

The independent trace recount takes the original unpacked public evidence as an additional input:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/matched-comparison/audit_matched_traces.py \
  /path/to/continuity-matched-execution/evidence \
  paper/continuity/artifacts/matched-comparison/sources/results-49.json \
  /path/to/recomputed-independent-review.json
```

The research driver and complete workload contract remain at [the executed research revision](https://github.com/billlza/q-periapt/tree/fec8472060728cc1bb35cf15042c117dda00e336/research/continuity-matched-comparison). Executing that driver creates a new run with its own source and executable identities; the original receipts remain unchanged.
