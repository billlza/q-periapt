# Retry readiness under a fixed opportunity budget

This packet supports the manuscript's native scheduling ablation. [Run 42551086845](https://github.com/billlza/q-periapt/actions/runs/42551086845), job 128946601334, executed research head `29f1c362b67bcd06123ea1bef847af82e9f9e100` through checkout `23f600f5b3ef69d9f0196efdaa66d146e271c9a4`. Preparation fixes protocol source `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. The source comparison covers 2,687 files, with two experiment modules added only to the native test file. Both exact tests use one freshly built, hash-bound executable.

The experiment contains 28 native executions: fourteen fresh immediate-policy baseline runs and fourteen runs with minimum application-retry age four. Each uses the same 2,048 directed opportunities, one 32-byte offered request per opportunity, 8,192-byte frame cap, send budget 32 or 64, capture cut and one of seven transport schedules. All fourteen fresh baseline rows reproduce their retained counterpart in the original 49-case comparison.

## Intervention and observed result

Each sender increments a public counter on its designated opportunity before local control planning. Every first application emission and application retry records that counter. A request becomes retry-ready once at least four of that sender's opportunity increments separate the current counter from its last emission. The existing fair cyclic arbitration selects the oldest eligible unacknowledged request. Control planning, cumulative ACK handling, first-application admission, ciphertext resumption and the other arbitration rules retain their code. The policy uses the sender's ACK state. Independently observed delivery history classifies the cost after execution.

All twelve bidirectional or resumed budget/schedule pairs deliver more applications, with increases of 16.84% to 43.39%. Alternating delivery changes from 688 to 971 at budget 32 and from 718 to 999 at budget 64. The derived counts stay 63 and 127, with post-capture denominators 970 and 998. Retries after prior logical delivery change from 592/572 to zero. All emitted frame bytes remain in the cost accounting: bytes per delivery fall by 11.41%/19.70% for these alternating runs, while budget-32 loss and reordering increase that ratio by 14.37% and 3.94%. Their service still increases.

Both age-four lossy runs and the budget-64 asymmetric run retain one committed application without a logical delivery at the end of the observation. The offline-prefix derived counts increase by one while the delivered service also grows. One-way service remains 32/64 applications in epoch zero; substituting one control frame for one application retry adds 4,605 bytes in each case. The retained full rows expose these counts and denominators directly.

These are service and work measurements per fixed directed-opportunity budget. The combined elapsed experiment time belongs to the execution receipt. The paper's comparison uses completed applications, full frame bytes and real journal counters.

## Bound evidence

`source_identity.json` binds the local packet to its original paths and hashes. Gzip streams use a deterministic header and preserve the exact original bytes after decompression.

- `sources/retry-age-report.json.gz` is the original 206,192-byte executed report, SHA-256 `7771c25ad23271fa2676b81dfe53b1ecfc3ec1ec2301893d4eb914fb56c738ee` after decompression.
- `sources/independent-audit.json` recounts all 28 public traces and verifies all 29 public-evidence manifest entries, including the report. It independently reconstructs retry ages, post-delivery retries, emitted bytes, first commitments, logical deliveries, derived counts and durability work.
- `sources/reviewed-analysis.json`, `.csv` and `reviewed-results.md` retain all fourteen paired rows, their raw counts, ratios, residual committed work and independent conclusions.
- `sources/provenance-review.json` binds the hosted run, actual checkout and parents, protocol source, source derivative, two passing exact native tests and fourteen source/readiness controls. It verifies all 42 members of archive 13650034930 against their extracted bytes. The complete archive is 12,213,618 bytes with SHA-256 `59866ec99686b1068f016ebefc0476802e8102d890bc4a1e8cce6630b9d9d3a1`.
- The remaining source snapshots and receipts identify the original driver, runner, workflow, executable and controls. The original audit and summarizer source snapshots retain the identities named by their historical receipts.

## Recompute the manuscript projection

From the repository root:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/retry-readiness/analyze_retry.py --check
```

Without `--check`, the same command regenerates `analysis.json` and `paper/continuity/retry-readiness-table.tex`. The generator reads fixed, hash-pinned packet names and the unchanged retained `results-49.json`. It verifies the full policy/profile/schedule inventory and crosses the original report with the independent trace recount and reviewed paired projection. The generated table displays all seven schedules; the complete fourteen paired rows remain in the packet.

For a complete public-trace recount, obtain the hash-identified archive and extract `continuity-retry-age-execution`. Copy `sources/audit_retry_ablation.py.txt` to an audit work directory as `audit_retry_ablation.py`, with the current `artifacts/matched-comparison/audit_matched_traces.py` beside it. Run the former with the extracted execution directory, retained `artifacts/matched-comparison/sources/results-49.json` and a new output JSON. The metric and detail objects can then be compared with the retained audit. A fresh audit records the current checker-source hashes; the historical receipt keeps its original checker identity.

The native execution performs key agreement, the positive and altered-seed AEAD checks, and journal operations. The independent audit recounts public observations and checks source and execution identities. The packet's projection operates on those executed and reviewed inputs.
