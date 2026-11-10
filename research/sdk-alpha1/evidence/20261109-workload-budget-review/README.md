# Existing-evidence workload budget review

This packet supplies the source mapping and arithmetic behind the
[0.2.0 supported-workload budget decision](../../../../docs/continuity/SUPPORTED_WORKLOAD_BUDGETS_0_2.md).
It distinguishes implemented admission limits, retained observations and selected
regression budgets. The six numeric values and their desktop reference scope are
selected; issuer-selected B and the application/connection owner's existing PQ
progress responsibility remain in force. Final chosen-artifact verification and
coordinated freezing remain in the existing admission sequence. The existing
`BUDGETS_V1.json` stays unfrozen.

## Completed review

- All 21 limits in `BUDGETS_V1.json` match their current Rust constants and are
  present in the compiled descriptor source.
- All 116 inspected current source/document/evidence files match their immutable
  Git blob identities at `6a2ee33af2d67bb982d339cbeb49f2310c7e7032`.
- The complete native `src/` tree comparison against measurement source
  `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8` has 618 paths: 612 identical,
  four test differences and two production changes extracting the existing
  16-valued fanout constant. `RUNTIME_DELTA.diff` records both production changes.
- Independent arithmetic over the committed individual observations reproduces
  all 12 phase groups (48 phase intervals), 90 operation groups (1,560 spans)
  and 20 memory groups (80 stage samples). It checks exact rational pooled rates,
  complete elapsed-time accounting, counts, medians, observed maxima, eligible
  empirical p95 and Witness distributions.
- The capacity fixture's measured peak RSS and physical database maximum are
  retained separately from the encoded-image cap and ordinary stage samples.

`BUDGET_REVIEW.json` contains the complete derived tables and selected policy.
The selected rule multiplies the largest retained observation by 1.25 and rounds
upward to one second or one MiB. This engineering allowance yields complete
reference-workload ceilings of 11/19/6/11 seconds (single local, single Witness,
fanout local, fanout Witness) and capacity-fixture ceilings of 200 MiB whole-process
peak RSS and 15 MiB sender database bytes. The rule is not a statistical bound;
its exact desktop reference scope introduces no new runtime limit, CI gate,
device requirement or mobile/larger-recipient quantitative admission condition.

## Reproduce the source and arithmetic review

From a checkout with the exact recorded inputs, run:

```sh
python3 research/sdk-alpha1/evidence/20261109-workload-budget-review/review_existing.py
```

For a separate source snapshot, pass `--repository /absolute/path/to/source`.
The recorded input snapshot is commit
`6a2ee33af2d67bb982d339cbeb49f2310c7e7032`; subsequent admission-plan updates
should be reviewed with their own identity, while this arithmetic is reproduced
against that snapshot.
`SOURCE_INPUTS.json` binds the exact input bytes; a later changed input is rejected
instead of being silently combined with the old measurements. `--output` writes
the resulting JSON to an explicitly supplied path.

The review uses the individual observations already included in the committed
summary files and the retained source. It runs no native workloads, launches no
devices, and does not replay the larger historical capture archives. Those
archives' existing readbacks, negative controls, package/binary identities and
execution dates keep their original scope. The current review's source/number
checks are recorded in `VERIFICATION.json`.

## Files

| File | Purpose |
| --- | --- |
| `SOURCE_INPUTS.json` | Exact paths, byte counts, SHA-256 and Git blob identities for the reviewed current inputs |
| `SOURCE_MAPPING.json` | Native-tree comparison and interpretation of the production-source delta |
| `RUNTIME_DELTA.diff` | Complete production-source differences from the measured native core |
| `review_existing.py` | Self-contained source/constant and independent numeric review |
| `BUDGET_REVIEW.json` | Observations, selected budgets/policy and verification counts |
| `VERIFICATION.json` | Executed review result and exact output identities |
| `MANIFEST.json` | Complete new packet inventory and decision-document identity |

The policy decision is complete. The next actions are the existing final
chosen-artifact verification and coordinated specification/release lock. This
packet adds no new experiment or acceptance gate.
