# Candidate CI snapshot — 11 November 2026

This read-only snapshot was collected from **10:28:17 to 10:29:43 UTC**. `STATE.json` binds the branch heads, complete check pagination, protected-context rules, individual checks and the retained experiment's comparison job.

| Source | Exact head | Check results | Protected contexts successful |
| --- | --- | --- | --- |
| Canonical paper, PR #119 | `87fee58926f8b849a142018efb6d7502cbad673f` | 38 success, 3 queued, 1 existing CodeQL aggregate failure | 32 / 33 |
| SDK integration, PR #121 | `4870db5eff0a611973a302f29e94c0992df66cfe` | 8 success, 10 in progress, 126 queued | 1 / 33 |
| Main | `48d0fb9a5651b50494ec33d025dda52bd2ff5eae` | Protected source unchanged | 33 required contexts enforced for everyone |

All 33 required contexts remain bound to GitHub Actions application 15368. The paper's only outstanding required context is `bindings-swift`, job 130438613119, queued. Its separate Swift CodeQL analysis and Android runtime job are also queued. The SDK's successful required context is the ARM Linux package; all remaining required contexts are queued in this snapshot.

The paper's known CodeQL aggregate result reports the 14 source-reviewed annotations and the still-missing Swift upload. The successful Rust analysis and complete dependency audit are documented in [the hosted qualification packet](../20261111-paper-hosted-review/README.md). No new candidate failure was found during this snapshot.

The original fixed-plan experiment's comparison job 130447340947 remains queued. Its two evaluator arms have completed with the recorded supervised timeouts. [The outcome packet](../20261111-summary-join-outcome/README.md) retains the original execution receipts and the independently run local comparison; [the projection prototype](../20261111-summary-target-projection/README.md) records the subsequent compiled implementation candidate.

This is a timestamped observation. Existing checks, rules and branch heads were not changed while collecting it.
