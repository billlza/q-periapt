# Integrated completion-boundary controls and checkout applicability

The integrated candidate combines query source `ed38e305552db2825d90622c130973df87e16d50` with completion-boundary
repair `3b042375d4ac8e40b10d07941595341a6cc9b807`. The original combined run passes **298/298 tests in 10.642
seconds**, supervised wall time 11.452560882 seconds. Its command,
timestamps and unchanged-source result are preserved in `RESULT.json`; the
complete original verbose output is `controls.log`.

`CANDIDATE.json` binds all 623 artifact and
workflow working files (16,946,225 bytes).
The combined index tree is `7ff2bcc70f29ef8055c011ceeccbbbe55ed7dd9c`. The one
working/index difference is the original stderr fixture path added to
`codeql-summary-control.yml`; the candidate inventory includes those exact
working bytes. Documentation is outside this control-input inventory.
These identities bind this tested candidate without assigning a final merge
commit or a subsequent default-plan decision.

## Six-module subset

The existing verbose log contains all **182 passed tests** belonging to the
workflow's six-module preflight set:

| Module | Passed cases |
| --- | ---: |
| summary control | 97 |
| archived source input | 5 |
| process resources | 23 |
| summary plan | 16 |
| progress/completion reader | 17 |
| summary projection | 24 |

`READBACK.json` records all eleven module totals and the four added completion
boundary test methods. The 182 cases are a verified subset of the original
298-case run. The earlier 178-case sparse-input execution remains bound to
its earlier source; this readback does not create another test execution.

## Checkout applicability

The qualified checkout implementation and contract test at `7c1c1b6f95747b9ccb877b803bd1ad7cee3cdd9d` are
byte-identical to those in query source `ed38e305552db2825d90622c130973df87e16d50`. The new external head
changes only `codeql_evaluator_logs.py` and `test_codeql_progress.py` relative
to base `d2f9035c341db488bf0aba7b440d6548660d62b7`. Neither checkout file is changed by that repair.

All 542 omitted historical ZIP paths, Git blob identities and modes are
identical between the qualified and new external trees, retaining the exact
4,787,753,249-byte omission set. Both trees contain 7,929 tracked files and
7,387 retained files, including 1,241 Rust sources. The complete research tree
is unchanged, including all 68 previously authenticated archived Rust source
snapshots and their pin manifests. No new omission or provenance exception is
introduced by the integration.

The prior hosted result remains **15.861989596 seconds** and **100,256,247
bytes of Git object-directory storage**, measured at the qualified source.
`PRIOR_CHECKOUT_READBACK.json` preserves that original result unchanged;
`CHECKOUT_APPLICABILITY.json` records the current tree comparison and exact
checkout blob bindings. This is a source-applicability readback, not a new
checkout timing measurement.

All three original control files and the prior qualification result are copied
byte for byte. No additional test, compilation, query, CI or reference update
was executed while assembling this packet.
