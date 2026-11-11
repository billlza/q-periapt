# Complete query receipts from original stderr

Production [b5185165](https://github.com/billlza/q-periapt/commit/b5185165283880527a54289b47397fde78ddf553) binds completion to all 39 distinct admitted query identities in the original `analyze.stderr`. The shared bounded parser also supplies live progress. The version-two plan receipt records the stream's bytes, digest and query set; publication independently rereads the uploaded original stderr.

The internal evaluator observations remain unchanged. They supply the 39 query starts, 39 precompiled loads, zero compilations and actual allocation. Their observed completion-message count is retained separately from the complete stderr identity set. Fresh BQRS results, SARIF, source and runtime admission keep their existing roles.

## Executed validation

The complete integrated run passed **293 tests in 10.577 seconds** on tree `8bd4c68aef4ddabe448f47996a709619b5c03924`. `combined/controls.log` is the full original 54,521-byte log; its command, interpreter, start/end times and return code are in `combined/VALIDATION.json`. The local tested commit and public production commit have exactly the same tree, as recorded in `SOURCE_BINDING.json`.

The targeted run passed 201 tests in 6.473 seconds, including eight new controls. `targeted/targeted-tests.tail.log` preserves the final streamed output chunk, with that scope stated in its original validation receipt. The complete integrated log above supplies full retained output for the final source. The original targeted handoff manifest and receipts are retained byte-for-byte.

Original [run 43032937156](https://github.com/billlza/q-periapt/actions/runs/43032937156/job/130564344658) supplied the actual regression input. Its internal evaluator log recorded 37 completion messages, while original stderr recorded all 39 distinct queries. The old validator rejects those original observations. The repaired validator accepts the unchanged observations together with the exact stderr query set; `targeted/REPLAY_BEFORE.json` and `targeted/REPLAY_AFTER.json` retain both outcomes. The original stderr and observation receipt are included under `original/`.

The new controls exercise missing, duplicate, unknown and malformed completion messages; bounded and nonredirected file reading; changed stderr bytes; publication rereading; and loss of a completion despite complete internal log messages. Existing progress-output and failure-propagation controls pass with the shared parser. The raw stderr regression fixture has a `-text` Git attribute to preserve its original bytes across platforms.

This packet records receipt validation and integrated controls. It performs no additional extraction, query execution, BQRS decoding or publication. The originating wrapper's final outcome remains failure; its successful command exit, SARIF and missing BQRS artifact members are retained in the [original execution packet](https://github.com/billlza/q-periapt/tree/4d589266c71236974519bba3d03fffa27304d713/research/sdk-alpha1/evidence/20261111-codeql-wrapper-completion). Fresh wrapper execution is recorded separately.
