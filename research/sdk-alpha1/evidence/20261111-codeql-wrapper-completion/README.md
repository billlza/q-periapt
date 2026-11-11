# Full wrapper execution and completion-receipt readback

[Run 43032937156](https://github.com/billlza/q-periapt/actions/runs/43032937156/job/130564344658)
used workflow source `cd33c64e34a39046a57010bfa56f6964acdca2c2` and production
source `951b8dcaebc11223bf01c79c1c4c3a20349be989`. Its nine workflow-contract
tests passed in 0.006 seconds. The frozen nonempty Rust fixture extracted
successfully in 46.486 seconds. The production `database analyze` command
returned zero after **87.696 seconds**, emitted a distinct completion for each
of the **39 admitted queries**, and exported native Rust SARIF.

The hosted method then stopped with `PlanError: production evaluator completion
census differs`. The internal execution log contains 39 starts and precompiled
loads, zero compilations and one evaluator invocation, but only 37 completion
messages. The original stderr contains all 39 canonical completion messages,
each exactly once. The two messages absent from the internal log identify
`DisabledCertificateCheck` and `UseOfHttp`; their corresponding produced-BQRS
messages are absent there as well. The retained bytes establish this divergence;
they do not identify its upstream logging mechanism.

## Independent readback

`READBACK.json` and `COMPLETION_EVENTS.json` record a read-only comparison against
the fixed query manifest and exact production Git objects. They verify all 12
source-contract files, the full 39-query completion set in stderr, the internal
load/start/compilation census and the actual evaluator allocation. That allocation
is 3,484 MiB of Java heap and 9,329 MiB outside the heap within the requested
14,000 MiB budget, with four query threads and a 600-second supervisor.

The retained postcheck records the unchanged Stage3/Stage4 projection and private
runtime. Its runtime inventory contains 2,282 files and 231,156,107 bytes, with
canonical digest `1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90`.
The independently read SARIF is version 2.1.0, names CodeQL 2.27.2 and the native
Rust category, records successful invocation, and has no tool warning/error
notifications. This readback validates that retained file after the hosted
method stopped at the earlier completion check.

The original workflow conclusion remains **failure**. No BQRS file was included
in this artifact: the method stopped before copying query results into its
evidence directory. Consequently, this run has no new decoded SummaryStats or
29-row comparison receipt. The next wrapper revision retains database results
independently of the later checks. Previously retained baseline input bytes in
the ZIP retain their role as inputs, not outputs of this attempt.

## Original bytes

- `artifact.zip` is the unchanged 3,561,748-byte artifact `13862281372`, with
  SHA-256 `26a213027695de66807bd2c9999cd4287dbfa932b05cf06435fe027d4c033057`.
- `ZIP_MEMBERS.json` independently records all 172 member identities. The
  27,721,799-byte execution log remains inside the original ZIP rather than
  being duplicated as a loose file.
- `job.log` is the connector's complete decoded job log. `ARTIFACT_API.json`
  and `JOBS_API.json` preserve the corresponding API readbacks.
- `original/` contains unchanged selected command, source, plan, runtime,
  resource, failure and SARIF records. The full remaining records are in the ZIP.
- `readback.py` is the exact local readback method; it reads original bytes and
  committed sources without running CodeQL, a JVM, tests, extraction or queries.

`MANIFEST.json` covers every file in this packet except itself.
