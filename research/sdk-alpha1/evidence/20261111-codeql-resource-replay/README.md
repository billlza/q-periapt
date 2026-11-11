# Resource sampler timeout and isolated replay

This packet preserves two separate results on unchanged relevant source:

| Execution | Result |
| --- | --- |
| Original combined invocation | 285 tests: 284 passed and one resource-sampling test timed out; 23.789 seconds. |
| One isolated replay of the same test | Passed in 1.234 seconds with the original five-second bound and assertions. |

The combined validation recorded source tree
`ae1b6817cadd3b0847ecd1e2d16491fd2289f09f`. It finished before the GitHub API
created production commit `951b8dcaebc11223bf01c79c1c4c3a20349be989`, whose tree
is exactly the same. `SOURCE_BINDING.json` records this chronology and verifies
the replay's four test/sampler/control/supervisor file hashes against that
production tree. The original receipts keep their original source identifiers.

The timeout occurred while the bounded supervisor was waiting for both output
readers to signal EOF. The original test's temporary directory had already
been cleaned, so the aggregate traceback does not establish which process or
scheduling condition delayed completion. The recorded result remains
284 passes and one timeout.

The single replay retained 57 resource samples, including 47 observations of
both allocating processes. It completed normally with the same five-second
deadline, no partial censuses or process-read errors, and complete sampler
shutdown. Its command, raw output, resource observations and collection method
are retained. No source, fixture, assertion or timeout was changed.

`SOURCE_MANIFEST.json` is the unchanged handoff manifest. All 12 original
payload files are preserved byte for byte; `MANIFEST.json` additionally binds
this README and the source-binding receipt. Archive assembly only copied and
hashed existing evidence. No further test, CodeQL command or workflow was run.
