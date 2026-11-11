# Integrated Stage3 and Stage4 Python validation

The combined Stage3+Stage4 admission and live-log visibility changes passed **209 Python tests in 10.147 seconds**, with command exit 0. The tested local commit is `fe10c840a38e88ef6c358126e703ed5a20cd167b`, tree `94e532b4414b552a94ce8e161e9bb319a86246d9`. The published source commit `ff193302f207bb3f06a2941a7c6bf98a2eeb5a17` has that same tree and parent `faabcff16fc49e1a99388c68f0991a2bfd64d509`.

The invocation was:

```sh
python3 -m unittest -q test_codeql_summary_archive_input test_codeql_summary_control test_codeql_summary_plan test_codeql_summary_projection test_codeql_process_resources test_codeql_rust_profile test_codeql_workflow_contract
```

It ran from `/workspace/scratch/4b61438fb07b/codeql-stage34-integration/artifact`, with combined stdout and stderr retained in `integrated-tests.log`. The reported start is approximately 11:58:56 UTC; the last child trace in the log is 11:59:05.072 UTC. The 10.147-second duration is taken directly from the unittest footer. No exact command finish timestamp is inferred from that last child trace.

`INTEGRATED_TESTS.json` binds the command, source tree, original log and per-file identities for the test modules, their repository import closure, workflows and fixed query/plan assets. This is the integrated Python result for the identified tree. Production CodeQL workflow behavior was unchanged by this source update, and the separate retained-project query experiment remains independently recorded. The packet adds no new test run, CodeQL invocation or CI-status inference.
