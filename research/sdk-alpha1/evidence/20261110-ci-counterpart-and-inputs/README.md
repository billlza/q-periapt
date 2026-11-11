# Installed counterpart and workflow-input CI repair

The `check` job [129343930688](https://github.com/billlza/q-periapt/actions/runs/42670061452/job/129343930688)
ran 3,644 Python tests and reported two errors and one failure. Its checkout log
identifies `refs/remotes/pull/143/merge`, commit `0cd7d39b90059757d7cefb86cc1d7c61dcd1c6b9`.
The affected modules and counterpart manifest are byte-identical at integration
commit `471900bfe8070d1021a1feb67481437d599d80ba`. `FAILED_CHECK_SOURCE.json`
records these identities. GitHub associates check records with the paper head;
the checkout identity identifies the engineering merge tree actually tested.

## Counterpart installation

The native counterpart retains the Rust import alias
`q-periapt-continuity-identity-candidate`, whose Cargo declaration explicitly
selects package `q-periapt-continuity` at `=0.2.0`. The archive installer now
recognizes that exact alias contract and preserves it while replacing its source
path with the installed package path. The package name, exact version, dependency
fields, workspace isolation, original lock bytes, and all other dependency edges
remain checked. Regressions cover the renamed package, a changed exact version,
a version range, changed dependency key, and added dependency features.

## Workflow inputs

The one-shot Python guard previously treated file-selection and checksum input
data as script execution. It now recognizes literal `with.sparse-checkout` data
under a pinned checkout action, complete literal `sha256sum` argument lists, and
the existing interpreter-path search loop header. Run/env entries, unpinned or
different actions, injected shell separators, command substitutions, broken
continuations, and actual direct Python/script invocations retain rejection.
YAML-looking text inside shell block scalars cannot impersonate checkout data.
The guard was exercised against all 22 current workflow files and again against
the added process-resource sampler workflow.

## Reproduction

The original 12 focused tests reproduce the hosted two errors and one failure.
The candidate's 15 focused tests pass, including the full independent-counterpart
module and five workflow guards. A separate five-test combined-workflow run passes.
These are Python source/manifest and invocation-contract checks; native Rust
compilation is performed by the existing hosted package workflow.

```sh
sh artifact/python-run.sh -m unittest -v test_continuity_independent_package \
  test_proof_to_byte_release.ProofToByteReleaseMarkerTests.test_ci_repository_python_calls_use_one_shot_runner \
  test_proof_to_byte_release.ProofToByteReleaseMarkerTests.test_python_runner_guard_distinguishes_trigger_paths_and_execution \
  test_proof_to_byte_release.ProofToByteReleaseMarkerTests.test_python_runner_guard_distinguishes_archive_members_and_execution \
  test_proof_to_byte_release.ProofToByteReleaseMarkerTests.test_python_runner_guard_distinguishes_sparse_checkout_data_and_execution \
  test_proof_to_byte_release.ProofToByteReleaseMarkerTests.test_python_runner_guard_distinguishes_checksum_inputs_and_interpreter_search
```

The packet preserves the failure excerpt, original log identity, baseline and
candidate logs, combined-workflow result, and exact source bindings. The complete
decoded job log is preserved with the research delivery.
