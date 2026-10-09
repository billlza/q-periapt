# Isolate configuration qualification from earlier private fixtures

On e0e1dee0, Linux installed job 113978076400 failed both new configuration tests
with `AlreadyExists` before any configuration client operation. The earlier C
connection trace sets `QPERIAPT_PUBLIC_SERVICE_EVIDENCE` to its private fixture
directory. `qualify_configuration` copied that runtime environment into its new
helper. Native fixture setup correctly refused to recreate the existing directory.
The focused isolated prototype had a clean environment, so it did not expose this
integration condition.

The collector now removes that prior workload's private-fixture selector from its
child environment. Each configuration scenario creates its own temporary private
fixture. The separate `QPERIAPT_CONFIGURATION_EVIDENCE` selector still records and
verifies only the selected public request, original trust and genesis files. The
caller environment and previous directory remain unchanged. No existing state is
adopted, deleted or reset; SDK validation and native filesystem rules are unchanged.

The regression test fails before the fix and passes afterward. A real native/C run
with an existing inherited directory reproduces the same two immediate failures;
with the change, the identical helper/client binaries pass both tests and all six
trust/carrier scenarios with public readback. The old empty directory is unchanged
in both runs. `CHECKS.json` binds the binaries, validator revisions and CI archive.
All 36 related artifact reader tests pass. The Linux native 39-test admission output
is retained separately; successful hosted execution of the repaired collector still
requires a new CI run.

The exact diagnostic driver was run from `target/configuration-env-isolation-current`;
its prerequisite qualified binary paths are retained in the command records.
