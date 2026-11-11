# Bounded CodeQL sink review

Source: PR #115 head `3c9df1feeb7857e53ac4d6269788d20c87851459`, integration base `56eb5dca95a913539040d0939c733d1f11f89d50`, run [42959257074](https://github.com/billlza/q-periapt/actions/runs/42959257074). All four downloaded language archives name merge `834c67183c403fd10d65600252ecbcb950c1af11` and tree `0f281a963c2bd0e6f203c025a99d507ae73da9c2`. The JSON companion records each archive and reviewed source-file SHA-256.

## Populations

Raw archives contain 1,413 results: Python 1,410, C/C++ 3, Actions 0 and Java 0. The PR gate reports 519 new/comparison alerts (12 critical and 507 high). These populations differ: full-source SARIF results cannot be substituted for the PR baseline-comparison count. The Python critical-class raw set includes one code-execution and 52 command-line records.

## Reviewed paths

| Sink | Source-specific result | Remaining boundary |
| --- | --- | --- |
| `python_bootstrap.py:44` | The reported flow is the explicit CLI `-c` code argument. Startup isolation uses `-I -S -B`, a private cache prefix and cleaned Python environment. | Callers must supply trusted code to `-c`/stdin. This review does not certify every caller. |
| `git_provenance.py:117` | The two reported origins choose an operator repository/verifier path. The program is fixed `/usr/bin/git`; selectors remain single `--git-dir=`/`--work-tree=` values under a minimal environment. The publication verifier additionally requires its owned canonical mode-0700 fixed-root child. | The helper remains responsible for constructing each intended Git subcommand and its operands. |
| `bounded_process.py:356` | The helper provides resource/ownership boundaries and separate argv/executable invocation. Four SARIF representative origins were traced: hosted Android control, Android JDK selection, explicit Gradle selection and enumerated Apple `host_target`. | This is not an executable allowlist. Nineteen other related source entries remain unreviewed here; `shell=False` does not close them. |
| `setup_client.c:20` | The qualification harness discards inherited `QPC_TEST_*` variables and supplies its own receipt. The writer checks regular type, same UID, mode 0600 and one link after `O_NOFOLLOW` open. | The standalone C helper alone does not impose a directory allowlist. |
| `sync_probe.c:89` | The independent test-only probe opens the harness-selected target read-only, checks same UID/0600/regular/single-link and retains its device/inode for interception. | Confinement includes the private harness workspace and rebuilt environment. |
| `sync_probe.c:95` | A harness-generated receipt is created with `O_EXCL`, `O_NOFOLLOW` and mode 0600. | `O_NOFOLLOW` protects the final component; it is not a complete ancestor-path constraint. |

The C probe is compiled as a separate fault-injection artifact by `continuity_c_consumer.py`; it is not linked into the SDK library. `continuity_package.py` admits a fresh evidence output and creates a private temporary workspace. `continuity_c_faults.Matrix` removes inherited loader and test-injection variables before rebuilding exact target/log values, while setup-I/O cases use private subdirectories.

## Executed verification

Four existing controls pass: caller Git-environment redirection, exact explicit process environments, absence of a generic execution CLI, and separate executable/argv invocation. Their names and the complete attempted command are in the JSON companion and `codeql-core-sink-controls.log`.

The combined command exits 1 because two additional Python launcher tests fail to reach their bodies: the sparse review checkout omits the HQC README required by their class-wide proof-input snapshot. They are recorded as **not executed**, not as test passes or as a launcher regression. C runtime probes were not executed in this source review.

## Disposition

This bounded review established the source-specific interface and harness constraints above and did not produce an unauthorized-execution or path-confinement counterexample for those paths. No alert was dismissed and no scanning policy was changed. The remaining raw findings and the 19 untraced bounded-process origins retain their open status. The overall CodeQL gate remains unresolved; its complete result set is not classified as false positives.
