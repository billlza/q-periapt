# Real directory CLI and independent receipt readback

Local Apple Silicon validation of the P2 directory path, based on `6084f3bfb09333f6b66291b38809ed512296a27b` plus the exact worktree files hashed in `RESULT.json`. These are source-built Rust CLI results and focused installed Python wheel results. They are not an installed Rust counterpart, a complete installed lifecycle run, CI qualification, or release approval.

`CAPTURE.zip` contains two sets of original public artifacts, the independent source and installed-wheel readbacks, selected command logs, the tested source files, and the actual wheel. `SHA256.json` identifies each member. It contains no directory database, signing private key, wrapping key, or current policy material.

The existing `publication::actual_cli_verifies_one_time_publication_without_opening_state` test now drives 31 real directory CLI processes and four isolated historical-verification processes per profile. Debug passed in 10.46 seconds; Release passed in 4.14 seconds. The original device-state byte-invariance assertion remains mandatory and passed.

The actual CLI commits the first allocation before an occupied output file prevents publication. Lookup and exact retry recover identical original receipt bytes. A changed request with the same operation is rejected as `Conflict`. Each single-algorithm reuse is rejected as `KeyAlreadyReserved` before and after cancellation. A new pair succeeds after cancellation. Direct read-only ledger observations are 1 operation after exact retry, still 1 after cancellation and all refusal cases, and 2 after the fresh pair. Only these public counts are exported.

Test-only signed publication variants change one or both public keys while retaining the independently selected device and publication context. The production importer admits each variant before the real directory CLI exercises reservation checks. A second test ledger with the same test signer deliberately issues a conflicting receipt. Both SDK and independent Python/OpenSSL verification produce the same canonical conflict bytes, including reversed input order; an exact original retry is not a conflict.

For each profile, the independent source reader and a freshly pip-installed wheel verify the same 15 public files. They reject the original P-256 signature mutation, a separate ML-DSA signature mutation, wrong service identity, wrong public key, and treating exact retry as conflict. The historical reader receives only the closed public artifact set and cannot read the private ledger or current authorization inputs. Historical signatures do not establish current permission, cancellation, delivery, or consumption; cancellation and occupancy are separately observed in the real CLI trace.

The final wheel is `qperiapt_continuity_reference-0.0.0-py3-none-any.whl`, SHA-256 `596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094`. Its installed modules, metadata, original wheel and copied harness were checked against the captured source before and after the focused run. Python was 3.14.10; Rust was 1.98.1. Provider and executable identities are in `RESULT.json`.

Actual checks:

- Debug and Release: `cargo test --locked --offline --manifest-path research/continuity-reference-app/Cargo.toml --test native_device publication::actual_cli_verifies_one_time_publication_without_opening_state -- --exact --nocapture` (Release adds `--release -j 2`), with an explicit new absolute `QPERIAPT_DIRECTORY_PUBLIC_OUTPUT`.
- Independent source and installed-wheel `directory_cli_checks.py --provider-root ... --input ... --output ...` against each profile's same public bytes.
- `cargo clippy --locked --offline --manifest-path research/continuity-reference-app/Cargo.toml --test native_device -- -D warnings`.
- `cargo fmt --manifest-path research/continuity-reference-app/Cargo.toml -- --check` and `git diff --check`.
- 56 `test_continuity_independent*.py` regressions and 13 workflow-partition regressions; all passed. These synthetic evidence-rejection tests supplement the actual cryptographic executions.

Earlier failures remain recorded rather than relabeled: missing OpenSSL build discovery, a new fixture error-conversion compile error, an unwanted fixture status query that changed enrollment database pages, and a bootstrap invocation that correctly refused a script outside its selected root. The fixture now receives its already-retained signing ID; no invariant was weakened. The isolated installed reader uses the existing copied-bootstrap layout without changing its confinement check. The large failing state-comparison log remains local under `target/directory-cli-crosscheck/cli-03.stderr`; its size and digest are recorded in `RESULT.json`, and private page bytes are excluded from the archive.

The independent workflow and full installed-wheel runner are wired to this required public-artifact path. That new CI path and the complete installed lifecycle have not yet executed. No workflow was triggered, and no commit or push was made as part of this local P2 validation.
