# Clang executable identity across analysis working directories

The adjacent tool-selection review found the same relative-path defect in
`codeql_rust_profile.prepare()`. It selects Clang using `shutil.which()` in the
caller directory, invokes the target probe in the repository directory and
forwards the selected string through `CC_wasm32_unknown_unknown` to Cargo
compilation roots. A relative PATH entry can select different executables at
those working directories.

Clang's selected pathname is now made absolute immediately after lookup.
The final symlink is retained, preserving compiler/multicall dispatch by
launcher name. The compiler target probe, Rust compiler identity, query suite,
threat model, memory/thread budgets, deadlines and extraction/publication gates
are unchanged.

The two regressions run harmless executable fixtures through the actual
`prepare()` target probe and `ProfileRun.command()` subprocess path. They cover
different caller/repository executables, a `clang` symlink to a multicall
fixture, and reuse of the selected compiler from a nested consumer directory.
The earlier version/source setup is isolated because these tests target the
executable-selection boundary; no Rust compiler or CodeQL query runs in them.

Both cases fail against the original source and pass after the correction.
A mutation using `Path.resolve()` instead of `Path.absolute()` fails the
multicall-name case. `COMPILER_BOUNDARY_CHECKS.json` records their source/test
hashes and outcomes. The full profile module passes 17 tests; the unchanged
seven-module CodeQL preflight command now passes 118 tests with no skips.

The adjacent live call sites were checked for this specific working-directory
transition. OpenSSL in `standard_tls_interop` and Node/npm in the WASM consumer
are already resolved before their invocations. Android runtime/instrumentation
control invocations of avdmanager, javac and keytool retain their lookup working
directory. No change was made to those boundaries or archived experiment
drivers.
