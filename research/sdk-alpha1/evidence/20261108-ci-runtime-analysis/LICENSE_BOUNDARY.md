# Cargo executable identity during license collection

The current Python CodeQL result at `artifact/third_party_licenses.py:120`
identified a remaining executable-selection defect. `_cargo_metadata()` calls
`shutil.which("cargo")` in the caller's directory and then runs Cargo with the
repository as its working directory. When a PATH entry is relative, the selected
string can be `bin/cargo`. Changing the working directory then executes
`repository/bin/cargo` instead of the executable selected in the caller's
directory. The repository can therefore supply a different program at this
boundary. The affected condition is a relative PATH entry together with a
repository root different from the caller's directory.

The repair makes the selected pathname absolute before changing the working
directory. It preserves the final symlink and launcher name: Cargo installations
can use a `cargo` symlink to the `rustup` multicall executable, whose selected
name controls dispatch. The environment, metadata command, strict JSON parsing,
dependency closure, lock checksums, license validation and failure handling are
unchanged.

## Causal checks

Two harmless subprocess fixtures exercise the actual invocation boundary.
The first installs different JSON-emitting `cargo` programs in the caller's
and repository's `bin` directories. The original implementation selects the
repository's program; the repair selects the caller's program. The second uses
a `cargo` symlink to a `rustup` fixture that reports its invocation name. The
repair preserves `cargo`; a mutation using `Path.resolve()` instead of
`Path.absolute()` reports `rustup` and fails the test.

Both new tests pass on the local Linux runtime. The original source produces
one failed assertion and one process-start error. The dereferencing mutation
produces one failed assertion. All 14 tests in `test_third_party_licenses` pass
with no skips. `LICENSE_BOUNDARY_CHECKS.json` binds these results to the source
and test SHA-256 hashes and records the runtime. Windows fixtures use `.cmd`
launchers; their native results belong to the next hosted cohort.

## Relation to the retained SARIF

Python artifact `13601032646` from CodeQL run `42439010975` analyzes merge
`cf5bf0195936c2f38197aa571c452a216c757abe` for integration head
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9`. Its ZIP SHA-256 is
`ede472935750dab9fcdbac976e0c5f983f0cbc5cf15c448ef2353999c9bcd2e8`.
The license collector's source at that head matches the pre-repair source
recorded in `LICENSE_BOUNDARY_CHECKS.json`.

Compared by rule, primary path and stable primary-location fingerprint with
pre-fix Python artifact `13599962096` from run `42436153297`, the retained
current scan removes the two previously fixed native-program Critical locations
in `run.py` and `native_restart.py`. The ABI inspector's generic command sink
remains; its library operands are now absolute before the existing regular-file
and basename checks. The sole added High result is the regression fixture's
`read_bytes()` at `artifact/test_c_abi_contract.py:420`, reached through fixed
test directory names inside a private temporary directory.

The full current Python scan contains 52 Critical and 1,243 High results; the
C++ scan contains four High results. These are full-scan counts, distinct from
the server's PR-specific 17 Critical and 424 High aggregate. The 1,188 Python
path-injection results retain their own review status; this focused repair does
not adjudicate that corpus. No result was dismissed, suppressed or assigned a
different severity, and no security threshold or accepted status was changed.
