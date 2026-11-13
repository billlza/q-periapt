# Independent registration against an installed Rust counterpart

The native counterpart now builds outside the checkout from eight validated SDK
0.2.0 archives and a freshly packaged current Continuity candidate. The public
[build entry point](../../../../artifact/continuity_independent_package.py) uses a
separately pinned SDK report and the existing package/source validators.

The formal run used a clean ordinary checkout at
`69d478e17eb3acafaf7dc22ead941c491d3f3205`. Release build and release Clippy with
`-D warnings` passed. Cargo resolves nine product crates, 118 external packages,
only the counterpart as a workspace member, and exactly the original lockfile
bytes (`cc6e7de9921a0e051cb03b587ed5b194372427efe6f96ef829c7b5a025cd2d8d`).
The SDK report comes from artifact `12137655956` of run `39129232908`; current
source correspondence is checked in addition to archive/report hashes.

The installed executable SHA-256 is
`60c66db3973b9e1d8aabc22e3a87345b49e0a6d5ea080b1e855c6bbaf1e553fa`.
That exact binary ran the independent registered-owner lifecycle: 42 local and
50 witnessed process operations, 21 actual SIGKILL cuts, original enrollment,
rekey, expiry, independently approved pending-write recovery and same-key renewal.
Two public readers bind the graph, archive contents, original lock, executable,
99 peer sources and signed public protocol records. Each profile also preserves
the ten direct refusal/lifetime controls. The build report remains explicitly
build-only; separate runtime receipts establish execution.

The prototype initially made installed path dependencies workspace members,
bringing in unwanted development dependencies and an ignored-profile warning.
Cargo's [workspace rules](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields)
explain this automatic membership. Explicit literal exclusions restored the
intended graph; an unnecessary optional Rustls patch was removed. The full lock
then returned to the original bytes. No dependency-version check or warning gate
was weakened. These failures and their manifests are retained.

The first public-entry attempt correctly refused a linked worktree under the
existing release provenance rule. A normal checkout of the same commit was used.
Its first execution then caught a duplicate lockfile copy; preparation now copies
the tracked inputs once and refuses an existing installation. Seven helper tests
pass, including complete setup, graph/source substitutions, exact lock retention
and malformed CI selection. Actionlint and diff checks pass.

The current CI extension adds only a selection validator and dispatch inputs;
every existing build-function AST is unchanged from the formal run. Providing
both `sdk_run_id` and `sdk_report_sha256` selects installed qualification; partial
inputs fail. The [download action's cross-run interface](https://github.com/actions/download-artifact#download-artifacts-from-other-workflow-runs-or-repositories)
uses the same repository's read-only artifact access. Hosted installed execution
is a subsequent gate, not established by this local receipt.

`CAPTURE.zip` contains 1,582 members and 19,857,449 bytes, SHA-256
`48780014d1ce7dc471299db12293aa0cdb6cd90e165b8c569ddd962621dbbec4`.
It retains exact SDK inputs, candidate/native artifacts, formal and prototype
records, public runtime bytes, readers and a verified manifest. Private
registration/session images and wrapping values are excluded. The seal repair
record distinguishes a native journal locator from the Python configuration;
it also records that a shell-path typo overwrote the first seal-error log after
the error had been observed. It does not claim those original stderr bytes survived.

This closes the tested native archive boundary on Apple Silicon. The Python
reference still runs from source, and the endpoints use the same host and trusted
fixture control pipe. Installed Python distribution, cross-host application
carrier, deployed account authentication, remaining multi-device lifecycle,
physical erasure, power loss, retained-state PCS and full 0.2.0 release admission
remain separate work.
