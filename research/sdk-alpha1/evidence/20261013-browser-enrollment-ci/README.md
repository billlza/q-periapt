# Shared browser enrollment CI execution

The canonical `artifact/continuity_browser_creation.py` driver completed from
current source with pinned Rust 1.98.1, wasm-pack 0.15.0, Node 26.3.0 and
Playwright CLI 0.1.22. `accepted/BROWSER_ENROLLMENT.json` contains the source,
served-file and executable hashes checked before and after execution. This is
shared-engine source qualification, not an installed product browser package or
an independent implementation.

The real Chromium run exercised 12 creation/recovery scenarios, including eight
Worker terminations. Four delayed native-completion cases retained the storage
lease after the caller deadline and reported `ClosePending`; competing owners
were refused until the actual release receipt. An existing foreign directory
was refused and its marker preserved. The native engine verified all 19 captured
requests, representing seven distinct browser-generated signing identities,
and issued the corresponding credentials. Browser and loopback-server cleanup
completed before the driver recorded success.

`CAPTURE.zip` retains public inputs, requests, issued credentials and command
records. It excludes private issuer keys, private stores and browser profiles.
The archive has 310 members and SHA-256
`8c11a16297792cc71cfaf7339df2a4e0953cbfefb8f827e0c569756906a77223`.

Two failed driver attempts are preserved. `path-refusal` used macOS's temporary
directory alias and was rejected by canonical-path admission. The driver now
resolves that fresh directory. `directory-refusal` completed the browser cases
but used a mode-0755 credential output directory, which private publication
refused. `directory-control` verifies the same 19 requests into a fresh
mode-0700 directory; the final complete run used that correction. Neither fix
changed the storage admission rules.

The record/package rejection tests passed (21 tests); JavaScript syntax and
Rust formatting passed. Local actionlint still reports the same two pre-existing
`ubuntu-26.04` label diagnostics as the parent workflow; it produced no new
diagnostics. The CI upload list retains only the public output directory and
the two served public input files.

Hosted execution of this new CI step remains pending. Native whole-suite and
installed Rust/C/Swift qualification have separate receipts. Operational browser
activation, installation/session owners, root/roster lifecycle, transports,
product packaging and migration remain open. The earlier browser storage
rollback, same-origin and logical-erasure limitations still apply.
