# Browser enrollment control and recovery checks

Source `83bb4b29a82e9eb2379a5df7b26bc01dd0669140` adds optional browser controls using the existing authenticated
HTTP transactions. Original correlations are saved before requests. Submitted
proofs remain immutable; a new explicit reapproval retains its own correlation
and selected predecessor. Failed attempts stay in the record. The host still
atomically admits one source successor and rejects a changed approved device key.

All 16 Node model/transport regressions passed, using explicitly substituted HTTP
and storage. Two added recovery regressions first failed and now pass without
overwriting the original attempt/proof. Current Rust debug tests passed 26 entries
(25 behavioral tests and one dispatcher), including actual HTTP and exact static
module delivery. Strict all-target Clippy, final release build, JavaScript syntax,
format/diff checks and workflow lint passed. Earlier release tests also passed,
before the final browser-only corrections; they are recorded with that boundary.

The final release executable reopened the original empty preview database. Actual
Chrome initialization showed the optional example, initialized module content,
hidden anonymous enrollment controls and no captured console error/warning entries.
This was read-only: no account, credential or device was created. Browser translation
was observed, so completion tracking uses internal state instead of displayed text.

The capture preserves exact source, positive/negative regressions and local driver
diagnostics. A local check driver stopped on an existing output filename, and a
later label replacement selected a nonexistent lint executable; neither was a
passed check. They were corrected with explicit command lists and preserved outputs.
Private databases, cookies, private keys and executable bytes are excluded. The
real user's account database and localhost8087 service were untouched.

Complete real-browser authorization with an installed independent consumer and
live signed policy/trust remains open. Browser local storage is not a rollback
witness or power-loss durability guarantee. This is component progress, not full
0.2.0 lifecycle or release admission.
