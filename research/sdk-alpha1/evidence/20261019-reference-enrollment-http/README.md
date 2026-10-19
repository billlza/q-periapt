# Authenticated enrollment HTTP adapter

Source `9e0c067987bfbd63a104be83b315f08dfbfc167a` connects the reference host's existing enrollment transactions
to bounded same-origin HTTP routes. Authentication remains host-owned; no account
signup or Passkey dependency is added to the SDK. The adapter returns committed
issuance bytes directly and keeps historical responses separate from current
root/roster observations.

Debug and release each passed 26 entries (25 behavioral tests and one existing
child dispatcher). Three new scenarios use actual loopback TCP, software WebAuthn
signatures and native SDK device proofs. They cover account/Origin/input isolation,
original-request retries, a response-body disconnect and original-database reopen,
roster-conflict reapproval, cancellation and suspension. The existing library
suite retains its 14 distinct SIGKILL boundaries; these are not new HTTP cuts.
Strict all-target Clippy, release build, formatting and diff checks passed.

A new boundary error was reproduced before repair: omitting the reapproval
predecessor silently selected an empty roster and returned 200. The decoder now
requires that field, while explicit null still selects the empty roster. The
capture preserves the failing regression and pre-fix sources, plus the initial
test-macro compilation failure. It contains exact app/workflow source and public
diagnostics, not account databases, private keys or executables.

This is local component evidence. Browser enrollment controls, installed-client
acceptance with independently authenticated live policy/trust, deployed HTTPS,
full replacement and the expired-unissued credential transition remain open.
The real user's account database and existing local service were not modified.
