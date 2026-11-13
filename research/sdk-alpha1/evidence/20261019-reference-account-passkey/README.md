# Real Passkey account login and restart

The independent reference application at `a62c9a69` passed eight regression
checks, strict all-target Clippy, formatting and a real local browser ceremony.
The user created a Passkey and authenticated. After the owned server stopped and
reopened the same account database, the old session was invalid and the same
account authenticated again using its retained Passkey. No database recreation
or test credential substitution was performed.

The software-authenticator regressions use real signatures with a simulated UV
flag; those tests are separately identified and do not stand in for the user's
browser ceremony. The initial storage-test failure and the first user-facing
unknown-account error are retained in the capture with their corrections.

The public capture contains exact source, lockfile and nonsecret command results.
Screenshots containing the chosen account name and the actual private database
remain local. Device enrollment approval/issuance, deployed HTTPS and installed
application qualification are still open. This is account-login progress toward
the full lifecycle, not a 0.2.0 release-admission claim.
