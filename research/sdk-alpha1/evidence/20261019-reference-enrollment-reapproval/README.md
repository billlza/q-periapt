# Enrollment reapproval with original device state

At `746d83f8468b0fb36b66b4e8e8eabe18d58a1145`, the optional native reference
host adds explicit schema-3 reapproval. A newly authenticated decision can select
the current roster while preserving the original device intent, signed request
and private signing owner. One transaction closes the previous decision, retains
its request/history, moves the signer reservation and publishes the successor.
Repeating the same correlation ID returns that original successor; it never
branches, retargets the root or silently follows a later transition. Explicitly
cancelled and issued operations stay terminal for reapproval.

Debug and release suites each passed 23 entries (22 behavioral tests and one
child dispatcher), including 14 distinct real SIGKILL boundaries. Tests reopen
the original SDK client, compare its request and signing files, and verify the
new credential with the original controlled signer. Negative cases cover wrong
accounts/requests/checkpoints, reused correlations, root suspension, terminal
grants and unchanged credential validity. Expiry fixtures use explicit historical
inputs; they are not real-time expiry measurements.

Strict all-target Clippy, formatting, workflow lint and the strict release build
passed. Actual old/new executables operated on the original preserved empty CLI
database: the old reader accepted schema2, explicit upgrade/retry retained its
inode, the old reader refused schema3, and the new reader reopened it over actual
TCP. Pre-upgrade bytes were saved but never restored. Account-record preservation
is separately tested with real signatures from a software authenticator. The
real user's account database was not upgraded.

The capture contains exact app/workflow source and nonsecret diagnostics,
including the initial test-helper trait-import compilation failure. Private
databases, key files and executables remain local. SDK dependency source is
identified by the Git head rather than duplicated here. Enrollment HTTP/browser
controls, installed independent clients, deployed HTTPS, full replacement and
the expired-unissued-credential transition remain open. This is component
progress, not full lifecycle or release admission.
