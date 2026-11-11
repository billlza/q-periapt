# Durable host-authorized enrollment transactions

At `697e15a83265fd4061d9187221b49256bb495b2b`, the optional reference host
implements explicit schema admission, recoverable root preparation, host-approved
original requests, atomic complete-roster/result publication, exact result
recovery, cancellation and an enrollment suspension fence. The invitation's
caller-retained correlation ID also recovers a lost initial host operation ID.
No Q-Periapt account registration is required to use the SDK.

Local checks passed 18 test entrypoints (17 behavioral tests plus one child
dispatcher), including ten actual SIGKILL boundaries, two-device signature/roster
verification and actual loopback TCP. Strict all-target Clippy, formatting,
workflow lint and the final `-D warnings` release build passed. The final binary
reopened the original CLI test database, served an anonymous401 and stopped
cleanly without init, upgrade or reset. The real user's account store was untouched.

The capture preserves the initial snapshot-test error, the reproduced overly
broad issuer-failure shutdown and its repair, release-tool loader warnings and
their task-local correction, and the mio dependency resolution review. The
Windows named-pipe upstream delta remains a separate SDK dependency review item.
No warning suppression or weakened check was used.

Authentication here uses a software authenticator; native enrollment uses real
SDK-generated requests and controlled signing owners at current host time.
HTTP/browser enrollment controls, installed independent clients, deployed HTTPS,
revocation/full root replacement, sync-fault injection, power-loss durability and
the rest of the full lifecycle remain open. This is component progress, not
release admission. `CAPTURE.zip` contains source and nonsecret diagnostics only;
private database/key files and executables stay local.
