# First configuration through actual communication and original-message recovery

The first-configuration consumer now continues its own newly generated device
identity through independent registration, local installation activation, copied
explicit peer inputs and real TLS communication. Both fixed and recoverable SDK
trust profiles start from an absent installation directory. No SDK database,
wrapping key, signer, enrollment, installation, journal or archive is copied from
a prepared device. Transport TLS credentials and signed public policies remain
explicit host inputs; the independent authority issues the new device's grant.

After connection, the native receiver exits with code 77 after durably recording
the application effect. The foreign sender must report an uncertain transport
result with the exact message locally committed. A separate process opens the
original configured installation and session, retries that message, and requires
acknowledged status. The receiver's public effect record stays identical, exactly
one application-effect file exists, and the registration request remains byte for
byte unchanged after traffic. This is application deduplication with retained
identity, not a promise of exactly-once arbitrary external effects.

Eight actual profile executions passed: C and Swift Debug/Release, plus Kotlin
Debug/Release with both G1 and Serial. Each execution covers two new local
connection/recovery flows and retains the four signed-TCP/mTLS witness
registration/activation cases. There are 16 new communication flows and 32
retained witness-activation scenarios. The latter do not yet demonstrate first
configuration followed by **witnessed traffic**; that composition remains open.
Swift was rebuilt with warnings denied and its loaded native library was observed
through ordinary dyld logs. Kotlin was built outside the checkout against the
previously qualified Maven SDK with strict dependency verification and warnings
denied. These are component-consumer executions, not a freshly rebuilt complete
release distribution or a new CI result.

The shared test bundle helper now derives the exact initiator device/generation
from the independently pinned, verified certificate instead of assuming device
71. Existing legacy and configured registration/roster-recovery flows passed in
both Debug and Release after that extraction. All-target Clippy and Rust 1.90
checks passed. Clippy first rejected two direct slice indices in the new test;
they were replaced by checked reads. No lint or assertion was suppressed.

The installed configuration reader now requires the connection markers and five
additional public records for each local profile. Across all six trust/carrier
scenarios it accepts exactly 44 public files, verifying original registration,
session, uncertain message, acknowledgement and application-effect linkage.
Seven reader tests include missing/duplicated markers and corrupted/truncated
connection records. Signature verification is performed by the real native
engine; the public reader is structural, not an independent cryptographic engine.

`CHECKS.json` records commands, binary identities, source-copy hashes and public
readbacks. `PUBLIC_CAPTURE.zip` contains only selected public records, logs and
qualified consumer sources; no private runtime databases or generated keys.
The new shared helper is included in the mandatory 442-file Rust source census.
Full integrated preflight, CI, witnessed and continued-policy composition,
physical/minimum-OS acceptance and the broader 0.2.0 release gates remain separate.
