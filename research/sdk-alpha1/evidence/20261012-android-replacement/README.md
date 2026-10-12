# Android-created device replacement and original-peer traffic

Both the original and next-generation identities are created through the Android
public configuration/enrollment API. Each installation generates and retains its
own device key, wrapping key and journal. An independently pinned native issuer
verifies the public enrollment request and approves the new generation; required
witness replacement retires the original subject. No private device state is copied
between installations or supplied by the issuer.

The same original C counterparty accepts the independently signed next roster
through its public admission API. Android establishes a fresh session with a
different session/message identity. The receiver commits a new business effect
and exits before acknowledgement; reopening and retrying the original successor
message confirms consumption without repeating that effect. The receiver retains
exactly two effects: the original device's old message and the successor's new one.

The old installation also completes restricted retirement: unchanged complete
report, independently authorized host acknowledgement, journal and signer erasure,
and exact reopening. Report tampering, the wrong receipt purpose, and operational
resumption after retirement are refused. Three actual process cuts per trust
profile occur after the report, journal erasure and signer erasure.

Debug/Release host runs pass 128 Java calls and twelve process cuts. The installed
minified, non-debuggable APK passes 64 ART calls and six process cuts on the accepted
API 37 arm64 phone. All owned installations and reverse mappings were removed.
This satisfies this software route's physical acceptance on the agreed single
phone; no API 36 or second device is required.

The first full host attempt failed when the C counterparty opened the new session
without persisting the signed roster advance: Checkpoint 105. The failure is retained
in the capture. Adding the existing explicit peer-roster admission closes that
missing integration step; it does not relax a checkpoint or authorize replacement
from incoming bootstrap bytes. Strict Rust compilation and Clippy pass.

`CAPTURE.zip` contains 1,968 source, public-record, command and diagnostic members
plus a hash manifest. `CHECKS.json`, `SOURCE_COHORT.json` and `ARCHIVE_READBACK.json`
bind the actual sources, packages and executions; six complete archived routes are
reread and ten deliberately changed public records are rejected. The same AAR and
native engine as the preceding retirement qualification are used. Only the test
consumer's explicit private installation-slot selection changes; the capture keeps
the earlier library source snapshot separately. Private keys and journals are not
archived.

This is one protocol implementation across language/platform boundaries, with an
independent issuer role and native C counterparty. It does not establish independent
protocol implementations, physical flash erasure, power-loss behavior, account-root
replacement or release readiness. Main integration remains pending after the completed
roster qualification; the work is isolated in `target/continuity-android-replacement`.
