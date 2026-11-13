# Android independent protocol-policy renewal

Code: `b8c8226c64ed8ab928c36bd303f3a3fb96bde5d0`. This is the unpublished
Continuity Android adapter over `qpc-owner/1`, separate from the product SDK ABI 2.
[CHECKS.json](CHECKS.json) binds source, artifacts and validation scope.

The same accepted API 37 phone completes 234 ART calls across fixed/recoverable
SDK trust and local, signed-TCP and mutual-TLS coordination. Protocol P0 actually
expires while the outer SDK policy, credential and roster remain live. The
application retains the original request, independently selects P2 and supplies
both account-root and policy-root approvals. Original signer, journal, session
and uncertain message survive; the receiver's business effect remains exactly one.

Required-witness Commit persists before its reply is lost. Reopening and querying
the exact original proposal recovers Applied and completes retirement without
another policy Commit or Close. Missing current-target selection, missing required
registry, bad approval, substituted scope and cancelled staging fail explicitly.
Historical terminal state grants no fresh traffic authority. Local storage uses
explicit pins; it cannot silently acquire required-witness protection.

Validation includes 1,482 host Java processes across Debug/Release, 35 reader
tests, 27 package/first-configuration tests, 81 source-inventory tests, strict
Clippy, changed-file rustfmt and the existing C first-use regression. The native
runtime sources and engine bytes match the preceding 909-test qualification;
those native tests were not rerun for this adapter change. Source gate output is
retained in [SOURCE_GATE.stdout](SOURCE_GATE.stdout).

The captures preserve the actual JNI field-capacity failure, test-harness repairs,
and an export-list failure. `ADAPTER_BOUNDARY_CAPTURE.zip` contains the JNI
red/green logs. The C target-creation command emits logs, not the extra payload
file initially requested by the export list. The new export regression reproduces
that failure; the corrected export is independently read back. Host recovery uses
only successful commands with exact recorded arguments and matching source,
tools, native libraries and AAR Java bytes. The remaining commands execute normally.

Witness, issuer and native receiver use the reference implementation on the Mac;
this does not claim an independent protocol implementation. Android SDK-authority
expiry/revocation, roster renewal, retirement, root replacement and broader 0.2.0
release admission remain separate work. No second phone or API 36 hardware is
required for the agreed physical-device acceptance.
