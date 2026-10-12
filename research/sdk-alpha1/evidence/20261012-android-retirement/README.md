# Android original-device retirement qualification

The isolated Android adapter passes 84 host Java calls in Debug/Release and
42 ART calls on the already accepted API 37 arm64 phone. Fixed and recoverable
SDK trust each cover the same lifecycle. Twelve host and six ART process cuts
occur after retaining the complete report, erasing the original journal, and
erasing the original signer. Reopening preserves the same report and terminal
state. All owned device installations and ADB reverse mappings were removed.
This phone satisfies the agreed physical-device acceptance scope; API 36 hardware
and a second phone are not required.

The Android API creates the original signer, wrapping key, enrollment and journal
on its own platform. An independently pinned account issuer approves registration;
the native C peer commits the original uncertain message before exiting without
acknowledgment. Independently authorized native generation replacement then retires
the original subject. Only public approval and witness inputs cross back to Android.
The cleanup owner exposes neither traffic nor signing capability.

Actual native verification rejects a same-length modified report with 208,
the report receipt used in place of the host acknowledgement with 102, and ordinary
enrollment resumption after retirement with 215. Cancellation returns 302.
The complete original report remains equal across erasure and reopen, and the
peer's original business effect remains unchanged. These are logical erasure and
process-interruption observations; they do not claim physical flash erasure or
power-loss behavior. Successor activation is native. Fresh Android successor
traffic and root replacement are separate software work.

`CHECKS.json` binds the source, host execution, AAR and installed minified,
non-debuggable release APK. `CAPTURE.zip` retains 1,235 members plus a hash manifest:
source, selected public input/output records, commands and device observations.
Device keys, journals, the qualification signing key, and fixture TLS private keys
are not archived. `ARCHIVE_READBACK.json` records six archived route readbacks and
eight rejected public-record mutations. The archived `reader/readback.py` can run
using only Python's standard library; its `archive(path)` entry verifies all member
hashes and public bindings. It is not a replacement for native signature or secret
MAC verification.

The adapter remains isolated under `target/continuity-android-retired-next` following
the now-completed integrated roster regression. It has not yet been
integrated into the main bindings, pushed to CI, or admitted as a release.
