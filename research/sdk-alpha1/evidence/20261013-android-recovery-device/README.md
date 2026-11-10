# Android first-use recovery on the accepted physical phone

The current installed-package engine at `7290c6f02b0fdebbaaed5b2916dc68904267710a`
completed both fixed-root and recoverable-root profiles on the previously
accepted API 37 arm64 phone. No second phone or API 36 device is required.

The minified, non-debuggable Release APK used AAR
`9c3aabeff7e07ed75adf69689ed87d229c2c05b1270166080085320507e7fbcc`.
Its native engine and JNI bridge were byte-equal to the AAR members, had exactly
the expected exports and passed 16 KiB ELF/APK alignment checks. Java and C builds
used strict warnings. The successful APK SHA-256 is
`fa26f421cc0bc78d62e66bcc2139f51651c0e038c5a832addb9f90b37024fdf7`.

There were **84 SDK calls in distinct ART processes**, plus two separate fixture
transfer processes. The phone generated its own signing identity and original
installation in each profile. A native host issuer authenticated the request;
two native counterparties then exercised actual mutual TLS through explicitly
owned wireless-ADB TCP mappings. The workload preserved original operation,
session and message identities through two receiver exit-77 cuts, exact retry,
zero-exchange retained results, input/recipient refusals and concurrent member
cancellation. Each operation ended with confirmed process absence.

Recovery compared every original recipient, retained complete session reports
before acknowledgement, rejected altered archives with 208, restored four
original authenticated archives, rejected retired aggregate selection with 112,
and left the account position unchanged. Four complete session reports were
reread before and after acknowledgement, producing eight identical paired
captures. The native fixture and the public reader both checked the original
results. The run-owned app was removed and its absence verified.

Two failed device attempts remain in the capture. The first exceeded ADB's
shell-command budget: a no-SDK `true` control succeeded at 60,000 bytes and failed
at 66,000 bytes with the same `error: closed`. The driver now sends bounded
fixture batches and requires each staging receipt before starting the SDK call.
The second reached recovery but Android rejected the test host's hard-link
publication of its accounting report. No cleanup acknowledgement was issued.
The shared test-host helper now uses an exclusive writer lock, atomic rename,
file synchronization and directory synchronization. Exact repeats remain
idempotent; conflicting records and busy writers fail. Cross-process exclusion,
conflicting/absent records and later publication were also checked on the host,
and this regression now runs in the canonical JNI recovery qualifier.

[CHECKS.json](CHECKS.json) inventories all 2,143 members of
[CAPTURE.zip](CAPTURE.zip), SHA-256
`a7ddf69f58a4811e16f2209b08e65f4a7ccf80fc4849e10adebd9a327391909d`.
Every member was reread; the extracted successful cohort replayed identically.
Four altered captures—missing process, wrong APK, truncated report and changed
original result—were rejected. Twelve existing JNI/recovery reader tests passed.
The archive excludes private keys, journal databases, fixture inputs, signing
keystores and binaries; the exact local AAR/APK remain retained by hash.

Among the shared Java probes, only the qualification-host report helper differs
from the AAR commit. The app-specific instrumentation is captured separately;
the production AAR is unchanged. This extends
physical acceptance to the first-use account recovery path. Required-witness
recovery retains its separately recorded host evidence. The native participants
share one protocol engine, so this is not independent-implementation evidence.
It makes no release, performance, energy or physical-erasure claim.
