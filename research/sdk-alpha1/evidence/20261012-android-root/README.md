# Android account-root replacement checkpoint

The isolated Android adapter completes four independently approved paths: the
original target, transition to another target, transition after the original
target was bound, and adoption of an already committed competing replacement.
Both original and target identities are created through public Android APIs. An
independent native issuer and witness authorize replacement; the existing native
C counterparty receives fresh successor traffic. This is shared-engine foreign
integration, not an independent Continuity implementation.

Debug/Release and fixed/recoverable trust pass **560 host Java calls and 96 actual
process cuts**. The minified, signed AAR consumer passes **280 ART calls and 48
actual cuts** on the already accepted API 37 phone. One phone satisfies the agreed
physical-device scope. All test installations and owned ADB reverse mappings were
removed. APK native members match the AAR and pass 16 KiB ZIP alignment checking.

The tests preserve original operation/report identity across restart, reconcile
unknown successor activation, reject invalid signatures, altered host reports and
wrong-purpose receipts, retain two distinct application effects across original
and successor traffic, and observe successor revocation when its controller closes.
Alternative targets have distinct account roots and separate private installations.

`HOST_CAPTURE.zip` contains 2,925 hashed public/source members; `ART_CAPTURE.zip`
contains 5,879. Archive-only readback rechecks 16 host and eight ART routes, along
with device process identities, result hashes and cleanup. Six public-linkage
mutation controls are rejected. Native execution authenticates signatures and
report MACs; the public archive reader does not claim to authenticate them. No
device keys, wrapping keys or journals are archived.

`FAILURES.zip` preserves two qualification-driver failures. The first original
ART route passed, but progress persistence reused an exclusive-create JSON writer.
Its executed result was reread before continuing. The transition driver then
exceeded ADB's observed shell-service command budget by resending retained approval
material: about 77 KB versus 64 KB for the original route. Read-only `true` commands
passed with 60,000/63,000 payload bytes and failed with 66,000/76,000 bytes. The
driver now transfers only newly available stage approvals into immutable input
slots, with an explicit command-size bound. SDK authentication is unchanged. All
four ART routes subsequently ran from fresh installations with the same APK/AAR.

The adapter is not yet integrated into the main source qualifier. The main
retirement integration run remains a separate source-bound producer; its inputs
must stay frozen until terminal completion. The subsequent
[noncommit/cancellation checkpoint](../20261012-android-root-controls/README.md)
adds direct API coverage with the same AAR. Final distribution integration and
the full 0.2.0 release scope remain separate work. The candidate interface is not
declared frozen or published.

See [the application call sequence](ACCOUNT_ROOT_USAGE.md), [combined checkpoint](CHECKS.json),
[host checks](HOST_CHECKS.json), and [ART checks](ART_CHECKS.json).
