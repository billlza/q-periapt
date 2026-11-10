# Android policy and roster composition records

`CAPTURE.zip` is the unchanged prototype capture identified in
`PROTOTYPE_CHECKS.json`: eight host routes (544 calls) and two ART routes
(136 calls), with real original-policy expiry, independently authorized policy
renewal, and witnessed roster Applied/Closed recovery. It retains the executed
source, public records and command outcomes. The original check file describes
the implementation state at capture time; its then-open local-policy and peer
roster items are not a current project status report.

The first current-reader run rejected the original archive because it omitted
five public inputs per route, including `inputs/renewal-operation`.
`PUBLIC_INPUT_SUPPLEMENT.zip` retains those 50 original files recovered from the
completed case directories. `SUPPLEMENT_CHECKS.json` records byte-for-byte
agreement of every overlapping public file and both archive hashes. No input
was synthesized and the original archive remains unchanged.

`ARCHIVE_READBACK.json` binds the current readers to an independent extraction
and verification of both archives and all ten composed records. It checks
original identity/session/message preservation, policy authorization, terminal
retirement and the absence of a fresh Commit/Close in historical recovery.
Native execution provides signature verification; public record linkage alone
does not authenticate fresh authority.

The reader regression in `artifact/test_continuity_android_roster.py` uses these
real records to reject swapped Applied/Closed outcomes, injected historical
Commit/Close messages, altered policy bindings and state changes after refusals.
This does not replace the fresh Debug/Release integrated qualification.
The existing accepted phone satisfies the physical-device scope.
