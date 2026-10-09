# Android 16 KiB post-install transport failure at b1006eb3

PR CI job **113746848451** failed with exit 2. Its full SDK consumer completed
all three Instrumentation tests. The subsequent minimal consumer installed
successfully, but post-install ownership admission observed:

1. One exact APK copy, then only **1,119,744 of 13,702,871 bytes** and transport
   disappearance.
2. The existing one-shot transport recovery, followed by another exact copy.
3. A second truncated copy of **6,271,488 bytes**, then sustained absence and
   expiration of the bounded ADB validation deadline.

The minimal consumer never reached Instrumentation. Source lines 2622–2628
fail on nonconvergent ownership before the Instrumentation command at line 2675.
Later device diagnostics and cleanup could not establish the package state;
cleanup remains unresolved. This differs from the earlier 33ca8c5c failure,
where both workloads had passed and the truncated copy happened during cleanup.

The recorded ADB server log reports `connection terminated: read failed` at
both transport cuts. A retained guest log also contains a GMS JIT SIGSEGV before
these cuts. That observation does not establish causation; neither OOM, the
emulator image nor the SDK is identified as the disconnect root cause here.

The independently existing push job **113745724145** succeeded. Its branch
`b1006eb3ce3082f13a785c283b18f9b23a1b0f5f` and PR merge
`54c5409379e9c596944253e0c8c01721143ed582` have the same Git tree
`c5048d8e343f05f90cc6fb74119269f262fb435c`. The successful downloaded artifact's
actual AAR and both result JSON members match their proof hashes. Both profiles
report pass, and the failed/successful runs record the same AAR and ADB hashes.
Run IDs and signed APKs are distinct; full environment equivalence is not claimed.
This is observed intermittency, not a stability qualification or a causal test.

The failure diagnostics artifact **11605482905** is 102,255 bytes, SHA-256
`472ddde06b93b493ea8b72ab193ddd6288939f3eeb5405d6c87e6a8a955dcf27`.
The successful runtime artifact **11605992143** is 73,264,596 bytes, SHA-256
`9f0875ae11f9be76040290eb53b95c70923e346e586ac9de2450795cb081939b`.
Both API digests and sizes were checked against downloads. The latter large
archive remains local; selected proofs/readback and its metadata are retained
here. A full local replay of its runtime closure was not performed.

No application, emulator, ADB, timeout, ownership check or retry behavior was
changed. No new CI run was requested to obtain the successful comparison.
The failure's cause and stable Android 16 KiB acceptance remain open.
