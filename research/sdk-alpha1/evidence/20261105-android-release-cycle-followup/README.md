# Directly supervised Release joint-cycle follow-up

The six previously unfinished Release joint-cycle routes completed on the
original installed `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20` cohort. The actual
test command returned zero in 553.412 seconds; the follow-up including input
checks and readback took 557.086 seconds. The original 900-second command and
16 MiB stream bounds were retained.

Each route used fresh private fixture state. Both fixed and recoverable trust
ran over local, signed-witness and TLS carriers. The unchanged verifier checked
two applied credential/policy generations, three actual expiries, and retention
of the original identity, session, message and durable effect. The route census
is 57 foreign adapter processes for each local route and 80 for each signed/TLS
route, totaling 434. Actual test output reports six passed, none failed or
ignored. Original, public-export and archive-export copies all passed the same
existing route verifiers.

The Python owner supervised the Rust test process directly. There was no outer
Python supervisor with a separate aggregate timeout. A prior two-second
negative control exercised this same direct ownership shape: timeout remained
an error, both leaf and group leader disappeared, and no manual cleanup was
needed. The previous nested-layout counterexample remains preserved separately.
This change corrects the follow-up execution layout; it does not extend the
primitive into a general detached-process-tree supervisor.

The original five-hour aggregate remains failed. Its absent terminal consumer
and driver reports have not been fabricated or rewritten. This follow-up is
additional component evidence, not a replacement successful record for that
expired run. The old private fixture state was retained and was not reused.

The follow-up checked the pinned source inputs, original C consumer sources,
JDK identity, previously sealed Java archive, installed C library/receiver,
and its selected runtime files. Runtime identities were checked again after
execution. The archive retains actual test executable, JNI bridge, C runtime,
Java classes, public transcripts, drivers, source, original timeout receipt
and direct-timeout control. Private keys and mutable private storage are omitted.

`CAPTURE.zip`: 11,191,512 bytes, 1,941 members, SHA-256
`ffe3c4990631edff741acb2308f2742b1ef08cc6eb6149e32d92f6106ba2a716`.
Every member was CRC checked and byte-compared; `CAPTURE.json` contains the
closed inventory. All six route verifiers also passed on archive-exported data.

Scope remains macOS arm64 host JNI with the original installed C cohort. This
does not qualify the newer Windows-fixed source, an Android ART/emulator/device
run, the entire failed parent invocation, or a final release.
