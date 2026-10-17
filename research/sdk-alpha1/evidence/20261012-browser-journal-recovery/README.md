# Original encrypted journal recovery over browser OPFS

The original `DeviceJournal` now has one private `open_database` seam below its
native private-file admission. Native `open` still admits the file first and then
runs the same authenticated recovery body. No caller can supply an arbitrary
storage backend through a public journal API.

An isolated qualification checkout uses that seam with the previously exercised
OPFS backend. Its fixture module is absent from production source and package
exports. It calls the original `install_roster`, encrypted aggregate codec,
HMAC-authenticated `PendingWrite`, intent/state transactions and reopen recovery;
it does not implement a second journal state machine.

A fresh native journal and dual-signed identity/roster inputs are copied into
real OPFS files in Chrome 154.0.8037.99 on macOS arm64. The test fixtures use an
explicitly public constant wrapping key, byte 71 repeated 32 times. Real device
and root signing owners generate the public credentials/rosters and are closed;
their private keys are not exported. This experiment does not qualify browser
key provisioning or treat its archived test ciphertext as confidential data.

[RESULT.json](RESULT.json) records the normal update and exact retry, eight
injected I/O failures, eight actual Worker terminations and three wrong-opener
controls. A roster change takes two original two-phase transactions: first the
exact encrypted intent, then the state and intent removal. Every flush is
interrupted both before and after its real OPFS call.

| Interruption | Original state before journal recovery | Reopen result |
| --- | --- | --- |
| Flush 1 | Revision 1, no committed intent | Revision 1; exact roster may be retried |
| Flush 2 or 3 | Revision 1 plus original authenticated intent | Revision 2 with that intent's original encrypted target |
| Flush 4 | Revision 2, intent already removed | Same committed revision and encrypted image |

I/O errors return `CommitUncertain` with the injected cause and close the journal.
Worker cuts withhold the operation response; the controller waits for actual
lease release before reopening. A same-head retry performs zero writes and
zero syncs. Older and forked signed heads return `Protocol(Checkpoint)` and leave
the current image unchanged.

At the retained-intent boundary, a wrong wrapping key returns `Authentication`;
a wrong journal ID or device owner returns `Conflict`. Each attempt leaves the
original encrypted image and authenticated pending intent unchanged. This is
not a claim that redb performs no file-metadata I/O during open/close. The first
cut runner incorrectly expected authentication failure for the wrong owner.
The shared decoder checks the owner header first; the failed run is retained,
and a fresh test directory completed all eight cuts with the precise contract.
No product validation was relaxed to accommodate that script error.

The original pending file and browser recovery file are retained. The native
journal opens a separate copy of that same pending file through its original
private-file admission and authenticates/reconciles it. A separate native redb
reader then compares the stored bytes: the **6,098-byte target in the original
intent equals both the browser and native committed images byte for byte**, and
both completed files have removed the pending row. This is shared-engine
cross-target recovery, not an independent protocol implementation.

Native admission/corruption regression and the original responder recovery test
pass; the latter checks 40 sync failures across its five intent/state pairs.
Native all-feature and browser Clippy checks pass with `-D warnings`, and the
modified production file passes rustfmt. Initial probe-only compile errors are
retained with the failed cut-runner result.

[CHECKS.json](CHECKS.json) pins the 84-member [CAPTURE.zip](CAPTURE.zip), SHA-256
`c102d2e0ca83ac80b7b7f7a7a3011c3c7173705499a26a00014f3b5b59260254`.
The archive includes exact WASM/glue, native and browser database files, public
fixture metadata, source patches and probe sources, all runners and raw logs.
Every member was reread. Final Web Lock inventories were empty, the owned browser
was closed, and both owned servers terminated with status 143.

This exercises the existing **local journal** policy. It does not permit a
witness-required policy to operate locally. Browser installation/publication,
retained key owners, account/root transitions, asynchronous witness and peer
transport, live cancellation, whole-profile rollback and eviction recovery remain
integration work. The full browser Continuity owner and 0.2.0 release are not
admitted by this checkpoint. The next step must preserve these same original
intent and authority rules across the asynchronous witness boundary.
