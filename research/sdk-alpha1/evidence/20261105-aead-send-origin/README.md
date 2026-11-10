# Original send-input and retry evidence

Four existing native cases passed in both Debug and Release on
`39d35880b7f5bff012f9a1b09588adebb3bd22dd`, with Rust 1.98.1, locked offline
dependencies and warnings denied. No product or Rust test source changed.
These focused executions support the
[send-origin argument](../../../../docs/continuity/AEAD_SEND_ORIGIN_V1.md),
not the complete native suite, distinct derived keys or an AEAD/multi-epoch
security theorem. Each invocation runs exactly one named test and filters the
other 1,458 library cases.

| Profile | Case | Result | Test runtime | Provenance |
| --- | --- | --- | --- | --- |
| debug | single-sync | 1 passed, 0 failed | 37.28s | retained first execution |
| debug | fanout-sync | 1 passed, 0 failed | 5.22s | retained first execution |
| debug | fanout-process | 1 passed, 0 failed | 5.21s | retained first execution |
| debug | unsafe-reset | 1 passed, 0 failed | 1.91s | completion execution |
| release | single-sync | 1 passed, 0 failed | 33.04s | completion execution |
| release | fanout-sync | 1 passed, 0 failed | 3.93s | completion execution |
| release | fanout-process | 1 passed, 0 failed | 4.41s | completion execution |
| release | unsafe-reset | 1 passed, 0 failed | 1.33s | completion execution |

The aggregate sync case measures nine barriers and injects 18 before/after
faults per profile; recovery observes absent, reserved and committed states
without splitting member outcomes. The process case has **two** recipients and
a send budget of four. It kills owned children after reservation, after the
first private ciphertext computation and after aggregate commit. The previously
computed ciphertext equals the recovered ciphertext, replacement input is
refused, and competing writers return Busy.

The unsafe-reset case first confirms the shipping API's refusal. It then mutates
only an isolated, unpersisted private state, replaces the pending plaintext and
checks actual ciphertext-XOR/plaintext-XOR equality under the reused key. The
real abandonment API freezes and closes the affected sessions. This is a
negative composition control, not an admitted production attack. Across both
profiles the selected cases include eight owned child terminations; none is
physical power loss. Temporary fixture stores and private directories are not
exported. The precommit wire equality is asserted inside the executed test;
this capsule preserves its source and execution receipts, not those temporary
wire files.

The first outer reader failed after all three initial Debug commands passed:
it interpreted `Network::new(4, false)`'s budget as recipient cardinality. The
original script, traceback, failed result and streams are retained. Source
inspection establishes the actual two-recipient fixture. The corrected reader
rereads those three successful Debug commands, runs the Debug unsafe-reset case
and all four Release cases, and completes. No Debug command was rerun to erase
the original reader failure, and no product test assertion was changed.
Both attempts keep a 1,800-second parent limit, 900-second component limits and
16-MiB stream ceilings. Their elapsed times are 53.185 and 52.667 seconds.

The source inventory contains 21 pinned candidate files. Literal call-order
checks locate reservation before encryption, encryption before commit/release,
exact pending-input comparisons and cached outbox returns before key derivation.
These anchors support manual review; they are not a control-flow proof checker.
Actual Debug/Release test binaries were also reread and hashed. The conditional
simulation caches the first private encryption result by original send origin,
including later public ciphertext-digest observations. Distinct-key bounds,
challenge-plaintext comparison, receiver security and full composition remain
open.

`CAPTURE.zip` includes the original and corrected drivers/results, all eight
command receipts/streams, pinned source, the note and storage contract. All
83 members were reread byte-for-byte: 464,564 bytes, SHA-256
`8f8851e93417983da4454f8140174294868caf00d61a7fd1ff64aba1ffdc8cd6`.
`SOURCE_AUDIT.json` records scope, exact tests, binary hashes and the reader
correction; `FILES.json` binds all retained members. No hosted workflow or
remote branch changed.
