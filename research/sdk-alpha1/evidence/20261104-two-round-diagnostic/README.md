# Two-round witness search with diagnostic proof projection

This bounded diagnostic retained the operational model and all 40 original
query formulas, modes and attributes. It searched only
`two_rounds_recover_with_exposed_ancestor_is_executable`, temporarily projecting
the other 39 proof bodies according to the existing
[fragment-replay workflow](../../../continuity-recovery-symbolic/FRAGMENT_REPLAY.md).
The original complete certificate was retained unchanged. Any successful fragment
would have required restoration into that certificate and a separate full replay;
the diagnostic was never eligible as an accepted proof.

Tamarin 1.12.0 / Maude 3.5.1 again exhausted the unchanged 12-GiB heap, exiting
251 after 628.084 seconds, within the 900-second command bound. Search depth 256,
one worker, `-c30`, the 60-second derivation check and `--quit-on-warning` were
unchanged. No proof output or restoration was produced, and no independent replay
was started. The RTS reported maximum residency of 11,181,761,240 bytes and
12,480 MiB total memory; neither number is whole-process peak RSS.

This shows that projecting the supporting proof bodies did not resolve this
search within its bounds. It does not show that the witness is impossible or
supply a counterexample to the protocol. The previous successful main theorem
and 24 reusable dependencies remain scoped to their
[joint replay](../20261104-multi-epoch-replay/README.md); the 13 incomplete queries
remain incomplete. No automatic retry or resource-limit increase followed.

The canonical archive and both fixed tool binaries were rehashed unchanged
after failure. `CAPTURE.zip` retains the original and diagnostic theories, exact
driver/checkers, plan, terminal receipts and complete streams. Its 16 members
were reread byte-for-byte: 90,077 bytes, SHA-256
`82c00ba8efdad4b4d30077d8f40a74653c5169b717191d581a81838c66e25d80`.
