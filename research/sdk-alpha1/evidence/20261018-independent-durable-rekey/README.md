# Independent durable rekey and explicit format upgrade

The Python/OpenSSL reference now persists the original four-flight rekey,
directional cutovers and at most four traffic epochs independently of Rust/redb.
This checkpoint is based on `dcc7857a0f8ebfe5948c5111bf479b42892cf0b9` plus the
36 exact runtime source files recorded in `CHECKS.json`; hosted validation of this
increment is still pending. The actual counterpart is an ARM64 Mach-O binary with
SHA-256 `a84528fed78e1774820e5095bc5f8ed5f1c57109a7d11c360fdf9457a2b8607b`.

The final local owner run completes eight alternating rekeys, 150 fresh-process
operations, 11 real SIGKILL cuts and 75 actual Rust commands. Nine cuts concern
rekey protocol stages, one head publication and one explicit format upgrade.
All 32 identity-signed flights, public application bytes, worker PIDs and result
hashes pass a separate readback. Secret MAC/KEM/AEAD checks execute in the actual
interoperating runtimes; the public reader does not load private journal images.

The old snapshot writer is loaded from the previously committed storage capture,
with its source hash checked. Its epoch-zero state remains usable without an
implicit migration. Explicit upgrade commits the original state into `QPREFS02`,
survives an interrupted publication and is idempotent; the actual old reader
rejects version two. This is a session-format upgrade, not a complete installed
product upgrade workflow.

A real signed send budget of four blocks additional sends while two old-epoch
and two unconfirmed new-epoch sends remain charged. ACKs do not refund that
budget. Receipt confirmation advances its window, allowing the originally
unallocated message ID. An old unacknowledged outbox blocks retirement at target
four, remains exactly recoverable and admits the same pending offer after its
original ACK. Missing/wrong external signing owners, closed send directions,
future receives and expired authority are refused; status remains readable.

Three defects were reproduced and repaired in this new reference prototype:

- A pending plaintext fit while its eventual ciphertext row exceeded the image
  allowance by 113 bytes. The old prototype committed an impossible reservation.
  With 122 real full-size outboxes across two epochs, the repaired admission
  rejects 13,700 bytes before changing the head; 13,587 bytes fits exactly,
  commits, reopens and decrypts in Rust.
- Repeated interrupted head publication allocated another staging file and
  exhausted the 128-entry quota. A reserved output slot now finishes only the
  exact authenticated target prefix. Three kills at the quota recover that
  target while all 125 unrelated staging files remain unchanged. Three additional
  partial-prefix controls are constructed states, not syscall-interruption tests.
- A post-commit observer could close the owner yet still receive ciphertext.
  Result release now checks the owner again; the same committed ciphertext is
  recoverable by reopening the original store. Closed directory checks also
  prevent a missing descriptor from selecting the process working directory.

The original red traces and pre-fix source versions are retained. These were
defects in the uncommitted independent implementation, not newly demonstrated
defects in the established Rust SDK. Failed private fixtures remain local.

Separate regression lanes pass: 19 primitive-storage kills and 46 controls;
six epoch-zero session kills, 27 worker operations, nine native commands and
six malformed-codec controls; eight volatile rekeys with 132 native commands and
108 refusals; and 41 bootstrap/traffic commands with 51 refusals. Strict native
release build/all-target Clippy, rustfmt, actionlint, Python parsing and public
readback pass. The tracked Rust inventory remains 722.

`CAPTURE.zip` contains the six final public lanes, three failed public lanes,
exact runtime sources/binary, review and sealing scripts, and build/lint records.
Its manifest verifies every captured file. Path references identify separately
retained private fixtures; neither wrapping/signing keys nor private images are
included. The scripts retain their original workspace layout for reproduction.
`SOURCE_DELTA.json` records removal of one extra final newline in the shared test
driver after validation; the tested and committed versions have identical ASTs.
The capture retains the exact tested bytes. Hosted CI will hash committed bytes.

The owner has a different internal reservation cut from Rust: it persists the
generated offer key seed and computed unsigned response/root, then obtains
external identity signatures. Unsigned, unreleased signatures may be recomputed;
committed flights and authenticated intents retain their exact bytes. Disclosure
and refinement analysis must account for these cuts. No memory erasure,
whole-store rollback detection, hardware power-loss or post-compromise security
claim follows from these tests. Required witnesses, authority renewal/revocation,
closed-epoch application resolution, control-request scheduling, installation and
independent installed/cross-host lifecycle qualification remain open.
