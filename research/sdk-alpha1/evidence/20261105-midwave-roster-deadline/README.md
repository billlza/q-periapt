# Mid-wave roster deadline failure

The current remote wave remains incomplete. Run `42008993544`, job
`127182900723`, failed the Debug MSRV 1.90.0 roster-capacity test at source
`232ace17915407596d66f3a5fd7c7765251a38cc`. The runner artifact identifies Linux
x86_64, four online CPUs, approximately 16 GiB RAM and AMD EPYC 9V74.

The test ran for 816.42 seconds. Its last progress record was
`credential-renewed member=24` for a 32-member account. The subsequent original
account commit panicked with `anchor attempt deadline expired`. This is the
per-attempt three-second AnchorClient budget, not a reported job or aggregate
test timeout. The same error text can arise before signing, after signing,
after transport, or after reply verification. Existing evidence does not
identify which check expired or establish whether witness processing committed.
No timeout, assertion or protocol behavior has been changed to admit this run.

The exact source files, complete job log, five-member failure artifact and two
sets of live workflow snapshots are retained. The artifact's SHA-256 is
`7c8c2717154802e31905ed323c5485bf7863fca04c2b5c011f6425fcbb2e683c`.
The newer Windows PR log `127182954014` contains the same six test import/helper
errors already fixed locally in `8c182c777d70ad5f9c0a5a3b0fbc0f8d9e6b4916`.
That remote job remains failed; local cross-target checks do not replace its
required Windows execution.

`CAPTURE.zip`: 239,646 bytes, 32 members, SHA-256
`b6e985bba44b42b2738779b746ff64a2d775b29ad52c715d93c59a03d2d2bea6`.
Every member was read back against `CAPTURE.json`. Snapshot folder labels are
collection labels; individual job timestamps and counts are retained verbatim.
Jobs were still queued or running in the latest snapshot. No rerun,
cancellation or new remote push was performed.
