# Current-wave native Release and reference readback

The 2026-11-05 04:29:22 UTC snapshot refreshed all four open run inventories and
both PR heads. Eight completed inventories retain their earlier terminal rows.
PR #117 remains `475cd23923e45819b01b6041c91c44540ec056ec`; PR #118 remains
`6084f3bfb09333f6b66291b38809ed512296a27b`. Both are open. Across twelve runs,
333 jobs comprise 292 successes, 20 failures, three running, 16 queued and two
skips. No newly failed job appears since the 04:10 snapshot.

[Native Release job 126445763257](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126445763257)
passed on actual PR #117 merge checkout
`9aa535b48b464ec4d4a8b5a4b20221049a6067b9`. The complete decoded log records
1,451 library cases plus 32 other candidate cases and 31 SDK cases, all with
zero failed/ignored cases. This is the old hosted source's test inventory;
it is not the later local maintenance inventory or a rerun of newly added tests.
The independent public verification steps were skipped in this Release matrix
row and are not counted as executed. The native result upload succeeded:
artifact 13388450071, 62,119 bytes, digest
`533a898c28102e4dadd8d9749af6d5359e8d5316ad27e7b5ebab9d2f392f9c45`.
This success does not close the distinct Debug upload/order failure or qualify
the local corrected step ordering on a hosted runner.

[Reference job 126445737533](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126445737533)
passed on actual branch checkout
`475cd23923e45819b01b6041c91c44540ec056ec`. Its log records two executions each of
the pinned reference corpus and isolated 64-byte experiment, with seven
scenarios/14,336 sends per execution; the whole-KEM controls each record three
profiles, 21 scenarios and 43,008 sends. Their verification steps and evidence
upload succeeded. Reported artifact 13387463747 has 24,658,856 bytes and digest
`df830a22cc95c42201977f29804a8c9ab1da2dfe0fca02bcf76fc6bf64b8dc40`.
These replay results do not establish product performance, a protocol theorem,
or current-candidate platform qualification.

Neither artifact was downloaded locally. `CAPTURE.zip` retains both full
decoded job logs, step metadata, the complete snapshot, the previously captured
native workflow at the named merge, the classifier and its output. All eight
members were reread: 251,612 bytes, SHA-256
`5fa04b448f5267ba59f198518b932a392ab4a3efb92fd7a9b420b033adecae85`.
The current effective wave remains open. No push, rerun, cancellation or new
workflow was performed, and none of these results is a release claim.
