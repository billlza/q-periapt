# Linux independent control requests and target recovery

The Linux x86_64 [job 117715177507](https://github.com/billlza/q-periapt/actions/runs/39140980688/job/117715177507)
completes successfully at `a6760a651c19ae481510ff7e7c87a6a4a702718a`.
All seven runtime lanes pass, including the new independent control-only path.
Apple Silicon is still queued when this checkpoint is sealed; its separate local
ARM64 qualification does not substitute for that hosted job.

The original artifact is 4,984,289 bytes with 1,884 members, SHA-256
`f6e3b1a10feeea268c8ce47e6c8f7a336407a21f2d324455a32fbd7bde775a15`.
Both local public readers complete without diagnostics. They verify all 40
committed source hashes and the actual ELF x86_64 counterpart, SHA-256
`a876407985d050708db058177ccdfeb4d08e80c34b5a01b04b44351d67d1c2e0`.

The control lane retains seven targets, 111 fresh-process operations, 80 native
commands, 13 real SIGKILL cuts, 101 control results and 33 unique signed controls.
Public replay checks the original request/offer/receipt bytes, both signatures,
complete transcript chain, worker PID/cut markers, command hashes, current targets
and observed original application plaintext. The actual runtimes also exercise
13 private codec refusals and explicit version-two-to-three upgrade with pending
send/rekey state. Private images are not exported for public replay.

The four bounded fault schedules cover both initiating roles, dropping and
duplicating every distinct flight once without dummy application messages.
These are deterministic control-pipe tests; they do not qualify a network carrier
or establish scheduling performance/energy. Request preparation, cached output,
exhausted application budget, unsettled history and lost-final-receipt recovery
retain their separate meanings.

The six previous lanes remain passing: eight durable rekeys/150 workers/11 kills;
122-message exact-fit capacity admission; 19 storage kills/46 controls;
six epoch-zero kills/27 workers/nine native commands; eight volatile rekeys/132
commands/108 refusals; and 41 bootstrap/traffic commands/51 refusals. Their
complete public outputs remain in the same original artifact and are checked by
the separate regression reader.

`CAPTURE.zip` contains the exact downloaded artifact, both readers and outputs,
download validation, source files and job metadata. Its manifest verifies every
captured file. Required witnesses, renewal/revocation, application epoch resolution,
installed/cross-host identity lifecycle and disclosure/refinement analysis remain
open. No hardware power-loss, erasure, PCS proof or full release claim follows.
