# Linux independent durable rekey

The Linux x86_64 [job 117708434545](https://github.com/billlza/q-periapt/actions/runs/39138698714/job/117708434545)
completes successfully at `0466b276ac4780489cc92d533eac0f02917f071a`.
Its downloaded artifact has SHA-256
`08c5824dd079c4b8ef108c3f37473b3435cda619bfb0061b6b5f61927a9b1009`.
Apple Silicon remains queued when this checkpoint is sealed; this is a Linux
result, alongside the separate local ARM64 checkpoint.

The independent public reader verifies the exact 36 committed source hashes and
the actual ELF x86_64 counterpart, SHA-256
`adfc3507ad7c1951e01bf6b48f03dd51d79cb149a61b99e31640623bafd40e43`.
It rechecks eight durable rekeys, 150 fresh-process operations, 11 real SIGKILL
cuts, 75 native commands and all 32 signed rekey flights. The original signed
budget-four boundary, retained old outbox/ACK, original operation identities,
explicit old-format upgrade, expired status and close-before-release controls
all pass. The 122-message capacity boundary refuses the infeasible reservation
before commit and admits the exact-fit operation.

The same artifact retains and passes 19 primitive-storage kills/46 controls,
six epoch-zero kills/27 worker operations/nine native commands, eight volatile
rekeys/132 native commands/108 refusals, and 41 bootstrap/traffic commands with
51 refusals. Worker PID/cut records, command inputs/outputs, application bytes
and result hashes are checked independently after download. Secret KEM/MAC/AEAD
verification takes place in the actual runtimes; the public reader uses no private
images or keys.

`CAPTURE.zip` includes the original downloaded ZIP, all 36 source files, job and
artifact metadata, the strict download/readback scripts and their outputs. The
first adapted reader used the lane name `exchange` for the case `bootstrap-final`;
that path-mapping error and its failed trace are preserved. Restoring the original
case name makes the same checks complete; no runtime change was needed.

This qualifies the bounded local-only independent durable owner on Linux.
Required witnesses, renewal/revocation, application epoch resolution, independent
control requests, installation and cross-host/package qualification remain open.
No hardware power-loss, erasure, PCS proof or full release claim follows.
