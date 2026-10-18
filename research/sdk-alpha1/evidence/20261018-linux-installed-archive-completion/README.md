# Linux installed execution completes its final archive guard

The full Linux installed Rust/C [job 117682462608](https://github.com/billlza/q-periapt/actions/runs/39129232908/job/117682462608)
completes successfully at `23280124efd2f0f3003d4ce85e3db665f6ec8a25`.
Both Debug and Release run. The terminal package receipt has `completed=true`,
`partition_completed=true`, unchanged source identities and no failure. The
overall multi-platform workflow still has queued jobs; this checkpoint does not
call that entire workflow successful.

The 92,282,597-byte artifact contains 35,089 files and has SHA-256
`d4b0f8d780ec02d4fd05843821d87bcc84e673cff7911456300b2686ba76c960`.
Local readback verifies all 1,132 recorded source inputs against the exact Git
commit, equal before/after source inventories, the original installed dependency
graph and the final candidate archive guard. The candidate archive is 1,513,668
bytes, SHA-256 `02f1093562c3c45727367e8dabe25fd017ca8cd4c08b013a2e868aa2690f4397`.
Strict C11 input compilation and actual seek/tell/byte-preservation results are
verified for both profiles.

The original public readers also replay five Rust lifecycle records per profile:
enrollment, reopened enrollment, roster renewal, device replacement and retirement.
Seven C account contracts per profile replay account ownership, ordinary/own-account
delivery, TLS, ordinary/own-account TLS loss and witnessed delivery. These ten Rust
and fourteen C public replays agree with the recorded runtime results. Other C
checks retain the producer's successful observations; they were not all replayed
locally in this checkpoint. Binary hashes absent from the download remain producer
observations, not independent local binary verification.

Two local reader corrections are preserved: the selected Linux `/tmp` root must
be canonicalized on macOS before using the original path verifier; four loaded
reader modules outside the producer inventory are checked directly against pinned
Git. All original assertions remain, and the final reader exits successfully
without diagnostics. These were reader-environment/closure errors, not new native
runtime failures.

This supplies the new complete installed job required after the earlier final
archive `NameError`. The earlier failed job and its actual red/green guard replay
remain historical failures and evidence. Product SDK, candidate, bindings and
toolchain sources are unchanged through the independent-reference increment.

`CAPTURE.zip` contains the job receipt, complete package/C reports, source and
dependency receipts, candidate archive, selected command outputs, public replay
results and all reader attempts. Full original replay additionally needs the raw
artifact retained at `target/unix-installed-2328-01/installed.zip` or GitHub artifact
`12139878770`. The capture manifest checks every included file. Same-engine,
same-host installed execution does not establish an independent protocol,
hardware power-loss, performance or full release qualification.
