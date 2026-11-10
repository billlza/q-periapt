# Android 16 KiB guest ART crash observations

This is a diagnostic supplement to `20261105-platform-cleanup-observations`,
not a successful Android qualification or a retry. Both original jobs remain
failed because package removal was not confirmed.

The retained guest log from PR #118 push job `127186189837` records
`system_server` PID 551 receiving SIGSEGV at `12:01:58.024`, in
`art::gc::collector::MarkCompact::ScanObject<true>`. The first recorded start of
the SDK application is later, at `12:02:43.486`, under the restarted system
server. These two timestamps come from the same guest log.

The PR #117 push job `127187316739` records instrumentation finishing at
`12:05:21.212`, followed by `system_server` PID 544 receiving SIGSEGV at
`12:05:39.783`, in `artInstanceOfFromCode`. Its uninstall attempt encountered a
broken package-service pipe, and the subsequent bounded checks did not confirm
removal. This ordering also uses a single guest log.

Both guests reported 16,384-byte pages and the image fingerprint
`google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys`.
The two ART stacks have build ID `e4a3c6c284a8b17d09fd84d661cf181b`.
`READBACK.json` identifies exact log members, hashes, line numbers, timestamps,
frames, and pre-run memory readings. Matching image metadata does not identify
the two jobs as the same emulator instance.

These observations establish guest system-service native crashes. They do not
establish a shared ART defect, memory shortage, a specific upstream fix, or the
cause of every later cleanup failure. The captured frames are in ART rather
than the SDK native library; this is not a proof that every possible SDK
interaction is irrelevant. Decoded SDK instrumentation reports from the earlier
capture passed three tests in each job, but that does not override failed
cleanup or make either whole job pass.

`CAPTURE.zip` retains both original GitHub diagnostic ZIPs and the structured
readback. `CAPTURE.json` records every member's size and SHA-256. The archive was
CRC checked and every member was read back byte for byte. No system image,
memory limit, GC configuration, permission, test deadline, or release claim was
changed, and no remote rerun was triggered.
