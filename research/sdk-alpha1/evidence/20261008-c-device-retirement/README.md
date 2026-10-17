# Restricted C device retirement

This checkpoint extends unpublished `qpc-owner/1` with 13 restricted retirement
entries, for 119 total C exports. Product ABI 2 remains unchanged. The adapter
delegates to `RetiredDeviceEnrollment`; it does not implement another retirement
state machine or release operational signer/runtime authority.

On macOS arm64, Debug and Release each pass eight actual C cleanup processes.
The workload preserves the complete original report and host accounting, verifies
the independent purpose-21 acknowledgement, and reconciles exits without completion
after report persistence, journal erasure and signer erasure. Native Rust
independently reconstructs and compares the complete report, checks session/message
accounting and rejects ordinary enrollment after erasure. C also checks preparation snapshots, malformed/short receipt refusal,
wrong owner kind, cancellation, unchanged error outputs and consumed handles.

The unchanged original C registration reader passes its one executed/27 filtered
test census after the new workload moved into a separate test target. The original
native connection/replacement/retirement regression also passes. Rust 1.90 checks
all targets, Rust 1.98.1 strict Clippy passes, all 10 admission/layout tests pass,
and the 17 directly affected artifact tests pass with warnings treated as errors.
Earlier broader artifact tests and failed development attempts remain in captures.

`QUALIFICATION.json` binds changed source hashes, build/runtime commands, exact
binary identities and the capture digest. `CAPTURES.zip` contains logs, development
drivers, source-copy identities and explicitly exported synthetic public records.
It excludes wrapping keys, signer files, TLS private keys and private databases.
The admitted SDK crate report still matches the unchanged SDK workspace; this
checkpoint itself uses copied C sources with repository dependency patches.

This is source-based development evidence. Fresh installed-archive qualification,
Swift/Kotlin retirement owners and complete foreign replacement remain open.
Enrollment/replacement authority and fresh-generation TLS here still run in Rust,
on the same host and implementation. Logical erasure is not physical erasure or
destruction of backups/wrapping keys. No device, independent-protocol or release
qualification is claimed. CI now retains native and C retirement public outputs;
the live Rust CodeQL run must finish and retain its results before another push.

`REVIEW.json` and `REVIEW_CAPTURES.zip` retain the clean-clone source gate and
32 follow-up artifact tests. The reader rejects additional failed/ignored tests
with qualified names and extra result summaries, and rechecks both actual C
profiles. Header/docs now correctly distinguish canonical metadata bytes from
the separately returned keyed report ID; the cryptographic implementation did
not change. Installed execution from the frozen `ce70bf83` clone is still a
separate gate.

`PURPOSE_CONTROL.json` adds a real valid-signature substitution through both C
profiles: a purpose-20 report-retention receipt cannot authorize purpose-21
journal erasure. It returns `QPC_AUTHENTICATION`, consumes the admitted owner,
preserves failure output, and exact reopen observes the original journal still
Retained. The correct host ACK then completes the original flow. Native library
bytes are identical to the development component; only the C consumer gained
this additional negative control.
