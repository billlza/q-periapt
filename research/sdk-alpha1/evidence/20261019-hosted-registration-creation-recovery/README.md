# Hosted initial-registration recovery

Both terminal jobs in run `39216522760` passed at source
`ad3568427a0f22739b940bb17015c6d254acddce`: Apple Silicon/macOS and Linux x86_64.
The captured source and artifacts belong to that commit, before the separate
protocol-policy publisher was added.

Artifact readback checked the exact source, artifact digests and contents, Rust
Debug/Release 26 entries, 17 browser model tests, strict Clippy/build, and the
installed independent wheel's eight adapter and 16 client tests. The client
checks cover recovery of the same complete initial record, repeated recovery,
corruption/truncation and scope/advanced-state refusal. Missing complete original
records remain explicit failures; recovery never resets the device identity.

`RECEIPT.json` and the capture's `PUBLIC_MANIFEST.json` identify the two original
40-member CI artifacts, source snapshots and reader. This receipt consolidates
already-completed runs and does not rerun them. It does not establish real
browser-authorized device enrollment, operational policy publication, full
lifecycle acceptance or 0.2.0 release readiness.
