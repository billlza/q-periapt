# Communication schedules and retained-key exposure

This analysis presents the complete seven-schedule comparison already measured
by the pinned SPQR reference, its isolated 64-byte variant, and the three
whole-KEM controls. It uses the immutable corpus files at
`228c944fc476e3e57d6c08063cacb19bca5b360e`. The same files are byte-identical at
integration checkpoint `358b921ab3469ce49f166633fc9a762ff6ed7e3d`.
`source_identity.json` records the repository paths, Git blobs, lengths and SHA-256
digests. The four original JSON files are retained under `sources/`.

The displayed coordinate is endpoint A, after its first send and before send 1,
with 2,047 future sends. The analysis preserves each predictor's exact
reconstructed-key count and the count derived through a pending KEM private key.
It also computes mean component bytes per send from each trace's integer byte
total and its 2,048 sends. Decimal display uses three places with ties to even.
All six cuts and both owners remain in `analysis.json`: five profiles, seven
schedules and twelve snapshots give 420 cases.

The parser authenticates the four input files, rejects duplicate JSON keys and
non-finite numbers, and validates complete schedule and snapshot coordinates.
It checks future-send accounting, pending-key subset counts, actual drop and
duplicate counts, and each trace's declared unique-key inventory. These are
checks of the retained reports. The original Rust drivers and independent
predictors retain their native execution and cryptographic validation evidence.

From the repository root:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/reference-comparison/analyze_reference.py --check
```

Omitting `--check` regenerates `analysis.json` and the manuscript module
`reference-schedule-table.tex`. The check mode requires their exact deterministic
contents. The manuscript workflow verifies them before export.

The columns preserve the individual constructions' authentication and retention
interfaces. They measure component wire traffic and reconstructed message sets;
the source-backed Continuity comparison remains the next protocol experiment.
