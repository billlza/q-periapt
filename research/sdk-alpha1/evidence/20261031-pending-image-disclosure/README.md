# Pending-image reservation disclosure

This checkpoint establishes a concrete acquisition boundary at source commit
`4ae5f77ad6e81dce956be24511d7f5e429924bde`. It does not change the protocol or
the multi-epoch MAIN formula, and it is not a full computational or refinement
proof.

An isolated test-only patch interrupts a real child after its exact pending
write has committed, before the target becomes the current image and before
the KEM result is computed. Raw readback authenticates both rows without
ordinary open automatically applying the target. The current image lacks the
new token; the retained target contains it. Ordinary recovery then installs
the original sealed target byte for byte and preserves the original token.

For generation and encapsulation separately, the predictor receives only the
captured journal identity, old root, wrapping key and token, followed by public
control flights and ciphertexts. It receives no signer or later private state.
Each case decrypts six freshly generated application messages after restart,
three per direction. A wrong wrapping key fails. These observations require
including a captured `pending` target in exposure accounting; they do not
contradict MAIN after its exposure premises have been properly applied.

The corrected native Debug run passed both exact tests with Rust 1.98.1,
`--locked`, `-D warnings`, two build jobs and the existing 900-second command
bound. Each command filtered 1,389 other tests; those are not passes. The
original compile rejection for a missing test-only `ReadableDatabase` import
is preserved. The import was corrected without weakening checks or changing
runtime code. Process interruption is not physical power-loss qualification.

- [Capture receipt](CAPTURE.json) identifies the tested source, outcomes and archive.
- [Evidence archive](CAPTURE.zip) contains the exact baseline/probe source,
  `ISOLATED_PROBE-formatted-v2.patch`, reproduction drivers, raw failed/passing
  streams, owning-source snapshots and unchanged model excerpts.
- [Readback](READBACK.json) records archive and member identity checks.

To reproduce, apply the retained patch in a separate clean checkout at the
named baseline and run the two exact test names in
`attempt-02/CHECKS.json`. Do not reset an existing working tree. The patch is
retained here as an isolated regression asset; it is not installed in the
product source by this checkpoint. Captured fixture secrets are not included
in this archive.

The accompanying report also traces public pending-intent and retired-cleanup
fingerprints, complete public session/fanout metadata projections and
closed-epoch report keys. Their joint computational simulation, the full
whole-journal/signer/auxiliary-record mapping and post-quantum composition
remain separate obligations. No final package, platform, external-review or
release qualification follows from this checkpoint.
