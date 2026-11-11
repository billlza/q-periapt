# Original-record commitment inventory

This capture supports the [conditional six-interface argument](../../../../docs/continuity/HIDDEN_RECORD_COMMITMENTS_V1.md)
at source `eb08f978d4fa6a3fc1970ab0194007d21ade7355`. It records the actual
image/intent layouts and six raw-byte digest domains, including retirement,
Witness selection and account-root checkpoints omitted from the earlier
two-interface experiment. All eight target-bearing write tags retain the
24-byte image nonce. The three target-free cancellation tags are separate.

The audit reads source bytes, checks their Git identity, derives layout/domain
tables, records the relevant raw-pending uses and checks document links. Its
calculated offsets and pairwise domain-prefix comparisons are encoding checks,
not runtime qualification, a proof checker, or whole-program noninterference.
The mathematical argument is written in the linked note and applies
[Don–Fehr–Huang, Theorem 2](https://arxiv.org/pdf/2206.08132) under its explicitly
restricted experiment. No product implementation is modified by this capture.

`CAPTURE.zip` retains the audit procedure, selected original source files,
`AUDIT.json`, the three linked proof/review documents and the capture manifest.
`FILES.json` lists per-member sizes and hashes; `SHA256.json` records the archive
identity and full readback. No private journal image, key, pending target or
device state is included. Exact original-record acquisition, multiple images,
the accepted-prefix KEM simulator and complete multi-epoch composition remain
unclosed. The named reviewer has not assessed or accepted this result here.
