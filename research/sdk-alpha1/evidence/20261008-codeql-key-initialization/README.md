# Zero-initialized key-buffer review

This completes the previously partial review of result **695** in the original
780-result Rust SARIF from run `37703091965`, job `113070951972`. Result indices
belong to that exact SARIF, whose hash is retained. This is not a disposition of
the newer CodeQL run and does not remotely dismiss an alert.

The report names 23 key sinks but provides only four data-flow traces. Every
named sink was now inspected, including its key producer and relevant persisted
or erased-state path. All 21 inspected files at `db9cac63` are byte-identical to
the analyzed `1ca9ba6b` tree. `SOURCE_IDENTITY.json` records their hashes;
`RESULT_695.json` preserves the original result; `SINK_REVIEW.json` records each
sink's source location and concrete producer.

| Sinks | Observed producer before cryptographic use |
| --- | --- |
| 1–2 | The journal owner derives the complete signing key through HKDF. |
| 3–6 | The chain step expands 64 bytes and copies each exact 32-byte half. The disclosed-chain and fresh-key tests call that same schedule; the fresh test first fills its seed from entropy. |
| 7–8 | Journal provisioning fills the allocation from entropy; reopening reads the complete protected key file before returning the owner. |
| 9–10 | Bootstrap keys come from the SDK purpose derivation or the two-secret bootstrap schedule. Export copies the complete derived value. The independent vector test uses explicitly synthetic IKM. |
| 11–12, 16–17, 20, 22–23 | Domain-specific HKDF calls fill the whole buffer; errors propagate before HMAC construction. |
| 13–14, 18 | Report keys are filled from entropy before use and preserved as exact journal bytes. Absent/terminal placeholders do not grant a live key. |
| 15, 19, 21 | Adversarial tests explicitly derive the key before constructing or checking their MACs. Their test-only location alone is not the reason for disposition. |

The exhausted receive-chain zero assignment was checked separately from initial
allocation. Once `received >= receive_limit`, indexes at or beyond that limit
are refused before a new chain step; earlier indexes use retained skipped keys
or already committed input records. A missing report/confirmation key returns
an error before the reported cryptographic use.

The reported `[0u8; N]` source is buffer initialization or fenced erased state,
not an operational hard-coded key on these inspected paths. No cryptographic
constant or product code was changed to quiet the finding. No new runtime test
is claimed for this source review. It does not prove entropy health, arbitrary
host-supplied key quality, nonce uniqueness, protocol security, or physical
erasure. Those are separate properties and trust boundaries.

Together with the earlier six dispositions, **7 of the original 780 results**
now have completed dispositions; **773 remain without one**. No inference about
newer SARIF result counts or complete release security follows from this review.
