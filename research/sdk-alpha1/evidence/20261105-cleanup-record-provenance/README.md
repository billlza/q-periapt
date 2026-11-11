# Cleanup report storage and acquisition provenance

The [report-key source map](../../../../docs/continuity/CLEANUP_REPORT_MAC_V1.md#report-key-storage-and-acquisition-scope)
distinguishes session closure, fanout abandonment and closed-epoch resolution.
Thirteen encoder/transition/test files are pinned to
`4cda512f0e2a8d5e986f49a28261bd37a74cb0bb`; all thirteen are identical at the
locally validated product commit `1bdb29a20d1d9c68496648f3be91efad710e4b0c`.
No product or Rust test source was changed.

Session closure stores its report/key beside the complete private session
state. Fanout stores its report/key in a separate batch record and authenticates
the member session payloads. Closed-epoch resolution stores its key inside one
traffic entry and returns unconsumed plaintext to the authorized application;
the existing public contract already distinguishes this from metadata-only
closure/abandonment. Their acknowledgement paths remove or zero current logical
key owners, without promising to erase historical copies or caller-owned data.

Two consequences constrain the existing proof obligation. A fanout batch-key
fragment does not necessarily contain a member's private state, so its exposure
alone cannot be assumed to trigger the selected-session Snapshot exclusion.
Also, a pending resolution key/tag is included when a later report MAC covers
the complete session payload. A joint report reduction must handle this private
key dependency. These are source observations about the unfinished native
interface mapping, not a demonstrated protocol attack or a new corruption
exclusion. The conditional one-report lemma remains conditional.

The capsule references nine already completed cases in the
[1,461-case Release run](../20261105-renewal-roster-verification/README.md):
four closed-epoch resolution cases, three session closure cases and two fanout
abandonment cases. Each has one exact `... ok` line in the original full log.
The selected cases cover retained data and report IDs, authorization/tamper
refusals, rekey closure boundaries, original sync-fault recovery and process
cuts. They do not execute every nested-report combination or arbitrary partial
acquisition. **No new native test was run for this source audit.**

The full original log, its receipts and the original inventory-reader failure
are retained in the capsule. The existing independent readback resolved that
reader's two legitimate `should panic` annotations; this audit does not rewrite
the original failure as a successful driver run. The original validation ZIP
has SHA-256 `9c6e0a574fe197d88f4e3b2ba6299948c28d2a490e444e919e7ba970580e3a34`;
the original test binary identity remains in `SOURCE_AUDIT.json`.

`CAPTURE.zip` contains the thirteen source files, source-map note, capture
script, prior-run receipts/streams and this audit's source/test mapping. All
21 members were read back and checked against `FILES.json`: 126,506 bytes,
SHA-256 `3c570c98d3611b0cd44eba1ee0ee0a9caa7601e95069666317450f4689d1899a`.
This closes a report inventory/provenance task, not the multi-report simulation,
all native acquisitions, physical erasure or the multi-epoch computational proof.
