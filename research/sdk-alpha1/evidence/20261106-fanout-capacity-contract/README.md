# Retained fanout quota in the compiled contract

The numeric descriptor previously exposed the 128 session/operation-record
quota but omitted the journal's separate 16-record fanout limit. Both the
fanout admission and decoder already enforced that smaller quota. A consumer
using the descriptor alone could therefore plan capacity without a relevant
existing constraint.

The runtime and compiled descriptor now share
`contract::MAX_RETAINED_FANOUT_RECORDS = 16`. Descriptor schema 3 adds
`maximums.retained_fanout_records`; the closed-field verifier rejects schema 2
and a schema 3 descriptor with that field missing. This is a metadata correction:
the runtime limit stays 16, and its admission/decoder predicates are unchanged.
Protocol identifiers, signed bytes, storage formats and the product ABI are not
changed. The product contract remains unfrozen.

The [storage contract](../../../../docs/continuity/STORAGE_RECOVERY_V1.md) now
explains that the 16 fanout records also count against 128 operation records and
the aggregate image cap. Acknowledgement alone does not release the aggregate's
slot. Explicit retirement requires the complete original bindings and terminal
member outcomes; reserved/abandoning work, remaining committed ciphertext and
pending resolution prevent retirement. The monotonic ID remains retired after
reopening. These combined ceilings do not promise that every maximum-sized
object can coexist.

## Observed validation

The added Python regression first failed under the prior checker because a
schema 2 descriptor without the quota was accepted. After the change, all eight
contract tests pass, including omission and value changes. The actual installed
schema 2 descriptor retained from source
`21e00e9c3cfd193b9f51491888347f583620dfe0` was executed before and after this
change: it matched the pre-change budgets, then failed the new schema check.
Its SHA-256 is
`cf4bdccd3372bbabffc0d219c0d3db64b4e84baff71f1bec1d98bbbbc9ec4490`.
It is an older installed descriptor, not a newly built binary of parent
`107b17ccb6ef45d016932ffceb9d731a9f00235c`.

The new source-built Release descriptor passes the exact compiled comparison,
including 16 retained fanout records, 128 session/operation records and
32 roster devices. Its SHA-256 is
`a4122e901315fb517243c4771f0bbcd5c503eda73ec6d6f9adb58d3de5e88a15`.

Two actual native tests pass in both Debug and Release, for four executions:

- `account_fanout_capacity_and_id_scope_preserve_earlier_committed_work` now
  fills all 16 slots, observes an unchanged journal and unreserved next ID on
  refusal, and replays the first original ciphertext. Retirement before
  consumption is refused. After authenticated consumption, capacity is still
  full. Explicit retirement and reopening free exactly one slot; the old ID is
  rejected, the original next ID is admitted, and all fifteen other original
  batches retain their exact ciphertexts. Capacity refusal applies again after
  that one replacement is admitted. Wrong-journal ID rejection also remains.
- `account_fanout_abandonment_does_not_need_an_extra_batch_slot_at_capacity`
  retains the existing full-capacity abandonment regression.

The native tests use the actual source journal/API implementation with their
existing fixtures. They do not measure installed-package throughput or qualify
32-recipient resource use. Other library tests were not rerun for this constant
extraction. Strict all-target Clippy with warnings denied and the formatter
check pass with the original TLS features enabled. No timeout or assertion is
relaxed. The initial formatting-only failure is retained alongside its repair.

## Evidence and remaining scope

[VALIDATION.json](VALIDATION.json) records the ten exact commands and their
results, including the intentionally rejected old descriptor. Validation runs
from 2026-11-06 05:48:45 to 05:57:09 UTC. [CHECKS.json](CHECKS.json) pins the
nine changed source/document files before and after the change, the source
inventory and test executables hashed after execution. The runtime source
comparison verifies that the only operational edit replaces the private
16-valued constant with the shared 16-valued constant.

[CAPTURE.zip](CAPTURE.zip) contains 77 members, 226,307 bytes, SHA-256
`057e5be1bed6e9f4735e778ccb7e448d075de4730a5080a2adadf432f5b64237`.
It retains command receipts/logs, red/green evidence, the original format failure,
both descriptor outputs, old native provenance, source snapshots and the
validation/retention scripts. Every member was reread against
[FILES.json](FILES.json). Native executables and private runtime stores are not
inside this capsule; this hash/readback is not a native execution replay.

Current source `5678d101` Kotlin/Swift package qualifications run independently
in their unchanged isolated checkout. Their results retain that lineage. This
checkpoint supplies source-level contract and capacity evidence; final package
identity, declared resource budgets, platform qualification, protocol/ABI
admission, external review and release remain separate obligations.
