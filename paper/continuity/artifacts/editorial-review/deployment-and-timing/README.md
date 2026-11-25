# Deployment discussion and absolute timing measurements

This revision addresses three questions left open by the manuscript's
two-party experiments: what happens when device state is synchronized, how
the journal discipline maps to SQLite/WAL, and how long the measured
operations take on an explicitly identified host.

## Changes to the manuscript

Section 8 distinguishes per-device pairwise sessions from two devices
advancing one copied endpoint state. Device namespaces and ownership
transfer preserve the original draw. An unchanged copied version keeps its
first-save event. The proposed extension gives each device its own journal
and treats its fanout sessions as local siblings. Account-wide and group
security additionally require their membership and plaintext-copy rules.

The adjacent SQLite/WAL discussion identifies the pending-operation
transaction, the later state/outbox transaction, and uncertain-outcome
reconciliation. Local writer serialization does not replace protocol owner
and version checks. The discussion separates FULL/NORMAL durability from
application crashes, commit from checkpoint, and logical rollback from
physical acquisition of an intact version. This is a proposed storage
mapping, not a claim that a SQLite adapter has been implemented or tested.
Eight official references support the mechanisms; `primary-sources.json`
separates those facts from the manuscript's provenance inference.

Section 7.6 adds two measurements using the exact service-source revision
`358b921ab3469ce49f166633fc9a762ff6ed7e3d`. Table 15 gives wall-clock and
process CPU means for six cryptographic backend operations. Table 16 gives
mean, median, 95th percentile and maximum for 256 individually timed
same-host deliveries between distinct real file journals. The wall-clock
delivery mean is 24.531298 ms; process CPU mean is 18.690721 ms. All samples,
including the largest wall interval of 257.105098 ms, remain in the data.

The delivery interval includes sender reservation/state/outbox persistence
and receiver state/inbox persistence, ending at committed plaintext. It
does not contain network delay, bootstrap, rekey, application consumption
or acknowledgement processing. The separate primitive measurements omit
OS randomness acquisition and storage. Neither capture is used to convert
the earlier directed-opportunity budgets into real-time throughput.

## Evidence and verification

`../../latency/` retains the source closure, harnesses, lockfiles, compiler
and host receipts, raw timings, generated statistics and tables. Its checker
verifies 625 upstream blobs by Git object ID and SHA-256 and recalculates
both manuscript tables. An initial capture of a newer backend remains
explicitly separated under `preliminary-9503/`; it supplies no paper number.

The retained model and measured delivery boundary were independently
checked against the definitions and native source. The optional syscall
trace was denied by the capture environment; the artifact records that
failure and makes no measured sync-count claim.

The integrated `make check` target passed. A fresh nine-file submission
export compiled with exactly matching plain and layout text; all 48 fonts
are embedded, and final compiler logs have no warnings, missing glyphs or
underfull/overfull boxes. The reading copy has 128 pages, a 229-word abstract
and seven keywords. New tables, discussion, references and the timing
appendix were visually inspected.

`source-preservation.json` checks all 40 original canonical modules. The
58 formal statements, 53 proofs, 170 displayed mathematical groups and 741
original artifact files remain byte-identical. The original quantitative
tables, author metadata, declarations and bibliography entries are retained.
The research-question table gains a row linking execution cost to the new
measurement. `validation.json`, `build-check.json` and
`source-export-check.json` identify the local verification receipts.
