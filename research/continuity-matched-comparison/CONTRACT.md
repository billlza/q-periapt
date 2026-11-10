# Matched directed-opportunity experiment

## Question and execution unit

The experiment measures application admission, passive snapshot reconstruction,
charged communication, and persistence work under one fixed sequence of directed
transport opportunities. One opportunity permits **one emitted frame**, with an
8,192-byte frame cap. An output created while receiving a frame is queued; its
transmission requires a later opportunity in the output's direction.

Each of 2,048 opportunities also offers one 32-byte application request to its
designated sender. The request identity is the opportunity index. A blocked
request remains in that sender's FIFO. The report separately counts offered,
first-committed, delivered, and uncommitted requests. Exposure is reported both
as the exact reconstructed request set and against the admitted-request count;
unadmitted requests never count as recovered secret messages.

The seven direction/delivery schedules are the existing alternating, lossy,
reverse-batches-of-seven, immediate-network-duplicate, 9:1, offline-prefix-256,
and one-way schedules. Loss and delivery order depend on the common opportunity
ID, not on a protocol's message counter. A network duplicate adds a delivery of
the same emission. A protocol retry consumes another opportunity and preserves
its existing logical operation and exact frame. At the end, already emitted
queued frames can be delivered; replies they create remain unsent.

## Capture

Capture occurs **before opportunity 1**, after opportunity 0's scheduled local
and network actions, before any local computation for opportunity 1. Both owners
are captured in separate predictor instances. The observation object is the
complete current session-state representation, including retained roots,
traffic chains, skipped keys, and pending protocol entropy. Public transcript
access includes every emitted frame, including a frame dropped before peer
delivery. Future private state and future RNG inputs are excluded.

For Continuity, an authenticated session record plus its matching wrapping key
maps to that record's complete decoded `State`; unrelated journal records and
the separately owned identity signer are outside this capture. Initial matched
profiles use application-send budgets 32 and 64. The native harness checks that
this fixed cut precedes pending next-rekey entropy in both owners. Its predictor
is constructed from the actual captured record and then detached from the honest
journals. The SPQR and whole-KEM predictors retain their existing complete-state
captures, including any pending key created by their first opportunity.

This is a passive disclosed-session-state experiment. The distinct authentication
authorities are recorded with each construction. `not_derived` is the specified
predictor's outcome; the established computational theorems retain their games.

## Constructions and arbitration

The reference starts are SPQR at upstream
`f2589fef855c10f39d72634dab3d14654dd410bf` (32-byte chunks), its retained 64-byte
variant, and whole-KEM local-send intervals 1, 32, and 64. Their pinned component
engines and predictors run through the existing locked Cargo workspaces.

Continuity starts at an established, activated native session using the existing
`Pair` fixture and real `DeviceJournal` methods. Budgets 32 and 64 use the existing
policy interface. Each owner cycles fairly over ready control, acknowledgement,
exact-retry, and new-application queues. The initial queue cursor chooses the
first application request. Advancing the control driver may prepare an output;
it never transmits that output outside an opportunity. A full application-send
budget requests the next rekey. `Suspended`/`RekeyRequired` admission outcomes are
recorded explicitly; other unexpected errors fail the experiment.

Reference components already combine a control fragment with one message-key
allocation. They consume one directed opportunity per component frame. The
observer records their actual component bytes. A separate common 32-byte payload
AEAD audit can account for complete reference envelopes using private measurement
key feeds; raw keys remain confined to the measurement process and are excluded
from the published evidence. Native application, control, ACK, and retry frame
bytes retain separate columns so their service work is visible.

## Persistence and timing

Native measurements include committed journal revision increments and actual
`sync_data` calls through the existing counting backend, with provisioning and
bootstrap outside the measured interval. Reference state-return/serialization
operations are logical persistence operations. Physical sync and physical write
metrics are null for reference runs without a storage adapter. These fields are
not converted into zero-cost disk claims. Timing columns retain the measured
operation boundary and are not used for a cross-service speed ranking.

## Controls and publication

The schedule checker rejects a second emission in one opportunity, a wrong-owner
emission, an uncharged response, delivery of a nonexistent emission, a changed
duplicate, and substituted capture coordinates. A minimal four-flight model
provides an explicit counterexample: a receive-drains-replies loop completes an
exchange under an A-only opportunity sequence, whereas charged transmission
leaves B's first reply queued. This control checks the accounting rule.

Native execution additionally checks exact plaintext recovery, independent HMAC
chain prediction from the captured seeds, wrong-seed rejection, distinct new
message keys, and no new logical delivery on an exact retry. Hosted output is
accepted only with the exact prepared-source hashes, Cargo lockfiles, executable
identity, complete scenario/profile inventory, and successful exit status. A
dedicated workflow performs the real native/reference runs; local schedule and
parser controls are retained as their own execution class.
