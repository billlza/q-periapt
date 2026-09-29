# Independent control progress candidate

The v6 candidate adds identity-signed requests and target-bound control steps to
the existing four-flight rekey. These APIs use real journal transactions and do
not require an application to send dummy data. They are not yet the installed
product transport, a recovery proof or a selected periodic-rekey policy.

## Request grammar and authority

The next target's non-proposer may request progress. The exact 153-byte body is:

`QPRKRQ01[8] || profile[32] || context[32] || session[32] || completed:u64 || target:u64 || requester:u8 || parent[32]`

The target is `completed + 1`, using the same checked limits and parent transcript
as the offer. The requester is the opposite of the target's designated proposer.
The request uses the normal strict hybrid-signature envelope, with distinct
identity purpose **13**. Both signatures must verify against the requester's
credential from the exact context. The v6 profile binds `control-request/v1`
alongside the application budget and settled-prefix contracts. There is no
unsigned wake-up or fallback to a previous profile.

A request grants no application slot and installs no key. It does not assert
that the requester has settled old history. The actual offer and response still
check their respective histories before reserving new KEM material. A request
alone does not prevent explicit application accounting of older closed epochs.

## Durable preparation, cancellation and replay

`prepare_rekey_request` first commits purpose/body-bound signing randomness, then
computes the hybrid signature and commits the exact public outbox. The body is
derived from the retained epoch/context/parent; none of those fields can change
while this request is pending. Reopening resumes that reservation, and repeated
release returns the same bytes. Policy, roster and required-witness checks apply
before work and release. An invalid cached signature closes the owner.

`respond_rekey_request` authenticates every field and both signatures before
calling the existing offer transaction. Concurrent or duplicate valid requests
join the same target and offer. A request for the retained completed target can
only replay that target's old offer. Older targets fail with `Retired`; future,
wrong-role and cross-context targets fail without reserving work. There is no
request nonce cache or unbounded list of peer requests.

One optional local request is retained alongside the existing control plan. It
is erased on actual local completion. If an offer arrives while request signing
is pending, the response may proceed; completion satisfies that same request and
retires the unused reservation. Cancellation of dispatch never clears or replaces
the journal's pending state. A lost commit/release result requires exact journal
reconciliation, just like the other flights.

The unpublished journal advances to **v17** (`continuity_device_candidate_v17`,
`QPVLT017`, `QPVIMG17`), message state **QPMST009** and control **QPRKST03**.
The request phase (`0` absent, `1` plus a 64-byte signing reservation, `2` plus
the fixed signed request) precedes the existing offer/response/completion plan.
Earlier images are refused without reset or implicit migration. Traffic records
remain QPTEPO03; the signed policy remains the 200-byte QPSESP03 grammar.

## Control steps and host scheduling

`advance_rekey_control(context, session, target, signer, now)` starts or resumes
one explicit target. It chooses a request for the non-proposer, an offer for the
proposer, or the exact retained input needed to resume an admitted later flight.
It performs at most one flight preparation and returns at most one fixed-size
public output. Once that target is locally complete, it returns
`LocallyConfirmed(target)` and never silently starts another epoch.
`rekey_progress.pending_epoch` includes a retained request. Its read-only status
does not authorize dispatch after authority loss.

`receive_rekey_control` strictly identifies one request/offer/response/final/receipt
and routes it through the same authenticated transaction APIs. Accepted receipts
return local completion rather than manufacturing another acknowledgement. The
caller keeps servicing inbound control after local completion: if a receipt was
lost, the proposer's repeated final elicits the exact retained receipt. The last
completed transcript also permits this while the responder has started the next
target. A peer cannot advance two targets without the other peer's participation.

The host must assign a bounded retry count, monotonic deadline and queue capacity
to each explicit target and keep control delivery independent of application
payloads. On cancellation or exhaustion it reports that outcome, stops dispatch
and retains the target for reconciliation. A transport timeout does not mean
that a journal write or peer receipt failed to commit. These synchronous step
APIs introduce no background task, automatic retry loop or unbounded queue.
The test driver uses at most 32 polls and eight deliveries per poll, with a
32-packet queue. Those are test schedule bounds, not product retry defaults.

## Verification scope

The targeted tests use actual signatures, hybrid KEM operations and encrypted
journals. They cover repeated/retired targets, both directions of one-way traffic,
an otherwise idle peer, loss and duplication of each control flight, dispatch
cancellation followed by owner reopen, request/offer sync faults and request
process cuts. Signed wrong context/profile/role/epoch/parent and signature-purpose
substitution must leave the recipient's revision unchanged. Separate public-byte
vectors include the request and verify both signatures with OpenSSL.

The final 2026-09-29 source passes **166 release tests in 248.18 seconds** (278.681
including compilation). The five control-specific tests measure eight sync
barriers for request preparation and thirteen for request-driven offer admission;
all **42 before/after faults** recover. Three process cuts cover request reservation,
signature computation before pinning and committed outbox. At each cut a separate,
deadline-bounded competing process observes `Busy`, and post-kill recovery completes
the actual exchange. The required-witness test loses the sixth request, the final
request-release query, then reopens and releases the already committed request.
Cached-signature corruption closes the owner; signed field changes and purpose
substitution leave the receiving journal revision unchanged.

The public-only oracle now verifies **20 envelopes and 100 signature negatives**,
including purpose 13 and the exact request-to-offer context/epoch/parent binding;
30 membership proofs and nine selections also pass. The separate witness oracle
verifies 12 envelopes and 60 negatives. Strict all-target Clippy passes on Rust
1.98.1 and 1.90. Formatting, warning-strict documentation and 45 standalone
source/inventory checks pass for 188 tracked Rust files. Source archives, raw
commands/results and binary hashes remain distinct from the prior v5 evidence.

An initial all-target build found the missing new field in the prior-control
reconstruction, and subsequent checks found a test-helper lint and an incorrect
mutable fixture borrow. Those diagnostics are retained; the implementation and
tests were corrected without allowing or suppressing a lint. A preceding full
166-test pass is retained separately from the final run after replay admission
was reordered to avoid demanding a future epoch when replaying completed work.

These finite schedules do not establish arbitrary network liveness, global directory
consistency or continuous PQ secrecy recovery. Product transport scheduling,
periodic trigger policy, installed cross-language service integration and the
matched durable-performance comparison remain required.
