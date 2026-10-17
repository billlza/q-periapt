# Inherited-root multi-epoch projection

Status: **the unbounded transition model parses, but no property or witness is
verified in this checkpoint.** Six bounded proof-search processes reach their
deadlines without a terminal verdict inventory. Timeouts are neither attacks nor
security proofs. The earlier checked single-exchange results remain scoped to
their own models.

The [editable model](../../../continuity-recovery-symbolic/multi-epoch.spthy)
preserves one stable session/context, permanent device roles, alternating
proposers, inherited roots and completed four-flight transcript parents across
arbitrarily many rounds. Only the initial root is sampled independently and made
public. Local confirmation and active sending epoch are separate: the proposer
installs new sending state before receiving the receipt, while the responder can
reserve the next offer after sending that receipt. Signed closing counts fence
new sends during the two closing-signature reservations.

The [source correspondence map](MODEL_MAP.md) identifies the relevant Rust
transitions and the abstractions that remain. This is a new source-grounded
projection, not a proved extension or refinement of the SDK or earlier theory.

Four queries are retained in full:

- A two-round normal execution with the actual first completed root known to the
  attacker and both second-round reservations after Cut. This requests
  reachability, not secrecy.
- A delayed first-round receipt, one captured second-round generation reservation
  before Cut, and knowledge of the exact second-round payload. This is a proposed
  symbolic counterpart of the earlier SDK counterexample; no symbolic witness
  has yet been accepted here.
- Each reservation inherits a root/parent from an earlier local Ready event.
- A proposed secrecy statement for an arbitrary selected recovery epoch, with
  both reservations after Cut, no disclosure of the actual target identity keys,
  no selected-epoch entropy disclosure, and no acquisition of any target-session
  record written after Cut. Other epochs and sessions remain in the model.

The last capture condition covers subsequent epochs because they can retain a
prior recovery root. It is a hypothesis about attacker access, not a condition
the runtime can infer from protocol progress. No restriction bans disclosures;
the only trace restriction enforces signature/confirmation equalities.

| Experiment | Input change from the original model | Deadline / heap | Observed terminal result |
| --- | --- | --- | --- |
| `execution-03` | None; normal execution query | 600 s / 12 GiB | Timeout, no verdict; saturation step 1 |
| `inheritance-04` | None; inheritance query | 300 s / 6 GiB | Timeout, no verdict; saturation step 1 |
| `inheritance-06` | Defer eight send-state/permit premise sources | 300 s / 6 GiB | Timeout, no verdict; saturation step 1 |
| `inheritance-09` | Also defer other honest protocol premises | 300 s / 6 GiB | Saturation completes; timeout before terminal inventory |
| `inheritance-12` | Also defer five network-input premise sources | 300 s / 6 GiB | Saturation completes; timeout before terminal inventory |
| `inheritance-14` | Prioritize two Ready premises on the `09` variant | 300 s / 6 GiB | Saturation completes; timeout before terminal inventory |

All use pinned Tamarin 1.12.0 / Maude 3.5.1, one thread, full derivation checks,
`--quit-on-warning` and bounded output. The process runner allows a five-second
interruption grace period, then kills only its owned group if necessary. All six
groups are absent at capture. The last three logs show completion of saturation;
they do not isolate the cost of subsequent processing or prove the search is
looping. No resource threshold was relaxed. These costs describe the prover,
not SDK runtime performance.

Each parser-valid variant erases byte-for-byte to the original complete theory
after removing search annotations. The official manual documents
[`no_precomp` and priority annotations](https://tamarin-prover.com/manual/master/book/011_advanced-features.html#fact-annotations)
as controls on precomputation and search; they do not alter unification.
An earlier annotation generator also matched let-term applications and was
rejected by the parser. Its input, script and error remain in the archive; a
fresh generator confines annotation to premises. It was never used for proof.

Perfect cryptography, individual-record capture and atomic admitted transitions
remain abstractions. Whole-journal image encryption and restore, concrete KDF
and hybrid security, signing randomness, message chains/nonces, receive state,
history retirement, policy/witness admission and crash refinement remain open.
Successor counters overapproximate finite checked integers, and initial traffic
is omitted. Cut exposes both wrapping keys; the negative query captures one
responder record but does not grant only one key. The witnesses require distinct
identities, not distinct wrapping keys.

The next proof investigation must distinguish source-generation cost from
query-solving cost, for example with bounded precompute-only diagnostics and
inspection of raw/refined sources. Repeating full searches or changing the
protocol to reset roots would not resolve that uncertainty. The normal and
negative two-round traces, structural property and arbitrary-epoch secrecy
statement all remain unproved. This model is not added to a passing CI profile.

`CAPTURE.json` records exact inputs, commands, terminal receipts and member hashes;
`READBACK.json` records a complete readback of all 69 members. The archive is
99,213 bytes, expands to 393,472 bytes, and has SHA-256
`b65c5fade336985d09049adc3b60263a0140431fb26b4e3ba22911d19847031c`.
Only public symbolic experiments and relevant source files are included. No
private device or SDK cohort was reopened, and no product code changed.
