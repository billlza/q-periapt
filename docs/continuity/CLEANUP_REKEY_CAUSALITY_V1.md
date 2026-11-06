# Cleanup fences and the selected rekey reservation

This is a conditional phase/causality argument for the native ordinary-journal
history, with focused Debug/Release executions. It narrows one part of the
[KEM adapter](KEM_CHALLENGE_ADAPTER_V1.md) correspondence problem. It is not
a MAC-hiding theorem, a complete native-to-virtual reduction, a new Tamarin
certificate or the completed multi-epoch secrecy claim. Runtime sources are
unchanged from `932e6e5d5c84efcb2d42fb194cb748c446cde6db`; one existing test is
extended. [The evidence](../../research/sdk-alpha1/evidence/20261106-cleanup-causality/README.md)
pins the exact sources, test change and executions.

## A closed peer can still have a sending counterpart

The extended native test checks three schedules in the original session:

| Point at which one endpoint closes | Subsequent observed behavior |
| --- | --- |
| Proposer has a committed offer, with its generation token still retained | The responder can generate its response, but the closed proposer refuses acceptance. The responder's next message ID still belongs to epoch zero. |
| Responder has a committed response | The live proposer accepts that retained response, reaches `FinalReady`, and releases an actual 137-byte epoch-one ciphertext. The closed responder refuses reception with `Suspended`. |
| Proposer has a committed final | The live responder accepts the retained final, completes its own cutover and releases an actual 136-byte epoch-one ciphertext. The closed proposer refuses reception with `Suspended`. |

The latter two ciphertext lengths reflect the test's distinct synthetic
plaintexts. They are observations, not protocol limits. No business delivery to
the closed peer is claimed. In particular, a proof about a target **send**
cannot replace that event with successful receipt, both peers' confirmation,
or the absence of any cleanup report. The two actual sends refute the blanket
shortcut “one endpoint has closed, so no target-epoch message can exist.”

## Where the selected KEM coins remain

Fix a positive epoch `e` and the matched original generation/encapsulation
invocations from the adapter. Assume its honest body-origin and exact binding
premises: accepted selected flights come from that original history, outside
the separately accounted forgery/collision/origin events. Use the existing
one-authoritative-lineage contract, rather than granting a restore/fork of a
previous live image. None of these premises is established merely by a report
ID or a local epoch counter.

The source's logical control encodings have this dependency order:

- [`rekey::Plan`](../../research/continuity-identity-candidate/src/durable/messages/rekey.rs)
  retains the selected generation token only in `Key`, `Signing` and `Ready`
  (phases 1–3). `accept_rekey_response` replaces that plan with the phase-7
  completion plan containing the derived root and signing reservation, before
  the final is produced. `FinalReady` installs sending epoch `e` in phase 8.
- [`response::Stage`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs)
  retains the selected encapsulation token only in phase 4. Phase 5 replaces it
  with the ciphertext body, derived root and signing reservation. Phase 6
  persists the ready response before ordinary release.
- [`completion`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs)
  installs the responder's sending epoch `e` when it commits the receipt after
  accepting the original final. That final requires the proposer's preceding
  completion path. It does not require that the proposer has received the receipt.

Therefore an ordinary target-epoch send in the matched history needs both
selected-token stages to have been passed. This is about the state used for
operational admission. Historical images, old pages, backups and pending source
copies may still contain tokens; no physical erasure is inferred. A pending
transition also fences its predecessor rather than authorizing new work from
that older applied image.

## A retained ordinary intent is different from an attempted close

Both independent closure and fanout abandonment first construct their report,
then retain the freezing target through the ordinary write-intent path.
Ordinary successful report release additionally checks the storage/Witness
boundary. An error from `begin_*` alone identifies neither a committed freeze
nor an absent intent.

The [ordinary intent implementation](../../research/continuity-identity-candidate/src/durable/write_intent.rs)
and [`Active::load_image`](../../research/continuity-identity-candidate/src/durable.rs)
give a narrower, inspectable barrier:

1. A retained original ordinary `PendingWrite` contains the exact sealed target.
   A different reservation cannot overwrite its occupied pending slot.
2. Operational image admission refuses a pending intent. Local recovery applies
   the exact target; witnessed reconciliation first establishes its required
   Witness outcome and then applies that same target.
3. Ordinary apply removes the intent in the transaction that installs its
   original target. The separate credential/policy cancellation machinery is
   not a generic API for discarding an ordinary closure target:
   `retire_witnessed_credential_intent_in_database` checks the retained
   `credential_intent`, and `credential_proposal` rejects a write without the
   required `BoundTransaction::Credential` binding. An ordinary closure write
   is constructed with `binding: None`.
4. Once the closure/abandonment target is installed, normal application and
   rekey operations are fenced. Acknowledgement produces terminal, keyless
   session records rather than reopening the original session.

Thus, for the ordinary core history above, a genuinely retained freezing target
cannot be treated as permission to resume its live predecessor. This argument
does not claim an exhaustive refinement of every root/Witness handoff,
platform storage failure or hostile modification. Those compositions must retain
the same barrier or establish their own correspondence before using it.

The public pending-recovery path makes this distinction observable:
[`inspect`](../../research/continuity-identity-candidate/src/durable/write_intent/pending_recovery.rs)
projects both the original source and proposed target through
[`project_records`](../../research/continuity-identity-candidate/src/durable/retired_report.rs).
A target session can expose `previous_closure: Some(report_id)` before Witness
application or local image installation. That metadata is neither a commit
receipt nor permission to ignore the retained intent. The executed recovery
tests observe this pre-/post-Witness distinction, preserve the original proposal
and report through joint renewal, and complete the same report acknowledgement.

## Conditional stopping rule for the selected KEM pair

Suppose a cleanup target is genuinely retained or installed in that ordinary
history, and the frozen member's current control payload still contains the
**selected original generation or encapsulation token** for epoch `e`. The
origin is a semantic invocation identity, not an accidental equal byte string
or merely the current global revision.

There could not already have been a matched epoch-`e` send: the necessary
generation/completion or encapsulation/response stage would have consumed that
current token. While constructing this target, exclusive admission prevents a
competing local control transition from overtaking it. The peer's available
earlier flights do not supply the missing authenticated final or response.
After the retained-intent barrier, the necessary local transition remains
fenced. Consequently no matched epoch-`e` send exists in a continuation of
this particular original history.

For a fixed-pair experiment whose eligibility requires that send, this is a
conditional reason for its unconditioned `Eligible AND output` bit to be zero.
It applies to that selected pair, not to every target an adaptive adversary
could choose in another session/history. It does not reject a real SDK call,
condition probabilities on cleanup success, or add a new Snapshot/entropy
exclusion. An efficient native origin/intent classifier is still required to
use this rule inside the complete adapter.

The rule deliberately does not cover a response-ready/final-ready cleanup
whose selected token has already been consumed; the executed counterexamples
show why. Nor does it cover failures before a target is durably retained,
transient report material, acquired partial residues, independently restored
histories or merely seeing an unverified report identifier. Errors and the
zero-MAC branch retain their actual semantics.

This can remove some terminal continuations from a selected **KEM-coins**
serialization problem. It does not remove the
[cleanup-MAC simulation obligation](CLEANUP_REPORT_MAC_V1.md): later root,
traffic-key or AEAD hybrids may hide state that remains after the target send;
report-key dependencies and permitted acquisitions still matter. The unchanged
MAIN predicate, shared-oracle composition and full private-state bridge remain
required.
