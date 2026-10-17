# Retained-record provenance and the remaining secrecy proof gap

Three auxiliary properties are now independently checked with Tamarin 1.12.0
and Maude 3.5.1. They constrain the persistence part of the recovery argument;
they do not prove message secrecy or the complete product protocol.

| Property | Verified steps | Scope |
| --- | ---: | --- |
| `retained_record_has_saved_origin` | 13 | Every Snapshot has an earlier matching Saved event. |
| `stored_records_follow_fresh_reservations` | 42 | When both reservations follow Cut, every record of that exchange is saved after Cut. |
| `captured_contents_have_stored_origin` | 16 | The exact content read corresponds to an earlier write under explicit observer labels. |

The first two properties are additional lemmas on an isolated copy of the
existing model. Its rules, equations, restriction and original five complete
lemma declarations are unchanged. They are marked `reuse`, but neither is
accepted merely because another query uses it. A fresh process replays both
proofs without `--prove`. A control removes the 13-step proof while retaining
the 42-step proof. The process still exits zero and verifies the remaining
helper; the required helper group is correctly rejected as incomplete.

The content property uses a separate observational extension: one content label
on each of 11 writes, and one on Snapshot. The preparation checks each write
label against the actual Stored fact. Erasing all 12 labels recovers the preceding
model byte for byte. No premise, state fact, network output, fresh value or
restriction is added. These are proof observations, not SDK logs. The new source
lemma is independently proved and replayed in 16 steps. Its original five query
declarations and the two timing-helper declarations remain unchanged.

The relevant distinction between proof-method hints, reusable lemmas and source
lemmas follows the [Tamarin lemma documentation](https://tamarin-prover.com/manual/master/book/007_property-specification.html#lemma-annotations).
The acceptance checks require the helper proofs themselves; an unproved lemma
is not admitted as an assumption supporting a security claim.

The main `clean_reservation_recovers_symbolic_message_secrecy` query is still
unproved. Four bounded attempts fail to produce an accepted terminal result:
ordinary search (180 seconds), induction (600), use of the timing helpers (300),
and use of the content source lemma (300). The two longer cleanup cases require
SIGKILL after the five-second SIGINT grace period; all owned process groups are
confirmed absent. These timeouts are not counterexamples.

Two oracle diagnostics each rank 80 calls, then explicitly leave later goals
open. They produce incomplete proof trees of 229 and 238 steps. All ranked
outputs are checked permutations of actual goal indices; the diagnostic stop
limits search, not modeled traces. The [oracle documentation](https://tamarin-prover.com/manual/master/book/011_advanced-features.html#using-an-oracle)
describes ranking and stopping at unranked goals. Both trees remain unaccepted.
The content source lemma also leaves partial precomputation chains; this
checkpoint establishes no general search-performance improvement or single
root cause for the unfinished main proof.

An initial byte comparison rejects different line wrapping of the honest
witness declaration in interactive and CLI output. A second setup attempt expects
`--parse-only --output` to create a file, but this tool emits its parsed theory on
stdout. Both failures are retained. The final check uses the pinned parser's
actual stdout and compares full declarations exactly; it also checks unchanged
raw declarations, the plain extension's operational prefix, observer erasure,
and oracle call inventories. No formula or trace restriction is weakened.

`CAPTURE.zip` has **101 public members**, SHA-256
`28e1bf06e240b79a7591d4f50f23c032155d812ee571b9a702965faa550b4905`.
`CAPTURE.json` binds all member digests and proof-input identities. Readback
verifies every member, independent replay/control results, semantic checks and
cleanup. Recipes, raw failed attempts, partial proof trees and oracle inputs
remain available. The canonical bare model remains unchanged; experimental
extensions are retained in this archive, not installed into product code.

The [four original checked statements](../20261015-recovery-symbolic-disclosure/README.md)
retain their separate evidence. The new helpers do not establish shared-device,
multi-epoch, computational, explicit-storage or Rust-refinement security. The
next proof work must address signature and KEM/traffic-secret provenance before
claiming the unchanged positive recovery condition suffices.

Base commit: `170bd63b7e6c873a4b0bd4d1dfcb65164d1dde5a`. No private SDK cohort or
device state is accessed, and no global tool installation is changed. The full
0.2.0 goal remains active; this is not release acceptance.
